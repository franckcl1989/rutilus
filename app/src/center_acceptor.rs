//! The Center's inbound connection layer (design §15, 0.7.0 S3b): the
//! dedicated listener that sites connect to.
//!
//! One accepted connection runs through four stages before it is handed
//! out:
//!
//! 1. **mTLS** — TLS 1.3 with a client certificate required and verified
//!    against the center CA as the only trust anchor
//!    ([`WebPkiClientVerifier`]). A client without a certificate, or with
//!    a certificate from any other CA, fails the handshake.
//! 2. **WebSocket** — the site's upgrade request on the `/center/v1`
//!    endpoint path, served as a binary frame transport (one frame per
//!    message).
//! 3. **Negotiation** — the first frame must be a `Hello`; the center
//!    answers every `Hello` with a `NegotiationResult` (§15.3), so a
//!    rejected site learns why it cannot join.
//! 4. **The frame loop** — every subsequent frame is dispatched to the
//!    connection's handler; a connection that goes silent for
//!    [`CENTER_DISCONNECT_AFTER`] (90 seconds, three heartbeat intervals)
//!    is declared dead.
//!
//! The connection identity is parsed from the presented client
//! certificate: its SHA-256 fingerprint (the mapping key to a registered
//! site instance — the next slice's job), its subject common name (the
//! site instance id it was issued for), and the site-identity fingerprint
//! the CA bound into the certificate at issuance.
//!
//! The center's own server certificate is issued by the center CA for the
//! listen address and persisted below `tls/` (`center-cert.pem`,
//! `center-key.pem`), so the certificate the operator pins on the site
//! side (§10.4 explicit trust) is stable across restarts.

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::{SinkExt as _, StreamExt as _};
use rustls::{RootCertStore, pki_types::CertificateDer, server::WebPkiClientVerifier};
use rutilus_application::{
    AdmissionRejection, AdmissionVerdict, BoundaryFuture, CenterSessionAdmission,
    CenterSessionAdmissionError, ResolvedSite, SiteIdentity,
};
use rutilus_center_protocol::{
    CENTER_DISCONNECT_AFTER, Envelope, EnvelopeMessage, FrameError, Hello, NegotiationDecision,
    NegotiationReason, NegotiationResult, encode_frame, negotiate,
};
use rutilus_domain::{CertificateFingerprint, InstanceId};
use rutilus_persistence::{CenterBindingRepositoryError, SqliteStore};
use rutilus_platform::RuntimePaths;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use crate::{
    CenterCa, CenterCaError, ListenAddress,
    center_ws::{CenterFrameHandler, InboundFrame, inbound_frame},
    tls_material::{pem_encode, persist_text, read_certificate, read_private_key},
    x509,
};

/// The bound for the TLS and WebSocket handshakes and the first-frame
/// `Hello` of one connection: a client that connects without handshaking
/// must not stall the listener forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The center server certificate and key file names below `tls/`.
const CENTER_CERT_FILE: &str = "center-cert.pem";
const CENTER_KEY_FILE: &str = "center-key.pem";

/// The timing bounds of one center connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterAcceptorOptions {
    /// The bound for the TLS and WebSocket handshakes and the first-frame
    /// `Hello` of one connection.
    pub handshake_timeout: Duration,
    /// How long the center waits for a frame before declaring the
    /// connection dead: [`CENTER_DISCONNECT_AFTER`], three heartbeat
    /// intervals, so two missed heartbeats are tolerated and the third
    /// triggers the disconnect.
    pub idle_timeout: Duration,
}

impl Default for CenterAcceptorOptions {
    fn default() -> Self {
        Self {
            handshake_timeout: HANDSHAKE_TIMEOUT,
            idle_timeout: CENTER_DISCONNECT_AFTER,
        }
    }
}

/// The center's inbound listener: one dedicated port, mTLS with the
/// center CA as the only trust anchor, WebSocket frames, and per-connection
/// negotiation.
#[derive(Debug)]
pub struct CenterAcceptor {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    address: SocketAddr,
    ca: Arc<CenterCa>,
    server_fingerprint: CertificateFingerprint,
    options: CenterAcceptorOptions,
}

impl CenterAcceptor {
    /// Binds the center listener with the default timing bounds.
    ///
    /// # Errors
    ///
    /// Returns [`CenterAcceptorError`] when the CA cannot be prepared, the
    /// center server certificate cannot be loaded or issued, the TLS
    /// configuration cannot be assembled, or the listener cannot be bound.
    pub async fn bind(
        paths: &RuntimePaths,
        listen: &ListenAddress,
    ) -> Result<Self, CenterAcceptorError> {
        let ca = CenterCa::generate_or_load(paths).map_err(CenterAcceptorError::Ca)?;
        Self::bind_with_ca(
            paths,
            listen,
            Arc::new(ca),
            CenterAcceptorOptions::default(),
        )
        .await
    }

    /// Binds the center listener with explicit timing bounds (tests use
    /// short bounds instead of the production 10/90-second pair).
    ///
    /// # Errors
    ///
    /// Returns [`CenterAcceptorError`] when the CA cannot be prepared, the
    /// center server certificate cannot be loaded or issued, the TLS
    /// configuration cannot be assembled, or the listener cannot be bound.
    pub async fn bind_with_options(
        paths: &RuntimePaths,
        listen: &ListenAddress,
        options: CenterAcceptorOptions,
    ) -> Result<Self, CenterAcceptorError> {
        let ca = CenterCa::generate_or_load(paths).map_err(CenterAcceptorError::Ca)?;
        Self::bind_with_ca(paths, listen, Arc::new(ca), options).await
    }

    /// Binds the center listener over one prepared CA (the runtime shares
    /// the CA between the acceptor and its certificate-issuer adapter, so
    /// the first-start generation happens exactly once).
    ///
    /// # Errors
    ///
    /// Returns [`CenterAcceptorError`] when the center server certificate
    /// cannot be loaded or issued, the TLS configuration cannot be
    /// assembled, or the listener cannot be bound.
    pub async fn bind_with_ca(
        paths: &RuntimePaths,
        listen: &ListenAddress,
        ca: Arc<CenterCa>,
        options: CenterAcceptorOptions,
    ) -> Result<Self, CenterAcceptorError> {
        let server = load_or_issue_server_certificate(paths, listen, ca.as_ref())?;
        let server_fingerprint =
            CertificateFingerprint::from_certificate_der(server.certificate.as_ref());
        let tls = build_server_config(ca.as_ref(), server)?;
        let listener = TcpListener::bind((listen.host().to_owned(), listen.port()))
            .await
            .map_err(CenterAcceptorError::Bind)?;
        let address = listener
            .local_addr()
            .map_err(CenterAcceptorError::LocalAddress)?;
        Ok(Self {
            listener,
            tls,
            address,
            ca,
            server_fingerprint,
            options,
        })
    }

    /// The center CA: the trust anchor and signing identity shared with the
    /// runtime's certificate-issuer adapter.
    #[must_use]
    pub fn ca(&self) -> Arc<CenterCa> {
        Arc::clone(&self.ca)
    }

    /// The bound listener address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The center CA certificate: the trust anchor a bound site loads to
    /// verify the center.
    #[must_use]
    pub fn ca_certificate(&self) -> CertificateDer<'static> {
        self.ca.certificate()
    }

    /// The SHA-256 fingerprint of the center's server certificate — the
    /// value the operator pins on the site side (§10.4 explicit trust).
    #[must_use]
    pub const fn server_fingerprint(&self) -> CertificateFingerprint {
        self.server_fingerprint
    }

    /// Issues one client certificate for a site binding against this
    /// center's CA.
    ///
    /// # Errors
    ///
    /// Returns [`CenterCaError`] when the CA cannot sign.
    pub fn issue_site_certificate(
        &self,
        site: InstanceId,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<crate::SiteClientCertificate, CenterCaError> {
        self.ca.issue_site_certificate(site, site_fingerprint)
    }

    /// Accepts one connection without an admission check: the mTLS
    /// handshake, the WebSocket upgrade, and the `Hello`/`NegotiationResult`
    /// negotiation, in that order. The returned connection is ready for the
    /// frame loop and carries the site's certificate identity.
    ///
    /// This is the raw accept used by the connection-level tests; the
    /// production accept loop uses [`Self::accept_with_admission`], so a
    /// site whose binding is not in force is refused at negotiation time.
    ///
    /// # Errors
    ///
    /// Returns [`CenterAcceptError`] for a failed handshake, a missing or
    /// unreadable client certificate, a non-`Hello` first frame, or a
    /// rejected negotiation. A rejected site still receives its
    /// `NegotiationResult` before the connection closes.
    pub async fn accept(&mut self) -> Result<CenterConnection, CenterAcceptError> {
        let mut connection = self.handshake().await?;
        connection.complete_negotiation().await?;
        Ok(connection)
    }

    /// Accepts one connection under the admission decision (audit follow-up
    /// F4): the mTLS handshake and the WebSocket upgrade, then the
    /// negotiation, whose `Hello` answer carries the admission verdict.
    ///
    /// An admitted site receives `NegotiationResult { accepted: true }`
    /// and the returned connection carries its resolved site. A refused
    /// site receives `NegotiationResult { accepted: false, reason:
    /// "not-bound" }` — the doc-sanctioned extensible reason code, never a
    /// wire change — before the connection closes, so the site learns that
    /// its binding is not in force and converges instead of retrying
    /// forever. An admission lookup failure refuses the connection without
    /// an answer: a broken center must not converge the site.
    ///
    /// # Errors
    ///
    /// Returns [`CenterAcceptError`] for a failed handshake, a missing or
    /// unreadable client certificate, a non-`Hello` first frame, a rejected
    /// negotiation, an admission refusal, or an admission lookup failure.
    pub async fn accept_with_admission<A: CenterAdmissionResolver + ?Sized>(
        &mut self,
        admission: &A,
    ) -> Result<AcceptedCenterConnection, CenterAcceptError> {
        let mut connection = self.handshake().await?;
        let site = connection
            .complete_negotiation_with_admission(admission)
            .await?;
        Ok(AcceptedCenterConnection { connection, site })
    }

    /// The common handshake of both accept paths: the mTLS handshake, the
    /// WebSocket upgrade, and the identity parse, in that order.
    async fn handshake(&mut self) -> Result<CenterConnection, CenterAcceptError> {
        let (stream, address) = self
            .listener
            .accept()
            .await
            .map_err(CenterAcceptError::Accept)?;
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&self.tls));
        let tls_stream =
            tokio::time::timeout(self.options.handshake_timeout, acceptor.accept(stream))
                .await
                .map_err(|_| CenterAcceptError::HandshakeTimeout {
                    timeout: self.options.handshake_timeout,
                })?
                .map_err(CenterAcceptError::Handshake)?;
        let identity =
            ClientIdentity::from_peer_certificates(tls_stream.get_ref().1.peer_certificates())?;
        let ws = tokio::time::timeout(
            self.options.handshake_timeout,
            tokio_tungstenite::accept_async(tls_stream),
        )
        .await
        .map_err(|_| CenterAcceptError::WebSocketTimeout {
            timeout: self.options.handshake_timeout,
        })?
        .map_err(|error| CenterAcceptError::WebSocket(Box::new(error)))?;
        Ok(CenterConnection {
            identity,
            ws,
            next_sequence: 1,
            acked_sequence: 0,
            address,
            options: self.options,
        })
    }
}

/// Resolves one presented client identity to its admission verdict, so the
/// accept path can answer a refused site at negotiation time (audit
/// follow-up F4).
///
/// The production resolver is the S5 [`CenterSessionAdmission`] over the
/// instance store; the trait keeps the acceptor free of the store type.
pub trait CenterAdmissionResolver: Send + Sync {
    /// Resolves the presented identity to its admission verdict.
    fn resolve(
        &self,
        identity: &ClientIdentity,
    ) -> BoundaryFuture<
        '_,
        Result<AdmissionVerdict, CenterSessionAdmissionError<CenterBindingRepositoryError>>,
    >;
}

impl CenterAdmissionResolver for CenterSessionAdmission<&SqliteStore> {
    fn resolve(
        &self,
        identity: &ClientIdentity,
    ) -> BoundaryFuture<
        '_,
        Result<AdmissionVerdict, CenterSessionAdmissionError<CenterBindingRepositoryError>>,
    > {
        // The identity parts are copied into an owned `SiteIdentity` before
        // the future, so the future never borrows the connection.
        let site_identity = SiteIdentity::from_parts(
            identity.fingerprint(),
            identity.subject().map(str::to_owned),
            identity.bound_site_fingerprint(),
        );
        Box::pin(async move { self.resolve(&site_identity).await })
    }
}

/// One accepted connection and its admission decision (audit follow-up F4).
#[derive(Debug)]
pub struct AcceptedCenterConnection {
    connection: CenterConnection,
    site: ResolvedSite,
}

impl AcceptedCenterConnection {
    /// The negotiated connection, ready for the frame loop.
    #[must_use]
    pub const fn connection(&self) -> &CenterConnection {
        &self.connection
    }

    /// The resolved site of the admitted connection.
    #[must_use]
    pub const fn site(&self) -> &ResolvedSite {
        &self.site
    }

    /// Consumes the accepted connection into its parts.
    #[must_use]
    pub fn into_parts(self) -> (CenterConnection, ResolvedSite) {
        (self.connection, self.site)
    }
}

/// The mTLS identity of one connected site, parsed from the client
/// certificate it presented (§15.1). The fingerprint is the mapping key to
/// the registered site instance; the subject is the site instance id the
/// certificate was issued for; the bound fingerprint is the site's own
/// identity fingerprint embedded at issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientIdentity {
    fingerprint: CertificateFingerprint,
    subject: Option<String>,
    bound_site_fingerprint: Option<CertificateFingerprint>,
}

impl ClientIdentity {
    fn from_peer_certificates(
        chain: Option<&[CertificateDer<'static>]>,
    ) -> Result<Self, CenterAcceptError> {
        let Some(chain) = chain else {
            return Err(CenterAcceptError::ClientCertificateMissing);
        };
        let Some(leaf) = chain.first() else {
            return Err(CenterAcceptError::ClientCertificateMissing);
        };
        let fingerprint = CertificateFingerprint::from_certificate_der(leaf.as_ref());
        let subject = x509::subject_common_name(leaf).map_err(CenterAcceptError::Certificate)?;
        let bound_site_fingerprint =
            x509::site_identity_fingerprint(leaf).map_err(CenterAcceptError::Certificate)?;
        Ok(Self {
            fingerprint,
            subject,
            bound_site_fingerprint,
        })
    }

    /// The SHA-256 fingerprint of the presented client certificate.
    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.fingerprint
    }

    /// The subject common name of the presented client certificate: the
    /// site instance id the center issued it for.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The site identity fingerprint bound into the certificate at
    /// issuance, when the extension is present.
    #[must_use]
    pub const fn bound_site_fingerprint(&self) -> Option<CertificateFingerprint> {
        self.bound_site_fingerprint
    }
}

/// One accepted, negotiated center connection.
#[derive(Debug)]
pub struct CenterConnection {
    identity: ClientIdentity,
    ws: WebSocketStream<TlsStream<TcpStream>>,
    next_sequence: u64,
    acked_sequence: u64,
    address: SocketAddr,
    options: CenterAcceptorOptions,
}

impl CenterConnection {
    /// The certificate identity of the connected site.
    #[must_use]
    pub fn identity(&self) -> &ClientIdentity {
        &self.identity
    }

    /// The remote address of the connected site.
    #[must_use]
    pub const fn peer_address(&self) -> SocketAddr {
        self.address
    }

    /// Sends one protocol message as the next outbox frame (§15.4): the
    /// connection assigns the outbox sequence and piggybacks the highest
    /// sequence received from the site.
    ///
    /// # Errors
    ///
    /// Returns [`CenterConnectionError`] when the envelope cannot be
    /// framed or the transport fails.
    pub async fn send(&mut self, message: EnvelopeMessage) -> Result<(), CenterConnectionError> {
        let envelope = Envelope {
            sequence: self.next_sequence,
            acked_sequence: self.acked_sequence,
            message: Some(message),
        };
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(CenterConnectionError::SequenceOverflow)?;
        self.send_envelope(envelope).await
    }

    /// Sends one envelope exactly as given (§15.4 — the reliable-outbox
    /// engine owns the envelope's sequence and acknowledgement watermark).
    ///
    /// The runtime's inbound engine presents the connection as the
    /// application [`CenterInboundSession`] boundary, which delivers the
    /// engine-built envelope verbatim; this is the verbatim path, while
    /// [`CenterConnection::send`] stays the connection-owned framing path of
    /// the acceptor's own replies.
    ///
    /// # Errors
    ///
    /// Returns [`CenterConnectionError`] when the envelope cannot be
    /// framed or the transport fails.
    pub(crate) async fn send_envelope(
        &mut self,
        envelope: Envelope,
    ) -> Result<(), CenterConnectionError> {
        let frame = encode_frame(&envelope).map_err(CenterConnectionError::Frame)?;
        self.ws
            .send(Message::Binary(frame))
            .await
            .map_err(|source| CenterConnectionError::Send {
                source: Box::new(source),
            })?;
        Ok(())
    }

    /// Waits for the next inbound envelope: one WebSocket message
    /// classified under the one-message-one-frame rule, with the idle
    /// timeout applied and control frames flushed.
    ///
    /// `Ok(None)` reports a clean close; the engine treats it as the end of
    /// the connection.
    ///
    /// # Errors
    ///
    /// Returns [`CenterConnectionError::IdleTimeout`] when no frame
    /// arrives within the idle window, and [`CenterConnectionError`] for
    /// transport and protocol failures.
    pub(crate) async fn receive_envelope(
        &mut self,
    ) -> Result<Option<Envelope>, CenterConnectionError> {
        let envelope = self.next_frame().await?;
        if let Some(envelope) = envelope.as_ref() {
            self.acked_sequence = envelope.sequence;
        }
        Ok(envelope)
    }

    /// Consumes the connection: reads frames and dispatches each to
    /// `handler` until the site goes silent for the idle timeout, the
    /// transport closes, or a protocol violation ends the connection.
    ///
    /// # Errors
    ///
    /// Returns [`CenterConnectionError::IdleTimeout`] when no frame
    /// arrives within the idle window, and [`CenterConnectionError`] for
    /// transport and protocol failures. A clean close returns `Ok`.
    pub async fn run<H>(mut self, mut handler: H) -> Result<(), CenterConnectionError>
    where
        H: CenterFrameHandler<CenterConnection>,
    {
        loop {
            let Some(envelope) = self.next_frame().await? else {
                return Ok(());
            };
            self.acked_sequence = envelope.sequence;
            handler.on_frame(&mut self, envelope).await;
        }
    }

    /// Reads one inbound frame: the next WebSocket message classified under
    /// the one-message-one-frame rule, with the idle timeout applied and
    /// control messages flushed (a ping's pong is queued by the transport).
    async fn next_frame(&mut self) -> Result<Option<Envelope>, CenterConnectionError> {
        loop {
            let inbound =
                match tokio::time::timeout(self.options.idle_timeout, self.ws.next()).await {
                    Ok(Some(Ok(message))) => {
                        inbound_frame(message).map_err(CenterConnectionError::Frame)?
                    }
                    Ok(Some(Err(source))) => {
                        // An abruptly closed transport is the site's normal
                        // end: it reconnects on its own schedule. Only a
                        // protocol-level failure is worth surfacing.
                        if connection_ended(&source) {
                            return Ok(None);
                        }
                        return Err(CenterConnectionError::Read {
                            source: Box::new(source),
                        });
                    }
                    Ok(None) => return Ok(None),
                    Err(_) => {
                        return Err(CenterConnectionError::IdleTimeout {
                            after: self.options.idle_timeout,
                        });
                    }
                };
            match inbound {
                InboundFrame::Envelope(envelope) => return Ok(Some(envelope)),
                InboundFrame::Control => {
                    // A ping's pong is queued by the transport; flush it to
                    // the wire so the peer's liveness probe is answered.
                    self.ws
                        .flush()
                        .await
                        .map_err(|source| CenterConnectionError::Flush {
                            source: Box::new(source),
                        })?;
                }
                InboundFrame::Closed => return Ok(None),
                InboundFrame::ProtocolViolation => {
                    return Err(CenterConnectionError::ProtocolViolation);
                }
            }
        }
    }

    /// The connection-establishment negotiation under the admission
    /// decision (audit follow-up F4): the first frame must be a `Hello`,
    /// and every `Hello` receives a `NegotiationResult` — an acceptance, a
    /// protocol-level rejection, or the `not-bound` admission refusal.
    ///
    /// # Errors
    ///
    /// Returns [`CenterAcceptError::AdmissionRejected`] when the admission
    /// refuses the site (the site received its `not-bound` answer), and
    /// [`CenterAcceptError::AdmissionLookup`] when the admission cannot be
    /// resolved (the connection is refused without an answer).
    async fn complete_negotiation_with_admission<A: CenterAdmissionResolver + ?Sized>(
        &mut self,
        admission: &A,
    ) -> Result<ResolvedSite, CenterAcceptError> {
        let hello = self.receive_hello().await?;
        match negotiate(&hello) {
            NegotiationDecision::Compatible => {
                // The admission runs before the acceptance answer: only a
                // site whose binding is in force is accepted; a refused
                // site learns the `not-bound` reason instead of being
                // accepted and dropped after the negotiation.
                match admission.resolve(&self.identity).await {
                    Ok(AdmissionVerdict::Admitted(site)) => {
                        self.send(EnvelopeMessage::NegotiationResult(NegotiationResult {
                            accepted: true,
                            reason: String::new(),
                        }))
                        .await
                        .map_err(CenterAcceptError::NegotiationReply)?;
                        Ok(site)
                    }
                    Ok(AdmissionVerdict::Rejected { reason }) => {
                        // The refusal answer is best-effort, exactly like
                        // the protocol-level rejection: the site must learn
                        // that its binding is not in force, but a failing
                        // transport must not mask the refusal itself.
                        let _ = self
                            .send(EnvelopeMessage::NegotiationResult(NegotiationResult {
                                accepted: false,
                                reason: NegotiationReason::NotBound.as_str().to_owned(),
                            }))
                            .await;
                        Err(CenterAcceptError::AdmissionRejected { reason })
                    }
                    Err(source) => {
                        // The admission lookup failed: the center cannot
                        // verify the site, so the connection is refused
                        // without an answer — a transient verdict, never a
                        // `not-bound` one, because a broken center must not
                        // converge the site's binding.
                        Err(CenterAcceptError::AdmissionLookup { source })
                    }
                }
            }
            NegotiationDecision::Rejected { reason } => {
                // The rejection answer is best-effort: the site must learn
                // why it cannot join, but a failing transport must not mask
                // the rejection itself.
                let _ = self
                    .send(EnvelopeMessage::NegotiationResult(NegotiationResult {
                        accepted: false,
                        reason: reason.as_str().to_owned(),
                    }))
                    .await;
                Err(CenterAcceptError::NegotiationRejected { reason })
            }
        }
    }

    /// The connection-establishment negotiation (§15.3): the first frame
    /// must be a `Hello`, and every `Hello` receives a `NegotiationResult`
    /// — an acceptance, or the stable reason code of the first failed
    /// check.
    async fn complete_negotiation(&mut self) -> Result<(), CenterAcceptError> {
        let hello = self.receive_hello().await?;
        match negotiate(&hello) {
            NegotiationDecision::Compatible => {
                self.send(EnvelopeMessage::NegotiationResult(NegotiationResult {
                    accepted: true,
                    reason: String::new(),
                }))
                .await
                .map_err(CenterAcceptError::NegotiationReply)?;
                Ok(())
            }
            NegotiationDecision::Rejected { reason } => {
                // The rejection answer is best-effort: the site must learn
                // why it cannot join, but a failing transport must not mask
                // the rejection itself.
                let _ = self
                    .send(EnvelopeMessage::NegotiationResult(NegotiationResult {
                        accepted: false,
                        reason: reason.as_str().to_owned(),
                    }))
                    .await;
                Err(CenterAcceptError::NegotiationRejected { reason })
            }
        }
    }

    /// Receives the first frame of one connection and validates it as a
    /// `Hello` (§15.3), recording its sequence as the peer's watermark.
    async fn receive_hello(&mut self) -> Result<Hello, CenterAcceptError> {
        let first = tokio::time::timeout(self.options.handshake_timeout, self.ws.next())
            .await
            .map_err(|_| CenterAcceptError::HelloTimeout {
                timeout: self.options.handshake_timeout,
            })?
            .ok_or(CenterAcceptError::Closed)?
            .map_err(|error| CenterAcceptError::Transport(Box::new(error)))?;
        let envelope = match inbound_frame(first).map_err(CenterAcceptError::Frame)? {
            InboundFrame::Envelope(envelope) => envelope,
            InboundFrame::Control => return Err(CenterAcceptError::ExpectedHello),
            InboundFrame::Closed => return Err(CenterAcceptError::Closed),
            InboundFrame::ProtocolViolation => return Err(CenterAcceptError::ProtocolViolation),
        };
        let Some(EnvelopeMessage::Hello(hello)) = envelope.message else {
            return Err(CenterAcceptError::ExpectedHello);
        };
        self.acked_sequence = envelope.sequence;
        Ok(hello)
    }
}

/// Whether a WebSocket read failure is just the peer's connection ending
/// (an I/O error on the dead socket, or the transport's own closed
/// markers) rather than a protocol-level failure.
fn connection_ended(error: &WsError) -> bool {
    matches!(
        error,
        WsError::ConnectionClosed | WsError::AlreadyClosed | WsError::Io(_)
    )
}

/// Loads the persisted center server pair below `tls/`, or issues a fresh
/// pair from the CA for the listen address and persists it (mode 0600).
/// A half-written pair is a hard error, never silently regenerated.
///
/// # Errors
///
/// Returns [`CenterAcceptorError`] for unreadable or invalid PEM material
/// or persistence failure.
fn load_or_issue_server_certificate(
    paths: &RuntimePaths,
    listen: &ListenAddress,
    ca: &CenterCa,
) -> Result<crate::center_ca::ServerCertificate, CenterAcceptorError> {
    let certificate_path = paths.tls_directory().join(CENTER_CERT_FILE);
    let key_path = paths.tls_directory().join(CENTER_KEY_FILE);
    match (
        read_certificate(&certificate_path),
        read_private_key(&key_path),
    ) {
        (Ok(certificate), Ok(key)) => Ok(crate::center_ca::ServerCertificate { certificate, key }),
        (Err(cert_error), Err(key_error)) if is_missing(&cert_error) && is_missing(&key_error) => {
            let server = ca
                .issue_server_certificate(listen)
                .map_err(CenterAcceptorError::Ca)?;
            persist_text(
                &certificate_path,
                &pem_encode("CERTIFICATE", server.certificate.as_ref()),
            )
            .map_err(CenterAcceptorError::Material)?;
            persist_text(
                &key_path,
                &pem_encode(
                    "PRIVATE KEY",
                    crate::tls_material::key_der_bytes(&server.key)?,
                ),
            )
            .map_err(CenterAcceptorError::Material)?;
            Ok(server)
        }
        (Err(cert_error), Err(key_error)) => Err(CenterAcceptorError::ReadPair {
            cert_error: Box::new(cert_error),
            key_error: Box::new(key_error),
        }),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error.into()),
    }
}

fn is_missing(error: &crate::tls_material::TlsMaterialError) -> bool {
    matches!(
        error,
        crate::tls_material::TlsMaterialError::ReadFile { source, .. }
            if source.kind() == io::ErrorKind::NotFound
    )
}

/// Builds the center's TLS server configuration: TLS 1.3 only, a required
/// client certificate verified against the center CA as the only trust
/// anchor (the mTLS core of the §15.1 transport), and the CA-issued server
/// certificate.
///
/// # Errors
///
/// Returns [`CenterAcceptorError`] when the trust anchor cannot be added,
/// the client-certificate verifier cannot be built, or the configuration
/// cannot be assembled.
pub(crate) fn build_server_config(
    ca: &CenterCa,
    server: crate::center_ca::ServerCertificate,
) -> Result<Arc<rustls::ServerConfig>, CenterAcceptorError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots
        .add(ca.certificate())
        .map_err(CenterAcceptorError::TrustAnchor)?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(CenterAcceptorError::Verifier)?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(CenterAcceptorError::TlsVersion)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![server.certificate], server.key)
        .map_err(CenterAcceptorError::TlsConfiguration)?;
    Ok(Arc::new(config))
}

/// A controlled failure while binding the center listener.
#[derive(Debug, Error)]
pub enum CenterAcceptorError {
    #[error("failed to prepare the center CA: {0}")]
    Ca(#[from] CenterCaError),
    #[error("failed to prepare the center server TLS material: {0}")]
    Material(#[from] crate::tls_material::TlsMaterialError),
    #[error("failed to read the center server pair ({cert_error}; {key_error})")]
    ReadPair {
        cert_error: Box<crate::tls_material::TlsMaterialError>,
        key_error: Box<crate::tls_material::TlsMaterialError>,
    },
    #[error("failed to add the center CA to the client-certificate trust store: {0}")]
    TrustAnchor(#[source] rustls::Error),
    #[error("failed to build the client-certificate verifier: {0}")]
    Verifier(#[source] rustls::server::VerifierBuilderError),
    #[error("TLS version selection failed: {0}")]
    TlsVersion(#[source] rustls::Error),
    #[error("failed to assemble the center TLS server configuration: {0}")]
    TlsConfiguration(#[source] rustls::Error),
    #[error("failed to bind the center listener: {0}")]
    Bind(#[source] io::Error),
    #[error("failed to read the center listener address: {0}")]
    LocalAddress(#[source] io::Error),
}

/// A controlled failure while accepting one center connection.
#[derive(Debug, Error)]
pub enum CenterAcceptError {
    #[error("the center listener failed while accepting: {0}")]
    Accept(#[source] io::Error),
    #[error("the TLS handshake timed out after {timeout:?}")]
    HandshakeTimeout { timeout: Duration },
    #[error("the TLS handshake failed: {0}")]
    Handshake(#[source] io::Error),
    #[error("the WebSocket handshake timed out after {timeout:?}")]
    WebSocketTimeout { timeout: Duration },
    #[error("the WebSocket handshake failed: {0}")]
    WebSocket(#[source] Box<WsError>),
    #[error("the first frame did not arrive within {timeout:?}")]
    HelloTimeout { timeout: Duration },
    #[error("the WebSocket transport failed: {0}")]
    Transport(#[source] Box<WsError>),
    #[error("the site closed the connection before the first frame")]
    Closed,
    #[error("the first frame was not a Hello")]
    ExpectedHello,
    #[error("a text WebSocket message arrived where the frame protocol expects binary frames")]
    ProtocolViolation,
    #[error("the site presented no client certificate")]
    ClientCertificateMissing,
    #[error("the client certificate cannot be read: {0}")]
    Certificate(#[from] x509::DerReadError),
    #[error("a frame could not be decoded: {0}")]
    Frame(#[from] FrameError),
    #[error("negotiation rejected the site: {reason}")]
    NegotiationRejected { reason: NegotiationReason },
    #[error("failed to answer the Hello: {0}")]
    NegotiationReply(#[from] CenterConnectionError),
    /// The admission refused the site (audit follow-up F4): the site
    /// received its `not-bound` `NegotiationResult` before the connection
    /// closed, so it can converge instead of retrying forever.
    #[error("admission refused the site: {reason}")]
    AdmissionRejected { reason: AdmissionRejection },
    /// The admission lookup failed; the connection is refused without an
    /// answer (a transient verdict, never a `not-bound` one — a broken
    /// center must not converge the site's binding).
    #[error("the admission lookup failed: {source}")]
    AdmissionLookup {
        source: CenterSessionAdmissionError<CenterBindingRepositoryError>,
    },
}

/// A controlled failure on one established center connection.
#[derive(Debug, Error)]
pub enum CenterConnectionError {
    #[error("no frame arrived within {after:?}; the connection is dead")]
    IdleTimeout { after: Duration },
    #[error("the WebSocket transport failed while reading: {source}")]
    Read {
        #[source]
        source: Box<WsError>,
    },
    #[error("the WebSocket transport failed while sending: {source}")]
    Send {
        #[source]
        source: Box<WsError>,
    },
    #[error("the WebSocket transport failed while flushing: {source}")]
    Flush {
        #[source]
        source: Box<WsError>,
    },
    #[error("a frame could not be decoded: {0}")]
    Frame(#[from] FrameError),
    #[error(
        "a text WebSocket message arrived where the frame protocol expects one binary frame per message"
    )]
    ProtocolViolation,
    #[error("the outbox sequence overflowed")]
    SequenceOverflow,
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        io, mem,
        net::{Ipv4Addr, SocketAddr},
        sync::Arc,
        time::Duration,
    };

    #[test]
    fn the_accept_error_fits_the_result_size_bound() {
        // The pedantic `result_large_err` lint bounds error enums carried
        // by `Result`; this pins the size so a new variant cannot silently
        // regress the happy path's stack cost.
        let accept_size = mem::size_of::<CenterAcceptError>();
        let connection_size = mem::size_of::<CenterConnectionError>();
        assert!(
            accept_size <= 128,
            "CenterAcceptError is {accept_size} bytes"
        );
        assert!(
            connection_size <= 128,
            "CenterConnectionError is {connection_size} bytes"
        );
    }

    use futures::StreamExt as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use rutilus_center_protocol::{
        CENTER_PROTOCOL_VERSION, Envelope, EnvelopeMessage, Heartbeat, Hello, NV_REDFISH_BASELINE,
        capability_ledger_hash, decode_frame, encode_frame,
    };
    use rutilus_domain::{CertificateFingerprint, InstanceId};
    use rutilus_platform::RuntimePaths;
    use tokio::net::TcpStream;
    use tokio_rustls::client::TlsStream;
    use tokio_tungstenite::tungstenite::Message;

    use super::*;

    /// Probes one free loopback port.
    async fn free_port() -> io::Result<u16> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    /// Binds an acceptor on a free loopback port.
    async fn bind_acceptor(
        paths: &RuntimePaths,
    ) -> Result<(CenterAcceptor, ListenAddress), Box<dyn Error>> {
        let port = free_port().await?;
        let listen = ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
        let acceptor = CenterAcceptor::bind(paths, &listen).await?;
        Ok((acceptor, listen))
    }

    /// A raw TLS + WebSocket client (without the product's site client),
    /// for tests that present arbitrary certificate material or Hello
    /// frames. `trust` is the root store content; `identity` is the client
    /// certificate and key, or `None` for a client without a certificate.
    async fn raw_client(
        address: SocketAddr,
        trust: CertificateDer<'static>,
        identity: Option<(CertificateDer<'static>, PrivateKeyDer<'static>)>,
    ) -> Result<WebSocketStream<TlsStream<TcpStream>>, Box<dyn Error>> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trust)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?;
        let config = match identity {
            Some((certificate, key)) => builder
                .with_root_certificates(roots)
                .with_client_auth_cert(vec![certificate], key)?,
            None => builder.with_root_certificates(roots).with_no_client_auth(),
        };
        let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(address).await?;
        let server_name = ServerName::try_from("127.0.0.1")
            .map_err(|error| io::Error::other(error.to_string()))?;
        let tls = connector.connect(server_name, tcp).await?;
        let (ws, _) = tokio_tungstenite::client_async(
            format!("wss://127.0.0.1:{}/center/v1", address.port()),
            tls,
        )
        .await?;
        Ok(ws)
    }

    /// A recording frame handler: every received envelope is forwarded to
    /// the test through a channel.
    struct Recorder(tokio::sync::mpsc::Sender<Envelope>);

    impl CenterFrameHandler<CenterConnection> for Recorder {
        async fn on_frame(&mut self, _connection: &mut CenterConnection, envelope: Envelope) {
            let _ = self.0.send(envelope).await;
        }
    }

    /// A `Hello` frame envelope, negotiated or not.
    fn hello_envelope(protocol_version: u32, instance_id: &str) -> Envelope {
        Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Hello(Hello {
                product_version: String::from("test"),
                center_protocol_version: protocol_version,
                nv_redfish_baseline: String::from(NV_REDFISH_BASELINE),
                capability_ledger_hash: capability_ledger_hash().to_vec(),
                instance_id: instance_id.to_owned(),
                site_name: String::from("Test Site"),
                last_acked_sequence: 0,
            })),
        }
    }

    /// One accepted connection with an issued site identity, driven by a
    /// raw client. Returns the connection and the still-open raw client,
    /// so the caller can keep sending frames.
    async fn accept_with_identity(
        mut acceptor: CenterAcceptor,
        address: SocketAddr,
        ca_certificate: CertificateDer<'static>,
        identity: (CertificateDer<'static>, PrivateKeyDer<'static>),
        hello: Envelope,
    ) -> Result<(CenterConnection, WebSocketStream<TlsStream<TcpStream>>), Box<dyn Error>> {
        let server = tokio::spawn(async move { acceptor.accept().await });
        let mut ws = raw_client(address, ca_certificate, Some(identity)).await?;
        ws.send(Message::Binary(encode_frame(&hello)?)).await?;
        let connection = server.await.map_err(io::Error::other)??;
        // The raw client consumed the NegotiationResult reply.
        let reply = ws
            .next()
            .await
            .ok_or_else(|| io::Error::other("no negotiation reply"))??;
        let Message::Binary(payload) = reply else {
            return Err(io::Error::other("non-binary negotiation reply").into());
        };
        let envelope = decode_frame(&payload)?;
        let Some(EnvelopeMessage::NegotiationResult(result)) = envelope.message else {
            return Err(io::Error::other("the reply was not a NegotiationResult").into());
        };
        assert!(result.accepted);
        Ok((connection, ws))
    }

    #[tokio::test]
    async fn accepts_a_client_certificate_issued_by_the_center_ca() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (acceptor, _) = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();
        let site = InstanceId::generate();
        let site_fingerprint = CertificateFingerprint::from_bytes([0xAA; 32]);
        let identity = acceptor.issue_site_certificate(site, site_fingerprint)?;

        let (connection, _ws) = accept_with_identity(
            acceptor,
            address,
            ca_certificate,
            (identity.certificate(), identity.private_key()),
            hello_envelope(CENTER_PROTOCOL_VERSION, &site.to_string()),
        )
        .await?;

        // The connection identity is parsed from the presented certificate:
        // fingerprint, the site instance id subject, and the bound identity.
        assert_eq!(connection.identity().fingerprint(), identity.fingerprint());
        assert_eq!(
            connection.identity().subject(),
            Some(site.to_string().as_str())
        );
        assert_eq!(
            connection.identity().bound_site_fingerprint(),
            Some(site_fingerprint)
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_a_client_without_a_certificate() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();

        let server = tokio::spawn(async move { acceptor.accept().await });
        let client = raw_client(address, ca_certificate, None).await;
        assert!(
            client.is_err(),
            "the TLS handshake must fail without a client certificate"
        );
        assert!(
            server.await.map_err(io::Error::other)?.is_err(),
            "the acceptor must refuse the handshake"
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_a_certificate_from_an_unknown_ca() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();

        // A second, unrelated CA issues the client certificate: it cannot
        // chain to the acceptor's trust anchor.
        let foreign_directory = tempfile::tempdir()?;
        let foreign_paths = RuntimePaths::from_root(foreign_directory.path().join("instance"))?;
        let foreign_ca = CenterCa::generate_or_load(&foreign_paths)?;
        let foreign_identity = foreign_ca.issue_site_certificate(
            InstanceId::generate(),
            CertificateFingerprint::from_bytes([0xBB; 32]),
        )?;

        let server = tokio::spawn(async move { acceptor.accept().await });
        let client = raw_client(
            address,
            ca_certificate,
            Some((
                foreign_identity.certificate(),
                foreign_identity.private_key(),
            )),
        )
        .await;
        assert!(
            client.is_err(),
            "the TLS handshake must fail for a foreign CA certificate"
        );
        assert!(
            server.await.map_err(io::Error::other)?.is_err(),
            "the acceptor must refuse the foreign certificate"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_a_hello_with_the_wrong_protocol_version() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();
        let site = InstanceId::generate();
        let identity = acceptor
            .issue_site_certificate(site, CertificateFingerprint::from_bytes([0xCC; 32]))?;

        let server = tokio::spawn(async move { acceptor.accept().await });
        let mut ws = raw_client(
            address,
            ca_certificate,
            Some((identity.certificate(), identity.private_key())),
        )
        .await?;
        ws.send(Message::Binary(encode_frame(&hello_envelope(
            CENTER_PROTOCOL_VERSION + 1,
            &site.to_string(),
        ))?))
        .await?;

        let result = server.await.map_err(io::Error::other)?;
        assert!(matches!(
            result,
            Err(CenterAcceptError::NegotiationRejected {
                reason: NegotiationReason::ProtocolMismatch
            })
        ));

        // The site still learns why it cannot join: the rejection answer
        // arrives before the connection closes.
        let reply = ws
            .next()
            .await
            .ok_or_else(|| io::Error::other("no rejection reply"))??;
        let Message::Binary(payload) = reply else {
            return Err(io::Error::other("non-binary rejection reply").into());
        };
        let envelope = decode_frame(&payload)?;
        let Some(EnvelopeMessage::NegotiationResult(result)) = envelope.message else {
            return Err(io::Error::other("the reply was not a NegotiationResult").into());
        };
        assert!(!result.accepted);
        assert_eq!(result.reason, "protocol-mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn the_first_frame_must_be_a_hello() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();
        let site = InstanceId::generate();
        let identity = acceptor
            .issue_site_certificate(site, CertificateFingerprint::from_bytes([0xDD; 32]))?;

        let server = tokio::spawn(async move { acceptor.accept().await });
        let mut ws = raw_client(
            address,
            ca_certificate,
            Some((identity.certificate(), identity.private_key())),
        )
        .await?;
        let heartbeat = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix: 0 })),
        };
        ws.send(Message::Binary(encode_frame(&heartbeat)?)).await?;
        assert!(matches!(
            server.await.map_err(io::Error::other)?,
            Err(CenterAcceptError::ExpectedHello)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn runs_the_frame_loop_until_idle_timeout() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let port = free_port().await?;
        let listen = ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
        let acceptor = CenterAcceptor::bind_with_options(
            &paths,
            &listen,
            CenterAcceptorOptions {
                handshake_timeout: Duration::from_secs(2),
                idle_timeout: Duration::from_millis(300),
            },
        )
        .await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();
        let site = InstanceId::generate();
        let identity = acceptor
            .issue_site_certificate(site, CertificateFingerprint::from_bytes([0xEE; 32]))?;

        let (connection, mut ws) = accept_with_identity(
            acceptor,
            address,
            ca_certificate,
            (identity.certificate(), identity.private_key()),
            hello_envelope(CENTER_PROTOCOL_VERSION, &site.to_string()),
        )
        .await?;

        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let task = tokio::spawn(connection.run(Recorder(sender)));

        // The loop dispatches frames...
        let heartbeat = Envelope {
            sequence: 2,
            acked_sequence: 1,
            message: Some(EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix: 42 })),
        };
        ws.send(Message::Binary(encode_frame(&heartbeat)?)).await?;
        let envelope = receiver
            .recv()
            .await
            .ok_or_else(|| io::Error::other("no frame reached the handler"))?;
        let Some(EnvelopeMessage::Heartbeat(inner)) = envelope.message else {
            return Err(io::Error::other("the frame was not a Heartbeat").into());
        };
        assert_eq!(inner.sent_at_unix, 42);

        // ...and silence beyond the idle window ends it.
        let result = task.await.map_err(io::Error::other)?;
        assert!(matches!(
            result,
            Err(CenterConnectionError::IdleTimeout { after }) if after == Duration::from_millis(300)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn sends_acknowledged_frames_back_to_the_site() -> Result<(), Box<dyn Error>> {
        use rutilus_center_protocol::Ack;

        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (acceptor, _) = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        let ca_certificate = acceptor.ca_certificate();
        let site = InstanceId::generate();
        let identity = acceptor
            .issue_site_certificate(site, CertificateFingerprint::from_bytes([0x11; 32]))?;

        let (mut connection, mut ws) = accept_with_identity(
            acceptor,
            address,
            ca_certificate,
            (identity.certificate(), identity.private_key()),
            hello_envelope(CENTER_PROTOCOL_VERSION, &site.to_string()),
        )
        .await?;

        // The center's own outbox starts after the NegotiationResult
        // (sequence 1), and the acked sequence rides along.
        connection
            .send(EnvelopeMessage::Ack(Ack { sequence: 1 }))
            .await?;
        let reply = ws
            .next()
            .await
            .ok_or_else(|| io::Error::other("no reply"))??;
        let Message::Binary(payload) = reply else {
            return Err(io::Error::other("non-binary reply").into());
        };
        let envelope = decode_frame(&payload)?;
        assert_eq!(envelope.sequence, 2);
        assert_eq!(envelope.acked_sequence, 1);
        assert!(matches!(envelope.message, Some(EnvelopeMessage::Ack(_))));
        Ok(())
    }

    #[tokio::test]
    async fn the_server_pair_persists_across_binds() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let first_port = free_port().await?;
        let first_listen = ListenAddress::parse(&format!("127.0.0.1:{first_port}"))?;
        let first = CenterAcceptor::bind(&paths, &first_listen).await?;
        let first_fingerprint = first.server_fingerprint();
        assert!(paths.tls_directory().join("center-cert.pem").is_file());
        assert!(paths.tls_directory().join("center-key.pem").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.tls_directory().join("center-key.pem"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        // A second bind on a fresh port reuses the persisted server
        // identity: the certificate the operator pins stays stable across
        // restarts.
        let second_port = free_port().await?;
        let second_listen = ListenAddress::parse(&format!("127.0.0.1:{second_port}"))?;
        let second = CenterAcceptor::bind(&paths, &second_listen).await?;
        assert_eq!(second.server_fingerprint(), first_fingerprint);
        Ok(())
    }
}
