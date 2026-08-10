//! The Site's outbound connection layer (design §15, 0.7.0 S3b): the
//! site's single center connection.
//!
//! [`CenterClientConfig`] holds the site's center binding: the center's
//! address, the center CA certificate as the only trust anchor, the
//! operator-pinned SHA-256 fingerprint of the center's server certificate
//! (§10.4 explicit trust — the chain must root at the CA *and* the
//! presented leaf must match the pin, so no certificate can substitute for
//! the pinned one), the client certificate the center issued for this
//! site, and the site's instance identity carried by the `Hello`.
//!
//! [`CenterClientConfig::connect`] establishes one connection: TCP, TLS
//! 1.3 with the client certificate, the pin check, the WebSocket upgrade
//! on [`CENTER_WS_PATH`], and the §15.3 `Hello`/`NegotiationResult`
//! exchange — a rejected site learns the stable reason code. The
//! established [`CenterLink`] sends frames (§15.4 outbox sequence
//! assigned per connection) and runs the §15 heartbeat: one
//! [`Heartbeat`] every [`SITE_HEARTBEAT_INTERVAL`] (30 seconds) while it
//! reads the center's frames; a closed or failed transport ends the loop
//! and the caller reconnects.
//!
//! [`CenterClientConfig::connect_with_retry`] is the reconnect primitive:
//! it retries with the [`SITE_RECONNECT_AFTER`] (120-second) backoff until
//! one attempt succeeds or the caller's stop signal resolves. The
//! reconnect-after-disconnect loop itself belongs to the runtime slice,
//! which also owns the durable outbox that resumes from the last
//! acknowledged sequence (§15.4).

use std::{future::Future, io, sync::Arc, time::Duration};

use futures::{SinkExt as _, StreamExt as _};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use rutilus_center_protocol::{
    CENTER_PROTOCOL_VERSION, Envelope, EnvelopeMessage, FrameError, Heartbeat, Hello,
    NV_REDFISH_BASELINE, NegotiationReason, NegotiationResult, SITE_HEARTBEAT_INTERVAL,
    SITE_RECONNECT_AFTER, capability_ledger_hash, encode_frame,
};
use rutilus_domain::{CertificateFingerprint, InstanceId};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use crate::{
    ListenAddress,
    center_ws::{CenterFrameHandler, InboundFrame, inbound_frame},
};

/// The WebSocket path every site connects to on the center (§15.1). The
/// center listener serves exactly this endpoint of its dedicated port.
pub(crate) const CENTER_WS_PATH: &str = "/center/v1";

/// The bound for one connect attempt: TCP, TLS, WebSocket, and the
/// negotiation exchange.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The timing bounds of the site's center connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterClientOptions {
    /// How often the site sends a [`Heartbeat`] frame (§15.2):
    /// [`SITE_HEARTBEAT_INTERVAL`], 30 seconds.
    pub heartbeat_interval: Duration,
    /// The bound for one [`CenterClientConfig::connect`] attempt.
    pub connect_timeout: Duration,
}

impl Default for CenterClientOptions {
    fn default() -> Self {
        Self {
            heartbeat_interval: SITE_HEARTBEAT_INTERVAL,
            connect_timeout: CONNECT_TIMEOUT,
        }
    }
}

/// The site's center binding: the center address, the explicit trust
/// material (§10.4), the site's client certificate, and the site instance
/// identity the `Hello` carries.
#[derive(Clone, Debug)]
pub struct CenterClientConfig {
    center: ListenAddress,
    pinned_fingerprint: CertificateFingerprint,
    instance_id: InstanceId,
    site_name: String,
    tls: Arc<rustls::ClientConfig>,
    options: CenterClientOptions,
}

impl CenterClientConfig {
    /// Builds the site's center binding. `ca_certificate` is the center
    /// CA certificate (the only trust anchor), `pinned_fingerprint` the
    /// operator-pinned fingerprint of the center's server certificate,
    /// and `client_certificate`/`client_key` the pair the center issued
    /// for this site.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError`] when the CA certificate cannot be
    /// added to the trust store, or the TLS client configuration cannot be
    /// assembled (for example a client certificate that does not match
    /// its key).
    pub fn new(
        center: ListenAddress,
        ca_certificate: CertificateDer<'static>,
        pinned_fingerprint: CertificateFingerprint,
        client_certificate: CertificateDer<'static>,
        client_key: PrivateKeyDer<'static>,
        instance_id: InstanceId,
        site_name: String,
    ) -> Result<Self, CenterClientError> {
        let mut roots = RootCertStore::empty();
        roots
            .add(ca_certificate)
            .map_err(CenterClientError::TrustAnchor)?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(CenterClientError::TlsVersion)?
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![client_certificate], client_key)
            .map_err(CenterClientError::TlsConfiguration)?;
        Ok(Self {
            center,
            pinned_fingerprint,
            instance_id,
            site_name,
            tls: Arc::new(tls),
            options: CenterClientOptions::default(),
        })
    }

    /// Replaces the timing bounds (tests use a short heartbeat interval
    /// instead of the production 30-second one).
    #[must_use]
    pub fn with_options(mut self, options: CenterClientOptions) -> Self {
        self.options = options;
        self
    }

    /// The center's address as recorded on the binding.
    #[must_use]
    pub const fn center_address(&self) -> &ListenAddress {
        &self.center
    }

    /// Establishes one connection to the center: TCP, TLS 1.3 with the
    /// site's client certificate, the §10.4 pin check, the WebSocket
    /// upgrade, and the `Hello`/`NegotiationResult` negotiation.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError`] when the establishment times out, the
    /// center cannot be reached or verified (including a pin mismatch),
    /// the WebSocket upgrade fails, or the center rejects the
    /// negotiation with its stable reason code.
    pub async fn connect(&self) -> Result<CenterLink, CenterClientError> {
        tokio::time::timeout(self.options.connect_timeout, self.connect_inner())
            .await
            .map_err(|_| CenterClientError::ConnectTimeout {
                timeout: self.options.connect_timeout,
            })?
    }

    /// Connects with the reconnect backoff: after every failed attempt the
    /// site waits [`SITE_RECONNECT_AFTER`] (120 seconds) before retrying,
    /// until one attempt succeeds or `stop` resolves.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError::StopRequested`] when `stop` resolves
    /// between attempts.
    pub async fn connect_with_retry<Stop>(
        &self,
        stop: Stop,
    ) -> Result<CenterLink, CenterClientError>
    where
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        loop {
            match self.connect().await {
                Ok(link) => return Ok(link),
                Err(error) => {
                    eprintln!(
                        "center connection failed: {error}; retrying in {SITE_RECONNECT_AFTER:?}"
                    );
                }
            }
            tokio::select! {
                () = tokio::time::sleep(SITE_RECONNECT_AFTER) => {}
                () = stop.as_mut() => return Err(CenterClientError::StopRequested),
            }
        }
    }

    async fn connect_inner(&self) -> Result<CenterLink, CenterClientError> {
        let tcp = TcpStream::connect((self.center.host().to_owned(), self.center.port()))
            .await
            .map_err(|source| CenterClientError::Connect {
                address: self.center.to_string(),
                source,
            })?;
        let server_name = server_name_for(&self.center)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls));
        let tls_stream = connector
            .connect(server_name, tcp)
            .await
            .map_err(CenterClientError::Handshake)?;
        verify_pin(&tls_stream, self.pinned_fingerprint)?;
        let (ws, _) = tokio_tungstenite::client_async(self.ws_url(), tls_stream)
            .await
            .map_err(|error| CenterClientError::WebSocket(Box::new(error)))?;
        let mut link = CenterLink {
            ws,
            next_sequence: 1,
            acked_sequence: 0,
            options: self.options,
        };
        link.complete_negotiation(self).await?;
        Ok(link)
    }

    fn ws_url(&self) -> String {
        // `ListenAddress`'s Display brackets IPv6 literals, so the URL is
        // valid for DNS names, IPv4, and IPv6 hosts alike.
        format!("wss://{}/{}", self.center, CENTER_WS_PATH)
    }

    fn hello(&self) -> Hello {
        Hello {
            product_version: env!("CARGO_PKG_VERSION").to_owned(),
            center_protocol_version: CENTER_PROTOCOL_VERSION,
            nv_redfish_baseline: String::from(NV_REDFISH_BASELINE),
            capability_ledger_hash: capability_ledger_hash().to_vec(),
            instance_id: self.instance_id.to_string(),
            site_name: self.site_name.clone(),
            // The reliable outbox resumes from the last acknowledged
            // sequence (§15.4); the durable outbox is the runtime slice's
            // concern, so a fresh connection starts from zero.
            last_acked_sequence: 0,
        }
    }
}

/// The TLS server name of the center: an IP literal is verified against
/// the certificate's IP SAN, anything else against its DNS SAN.
///
/// # Errors
///
/// Returns [`CenterClientError::ServerName`] when the host is neither an
/// IP literal nor a valid DNS name.
fn server_name_for(center: &ListenAddress) -> Result<ServerName<'static>, CenterClientError> {
    if let Some(ip) = center.ip() {
        return Ok(ServerName::from(ip));
    }
    ServerName::try_from(center.host().to_owned()).map_err(CenterClientError::ServerName)
}

/// The §10.4 explicit trust check after the TLS handshake: the presented
/// server certificate's SHA-256 fingerprint must equal the operator's pin.
/// The chain has already rooted at the center CA; the pin makes the trust
/// decision explicit and substitution-proof.
///
/// # Errors
///
/// Returns [`CenterClientError::PeerCertificateMissing`] when the center
/// presented no certificate, and [`CenterClientError::PinMismatch`] when
/// the presented fingerprint differs from the pin.
fn verify_pin(
    tls_stream: &tokio_rustls::client::TlsStream<TcpStream>,
    expected: CertificateFingerprint,
) -> Result<(), CenterClientError> {
    let Some(chain) = tls_stream.get_ref().1.peer_certificates() else {
        return Err(CenterClientError::PeerCertificateMissing);
    };
    let Some(leaf) = chain.first() else {
        return Err(CenterClientError::PeerCertificateMissing);
    };
    let actual = CertificateFingerprint::from_certificate_der(leaf.as_ref());
    if actual != expected {
        return Err(CenterClientError::PinMismatch { expected, actual });
    }
    Ok(())
}

/// One established, negotiated site-to-center connection.
pub struct CenterLink {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    next_sequence: u64,
    acked_sequence: u64,
    options: CenterClientOptions,
}

impl CenterLink {
    /// Sends one protocol message as the next outbox frame (§15.4): the
    /// connection assigns the outbox sequence and piggybacks the highest
    /// sequence received from the center.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError`] when the envelope cannot be framed or
    /// the transport fails.
    pub async fn send(&mut self, message: EnvelopeMessage) -> Result<(), CenterClientError> {
        let envelope = Envelope {
            sequence: self.next_sequence,
            acked_sequence: self.acked_sequence,
            message: Some(message),
        };
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(CenterClientError::SequenceOverflow)?;
        let frame = encode_frame(&envelope).map_err(CenterClientError::Frame)?;
        self.ws
            .send(Message::Binary(frame))
            .await
            .map_err(|source| CenterClientError::Send {
                source: Box::new(source),
            })?;
        Ok(())
    }

    /// Sends one envelope exactly as given (0.7.0 S4).
    ///
    /// The §15.4 durable outbox — owned by the application engine — assigns
    /// the envelope's sequence, so this raw send bypasses the
    /// connection-local counter of [`Self::send`] and delivers the envelope
    /// as built.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError::Frame`] when the envelope exceeds the
    /// protocol frame limit, and [`CenterClientError::Send`] when the
    /// transport fails.
    pub async fn send_envelope(&mut self, envelope: Envelope) -> Result<(), CenterClientError> {
        let frame = encode_frame(&envelope).map_err(CenterClientError::Frame)?;
        self.ws
            .send(Message::Binary(frame))
            .await
            .map_err(|source| CenterClientError::Send {
                source: Box::new(source),
            })?;
        Ok(())
    }

    /// Waits for the next inbound envelope (0.7.0 S4).
    ///
    /// WebSocket control frames (ping, pong) are absorbed — the pong is
    /// flushed to the wire — and `Ok(None)` reports a clean close of the
    /// connection, which the engine treats as the reconnect trigger.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError::Frame`] when a binary message does not
    /// decode as exactly one frame, [`CenterClientError::ProtocolViolation`]
    /// for a non-binary data message, and [`CenterClientError::Transport`]
    /// for transport failures.
    pub async fn receive_envelope(&mut self) -> Result<Option<Envelope>, CenterClientError> {
        loop {
            match self.ws.next().await {
                Some(Ok(message)) => {
                    match inbound_frame(message).map_err(CenterClientError::Frame)? {
                        InboundFrame::Envelope(envelope) => return Ok(Some(envelope)),
                        InboundFrame::Control => {
                            self.ws
                                .flush()
                                .await
                                .map_err(|source| CenterClientError::Flush {
                                    source: Box::new(source),
                                })?;
                        }
                        InboundFrame::Closed => return Ok(None),
                        InboundFrame::ProtocolViolation => {
                            return Err(CenterClientError::ProtocolViolation);
                        }
                    }
                }
                Some(Err(source)) => {
                    return Err(CenterClientError::Transport {
                        source: Box::new(source),
                    });
                }
                None => return Ok(None),
            }
        }
    }

    /// Consumes the connection: sends one [`Heartbeat`] every heartbeat
    /// interval and dispatches every center frame to `handler`. The loop
    /// ends when the transport closes or fails — the site then reconnects
    /// with the backoff.
    ///
    /// # Errors
    ///
    /// Returns [`CenterClientError::Closed`] when the center closes the
    /// connection or the transport ends, and [`CenterClientError`] for
    /// transport and protocol failures.
    pub async fn run<H>(mut self, mut handler: H) -> Result<(), CenterClientError>
    where
        H: CenterFrameHandler<CenterLink>,
    {
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + self.options.heartbeat_interval,
            self.options.heartbeat_interval,
        );
        loop {
            tokio::select! {
                _ = heartbeat.tick() => {
                    self.send(EnvelopeMessage::Heartbeat(Heartbeat {
                        sent_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
                    })).await?;
                }
                message = self.ws.next() => {
                    match message {
                        Some(Ok(message)) => {
                            match inbound_frame(message).map_err(CenterClientError::Frame)? {
                                InboundFrame::Envelope(envelope) => {
                                    self.acked_sequence = envelope.sequence;
                                    handler.on_frame(&mut self, envelope).await;
                                }
                                InboundFrame::Control => {
                                    self.ws.flush().await.map_err(|source| {
                                        CenterClientError::Flush {
                                            source: Box::new(source),
                                        }
                                    })?;
                                }
                                InboundFrame::Closed => return Err(CenterClientError::Closed),
                                InboundFrame::ProtocolViolation => {
                                    return Err(CenterClientError::ProtocolViolation)
                                }
                            }
                        }
                        Some(Err(source)) => {
                            return Err(CenterClientError::Transport { source: Box::new(source) })
                        }
                        None => return Err(CenterClientError::Closed),
                    }
                }
            }
        }
    }

    /// The connection-establishment negotiation (§15.3): sends the
    /// `Hello` and awaits the center's `NegotiationResult`.
    async fn complete_negotiation(
        &mut self,
        config: &CenterClientConfig,
    ) -> Result<(), CenterClientError> {
        self.send(EnvelopeMessage::Hello(config.hello())).await?;
        let envelope = loop {
            match self.ws.next().await {
                Some(Ok(message)) => {
                    match inbound_frame(message).map_err(CenterClientError::Frame)? {
                        InboundFrame::Envelope(envelope) => break envelope,
                        InboundFrame::Control => {
                            self.ws
                                .flush()
                                .await
                                .map_err(|source| CenterClientError::Flush {
                                    source: Box::new(source),
                                })?;
                        }
                        InboundFrame::Closed => return Err(CenterClientError::Closed),
                        InboundFrame::ProtocolViolation => {
                            return Err(CenterClientError::ProtocolViolation);
                        }
                    }
                }
                Some(Err(source)) => {
                    return Err(CenterClientError::Transport {
                        source: Box::new(source),
                    });
                }
                None => return Err(CenterClientError::Closed),
            }
        };
        let Some(NegotiationResult { accepted, reason }) =
            envelope.message.and_then(|message| match message {
                EnvelopeMessage::NegotiationResult(result) => Some(result),
                _ => None,
            })
        else {
            return Err(CenterClientError::ExpectedNegotiationResult);
        };
        self.acked_sequence = envelope.sequence;
        if accepted {
            Ok(())
        } else if reason == NegotiationReason::NotBound.as_str() {
            // The admission refusal (audit follow-up F4): the center says
            // the site's binding is not in force. It is classified before
            // the generic rejection so the sync engine can converge the
            // site instead of retrying forever.
            Err(CenterClientError::NotBound)
        } else {
            Err(CenterClientError::NegotiationRejected { reason })
        }
    }
}

/// A controlled failure while building, establishing, or running the
/// site's center connection.
#[derive(Debug, Error)]
pub enum CenterClientError {
    #[error("failed to add the center CA certificate to the trust store: {0}")]
    TrustAnchor(#[source] rustls::Error),
    #[error("TLS version selection failed: {0}")]
    TlsVersion(#[source] rustls::Error),
    #[error("failed to assemble the TLS client configuration: {0}")]
    TlsConfiguration(#[source] rustls::Error),
    #[error("failed to connect to the center at {address}: {source}")]
    Connect {
        address: String,
        #[source]
        source: io::Error,
    },
    #[error("the center host is not a valid TLS server name: {0}")]
    ServerName(#[source] rustls::pki_types::InvalidDnsNameError),
    #[error("the TLS handshake with the center failed: {0}")]
    Handshake(#[source] io::Error),
    #[error("the center presented no certificate")]
    PeerCertificateMissing,
    #[error(
        "the center certificate fingerprint {actual} does not match the pinned fingerprint {expected}"
    )]
    PinMismatch {
        expected: CertificateFingerprint,
        actual: CertificateFingerprint,
    },
    #[error("the WebSocket handshake with the center failed: {0}")]
    WebSocket(#[source] Box<WsError>),
    #[error("the connection establishment timed out after {timeout:?}")]
    ConnectTimeout { timeout: Duration },
    #[error("the center's first frame was not a NegotiationResult")]
    ExpectedNegotiationResult,
    #[error("the center rejected the connection: {reason}")]
    NegotiationRejected { reason: String },
    /// The center answered the `Hello` with the `not-bound` admission
    /// refusal (audit follow-up F4): the site's binding is not in force on
    /// the center, so the sync engine converges the site instead of
    /// retrying forever.
    #[error("the center refused the connection: the site binding is not in force")]
    NotBound,
    #[error("a frame could not be decoded: {0}")]
    Frame(#[from] FrameError),
    #[error("the WebSocket transport failed: {source}")]
    Transport {
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
    #[error(
        "a text WebSocket message arrived where the frame protocol expects one binary frame per message"
    )]
    ProtocolViolation,
    #[error("the connection to the center closed")]
    Closed,
    #[error("the outbox sequence overflowed")]
    SequenceOverflow,
    #[error("the reconnect loop was stopped")]
    StopRequested,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, mem, time::Duration};

    use rutilus_application::{CenterSession, CenterTransport};
    use rutilus_center_protocol::{Ack, Envelope, EnvelopeMessage, Heartbeat};
    use rutilus_domain::{CertificateFingerprint, InstanceId};
    use rutilus_platform::RuntimePaths;
    use tokio::net::TcpListener;
    use tokio_tungstenite::tungstenite::Message;

    use super::*;
    use crate::{
        CenterAcceptor, CenterAcceptorOptions, CenterCa, CenterConnection,
        center_acceptor::build_server_config,
    };

    #[test]
    fn the_client_error_fits_the_result_size_bound() {
        // The pedantic `result_large_err` lint bounds error enums carried
        // by `Result`; this pins the size so a new variant cannot silently
        // regress the happy path's stack cost.
        let size = mem::size_of::<CenterClientError>();
        assert!(size <= 128, "CenterClientError is {size} bytes");
    }

    /// Probes one free loopback port.
    async fn free_port() -> io::Result<u16> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    /// Binds an acceptor on a free loopback port with short timing bounds,
    /// so idle-timeout tests do not wait out the production 90 seconds.
    async fn bind_acceptor(
        paths: &RuntimePaths,
    ) -> Result<(CenterAcceptor, crate::ListenAddress), Box<dyn Error>> {
        let port = free_port().await?;
        let listen = crate::ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
        let acceptor = CenterAcceptor::bind_with_options(
            paths,
            &listen,
            CenterAcceptorOptions {
                handshake_timeout: Duration::from_secs(5),
                idle_timeout: Duration::from_secs(5),
            },
        )
        .await?;
        Ok((acceptor, listen))
    }

    /// The site-side config for one test, against the given acceptor.
    fn site_config(
        acceptor: &CenterAcceptor,
        identity: &crate::SiteClientCertificate,
        site: InstanceId,
    ) -> Result<CenterClientConfig, Box<dyn Error>> {
        let center =
            crate::ListenAddress::parse(&format!("127.0.0.1:{}", acceptor.address().port()))?;
        Ok(CenterClientConfig::new(
            center,
            acceptor.ca_certificate(),
            acceptor.server_fingerprint(),
            identity.certificate(),
            identity.private_key(),
            site,
            String::from("Test Site"),
        )?)
    }

    /// A recording frame handler, shared by the site and center sides.
    struct Recorder(tokio::sync::mpsc::Sender<Envelope>);

    impl CenterFrameHandler<CenterConnection> for Recorder {
        async fn on_frame(&mut self, _connection: &mut CenterConnection, envelope: Envelope) {
            let _ = self.0.send(envelope).await;
        }
    }

    impl CenterFrameHandler<CenterLink> for Recorder {
        async fn on_frame(&mut self, _connection: &mut CenterLink, envelope: Envelope) {
            let _ = self.0.send(envelope).await;
        }
    }

    /// A fresh site identity issued by the acceptor's CA.
    fn issued_identity(
        acceptor: &CenterAcceptor,
        site: InstanceId,
    ) -> Result<crate::SiteClientCertificate, Box<dyn Error>> {
        Ok(
            acceptor
                .issue_site_certificate(site, CertificateFingerprint::from_bytes([0x42; 32]))?,
        )
    }

    #[tokio::test]
    async fn site_connects_with_pinned_mtls_and_exchanges_frames() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let site = InstanceId::generate();
        let identity = issued_identity(&acceptor, site)?;
        let config = site_config(&acceptor, &identity, site)?.with_options(CenterClientOptions {
            heartbeat_interval: Duration::from_millis(200),
            connect_timeout: Duration::from_secs(5),
        });

        let (center_frames, mut center_rx) = tokio::sync::mpsc::channel(16);
        let center: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> =
            tokio::spawn(async move {
                let connection = acceptor.accept().await?;
                connection.run(Recorder(center_frames)).await?;
                Ok(())
            });

        // The site connects with its client certificate; the acceptor
        // consumed the Hello during negotiation (the connect succeeded
        // only because the Hello carried this instance identity).
        let mut link = config.connect().await?;

        // A frame round trip: the site sends a Heartbeat, the center
        // receives it with the outbox sequence after the Hello (the
        // Hello was sequence 1).
        link.send(EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix: 123 }))
            .await?;
        let heartbeat_frame = center_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::other("no Heartbeat reached the center"))?;
        assert_eq!(heartbeat_frame.sequence, 2);
        let Some(EnvelopeMessage::Heartbeat(heartbeat)) = heartbeat_frame.message else {
            return Err(io::Error::other("the frame was not a Heartbeat").into());
        };
        assert_eq!(heartbeat.sent_at_unix, 123);

        // The site's heartbeat loop: while `run` is alive, heartbeats
        // arrive roughly every 200 ms.
        let (site_frames, _site_rx) = tokio::sync::mpsc::channel(16);
        let site_run = tokio::spawn(link.run(Recorder(site_frames)));
        let mut heartbeats_seen = 0;
        while heartbeats_seen < 2 {
            let envelope = tokio::time::timeout(Duration::from_secs(5), center_rx.recv())
                .await
                .map_err(|_| io::Error::other("no heartbeat arrived in time"))?
                .ok_or_else(|| io::Error::other("the center loop ended early"))?;
            if matches!(envelope.message, Some(EnvelopeMessage::Heartbeat(_))) {
                heartbeats_seen += 1;
            }
        }

        // Ending the site's run closes the transport; the center loop
        // observes the close and ends cleanly.
        site_run.abort();
        let center_result = center.await.map_err(io::Error::other)?;
        assert!(
            center_result.is_ok(),
            "the center frame loop must end cleanly: {center_result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_a_center_whose_fingerprint_differs_from_the_pin() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (first, _) = bind_acceptor(&paths).await?;
        let first_pin = first.server_fingerprint();

        // A second center on the same CA (the CA files are copied over, the
        // server pair is not): it serves a different server certificate
        // that still chains to the same trust anchor.
        let second_directory = tempfile::tempdir()?;
        let second_paths = RuntimePaths::from_root(second_directory.path().join("instance"))?;
        std::fs::create_dir_all(second_paths.tls_directory())?;
        std::fs::copy(
            paths.tls_directory().join("center-ca.crt"),
            second_paths.tls_directory().join("center-ca.crt"),
        )?;
        std::fs::copy(
            paths.tls_directory().join("center-ca.key"),
            second_paths.tls_directory().join("center-ca.key"),
        )?;
        let (mut second, _) = bind_acceptor(&second_paths).await?;
        let second_fingerprint = second.server_fingerprint();
        assert_ne!(second_fingerprint, first_pin);

        // The site pins the first center's fingerprint but connects to the
        // second center: the chain verifies (same CA), the pin does not.
        let site = InstanceId::generate();
        let identity = issued_identity(&first, site)?;
        let config = CenterClientConfig::new(
            crate::ListenAddress::parse(&format!("127.0.0.1:{}", second.address().port()))?,
            first.ca_certificate(),
            first_pin,
            identity.certificate(),
            identity.private_key(),
            site,
            String::from("Test Site"),
        )?;
        let _center = tokio::spawn(async move { second.accept().await });

        // The pin check rejects before any frame is sent: the presented
        // certificate verified against the CA, but its fingerprint does
        // not match the operator's pin.
        let result = config.connect().await;
        assert!(matches!(
            result,
            Err(CenterClientError::PinMismatch { expected, actual })
                if expected == first_pin && actual == second_fingerprint
        ));
        Ok(())
    }

    #[tokio::test]
    async fn surfaces_a_rejected_negotiation_from_the_center() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let ca = CenterCa::generate_or_load(&paths)?;
        let listen = crate::ListenAddress::parse("127.0.0.1:8443")?;
        let server_identity = ca.issue_server_certificate(&listen)?;
        // The client's trust material is captured before the scripted
        // center consumes the CA and the server identity.
        let client_ca = ca.certificate();
        let client_pin =
            CertificateFingerprint::from_certificate_der(server_identity.certificate.as_ref());
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;

        let site = InstanceId::generate();
        let identity =
            ca.issue_site_certificate(site, CertificateFingerprint::from_bytes([0x33; 32]))?;

        // A scripted center that answers the Hello with a rejection.
        let scripted = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let acceptor =
                tokio_rustls::TlsAcceptor::from(build_server_config(&ca, server_identity)?);
            let tls = acceptor.accept(stream).await?;
            let mut ws = tokio_tungstenite::accept_async(tls).await?;
            let _hello = ws.next().await;
            let envelope = Envelope {
                sequence: 1,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::NegotiationResult(
                    rutilus_center_protocol::NegotiationResult {
                        accepted: false,
                        reason: String::from("baseline-mismatch"),
                    },
                )),
            };
            ws.send(Message::Binary(encode_frame(&envelope)?)).await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let config = CenterClientConfig::new(
            crate::ListenAddress::parse(&format!("127.0.0.1:{}", address.port()))?,
            client_ca,
            client_pin,
            identity.certificate(),
            identity.private_key(),
            site,
            String::from("Test Site"),
        )?;

        let result = config.connect().await;
        assert!(matches!(
            result,
            Err(CenterClientError::NegotiationRejected { reason })
                if reason == "baseline-mismatch"
        ));
        let scripted_result = scripted.await.map_err(io::Error::other)?;
        scripted_result.map_err(|error| io::Error::other(error.to_string()))?;
        Ok(())
    }

    #[tokio::test]
    async fn connect_with_retry_stops_on_the_stop_signal() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (acceptor, _) = bind_acceptor(&paths).await?;
        let site = InstanceId::generate();
        let identity = issued_identity(&acceptor, site)?;
        // A center address nothing listens on: every attempt fails.
        let config = CenterClientConfig::new(
            crate::ListenAddress::parse(&format!("127.0.0.1:{}", free_port().await?))?,
            acceptor.ca_certificate(),
            acceptor.server_fingerprint(),
            identity.certificate(),
            identity.private_key(),
            site,
            String::from("Test Site"),
        )?;
        let stop = async {};
        let result = config.connect_with_retry(stop).await;
        assert!(matches!(result, Err(CenterClientError::StopRequested)));
        Ok(())
    }

    /// The center-side handler that records every received frame and
    /// answers it with one Heartbeat, so the site's session receive has
    /// something to read.
    struct HeartbeatEcho(tokio::sync::mpsc::Sender<Envelope>);

    impl CenterFrameHandler<CenterConnection> for HeartbeatEcho {
        async fn on_frame(&mut self, connection: &mut CenterConnection, envelope: Envelope) {
            let _ = self.0.send(envelope).await;
            let _ = connection
                .send(EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix: 123 }))
                .await;
        }
    }

    #[tokio::test]
    async fn the_transport_adapter_preserves_envelopes_and_receives_frames()
    -> Result<(), Box<dyn Error>> {
        // The application boundary (0.7.0 S4): connect through the
        // CenterTransport trait, send an envelope whose durable sequence the
        // engine assigned, and receive the center's reply on the session.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let site = InstanceId::generate();
        let identity = issued_identity(&acceptor, site)?;
        let config = site_config(&acceptor, &identity, site)?;

        let (center_frames, mut center_rx) = tokio::sync::mpsc::channel(4);
        let center: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> =
            tokio::spawn(async move {
                let connection = acceptor.accept().await?;
                connection.run(HeartbeatEcho(center_frames)).await?;
                Ok(())
            });

        let mut session = CenterTransport::connect(&config).await?;
        // The envelope carries the durable outbox sequence; the transport
        // must deliver it exactly as given.
        let sent = Envelope {
            sequence: 42,
            acked_sequence: 7,
            message: Some(EnvelopeMessage::Ack(Ack { sequence: 42 })),
        };
        session.send(sent.clone()).await?;
        let received = center_rx
            .recv()
            .await
            .ok_or_else(|| io::Error::other("no frame reached the center"))?;
        assert_eq!(received, sent);

        // The center's echo reply arrives on the session's receive.
        let reply = session
            .receive()
            .await?
            .ok_or_else(|| io::Error::other("the session ended before the reply"))?;
        assert!(matches!(
            reply.message,
            Some(EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix: 123 }))
        ));

        center.abort();
        Ok(())
    }

    #[tokio::test]
    async fn connect_with_retry_connects_when_the_center_is_alive() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (mut acceptor, _) = bind_acceptor(&paths).await?;
        let site = InstanceId::generate();
        let identity = issued_identity(&acceptor, site)?;
        let config = site_config(&acceptor, &identity, site)?;

        let (center_frames, _center_rx) = tokio::sync::mpsc::channel(4);
        let center: tokio::task::JoinHandle<Result<(), Box<dyn Error + Send + Sync>>> =
            tokio::spawn(async move {
                let connection = acceptor.accept().await?;
                connection.run(Recorder(center_frames)).await?;
                Ok(())
            });
        // The first attempt succeeds; the backoff never runs.
        let mut link = config.connect_with_retry(async {}).await?;
        link.send(EnvelopeMessage::Ack(Ack { sequence: 1 })).await?;
        center.abort();
        Ok(())
    }
}
