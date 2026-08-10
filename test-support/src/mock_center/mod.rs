//! The scripted Mock Center (design §15, 0.7.0 S9): a loopback center
//! protocol listener that integration tests and E2E demos drive instead of
//! a real center.
//!
//! The mock mirrors the real center's mTLS surface: a CA that signs the
//! server certificate (whose fingerprint a site pins, §10.4) and one
//! client certificate per test site, plus the `Hello`/`NegotiationResult`
//! negotiation (§15.3) and the binary-frame WebSocket transport. It is
//! scripted, not implemented: [`MockCenterScript`] decides how the
//! negotiation answers (admit, or refuse with the `not-bound` reason — the
//! audit follow-up F4 convergence path), queues scripted replies to
//! content frames (an operation offer, a heartbeat, an explicit ack), and
//! records every received frame so tests can assert the exact wire
//! sequence the site produced.
//!
//! The default script is a healthy real center: every `Hello` admitted,
//! every content frame acknowledged (the §15.4 reliable transport needs
//! the ack for the site's outbox flush to progress).
//!
//! Module layout:
//!
//! - [`tls`] — the per-instance CA, server pair, and client-certificate
//!   issuer ([`MockCenterTls`], [`MockSiteIdentity`]).
//! - [`script`] — the programmable behavior and the recording
//!   ([`MockCenterScript`], [`ScriptedAdmission`], [`ScriptedReply`]).
//!
//! A connection that never completes the TLS handshake or the WebSocket
//! upgrade is dropped without failing the serve loop, exactly like the
//! real center's local-autonomy rule (§15.7).

mod script;
mod tls;

pub use script::{MockCenterScript, ScriptedAdmission, ScriptedReply};
pub use tls::{MockCenterTls, MockCenterTlsError, MockSiteIdentity};

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use futures::{SinkExt as _, StreamExt as _};
use rutilus_center_protocol::{
    Envelope, EnvelopeMessage, NegotiationResult, decode_frame, encode_frame,
};
use rutilus_domain::CertificateFingerprint;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::server::TlsStream;
use tokio_tungstenite::WebSocketStream;

use crate::mock_center::script::SharedScript;

/// The WebSocket upgrade path the site's client connects to.
const CENTER_WS_PATH: &str = "/center/v1";

/// The bound for the TLS handshake, the WebSocket upgrade, and the first
/// frame of one connection: a client that connects without handshaking
/// must not stall the listener forever.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// The timing bounds of one mock center connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MockCenterOptions {
    /// Whether the listener requires a client certificate signed by the
    /// mock center CA (the real center's §15.1 rule). Tests that only
    /// exercise the negotiation set this to `false`.
    pub require_client_cert: bool,
    /// The bound for the TLS and WebSocket handshakes and the first-frame
    /// `Hello` of one connection.
    pub handshake_timeout: Duration,
}

impl Default for MockCenterOptions {
    fn default() -> Self {
        Self {
            require_client_cert: true,
            handshake_timeout: HANDSHAKE_TIMEOUT,
        }
    }
}

/// A controlled failure of one mock center step.
#[derive(Debug, Error)]
pub enum MockCenterError {
    #[error("the mock center TLS material could not be generated: {0}")]
    Tls(#[from] MockCenterTlsError),
    #[error("the mock center listener could not be bound: {0}")]
    Bind(#[source] io::Error),
    #[error("the listener address could not be read: {0}")]
    LocalAddress(#[source] io::Error),
    #[error("the mock center acceptor failed: {0}")]
    Accept(#[source] io::Error),
    #[error("the TLS handshake timed out after {timeout:?}")]
    HandshakeTimeout { timeout: Duration },
    #[error("the TLS handshake failed: {0}")]
    Handshake(#[source] io::Error),
    #[error("the WebSocket handshake timed out after {timeout:?}")]
    WebSocketTimeout { timeout: Duration },
    #[error("the WebSocket handshake failed: {0}")]
    WebSocket(#[source] tokio_tungstenite::tungstenite::Error),
    #[error("the WebSocket transport failed: {0}")]
    Transport(#[source] tokio_tungstenite::tungstenite::Error),
    #[error("the site closed the connection before the first frame")]
    Closed,
    #[error("the first frame was not a Hello")]
    ExpectedHello,
    #[error("a frame could not be decoded: {0}")]
    Frame(#[source] rutilus_center_protocol::FrameError),
    #[error("a frame could not be encoded: {0}")]
    FrameEncode(#[source] rutilus_center_protocol::FrameError),
}

/// One accepted, negotiated mock center connection: the WebSocket stream
/// and the script shared with the serve loop.
struct MockCenterConnection {
    ws: WebSocketStream<TlsStream<TcpStream>>,
    script: SharedScript,
}

/// The scripted center protocol listener on loopback.
#[derive(Debug)]
pub struct MockCenter {
    listener: TcpListener,
    tls: MockCenterTls,
    address: SocketAddr,
    script: SharedScript,
    options: MockCenterOptions,
}

impl MockCenter {
    /// Binds the mock center listener on a free loopback port with the
    /// default options (client certificates required).
    ///
    /// # Errors
    ///
    /// Returns [`MockCenterError`] when the TLS material cannot be
    /// generated or the listener cannot be bound.
    pub async fn bind() -> Result<Self, MockCenterError> {
        Self::bind_with_options(MockCenterOptions::default()).await
    }

    /// Binds the mock center listener on a free loopback port with
    /// explicit options.
    ///
    /// # Errors
    ///
    /// Returns [`MockCenterError`] when the TLS material cannot be
    /// generated or the listener cannot be bound.
    pub async fn bind_with_options(options: MockCenterOptions) -> Result<Self, MockCenterError> {
        let tls = MockCenterTls::new(options)?;
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(MockCenterError::Bind)?;
        let address = listener
            .local_addr()
            .map_err(MockCenterError::LocalAddress)?;
        Ok(Self {
            listener,
            tls,
            address,
            script: Arc::new(MockCenterScript::new()),
            options,
        })
    }

    /// The bound listener address.
    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    /// The script handle: the test programs the admission and the replies
    /// and reads the recording through it.
    #[must_use]
    pub fn script(&self) -> Arc<MockCenterScript> {
        Arc::clone(&self.script)
    }

    /// The TLS material: the CA certificate, the server fingerprint, and
    /// the client-certificate issuer a test site needs.
    #[must_use]
    pub fn tls(&self) -> &MockCenterTls {
        &self.tls
    }

    /// The SHA-256 fingerprint of the mock center's server certificate —
    /// the value a site pins (§10.4).
    #[must_use]
    pub const fn server_fingerprint(&self) -> CertificateFingerprint {
        self.tls.server_fingerprint()
    }

    /// Serves the accept loop until the mock is dropped: one task per
    /// connection, each running the negotiation and the scripted frame
    /// loop, and no failure of one connection ever ends the listener
    /// (§15.7 local autonomy).
    pub fn serve(self) -> JoinHandle<()> {
        tokio::spawn(run_accept_loop(self))
    }
}

/// The accept loop: handshake and negotiate every connection, and run the
/// scripted frame loop until the peer closes.
async fn run_accept_loop(center: MockCenter) {
    let options = center.options;
    loop {
        let accepted = center.listener.accept().await;
        let Ok((stream, _address)) = accepted else {
            // The listener itself failed; the mock is over.
            return;
        };
        let tls = center.tls.clone();
        let script = Arc::clone(&center.script);
        tokio::spawn(async move {
            if let Err(error) = run_connection(stream, tls, script, options).await {
                eprintln!("mock center connection ended: {error}");
            }
        });
    }
}

/// One connection: the mTLS handshake, the WebSocket upgrade, the
/// scripted negotiation, and the frame loop.
async fn run_connection(
    stream: TcpStream,
    tls: MockCenterTls,
    script: SharedScript,
    options: MockCenterOptions,
) -> Result<(), MockCenterError> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls.server_config());
    let tls_stream = tokio::time::timeout(options.handshake_timeout, acceptor.accept(stream))
        .await
        .map_err(|_| MockCenterError::HandshakeTimeout {
            timeout: options.handshake_timeout,
        })?
        .map_err(MockCenterError::Handshake)?;
    let ws = tokio::time::timeout(
        options.handshake_timeout,
        tokio_tungstenite::accept_hdr_async(
            tls_stream,
            #[allow(clippy::result_large_err)]
            |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
             mut response: tokio_tungstenite::tungstenite::handshake::server::Response| {
                // The real center only upgrades the §15.2 path; a
                // different path is refused with 404, never upgraded. The
                // app's client builds the URL as
                //  (a doubled slash), so the
                // check matches the suffix.
                if request.uri().path().ends_with(CENTER_WS_PATH) {
                    Ok(response)
                } else {
                    *response.status_mut() =
                        tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
                    Err(tokio_tungstenite::tungstenite::handshake::server::ErrorResponse::from(
                        response.map(|()| None),
                    ))
                }
            },
        ),
    )
    .await
    .map_err(|_| MockCenterError::WebSocketTimeout {
        timeout: options.handshake_timeout,
    })?
    .map_err(MockCenterError::WebSocket)?;
    let mut connection = MockCenterConnection { ws, script };
    connection.negotiate(options).await?;
    connection.frame_loop().await
}

impl MockCenterConnection {
    /// The §15.3 negotiation: the first frame must be a `Hello`, and the
    /// script decides the answer. A refused site receives its
    /// `NegotiationResult` before the connection closes.
    async fn negotiate(&mut self, options: MockCenterOptions) -> Result<(), MockCenterError> {
        let first = tokio::time::timeout(options.handshake_timeout, self.ws.next())
            .await
            .map_err(|_| MockCenterError::HandshakeTimeout {
                timeout: options.handshake_timeout,
            })?
            .ok_or(MockCenterError::Closed)?
            .map_err(MockCenterError::Transport)?;
        let envelope = match first {
            tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                decode_frame(&bytes).map_err(MockCenterError::Frame)?
            }
            _ => return Err(MockCenterError::ExpectedHello),
        };
        let Some(EnvelopeMessage::Hello(_hello)) = envelope.message.as_ref() else {
            return Err(MockCenterError::ExpectedHello);
        };
        self.script.record(&envelope);
        match self.script.admission() {
            ScriptedAdmission::Admit => {
                self.send(Envelope {
                    sequence: 0,
                    acked_sequence: envelope.sequence,
                    message: Some(EnvelopeMessage::NegotiationResult(NegotiationResult {
                        accepted: true,
                        reason: String::new(),
                    })),
                })
                .await
            }
            ScriptedAdmission::RefuseNotBound => {
                // The refusal answer is best-effort, exactly like the real
                // center: the site must learn that its binding is not in
                // force, but a failing transport must not mask the refusal.
                let _ = self
                    .send(Envelope {
                        sequence: 0,
                        acked_sequence: envelope.sequence,
                        message: Some(EnvelopeMessage::NegotiationResult(NegotiationResult {
                            accepted: false,
                            reason: "not-bound".to_owned(),
                        })),
                    })
                    .await;
                Err(MockCenterError::Closed)
            }
        }
    }

    /// The frame loop: record every content frame, answer it with the next
    /// scripted reply (or the default ack), until the peer closes.
    async fn frame_loop(&mut self) -> Result<(), MockCenterError> {
        loop {
            let frame = match self.ws.next().await {
                Some(Ok(frame)) => frame,
                Some(Err(error)) => return Err(MockCenterError::Transport(error)),
                None => return Ok(()),
            };
            let envelope = match frame {
                tokio_tungstenite::tungstenite::Message::Binary(bytes) => {
                    decode_frame(&bytes).map_err(MockCenterError::Frame)?
                }
                tokio_tungstenite::tungstenite::Message::Ping(payload) => {
                    self.ws
                        .send(tokio_tungstenite::tungstenite::Message::Pong(payload))
                        .await
                        .map_err(MockCenterError::Transport)?;
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => return Ok(()),
                _ => continue,
            };
            self.script.record(&envelope);
            let reply = self.script.reply_for(&envelope);
            self.send(Envelope {
                sequence: 0,
                acked_sequence: envelope.sequence,
                message: Some(reply),
            })
            .await?;
        }
    }

    /// Sends one envelope as one binary frame.
    async fn send(&mut self, envelope: Envelope) -> Result<(), MockCenterError> {
        let frame = encode_frame(&envelope).map_err(MockCenterError::FrameEncode)?;
        self.ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(frame))
            .await
            .map_err(MockCenterError::Transport)
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::Ipv4Addr};

    use rutilus_center_protocol::{CENTER_PROTOCOL_VERSION, Hello, NV_REDFISH_BASELINE};
    use tokio::net::TcpStream;
    use tokio::net::TcpStream as ClientTcpStream;
    use tokio_rustls::client::TlsStream as ClientTlsStream;
    use tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio_rustls::{
        TlsConnector,
        rustls::{
            ClientConfig,
            pki_types::{CertificateDer, PrivateKeyDer, ServerName},
        },
    };
    use tokio_tungstenite::{
        WebSocketStream,
        tungstenite::{Message, client::IntoClientRequest as _},
    };

    use super::*;
    use crate::mock_center::script::ScriptedAdmission;

    /// Decodes one PEM document back into its DER bytes.
    fn der_from_pem(pem: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        use base64::Engine as _;
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        Ok(base64::engine::general_purpose::STANDARD.decode(body.trim())?)
    }

    /// Connects a raw site-like client to the mock center: mTLS with a
    /// client certificate issued by the mock CA, a WebSocket upgrade on the
    /// center path, and the `Hello`/`NegotiationResult` exchange.
    ///
    /// The address, identity, and script are captured before the mock is
    /// moved into its serve task, so the helper never borrows the mock.
    async fn connect_site(
        address: SocketAddr,
        identity: &MockSiteIdentity,
        ca_certificate: &CertificateDer<'static>,
    ) -> Result<(WebSocketStream<ClientTlsStream<ClientTcpStream>>, Envelope), Box<dyn Error>> {
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(ca_certificate.clone())?;
        let config = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from(der_from_pem(
                identity.certificate_pem(),
            )?)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der_from_pem(identity.key_pem())?)),
        )?;
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::try_from("localhost")?;
        let tls = connector.connect(server_name, stream).await?;
        let request = format!("wss://localhost:{}{}", address.port(), CENTER_WS_PATH)
            .into_client_request()?;
        let (ws, _response) =
            tokio_tungstenite::client_async_with_config(request, tls, None).await?;
        let mut ws = ws;
        ws.send(Message::Binary(encode_frame(&Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Hello(Hello {
                product_version: "0.1.0-test".to_owned(),
                center_protocol_version: CENTER_PROTOCOL_VERSION,
                nv_redfish_baseline: NV_REDFISH_BASELINE.to_owned(),
                capability_ledger_hash: rutilus_center_protocol::capability_ledger_hash().to_vec(),
                instance_id: "site-under-test".to_owned(),
                site_name: "Test Site".to_owned(),
                last_acked_sequence: 0,
            })),
        })?))
        .await?;
        let reply = ws.next().await.ok_or("no negotiation reply")??;
        let Message::Binary(bytes) = reply else {
            return Err("the reply was not a binary frame".into());
        };
        let envelope = decode_frame(&bytes)?;
        Ok((ws, envelope))
    }

    #[tokio::test]
    async fn the_mock_center_admits_a_site_and_acks_its_frames() -> Result<(), Box<dyn Error>> {
        let center = MockCenter::bind().await?;
        let script = center.script();
        let identity = center.tls().issue_client_certificate("site-under-test")?;
        let address = center.address();
        let ca_certificate = center.tls().ca_certificate();
        let task = center.serve();
        let (mut ws, result) = connect_site(address, &identity, &ca_certificate).await?;
        assert!(matches!(
            result.message,
            Some(EnvelopeMessage::NegotiationResult(ref result)) if result.accepted
        ));

        // A content frame (an event batch) is acknowledged with the
        // default ack of its sequence.
        ws.send(Message::Binary(encode_frame(&Envelope {
            sequence: 2,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Heartbeat(
                rutilus_center_protocol::Heartbeat { sent_at_unix: 0 },
            )),
        })?))
        .await?;
        let reply = ws.next().await.ok_or("no ack")??;
        let Message::Binary(bytes) = reply else {
            return Err("the reply was not a binary frame".into());
        };
        let ack = decode_frame(&bytes)?;
        assert!(matches!(
            ack.message,
            Some(EnvelopeMessage::Ack(ref ack)) if ack.sequence == 2
        ));

        // The script recorded the Hello and the heartbeat.
        let received = script.received();
        assert_eq!(received.len(), 2);
        assert!(matches!(
            received[0].message,
            Some(EnvelopeMessage::Hello(_))
        ));
        drop(ws);
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn the_mock_center_can_refuse_a_site_as_not_bound() -> Result<(), Box<dyn Error>> {
        let center = MockCenter::bind().await?;
        center
            .script()
            .set_admission(ScriptedAdmission::RefuseNotBound);
        let identity = center.tls().issue_client_certificate("site-under-test")?;
        let address = center.address();
        let ca_certificate = center.tls().ca_certificate();
        let task = center.serve();

        let (mut ws, result) = connect_site(address, &identity, &ca_certificate).await?;
        assert!(matches!(
            result.message,
            Some(EnvelopeMessage::NegotiationResult(ref result))
                if !result.accepted && result.reason == "not-bound"
        ));
        // The refused site's connection closes after the answer.
        let closed = ws.next().await;
        assert!(matches!(closed, None | Some(Err(_))));
        task.abort();
        Ok(())
    }

    #[test]
    fn the_mock_center_options_default_to_the_real_center_surface() {
        let options = MockCenterOptions::default();
        assert!(options.require_client_cert);
        assert_eq!(options.handshake_timeout, HANDSHAKE_TIMEOUT);
    }

    #[tokio::test]
    async fn a_mock_center_without_client_certificates_accepts_any_site()
    -> Result<(), Box<dyn Error>> {
        let center = MockCenter::bind_with_options(MockCenterOptions {
            require_client_cert: false,
            ..MockCenterOptions::default()
        })
        .await?;
        let address = center.address();
        let ca_certificate = center.tls().ca_certificate();
        let task = center.serve();
        // A plain client without any certificate still negotiates.
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        roots.add(ca_certificate)?;
        let config = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let stream = TcpStream::connect(address).await?;
        let server_name = ServerName::try_from("localhost")?;
        let tls = connector.connect(server_name, stream).await?;
        let request = format!("wss://localhost:{}{}", address.port(), CENTER_WS_PATH)
            .into_client_request()?;
        let (mut ws, _) = tokio_tungstenite::client_async_with_config(request, tls, None).await?;
        ws.send(Message::Binary(encode_frame(&Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Hello(Hello {
                product_version: "0.1.0-test".to_owned(),
                center_protocol_version: CENTER_PROTOCOL_VERSION,
                nv_redfish_baseline: NV_REDFISH_BASELINE.to_owned(),
                capability_ledger_hash: rutilus_center_protocol::capability_ledger_hash().to_vec(),
                instance_id: "site-under-test".to_owned(),
                site_name: "Test Site".to_owned(),
                last_acked_sequence: 0,
            })),
        })?))
        .await?;
        let reply = ws.next().await.ok_or("no negotiation reply")??;
        let Message::Binary(bytes) = reply else {
            return Err("the reply was not a binary frame".into());
        };
        let envelope = decode_frame(&bytes)?;
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::NegotiationResult(ref result)) if result.accepted
        ));
        drop(ws);
        task.abort();
        Ok(())
    }

    #[allow(dead_code)]
    fn assert_loopback(address: SocketAddr) -> bool {
        address.ip().is_loopback() || address.ip() == Ipv4Addr::LOCALHOST
    }
}
