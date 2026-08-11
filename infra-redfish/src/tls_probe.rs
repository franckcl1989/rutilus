use std::{
    fmt, io,
    sync::{Arc, Mutex},
    time::Duration,
};

use rustls::{
    ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::{
        VerifierBuilderError, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::CryptoProvider,
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rutilus_domain::{EndpointAddress, TlsCertificate, TlsCertificateError};
use thiserror::Error;
use tokio::{net::TcpStream, time::timeout};
use tokio_rustls::TlsConnector;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the platform CA store authenticated the observed leaf certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemCaStatus {
    Verified,
    Rejected,
}

/// A credential-free TLS observation suitable for an explicit trust decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsCertificateObservation {
    certificate: TlsCertificate,
    system_ca_status: SystemCaStatus,
}

impl TlsCertificateObservation {
    /// Borrows the leaf certificate presented by the BMC.
    #[must_use]
    pub const fn certificate(&self) -> &TlsCertificate {
        &self.certificate
    }

    /// Reports whether the platform CA store verified this exact certificate.
    #[must_use]
    pub const fn system_ca_status(&self) -> SystemCaStatus {
        self.system_ca_status
    }

    /// Separates the certificate from its platform-verification result.
    #[must_use]
    pub fn into_parts(self) -> (TlsCertificate, SystemCaStatus) {
        (self.certificate, self.system_ca_status)
    }
}

/// Performs a TLS-only, credential-free identity observation.
#[derive(Clone)]
pub struct TlsProbe {
    pub(crate) system_verifier: Arc<WebPkiServerVerifier>,
    pub(crate) provider: Arc<CryptoProvider>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
}

impl fmt::Debug for TlsProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TlsProbe")
            .field("connect_timeout", &self.connect_timeout)
            .field("handshake_timeout", &self.handshake_timeout)
            .finish_non_exhaustive()
    }
}

impl TlsProbe {
    /// Loads the platform CA store outside Tokio worker threads and builds a
    /// Rustls-only probe.
    ///
    /// # Errors
    ///
    /// Returns [`TlsProbeInitError`] when the blocking task fails, any native
    /// CA cannot be loaded, the store is empty, or the `WebPKI` verifier cannot
    /// be configured.
    pub async fn from_system_roots() -> Result<Self, TlsProbeInitError> {
        let roots = tokio::task::spawn_blocking(load_system_roots)
            .await
            .map_err(TlsProbeInitError::LoadTask)??;
        Self::from_root_store(roots, DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT)
    }

    /// Observes a BMC leaf certificate without sending HTTP bytes or BMC
    /// credentials.
    ///
    /// The probe records the leaf DER and delegates verification of that exact
    /// certificate to Rustls' standard `WebPKI` verifier in one handshake. It
    /// never sends application data and never creates an application-data
    /// channel for an untrusted certificate.
    ///
    /// # Errors
    ///
    /// Returns [`TlsProbeError`] for target, network, timeout, protocol,
    /// certificate-size, or observation-state failures.
    pub async fn probe(
        &self,
        address: &EndpointAddress,
    ) -> Result<TlsCertificateObservation, TlsProbeError> {
        let target = TlsTarget::from_address(address)?;
        let capture = Arc::new(CertificateCapture::default());
        let verifier = RecordingSystemVerifier {
            capture: Arc::clone(&capture),
            system_verifier: Arc::clone(&self.system_verifier),
        };
        let config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()
            .map_err(TlsProbeError::ConfigureTls)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let connection = self.connect(&target, Arc::new(config)).await;
        let captured = capture
            .take()
            .map_err(|_| TlsProbeError::ObservationState)?;
        let system_ca_status = match connection {
            Ok(()) => SystemCaStatus::Verified,
            Err(AttemptError::Handshake(source)) if is_certificate_validation_failure(&source) => {
                SystemCaStatus::Rejected
            }
            Err(source) => return Err(source.into_probe_error(target.endpoint)),
        };
        let certificate = match captured {
            CapturedCertificate::Certificate(der) => {
                TlsCertificate::from_der(der).map_err(TlsProbeError::InvalidPeerCertificate)?
            }
            CapturedCertificate::TooLarge { actual } => {
                return Err(TlsProbeError::InvalidPeerCertificate(
                    TlsCertificateError::TooLarge {
                        actual,
                        maximum: TlsCertificate::MAX_DER_BYTES,
                    },
                ));
            }
            CapturedCertificate::Empty => return Err(TlsProbeError::PeerCertificateMissing),
        };
        Ok(TlsCertificateObservation {
            certificate,
            system_ca_status,
        })
    }

    pub(crate) fn from_root_store(
        roots: RootCertStore,
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<Self, TlsProbeInitError> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let system_verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&provider))
                .build()
                .map_err(TlsProbeInitError::ConfigureVerifier)?;
        Ok(Self {
            system_verifier,
            provider,
            connect_timeout,
            handshake_timeout,
        })
    }

    async fn connect(
        &self,
        target: &TlsTarget,
        config: Arc<ClientConfig>,
    ) -> Result<(), AttemptError> {
        let tcp = timeout(
            self.connect_timeout,
            TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        .map_err(|_| AttemptError::ConnectTimeout)?
        .map_err(AttemptError::Connect)?;
        timeout(
            self.handshake_timeout,
            TlsConnector::from(config).connect(target.server_name.clone(), tcp),
        )
        .await
        .map_err(|_| AttemptError::HandshakeTimeout)?
        .map(|_| ())
        .map_err(AttemptError::Handshake)
    }
}

#[derive(Debug)]
struct TlsTarget {
    endpoint: String,
    host: String,
    port: u16,
    server_name: ServerName<'static>,
}

impl TlsTarget {
    fn from_address(address: &EndpointAddress) -> Result<Self, TlsProbeError> {
        let url = address.as_url();
        let host = url
            .host_str()
            .ok_or_else(|| TlsProbeError::InvalidTarget(address.to_string()))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| TlsProbeError::InvalidTarget(address.to_string()))?;
        let server_name = ServerName::try_from(host.clone())
            .map_err(|_| TlsProbeError::InvalidTarget(address.to_string()))?;
        Ok(Self {
            endpoint: address.to_string(),
            host,
            port,
            server_name,
        })
    }
}

fn load_system_roots() -> Result<RootCertStore, TlsProbeInitError> {
    root_store_from_native_result(rustls_native_certs::load_native_certs())
}

fn root_store_from_native_result(
    native: rustls_native_certs::CertificateResult,
) -> Result<RootCertStore, TlsProbeInitError> {
    if !native.errors.is_empty() {
        return Err(TlsProbeInitError::SystemRootLoad {
            failures: native
                .errors
                .into_iter()
                .map(|error| error.to_string())
                .collect(),
        });
    }
    if native.certs.is_empty() {
        return Err(TlsProbeInitError::NoSystemRoots);
    }

    let mut roots = RootCertStore::empty();
    for (index, certificate) in native.certs.into_iter().enumerate() {
        roots
            .add(certificate)
            .map_err(|source| TlsProbeInitError::InvalidSystemRoot { index, source })?;
    }
    Ok(roots)
}

fn is_certificate_validation_failure(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
        .is_some_and(|source| matches!(source, rustls::Error::InvalidCertificate(_)))
}

#[derive(Debug, Error)]
enum AttemptError {
    #[error("TCP connection timed out")]
    ConnectTimeout,
    #[error("TCP connection failed: {0}")]
    Connect(#[source] io::Error),
    #[error("TLS handshake timed out")]
    HandshakeTimeout,
    #[error("TLS handshake failed: {0}")]
    Handshake(#[source] io::Error),
}

impl AttemptError {
    fn into_probe_error(self, endpoint: String) -> TlsProbeError {
        match self {
            Self::ConnectTimeout => TlsProbeError::ConnectTimeout { endpoint },
            Self::Connect(source) => TlsProbeError::Connect { endpoint, source },
            Self::HandshakeTimeout => TlsProbeError::HandshakeTimeout { endpoint },
            Self::Handshake(source) => TlsProbeError::Handshake { endpoint, source },
        }
    }
}

#[derive(Default)]
enum CapturedCertificate {
    #[default]
    Empty,
    Certificate(Vec<u8>),
    TooLarge {
        actual: usize,
    },
}

#[derive(Default)]
struct CertificateCapture {
    state: Mutex<CapturedCertificate>,
}

impl fmt::Debug for CertificateCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateCapture")
            .finish_non_exhaustive()
    }
}

impl CertificateCapture {
    fn record(&self, certificate: &CertificateDer<'_>) -> Result<(), ObservationStateError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| ObservationStateError::Unavailable)?;
        *state = if certificate.len() > TlsCertificate::MAX_DER_BYTES {
            CapturedCertificate::TooLarge {
                actual: certificate.len(),
            }
        } else {
            CapturedCertificate::Certificate(certificate.as_ref().to_vec())
        };
        Ok(())
    }

    fn take(&self) -> Result<CapturedCertificate, ObservationStateError> {
        self.state
            .lock()
            .map(|mut state| std::mem::take(&mut *state))
            .map_err(|_| ObservationStateError::Unavailable)
    }
}

struct RecordingSystemVerifier {
    capture: Arc<CertificateCapture>,
    system_verifier: Arc<WebPkiServerVerifier>,
}

impl fmt::Debug for RecordingSystemVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordingSystemVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for RecordingSystemVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.capture
            .record(end_entity)
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        self.system_verifier.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.system_verifier
            .verify_tls12_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.system_verifier
            .verify_tls13_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.system_verifier.supported_verify_schemes()
    }
}

/// A failure while loading system trust before any BMC connection is made.
#[derive(Debug, Error)]
pub enum TlsProbeInitError {
    #[error("system CA loading task failed: {0}")]
    LoadTask(#[source] tokio::task::JoinError),
    #[error("one or more system CA certificates could not be loaded")]
    SystemRootLoad { failures: Vec<String> },
    #[error("the system CA store contains no certificates")]
    NoSystemRoots,
    #[error("system CA certificate {index} is invalid: {source}")]
    InvalidSystemRoot {
        index: usize,
        #[source]
        source: rustls::Error,
    },
    #[error("failed to configure the system WebPKI verifier: {0}")]
    ConfigureVerifier(#[source] VerifierBuilderError),
}

impl TlsProbeInitError {
    /// Provides native-store diagnostics without flattening them into the main
    /// error message.
    #[must_use]
    pub fn system_root_failures(&self) -> Option<&[String]> {
        match self {
            Self::SystemRootLoad { failures } => Some(failures),
            Self::LoadTask(_)
            | Self::NoSystemRoots
            | Self::InvalidSystemRoot { .. }
            | Self::ConfigureVerifier(_) => None,
        }
    }
}

/// A controlled failure during credential-free TLS identity observation.
#[derive(Debug, Error)]
pub enum TlsProbeError {
    #[error("validated endpoint address cannot be converted into a TLS target: {0}")]
    InvalidTarget(String),
    #[error("TCP connection to {endpoint} timed out")]
    ConnectTimeout { endpoint: String },
    #[error("TCP connection to {endpoint} failed: {source}")]
    Connect {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("TLS handshake with {endpoint} timed out")]
    HandshakeTimeout { endpoint: String },
    #[error("TLS handshake with {endpoint} failed: {source}")]
    Handshake {
        endpoint: String,
        #[source]
        source: io::Error,
    },
    #[error("TLS peer did not present a leaf certificate")]
    PeerCertificateMissing,
    #[error("TLS peer certificate is invalid product state: {0}")]
    InvalidPeerCertificate(#[source] TlsCertificateError),
    #[error("TLS certificate observation state is unavailable")]
    ObservationState,
    #[error("failed to configure credential-free Rustls observation: {0}")]
    ConfigureTls(#[source] rustls::Error),
}

#[derive(Clone, Copy, Debug, Error)]
enum ObservationStateError {
    #[error("certificate observation synchronization failed")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::SocketAddr, path::PathBuf};

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        ServerConfig, SupportedProtocolVersion,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use rustls_native_certs::{Error as NativeRootError, ErrorKind as NativeRootErrorKind};
    use tokio::{
        io::AsyncReadExt,
        net::TcpListener,
        task::JoinHandle,
        time::{sleep, timeout},
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    #[tokio::test]
    async fn verifies_a_system_ca_certificate_without_application_data()
    -> Result<(), Box<dyn Error>> {
        let server = TestTlsServer::start(1).await?;
        let mut roots = RootCertStore::empty();
        roots.add(server.certificate.clone())?;
        let probe =
            TlsProbe::from_root_store(roots, DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT)?;

        let observation = probe.probe(&server.address).await?;
        assert_eq!(observation.system_ca_status(), SystemCaStatus::Verified);
        assert_eq!(
            observation.certificate().certificate_der(),
            server.certificate.as_ref()
        );
        let (certificate, status) = observation.into_parts();
        assert_eq!(certificate.certificate_der(), server.certificate.as_ref());
        assert_eq!(status, SystemCaStatus::Verified);
        assert_eq!(server.finish().await?, vec![0]);
        Ok(())
    }

    #[tokio::test]
    async fn observes_an_untrusted_certificate_but_forces_handshake_rejection()
    -> Result<(), Box<dyn Error>> {
        let server = TestTlsServer::start(1).await?;
        let unrelated = generate_simple_self_signed([String::from("unrelated.invalid")])?;
        let mut roots = RootCertStore::empty();
        roots.add(unrelated.cert.der().clone())?;
        let probe =
            TlsProbe::from_root_store(roots, DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT)?;

        let observation = probe.probe(&server.address).await?;
        assert_eq!(observation.system_ca_status(), SystemCaStatus::Rejected);
        assert_eq!(
            observation.certificate().certificate_der(),
            server.certificate.as_ref()
        );
        assert_eq!(server.finish().await?, vec![0]);
        Ok(())
    }

    #[tokio::test]
    async fn rejects_a_hostname_mismatch_on_an_otherwise_trusted_certificate()
    -> Result<(), Box<dyn Error>> {
        // The shared test server's certificate covers the numeric loopback;
        // this test must see the hostname check fail, so it serves a
        // certificate that does not cover the address it connects to.
        let server = TestTlsServer::start_with_versions_and_sans(
            1,
            rustls::DEFAULT_VERSIONS,
            vec![String::from("localhost")],
        )
        .await?;
        let mut roots = RootCertStore::empty();
        roots.add(server.certificate.clone())?;
        let probe =
            TlsProbe::from_root_store(roots, DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT)?;
        let mismatched_address = endpoint_address(server.socket, "127.0.0.1")?;

        let observation = probe.probe(&mismatched_address).await?;
        assert_eq!(observation.system_ca_status(), SystemCaStatus::Rejected);
        assert_eq!(
            observation.certificate().certificate_der(),
            server.certificate.as_ref()
        );
        assert_eq!(server.finish().await?, vec![0]);
        Ok(())
    }

    #[tokio::test]
    async fn verifies_a_tls_1_2_certificate_without_application_data() -> Result<(), Box<dyn Error>>
    {
        let server = TestTlsServer::start_tls12().await?;
        let mut roots = RootCertStore::empty();
        roots.add(server.certificate.clone())?;
        let probe =
            TlsProbe::from_root_store(roots, DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT)?;

        let observation = probe.probe(&server.address).await?;
        assert_eq!(observation.system_ca_status(), SystemCaStatus::Verified);
        assert_eq!(
            observation.certificate().certificate_der(),
            server.certificate.as_ref()
        );
        assert_eq!(server.finish().await?, vec![0]);
        Ok(())
    }

    #[tokio::test]
    async fn bounds_a_stalled_tls_handshake() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let socket = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (_tcp, _) = listener.accept().await?;
            sleep(Duration::from_millis(100)).await;
            Ok::<(), io::Error>(())
        });
        let probe = test_probe(DEFAULT_CONNECT_TIMEOUT, Duration::from_millis(10))?;

        // Connect through the numeric IPv4 loopback the listener binds:
        // `localhost` can resolve to `::1` on Windows, which the IPv4-only
        // listener refuses and turns the expected handshake timeout into a
        // plain connection error.
        let result = probe.probe(&endpoint_address(socket, "127.0.0.1")?).await;

        assert!(matches!(
            result,
            Err(TlsProbeError::HandshakeTimeout { .. })
        ));
        server.await??;
        Ok(())
    }

    #[test]
    fn rejects_an_empty_native_root_store() {
        assert!(matches!(
            root_store_from_native_result(rustls_native_certs::CertificateResult::default()),
            Err(TlsProbeInitError::NoSystemRoots)
        ));
        assert!(
            TlsProbeInitError::NoSystemRoots
                .system_root_failures()
                .is_none()
        );
    }

    #[test]
    fn rejects_partial_native_root_loads_with_diagnostics() -> Result<(), Box<dyn Error>> {
        let mut native = rustls_native_certs::CertificateResult::default();
        native.errors.push(NativeRootError {
            context: "test root load",
            kind: NativeRootErrorKind::Io {
                inner: io::Error::other("test failure"),
                path: PathBuf::from("test-root.pem"),
            },
        });

        match root_store_from_native_result(native) {
            Err(error @ TlsProbeInitError::SystemRootLoad { .. }) => {
                let failures = error
                    .system_root_failures()
                    .ok_or_else(|| io::Error::other("system root failure lost its diagnostics"))?;
                assert_eq!(failures.len(), 1);
                assert!(failures[0].contains("test failure"));
            }
            result => {
                return Err(io::Error::other(format!(
                    "expected a system root loading error, got {result:?}"
                ))
                .into());
            }
        }
        Ok(())
    }

    #[test]
    fn validates_each_native_root_before_building_the_store() -> Result<(), Box<dyn Error>> {
        let generated = generate_simple_self_signed([String::from("root.invalid")])?;
        let mut valid = rustls_native_certs::CertificateResult::default();
        valid.certs.push(generated.cert.der().clone());
        assert_eq!(root_store_from_native_result(valid)?.len(), 1);

        let mut invalid = rustls_native_certs::CertificateResult::default();
        invalid.certs.push(CertificateDer::from(vec![0_u8]));
        assert!(matches!(
            root_store_from_native_result(invalid),
            Err(TlsProbeInitError::InvalidSystemRoot { index: 0, .. })
        ));
        assert!(matches!(
            TlsProbe::from_root_store(
                RootCertStore::empty(),
                DEFAULT_CONNECT_TIMEOUT,
                DEFAULT_HANDSHAKE_TIMEOUT
            ),
            Err(TlsProbeInitError::ConfigureVerifier(_))
        ));
        Ok(())
    }

    #[test]
    fn maps_every_connection_failure_without_losing_its_endpoint() {
        let endpoint = String::from("https://bmc.example");
        assert!(matches!(
            AttemptError::ConnectTimeout.into_probe_error(endpoint.clone()),
            TlsProbeError::ConnectTimeout { endpoint: actual } if actual == endpoint
        ));
        assert!(matches!(
            AttemptError::Connect(io::Error::other("connect"))
                .into_probe_error(endpoint.clone()),
            TlsProbeError::Connect { endpoint: actual, .. } if actual == endpoint
        ));
        assert!(matches!(
            AttemptError::HandshakeTimeout.into_probe_error(endpoint.clone()),
            TlsProbeError::HandshakeTimeout { endpoint: actual } if actual == endpoint
        ));
        assert!(matches!(
            AttemptError::Handshake(io::Error::other("handshake"))
                .into_probe_error(endpoint.clone()),
            TlsProbeError::Handshake { endpoint: actual, .. } if actual == endpoint
        ));
    }

    #[test]
    fn debug_views_do_not_expose_certificate_material() -> Result<(), Box<dyn Error>> {
        let generated = generate_simple_self_signed([String::from("debug.invalid")])?;
        let certificate = generated.cert.der().clone();
        let mut roots = RootCertStore::empty();
        roots.add(certificate.clone())?;
        let probe =
            TlsProbe::from_root_store(roots, DEFAULT_CONNECT_TIMEOUT, DEFAULT_HANDSHAKE_TIMEOUT)?;
        let capture = Arc::new(CertificateCapture::default());
        capture.record(&certificate)?;
        let verifier = RecordingSystemVerifier {
            capture: Arc::clone(&capture),
            system_verifier: Arc::clone(&probe.system_verifier),
        };

        assert_eq!(format!("{capture:?}"), "CertificateCapture { .. }");
        assert_eq!(format!("{verifier:?}"), "RecordingSystemVerifier { .. }");
        let probe_debug = format!("{probe:?}");
        assert!(probe_debug.contains("connect_timeout"));
        assert!(!probe_debug.contains(&format!("{:02X?}", certificate.as_ref())));
        Ok(())
    }

    #[test]
    fn bounds_certificate_capture_before_copying_der() -> Result<(), Box<dyn Error>> {
        let capture = CertificateCapture::default();
        let actual = TlsCertificate::MAX_DER_BYTES + 1;
        let oversized = CertificateDer::from(vec![0_u8; actual]);

        capture.record(&oversized)?;

        assert!(matches!(
            capture.take()?,
            CapturedCertificate::TooLarge { actual: observed } if observed == actual
        ));
        assert!(matches!(capture.take()?, CapturedCertificate::Empty));
        Ok(())
    }

    /// The subject alternative names of the scripted TLS server's leaf
    /// certificate: the DNS name the certificate has always carried, plus
    /// the numeric IPv4 loopback the tests connect through.
    ///
    /// The endpoint address must be the numeric loopback, never `localhost`:
    /// Windows can resolve `localhost` to `::1`, which the IPv4-only listener
    /// refuses, and the refused connection turns an expected handshake
    /// timeout into a plain connection error.
    const TEST_SERVER_CERTIFICATE_SANS: [&str; 2] = ["localhost", "127.0.0.1"];

    struct TestTlsServer {
        address: EndpointAddress,
        socket: SocketAddr,
        certificate: CertificateDer<'static>,
        task: JoinHandle<Result<Vec<usize>, io::Error>>,
    }

    impl TestTlsServer {
        async fn start(connections: usize) -> Result<Self, Box<dyn Error>> {
            Self::start_with_versions(connections, rustls::DEFAULT_VERSIONS).await
        }

        async fn start_tls12() -> Result<Self, Box<dyn Error>> {
            Self::start_with_versions(1, &[&rustls::version::TLS12]).await
        }

        async fn start_with_versions(
            connections: usize,
            versions: &[&'static SupportedProtocolVersion],
        ) -> Result<Self, Box<dyn Error>> {
            Self::start_with_versions_and_sans(
                connections,
                versions,
                TEST_SERVER_CERTIFICATE_SANS
                    .iter()
                    .map(|sans| String::from(*sans))
                    .collect(),
            )
            .await
        }

        /// Starts the scripted TLS server with an explicit certificate
        /// subject alternative name list, for tests that must provoke a
        /// hostname mismatch against the served identity.
        async fn start_with_versions_and_sans(
            connections: usize,
            versions: &[&'static SupportedProtocolVersion],
            sans: Vec<String>,
        ) -> Result<Self, Box<dyn Error>> {
            let CertifiedKey { cert, signing_key } = generate_simple_self_signed(sans)?;
            let certificate = cert.der().clone();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ServerConfig::builder_with_provider(provider)
                .with_protocol_versions(versions)?
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)?;
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let socket = listener.local_addr()?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let task = tokio::spawn(run_test_server(listener, acceptor, connections));
            Ok(Self {
                address: endpoint_address(socket, "127.0.0.1")?,
                socket,
                certificate,
                task,
            })
        }

        async fn finish(self) -> Result<Vec<usize>, Box<dyn Error>> {
            Ok(self.task.await??)
        }
    }

    fn endpoint_address(socket: SocketAddr, host: &str) -> Result<EndpointAddress, Box<dyn Error>> {
        Ok(EndpointAddress::parse(&format!(
            "https://{host}:{}",
            socket.port()
        ))?)
    }

    fn test_probe(
        connect_timeout: Duration,
        handshake_timeout: Duration,
    ) -> Result<TlsProbe, Box<dyn Error>> {
        let generated = generate_simple_self_signed([String::from("test-root.invalid")])?;
        let mut roots = RootCertStore::empty();
        roots.add(generated.cert.der().clone())?;
        Ok(TlsProbe::from_root_store(
            roots,
            connect_timeout,
            handshake_timeout,
        )?)
    }

    async fn run_test_server(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        connections: usize,
    ) -> Result<Vec<usize>, io::Error> {
        let mut application_bytes = Vec::with_capacity(connections);
        for _ in 0..connections {
            let (tcp, _) = listener.accept().await?;
            let handshake = timeout(Duration::from_secs(5), acceptor.accept(tcp))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test TLS handshake"))?;
            let bytes = match handshake {
                Ok(mut stream) => {
                    let mut byte = [0_u8; 1];
                    let read = timeout(Duration::from_secs(5), stream.read(&mut byte))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "test application read")
                        })?;
                    match read {
                        Ok(bytes) => bytes,
                        Err(source)
                            if matches!(
                                source.kind(),
                                io::ErrorKind::ConnectionAborted
                                    | io::ErrorKind::ConnectionReset
                                    | io::ErrorKind::UnexpectedEof
                            ) =>
                        {
                            0
                        }
                        Err(source) => return Err(source),
                    }
                }
                Err(_) => 0,
            };
            application_bytes.push(bytes);
        }
        Ok(application_bytes)
    }
}
