//! The Site posture (design 4.4, 0.6.0 S3): a long-running HTTPS console on
//! the management network.
//!
//! The Site reuses the Standalone runtime's instance and drain structure and
//! differs only in its listener: an explicitly requested address, HTTPS with
//! a rustls configuration narrowed to TLS 1.3, and no plaintext HTTP
//! fallback. The 0.6.0 acceptance "非 HTTPS 不允许远程登录" is enforced at
//! startup: a non-loopback listen address without TLS material is a hard
//! configuration error, never a degraded plaintext service.
//!
//! When no certificate is supplied, the Site generates a self-signed
//! certificate whose SAN covers the requested listen host, persists the pair
//! below `tls/` (private key mode 0600), and prints the certificate
//! fingerprint at startup.

use std::{
    fmt,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use axum::serve::ListenerExt as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rutilus_application::{Clock, CoreResourceReader, RedfishDiscovery, TlsIdentityProbe};
use rutilus_domain::{AuditActor, DeploymentPosture};
use rutilus_infra_redfish::{NV_REDFISH_DEVELOPMENT_BASELINE, RedfishGateway, TlsProbeInitError};
use rutilus_platform::{
    MasterKeyFile, MasterKeyFileError, RuntimePaths, SystemMasterKeyFile, SystemMasterKeyFileError,
    SystemSecretStore, SystemSecretStoreError,
};
use rutilus_security::{RewrapError, RewrappedMasterKey, UnlockSource, rewrap_master_key};
use rutilus_web::{AuthPolicy, AuthServices, ProductServices, WebProductInfo, router_with_auth};
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::net::TcpListener;

use crate::{
    StandaloneInstance, StandaloneInstanceCloseError, StandaloneInstanceError, StandaloneRunError,
    StandaloneUnlock, SystemClock, standalone_runtime::run_background_services,
};

/// One host:port pair for a Site listener, where the host is an IP literal
/// or a DNS name (the self-signed certificate SAN covers either form).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListenAddress {
    host: String,
    port: u16,
}

impl ListenAddress {
    /// Parses `HOST:PORT`, accepting `[V6]:PORT` for IPv6 literals.
    ///
    /// # Errors
    ///
    /// Returns [`ListenAddressError`] when the port is missing or out of
    /// range, or the host is empty.
    pub fn parse(value: &str) -> Result<Self, ListenAddressError> {
        let (host, port) = if let Some(rest) = value.strip_prefix('[') {
            let (host, port) = rest
                .split_once("]:")
                .ok_or(ListenAddressError::MissingPort)?;
            (host, port)
        } else {
            let (host, port) = value
                .rsplit_once(':')
                .ok_or(ListenAddressError::MissingPort)?;
            (host, port)
        };
        if host.is_empty() {
            return Err(ListenAddressError::EmptyHost);
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| ListenAddressError::InvalidPort)?;
        if port == 0 {
            return Err(ListenAddressError::InvalidPort);
        }
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }

    /// The listen host: an IP literal or a DNS name.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The listen port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Whether the host is an IP literal (vs. a DNS name).
    #[must_use]
    pub fn host_is_ip(&self) -> bool {
        self.ip().is_some()
    }

    /// The IP literal when the host is one; `None` for DNS names.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse::<IpAddr>().ok()
    }
}

impl FromStr for ListenAddress {
    type Err = ListenAddressError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl fmt::Display for ListenAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip() {
            Some(IpAddr::V6(ip)) => write!(formatter, "[{ip}]:{}", self.port),
            _ => write!(formatter, "{}:{}", self.host, self.port),
        }
    }
}

/// A controlled failure while parsing a Site listen address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ListenAddressError {
    #[error("Site listen address must be HOST:PORT")]
    MissingPort,
    #[error("Site listen port must be between 1 and 65535")]
    InvalidPort,
    #[error("Site listen host cannot be empty")]
    EmptyHost,
}

/// The Site listener configuration from the CLI.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SiteRunOptions {
    listen: ListenAddress,
    cert: Option<PathBuf>,
    key: Option<PathBuf>,
}

impl SiteRunOptions {
    /// Builds the Site listen configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SiteConfigError::CertificateWithoutKey`] when exactly one of
    /// `cert`/`key` is supplied.
    pub fn new(
        listen: ListenAddress,
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
    ) -> Result<Self, SiteConfigError> {
        if cert.is_some() != key.is_some() {
            return Err(SiteConfigError::CertificateWithoutKey);
        }
        Ok(Self { listen, cert, key })
    }

    #[must_use]
    pub fn listen(&self) -> &ListenAddress {
        &self.listen
    }

    #[must_use]
    pub fn cert(&self) -> Option<&Path> {
        self.cert.as_deref()
    }

    #[must_use]
    pub fn key(&self) -> Option<&Path> {
        self.key.as_deref()
    }
}

/// Whether the Site listener may serve plaintext HTTP.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ListenerPolicy {
    /// Loopback-only plaintext: acceptable for a local console.
    LoopbackPlaintext,
    /// TLS on any interface; the only posture for a management network.
    Https,
}

/// The 0.6.0 acceptance "非 HTTPS 不允许远程登录": a non-loopback listen
/// address without TLS material is a hard startup error, never a degraded
/// plaintext service.
fn listener_policy(address: SocketAddr, tls: bool) -> Result<ListenerPolicy, SiteConfigError> {
    if tls {
        return Ok(ListenerPolicy::Https);
    }
    if address.ip().is_loopback() {
        return Ok(ListenerPolicy::LoopbackPlaintext);
    }
    Err(SiteConfigError::RemotePlaintext { listen: address })
}

/// The TLS material the Site listener serves with.
#[derive(Clone, Debug)]
pub struct SiteTls {
    config: Arc<rustls::ServerConfig>,
    fingerprint: String,
}

impl SiteTls {
    /// Loads the provided certificate/key pair, or the persisted pair below
    /// the data directory's `tls/`, or generates and persists a self-signed
    /// pair covering the listen host.
    ///
    /// # Errors
    ///
    /// Returns [`SiteTlsError`] for unreadable or invalid PEM material, a
    /// certificate/key mismatch, generation failure, or persistence failure.
    pub fn load_or_generate(
        paths: &RuntimePaths,
        listen: &ListenAddress,
        provided: Option<(&Path, &Path)>,
    ) -> Result<Self, SiteTlsError> {
        if let Some((cert_path, key_path)) = provided {
            let cert = read_certificate(cert_path)?;
            let key = read_private_key(key_path)?;
            return Self::from_material(cert, key);
        }
        let cert_path = paths.tls_directory().join("cert.pem");
        let key_path = paths.tls_directory().join("key.pem");
        match (read_certificate(&cert_path), read_private_key(&key_path)) {
            // A previously generated pair is reused so the service keeps its
            // identity across restarts; a missing pair is generated fresh.
            (Ok(cert), Ok(key)) => Self::from_material(cert, key),
            (Err(cert_error), Err(key_error))
                if is_missing(&cert_error) && is_missing(&key_error) =>
            {
                Self::generate_and_persist(paths, listen)
            }
            (Err(cert_error), Err(key_error)) => Err(SiteTlsError::ReadPair {
                cert_error: Box::new(cert_error),
                key_error: Box::new(key_error),
            }),
            (Ok(_), Err(key_error)) => Err(key_error),
            (Err(cert_error), Ok(_)) => Err(cert_error),
        }
    }

    fn generate_and_persist(
        paths: &RuntimePaths,
        listen: &ListenAddress,
    ) -> Result<Self, SiteTlsError> {
        let (cert, key) = generate_self_signed(listen)?;
        let cert_path = paths.tls_directory().join("cert.pem");
        let key_path = paths.tls_directory().join("key.pem");
        persist_text(&cert_path, &pem_encode("CERTIFICATE", cert.as_ref()))?;
        persist_text(&key_path, &pem_encode("PRIVATE KEY", key_der_bytes(&key)?))?;
        Self::from_material(cert, key)
    }

    fn from_material(
        cert: CertificateDer<'static>,
        key: PrivateKeyDer<'static>,
    ) -> Result<Self, SiteTlsError> {
        validate_key_matches_cert(&cert, &key)?;
        let fingerprint = fingerprint(&cert);
        let config = build_server_config(cert, key)?;
        Ok(Self {
            config,
            fingerprint,
        })
    }

    /// The TLS server configuration to serve with.
    #[must_use]
    pub fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.config)
    }

    /// The SHA-256 fingerprint of the served certificate, printed at startup.
    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

fn is_missing(error: &SiteTlsError) -> bool {
    matches!(
        error,
        SiteTlsError::ReadFile { source, .. } if source.kind() == io::ErrorKind::NotFound
    )
}

fn key_der_bytes<'a>(key: &'a PrivateKeyDer<'a>) -> Result<&'a [u8], SiteTlsError> {
    match key {
        PrivateKeyDer::Pkcs8(key) => Ok(key.secret_pkcs8_der()),
        PrivateKeyDer::Pkcs1(key) => Ok(key.secret_pkcs1_der()),
        PrivateKeyDer::Sec1(key) => Ok(key.secret_sec1_der()),
        // `#[non_exhaustive]`: a future key encoding has no PEM form in this
        // release, so it cannot be persisted.
        _ => Err(SiteTlsError::UnsupportedPrivateKey),
    }
}

/// The defensive bound for one PEM file: certificates and keys are small.
const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;

fn read_bounded(path: &Path) -> Result<Vec<u8>, SiteTlsError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|source| SiteTlsError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.len() > MAX_TLS_FILE_BYTES {
        return Err(SiteTlsError::FileTooLarge {
            path: path.to_path_buf(),
        });
    }
    let bytes = std::fs::read(path).map_err(|source| SiteTlsError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    if bytes.len() as u64 > MAX_TLS_FILE_BYTES {
        return Err(SiteTlsError::FileTooLarge {
            path: path.to_path_buf(),
        });
    }
    Ok(bytes)
}

/// Reads one bounded PEM certificate file.
///
/// # Errors
///
/// Returns [`SiteTlsError`] when the file is missing, oversized, or not a
/// valid PEM certificate.
fn read_certificate(path: &Path) -> Result<CertificateDer<'static>, SiteTlsError> {
    use rustls::pki_types::pem::PemObject as _;

    let bytes = read_bounded(path)?;
    CertificateDer::from_pem_slice(&bytes).map_err(|source| SiteTlsError::InvalidCertificate {
        path: path.to_path_buf(),
        source,
    })
}

/// Reads one bounded PEM private key file.
///
/// # Errors
///
/// Returns [`SiteTlsError`] when the file is missing, oversized, or not a
/// valid PEM private key.
fn read_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, SiteTlsError> {
    use rustls::pki_types::pem::PemObject as _;

    let bytes = read_bounded(path)?;
    PrivateKeyDer::from_pem_slice(&bytes).map_err(|source| SiteTlsError::InvalidPrivateKey {
        path: path.to_path_buf(),
        source,
    })
}

/// Persists one PEM text atomically. The private key's 0600 restriction is
/// applied to the temporary file before any secret bytes are written.
///
/// # Errors
///
/// Returns [`SiteTlsError::WritePrivateKey`] retaining the exact I/O stage.
fn persist_text(path: &Path, content: &str) -> Result<(), SiteTlsError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "TLS material path has no parent directory",
            ),
        })?;
    std::fs::create_dir_all(parent).map_err(|source| SiteTlsError::WritePrivateKey {
        path: path.to_path_buf(),
        source,
    })?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|source| SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source,
        })?;
    restrict_private_key_permissions(temporary.path())?;
    std::io::Write::write_all(&mut temporary, content.as_bytes()).map_err(|source| {
        SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source,
        }
    })?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|source| SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source,
        })?;
    let persisted = temporary
        .persist(path)
        .map_err(|error| SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    persisted
        .sync_all()
        .map_err(|source| SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(())
}

/// Restricts a freshly created TLS temporary file to mode 0600 before any
/// secret bytes are written (Unix only; Windows has no POSIX modes).
#[cfg(unix)]
fn restrict_private_key_permissions(path: &Path) -> Result<(), SiteTlsError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        SiteTlsError::WritePrivateKey {
            path: path.to_path_buf(),
            source,
        }
    })
}

// The non-Unix twin mirrors the Unix signature so the call sites stay
// cfg-free; Windows has no POSIX modes to enforce.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_private_key_permissions(_path: &Path) -> Result<(), SiteTlsError> {
    Ok(())
}

/// Encodes one DER value as a standard base64-wrapped PEM block.
fn pem_encode(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    use std::fmt::Write as _;

    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::with_capacity(encoded.len() + 64);
    let _ = writeln!(pem, "-----BEGIN {label}-----");
    for chunk in encoded.as_bytes().chunks(64) {
        // Base64 output is pure ASCII, so bytes map one-to-one to characters.
        pem.extend(chunk.iter().map(|byte| *byte as char));
        pem.push('\n');
    }
    let _ = writeln!(pem, "-----END {label}-----");
    pem
}

/// Generates a self-signed certificate whose SAN covers the listen host and
/// whose private key is a fresh `P-256` key pair.
///
/// # Errors
///
/// Returns [`SiteTlsError::GenerateCertificate`] when key or certificate
/// generation fails.
// `Duration::from_days` is not stable in this toolchain, so the day
// multiples below are spelled out in seconds.
#[allow(clippy::duration_suboptimal_units)]
fn generate_self_signed(
    listen: &ListenAddress,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), SiteTlsError> {
    let key_pair = rcgen::KeyPair::generate().map_err(SiteTlsError::GenerateCertificate)?;
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .map_err(SiteTlsError::GenerateCertificate)?;
    if let Some(ip) = listen.ip() {
        params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
    } else {
        let name = rcgen::string::Ia5String::try_from(listen.host())
            .map_err(SiteTlsError::GenerateCertificate)?;
        params.subject_alt_names.push(rcgen::SanType::DnsName(name));
    }
    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::from_secs(60 * 60 * 24);
    params.not_after = now + Duration::from_secs(60 * 60 * 24 * 365 * 10);
    params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params
        .self_signed(&key_pair)
        .map_err(SiteTlsError::GenerateCertificate)?;
    let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
    Ok((certificate.der().clone(), key))
}

/// Refuses a certificate whose public key does not match the private key.
///
/// Both sides are compared as RFC 5280 `SubjectPublicKeyInfo` DER: the key's
/// SPKI from rustls's signing key, and the certificate's SPKI parsed with
/// the same webpki crate rustls uses for verification.
///
/// # Errors
///
/// Returns [`SiteTlsError::KeyCertificateMismatch`] when the pair does not
/// match, or a parsing error for either side.
fn validate_key_matches_cert(
    cert: &CertificateDer<'static>,
    key: &PrivateKeyDer<'static>,
) -> Result<(), SiteTlsError> {
    let signing_key = rustls::crypto::ring::sign::any_supported_type(key)
        .map_err(|_| SiteTlsError::UnsupportedPrivateKey)?;
    let key_spki = signing_key
        .public_key()
        .ok_or(SiteTlsError::UnsupportedPrivateKey)?;
    let end_entity =
        webpki::EndEntityCert::try_from(cert).map_err(SiteTlsError::UnsupportedCertificate)?;
    if key_spki.as_ref() != end_entity.subject_public_key_info().as_ref() {
        return Err(SiteTlsError::KeyCertificateMismatch);
    }
    Ok(())
}

/// Builds the Site's rustls configuration: TLS 1.3 only, no client
/// authentication.
///
/// The workspace rustls is compiled with the `tls12` feature (the Redfish
/// gateway needs TLS 1.2 for older BMCs), but the Site console explicitly
/// narrows its protocol versions to TLS 1.3.
///
/// # Errors
///
/// Returns [`SiteTlsError`] when version selection or certificate
/// configuration fails.
fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, SiteTlsError> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(SiteTlsError::TlsVersion)?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(SiteTlsError::TlsConfiguration)?;
    Ok(Arc::new(config))
}

/// The SHA-256 fingerprint of one certificate, printed colon-separated.
fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// The Site listener: the requested address served over TLS (or loopback
/// plaintext, which `bind` refuses off loopback).
#[derive(Debug)]
pub struct SiteBinding {
    listener: TcpListener,
    tls: Option<SiteTls>,
    address: SocketAddr,
}

impl SiteBinding {
    /// Binds the Site listener and enforces the HTTPS policy.
    ///
    /// # Errors
    ///
    /// Returns [`SiteRunError::Config`] for a non-loopback address without
    /// TLS material (the 0.6.0 hard error), [`SiteRunError::Bind`] or
    /// [`SiteRunError::LocalAddress`] for socket failures, and
    /// [`SiteRunError::Tls`] when the TLS material cannot be prepared.
    pub async fn bind(
        paths: &RuntimePaths,
        options: &SiteRunOptions,
    ) -> Result<Self, SiteRunError> {
        let listener = TcpListener::bind((options.listen.host().to_owned(), options.listen.port()))
            .await
            .map_err(SiteRunError::Bind)?;
        let address = listener.local_addr().map_err(SiteRunError::LocalAddress)?;
        let tls = match listener_policy(address, options.cert.is_some())? {
            ListenerPolicy::Https => Some(
                SiteTls::load_or_generate(
                    paths,
                    &options.listen,
                    options.cert.as_deref().zip(options.key.as_deref()),
                )
                .map_err(SiteRunError::Tls)?,
            ),
            ListenerPolicy::LoopbackPlaintext => None,
        };
        Ok(Self {
            listener,
            tls,
            address,
        })
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub fn url(&self) -> String {
        let scheme = if self.tls.is_some() { "https" } else { "http" };
        format!("{scheme}://{}/", self.address)
    }

    /// Serves the embedded Web application over the Site listener until a
    /// tracked shutdown future resolves, then waits for Axum's graceful
    /// drain. The certificate fingerprint is printed once, at startup.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bound listener fails while serving.
    pub async fn serve_until<Services, Gateway, Time, Shutdown>(
        self,
        policy: AuthPolicy,
        services: Arc<Services>,
        gateway: Arc<Gateway>,
        clock: Time,
        shutdown: Shutdown,
    ) -> io::Result<()>
    where
        Services: ProductServices + AuthServices + 'static,
        Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
        Time: Clock + Clone + 'static,
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let url = self.url();
        let router = router_with_auth(
            WebProductInfo::new(env!("CARGO_PKG_VERSION"), NV_REDFISH_DEVELOPMENT_BASELINE),
            AuditActor::LocalOperator,
            DeploymentPosture::Site,
            policy,
            services,
            gateway,
            clock,
        )
        .into_make_service_with_connect_info::<SocketAddr>();
        if let Some(tls) = self.tls {
            println!("Rutilus Site is listening at {url}");
            println!("TLS certificate fingerprint: {}", tls.fingerprint());
            let acceptor = tokio_rustls::TlsAcceptor::from(tls.server_config());
            // `tap_io` gives axum's generic `Connected` implementation
            // the accepted remote address, so the sign-in rate limiter
            // sees client addresses on the TLS path exactly as on the
            // plaintext path.
            let listener = TlsListener {
                listener: self.listener,
                acceptor,
            }
            .tap_io(|_| {});
            axum::serve(listener, router)
                .with_graceful_shutdown(shutdown)
                .await
        } else {
            println!("Rutilus Site is listening at {url} (loopback plaintext)");
            axum::serve(self.listener, router)
                .with_graceful_shutdown(shutdown)
                .await
        }
    }
}

/// The bound for one TLS handshake: a client that connects without
/// handshaking must not stall the listener forever.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// An axum listener that performs the TLS handshake on every accepted
/// connection. A failed handshake is one client's problem: it is recorded
/// and the listener keeps serving.
///
/// The handshake runs inline because axum's [`Listener::accept`] contract is
/// serial — hyper consumes the returned IO only after `accept` resolves, so
/// there is no per-connection task boundary to move the handshake to without
/// rearchitecting past the axum serve loop. The 10-second bound therefore
/// caps the damage of a stalled handshake: one slow client can delay, but
/// never starve, the remaining connections.
struct TlsListener {
    listener: TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = match self.listener.accept().await {
                Ok(accepted) => accepted,
                Err(error) => {
                    eprintln!("Site accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(stream)) => return (stream, address),
                Ok(Err(error)) => {
                    eprintln!("Site TLS handshake failed from {address}: {error}");
                }
                Err(_) => {
                    // Dropping the timed-out future closes the stalled
                    // connection, so the accept loop proceeds.
                    eprintln!("Site TLS handshake timed out from {address}");
                }
            }
        }
    }

    fn local_addr(&self) -> io::Result<Self::Addr> {
        self.listener.local_addr()
    }
}

/// Runs the Site posture over the initialized instance until the external
/// `stop` future resolves (the console stop signal, plus the Windows SCM
/// stop watch for services), draining through the same §7.8 order as the
/// Standalone runtime.
///
/// `unlock` is `Some` for an interactive passphrase unlock and `None` for
/// the unattended operating-system unlock that services use.
///
/// # Errors
///
/// Returns [`SiteRunError`] while preserving both server and close failures
/// if they occur during the same shutdown.
pub async fn run_site<Stop>(
    paths: &RuntimePaths,
    options: &SiteRunOptions,
    unlock: Option<&StandaloneUnlock>,
    stop: Stop,
) -> Result<(), SiteRunError>
where
    Stop: Future<Output = io::Result<()>> + Send,
{
    let gateway = RedfishGateway::from_system_roots()
        .await
        .map_err(SiteRunError::Gateway)?;
    let gateway = Arc::new(gateway);
    let binding = SiteBinding::bind(paths, options).await?;
    let instance = if let Some(passphrase) = unlock {
        StandaloneInstance::open(paths, passphrase)
            .await
            .map_err(SiteRunError::Open)?
    } else {
        let store = SystemSecretStore::new();
        StandaloneInstance::open_system(paths, &store)
            .await
            .map_err(SiteRunError::Open)?
    };
    let services_for_server = instance.state();
    let gateway_for_server = Arc::clone(&gateway);
    let run_result = run_background_services(
        instance.state(),
        gateway,
        move |policy, stop_watch, scheduler_done_receiver| {
            binding.serve_until(
                policy,
                services_for_server,
                gateway_for_server,
                SystemClock,
                async move {
                    let mut stop = stop_watch;
                    stop.stopped().await;
                    let _ = scheduler_done_receiver.await;
                },
            )
        },
        stop,
    )
    .await;
    let close_result = instance.close().await;
    match (run_result, close_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(SiteRunError::Run(source)),
        (Ok(()), Err(source)) => Err(SiteRunError::Close(source)),
        (Err(run), Err(close)) => Err(SiteRunError::RunAndClose { run, close }),
    }
}

/// Reports whether the instance already has an OS-protected envelope.
#[must_use]
pub fn has_system_master_key(paths: &RuntimePaths) -> bool {
    std::fs::symlink_metadata(paths.system_master_key_path()).is_ok()
}

/// Rewraps the instance master key to the operating-system unlock source
/// (one-time, at `service install --site` time) so the service can boot
/// unattended.
///
/// # Errors
///
/// Returns [`SiteInstallError`] when the passphrase envelope cannot be
/// loaded, the passphrase is wrong, the OS store rejects the key, or the
/// new envelope cannot be persisted.
pub async fn rewrap_to_system_unlock(
    paths: &RuntimePaths,
    passphrase: &SecretString,
) -> Result<(), SiteInstallError> {
    let protected = MasterKeyFile::new(paths.master_key_path())
        .load()
        .map_err(SiteInstallError::MasterKeyFile)?;
    let store = SystemSecretStore::new();
    let rewrapped = rewrap_master_key(
        &protected,
        passphrase,
        UnlockSource::System,
        None,
        Some(&store),
    )
    .await
    .map_err(SiteInstallError::Rewrap)?;
    let RewrappedMasterKey::System(system) = rewrapped else {
        return Err(SiteInstallError::UnexpectedRewrap);
    };
    SystemMasterKeyFile::new(paths.system_master_key_path())
        .create(&system)
        .map_err(SiteInstallError::SystemMasterKeyFile)?;
    Ok(())
}

/// A controlled failure while preparing the Site listener.
#[derive(Debug, Error)]
pub enum SiteConfigError {
    #[error(
        "refusing to listen on non-loopback address {listen} without TLS: remote login over plaintext HTTP is not allowed"
    )]
    RemotePlaintext { listen: SocketAddr },
    #[error("invalid Site listen address: {0}")]
    ListenAddress(#[from] ListenAddressError),
    #[error("the Site TLS certificate and private key must be provided together")]
    CertificateWithoutKey,
}

/// A controlled failure while preparing the Site TLS material.
#[derive(Debug, Error)]
pub enum SiteTlsError {
    #[error("failed to read the TLS file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read the TLS pair ({cert_error}; {key_error})")]
    ReadPair {
        cert_error: Box<Self>,
        key_error: Box<Self>,
    },
    #[error("TLS file {path} exceeds the size bound")]
    FileTooLarge { path: PathBuf },
    #[error("invalid TLS certificate {path}: {source}")]
    InvalidCertificate {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    #[error("invalid TLS private key {path}: {source}")]
    InvalidPrivateKey {
        path: PathBuf,
        #[source]
        source: rustls::pki_types::pem::Error,
    },
    #[error("the TLS certificate cannot be parsed: {0}")]
    UnsupportedCertificate(#[source] webpki::Error),
    #[error("the TLS private key type is unsupported")]
    UnsupportedPrivateKey,
    #[error("the TLS certificate and private key do not match")]
    KeyCertificateMismatch,
    #[error("failed to generate the Site self-signed certificate: {0}")]
    GenerateCertificate(#[source] rcgen::Error),
    #[error("failed to persist the Site TLS material at {path}: {source}")]
    WritePrivateKey {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("TLS version selection failed: {0}")]
    TlsVersion(#[source] rustls::Error),
    #[error("failed to assemble the TLS server configuration: {0}")]
    TlsConfiguration(#[source] rustls::Error),
}

/// A controlled failure before or during the Site server.
#[derive(Debug, Error)]
pub enum SiteRunError {
    #[error("failed to load platform TLS trust for the Site server: {0}")]
    Gateway(#[source] TlsProbeInitError),
    #[error("failed to prepare the Site listener: {0}")]
    Config(#[from] SiteConfigError),
    #[error("failed to bind the Site listener: {0}")]
    Bind(#[source] io::Error),
    #[error("failed to read the Site listener address: {0}")]
    LocalAddress(#[source] io::Error),
    #[error("failed to prepare the Site TLS material: {0}")]
    Tls(#[source] SiteTlsError),
    #[error("failed to open initialized Site state: {0}")]
    Open(#[source] StandaloneInstanceError),
    #[error("Site server failed: {0}")]
    Run(#[source] StandaloneRunError),
    #[error("Site server stopped but SQLite shutdown failed: {0}")]
    Close(#[source] StandaloneInstanceCloseError),
    #[error("Site server and SQLite shutdown both failed (server: {run}; close: {close})")]
    RunAndClose {
        run: StandaloneRunError,
        close: StandaloneInstanceCloseError,
    },
}

/// A controlled failure while rewrapping the master key to OS protection.
#[derive(Debug, Error)]
pub enum SiteInstallError {
    #[error("failed to load the passphrase-protected master key: {0}")]
    MasterKeyFile(#[source] MasterKeyFileError),
    #[error("failed to rewrap the master key to the operating system: {0}")]
    Rewrap(#[source] RewrapError<SystemSecretStoreError>),
    #[error("failed to persist the system-protected master key: {0}")]
    SystemMasterKeyFile(#[source] SystemMasterKeyFileError),
    #[error("the master-key rewrap produced an unexpected protection")]
    UnexpectedRewrap,
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::Ipv4Addr};

    use super::*;

    fn parse_listen(value: &str) -> Result<ListenAddress, ListenAddressError> {
        ListenAddress::parse(value)
    }

    #[test]
    fn parses_ip_and_dns_listen_addresses() -> Result<(), ListenAddressError> {
        let ipv4 = parse_listen("0.0.0.0:8443")?;
        assert_eq!(ipv4.host(), "0.0.0.0");
        assert_eq!(ipv4.port(), 8443);
        assert!(ipv4.host_is_ip());
        assert_eq!(ipv4.to_string(), "0.0.0.0:8443");

        let ipv6 = parse_listen("[::1]:8443")?;
        assert_eq!(ipv6.host(), "::1");
        assert_eq!(ipv6.to_string(), "[::1]:8443");

        let dns = parse_listen("rutilus.example.com:8443")?;
        assert_eq!(dns.host(), "rutilus.example.com");
        assert!(!dns.host_is_ip());
        assert_eq!(dns.to_string(), "rutilus.example.com:8443");

        assert!(matches!(
            ListenAddress::parse("127.0.0.1"),
            Err(ListenAddressError::MissingPort)
        ));
        assert!(matches!(
            ListenAddress::parse("127.0.0.1:0"),
            Err(ListenAddressError::InvalidPort)
        ));
        assert!(matches!(
            ListenAddress::parse(":8443"),
            Err(ListenAddressError::EmptyHost)
        ));
        assert!(matches!(
            ListenAddress::parse("127.0.0.1:99999"),
            Err(ListenAddressError::InvalidPort)
        ));
        Ok(())
    }

    #[test]
    fn refuses_non_loopback_plaintext_and_accepts_tls_anywhere() {
        assert!(matches!(
            listener_policy(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8443)), false),
            Err(SiteConfigError::RemotePlaintext { .. })
        ));
        assert_eq!(
            listener_policy(SocketAddr::from((Ipv4Addr::LOCALHOST, 8080)), false).ok(),
            Some(ListenerPolicy::LoopbackPlaintext)
        );
        assert_eq!(
            listener_policy(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 8443)), true).ok(),
            Some(ListenerPolicy::Https)
        );
        assert_eq!(
            listener_policy(SocketAddr::from((Ipv4Addr::LOCALHOST, 8443)), true).ok(),
            Some(ListenerPolicy::Https)
        );
    }

    #[test]
    fn validates_certificate_pairing() -> Result<(), ListenAddressError> {
        assert!(matches!(
            SiteRunOptions::new(
                parse_listen("127.0.0.1:8080")?,
                Some(PathBuf::from("cert.pem")),
                None,
            ),
            Err(SiteConfigError::CertificateWithoutKey)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn generates_persists_and_reuses_a_self_signed_pair() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let listen = parse_listen("127.0.0.1:8443")?;

        let first = SiteTls::load_or_generate(&paths, &listen, None)?;
        assert_eq!(first.fingerprint().split(':').count(), 32);
        assert!(paths.tls_directory().join("cert.pem").is_file());
        assert!(paths.tls_directory().join("key.pem").is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(paths.tls_directory().join("key.pem"))?
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }

        // A second boot reuses the persisted identity.
        let second = SiteTls::load_or_generate(&paths, &listen, None)?;
        assert_eq!(first.fingerprint(), second.fingerprint());
        Ok(())
    }

    #[test]
    fn generated_certificate_matches_its_private_key() -> Result<(), Box<dyn Error>> {
        let listen = parse_listen("127.0.0.1:8443")?;
        let (cert, key) = generate_self_signed(&listen)?;

        // The match check passes for the generated pair...
        validate_key_matches_cert(&cert, &key)?;
        // ...and refuses a pair from two different generations.
        let (_other_cert, other_key) = generate_self_signed(&listen)?;
        assert!(matches!(
            validate_key_matches_cert(&cert, &other_key),
            Err(SiteTlsError::KeyCertificateMismatch)
        ));
        Ok(())
    }

    #[test]
    fn fingerprints_are_colon_separated_uppercase_hex() -> Result<(), Box<dyn Error>> {
        let listen = parse_listen("127.0.0.1:8443")?;
        let (cert, _key) = generate_self_signed(&listen)?;
        let fingerprint = fingerprint(&cert);
        assert_eq!(fingerprint.split(':').count(), 32);
        assert!(
            fingerprint
                .split(':')
                .all(|byte| byte.len() == 2 && byte.chars().all(|c| c.is_ascii_hexdigit()))
        );
        Ok(())
    }

    #[test]
    fn pem_encoding_wraps_at_64_columns() {
        let der = vec![0xAB_u8; 100];
        let pem = pem_encode("PRIVATE KEY", &der);
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.ends_with("-----END PRIVATE KEY-----\n"));
        for line in pem.lines().filter(|line| !line.starts_with("-----")) {
            assert!(line.len() <= 64);
        }
    }

    /// Serves one TLS connection on a loopback pair and returns the bytes
    /// the server received, so tests can assert handshake and delivery.
    async fn serve_one_connection(
        config: Arc<rustls::ServerConfig>,
    ) -> Result<(SocketAddr, tokio::task::JoinHandle<io::Result<Vec<u8>>>), io::Error> {
        use tokio::io::AsyncReadExt as _;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut tls_stream = acceptor.accept(stream).await?;
            let mut received = Vec::new();
            tls_stream.read_to_end(&mut received).await?;
            Ok(received)
        });
        Ok((address, server))
    }

    #[tokio::test]
    async fn tls13_client_handshakes_and_tls12_client_is_refused() -> Result<(), Box<dyn Error>> {
        use rustls::pki_types::pem::PemObject as _;
        use tokio::io::AsyncWriteExt as _;

        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let listen = parse_listen("127.0.0.1:8443")?;
        let tls = SiteTls::load_or_generate(&paths, &listen, None)?;

        // The TLS 1.3 client trusts the self-signed certificate directly and
        // verifies the IP SAN, so a successful handshake asserts both the
        // TLS 1.3-only narrowing and the SAN coverage.
        let mut root_store = rustls::RootCertStore::empty();
        let cert = std::fs::read(paths.tls_directory().join("cert.pem"))?;
        let certificate = CertificateDer::from_pem_slice(&cert)
            .map_err(|error| io::Error::other(error.to_string()))?;
        root_store
            .add(certificate)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| io::Error::other(error.to_string()))?
        .with_root_certificates(root_store.clone())
        .with_no_client_auth();

        let (address, server) = serve_one_connection(tls.server_config()).await?;
        let client = tokio::net::TcpStream::connect(address).await?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1")
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut tls_client = connector
            .connect(server_name, client)
            .await
            .map_err(|error| io::Error::other(error.to_string()))?;
        tls_client
            .write_all(b"GET /api/v1/health HTTP/1.1\r\n\r\n")
            .await?;
        tls_client.shutdown().await?;
        assert_eq!(
            server.await.map_err(io::Error::other)??,
            b"GET /api/v1/health HTTP/1.1\r\n\r\n"
        );

        // A TLS 1.2-only client must be refused by the TLS 1.3-only server.
        // The client trusts the same self-signed root store as the TLS 1.3
        // client, so the refusal is attributable to the protocol version
        // alone: were the server to accept TLS 1.2, this handshake would
        // succeed (the certificate would verify) and the assertion fails.
        let tls12_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS12])
        .map_err(|error| io::Error::other(error.to_string()))?
        .with_root_certificates(root_store)
        .with_no_client_auth();
        let (address, server) = serve_one_connection(tls.server_config()).await?;
        let client = tokio::net::TcpStream::connect(address).await?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls12_config));
        let server_name = rustls::pki_types::ServerName::try_from("127.0.0.1")
            .map_err(|error| io::Error::other(error.to_string()))?;
        assert!(connector.connect(server_name, client).await.is_err());
        assert!(server.await.map_err(io::Error::other)?.is_err());
        Ok(())
    }
}
