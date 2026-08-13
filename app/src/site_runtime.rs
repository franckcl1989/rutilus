//! The Site posture (design 4.4, 0.6.0 S3): a long-running HTTPS console on
//! the management network.
//!
//! The Site reuses the Standalone runtime's instance and drain structure and
//! differs only in its listener: an explicitly requested address, HTTPS with
//! a rustls configuration narrowed to TLS 1.3, and no plaintext HTTP
//! fallback off loopback. The 0.6.0 acceptance "非 HTTPS 不允许远程登录" is
//! enforced at startup: every non-loopback listen serves HTTPS — with the
//! CLI-provided pair, the pair persisted below `tls/`, or, when neither
//! exists, a freshly generated self-signed certificate whose SAN covers the
//! requested listen host (private key persisted mode 0600). The certificate
//! fingerprint is printed at startup for out-of-band verification, and only
//! a loopback listen without any TLS material is served plaintext.

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

use axum::{http::StatusCode, serve::ListenerExt as _};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rutilus_application::{
    CenterSync, CenterSyncError, CenterSyncOptions, Clock, CoreResourceReader, RedfishDiscovery,
    TlsIdentityProbe,
};
use rutilus_domain::{
    AuditActor, CenterBinding, CenterBindingState, CertificateFingerprint, DeploymentPosture,
    InstanceId, InstanceKind, SiteInstance,
};
use rutilus_infra_redfish::{NV_REDFISH_DEVELOPMENT_BASELINE, RedfishGateway, TlsProbeInitError};
use rutilus_persistence::{CenterBindingRepositoryError, InstanceRepositoryError, SqliteStore};
use rutilus_platform::{
    MasterKeyFile, MasterKeyFileError, RuntimePaths, SystemMasterKeyFile, SystemMasterKeyFileError,
    SystemSecretStore, SystemSecretStoreError,
};
use rutilus_security::{RewrapError, RewrappedMasterKey, UnlockSource, rewrap_master_key};
use rutilus_web::{
    AuthPolicy, AuthServices, CenterServices, ProductServices, WebProductInfo, router_with_auth,
};
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{net::TcpListener, sync::oneshot};
use tower_http::timeout::TimeoutLayer;
use tracing::instrument;

use crate::{
    CenterClientConfig, StandaloneInstance, StandaloneInstanceCloseError, StandaloneInstanceError,
    StandaloneRunError, StandaloneUnlock, SystemClock, scheduler,
    standalone_runtime::{
        GRACEFUL_DRAIN_TIMEOUT, StandaloneState, run_background_services, serve_with_bounded_drain,
    },
    telemetry_sampler::TelemetryRetention,
    tls_material::{
        TlsMaterialError, key_der_bytes, pem_encode, persist_text, read_certificate,
        read_private_key,
    },
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
                cert_error: Box::new(cert_error.into()),
                key_error: Box::new(key_error.into()),
            }),
            (Ok(_), Err(key_error)) => Err(key_error.into()),
            (Err(cert_error), Ok(_)) => Err(cert_error.into()),
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

fn is_missing(error: &TlsMaterialError) -> bool {
    matches!(
        error,
        TlsMaterialError::ReadFile { source, .. } if source.kind() == io::ErrorKind::NotFound
    )
}

/// Maps the shared TLS material file failures onto the Site's error
/// vocabulary, so the Site listener's public error messages are unchanged
/// by the shared helper module.
impl From<TlsMaterialError> for SiteTlsError {
    fn from(error: TlsMaterialError) -> Self {
        match error {
            TlsMaterialError::ReadFile { path, source } => Self::ReadFile { path, source },
            TlsMaterialError::FileTooLarge { path } => Self::FileTooLarge { path },
            TlsMaterialError::InvalidCertificate { path, source } => {
                Self::InvalidCertificate { path, source }
            }
            TlsMaterialError::InvalidPrivateKey { path, source } => {
                Self::InvalidPrivateKey { path, source }
            }
            TlsMaterialError::UnsupportedPrivateKey => Self::UnsupportedPrivateKey,
            TlsMaterialError::Persist { path, source } => Self::WritePrivateKey { path, source },
        }
    }
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
///
/// `pub(crate)` so the doctor self-check can report the persisted pair's
/// fingerprint without re-parsing it.
pub(crate) fn fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    digest
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Acquires the Site TLS material in three tiers: the CLI-provided pair,
/// the pair persisted below `tls/` (reused so the service keeps its identity
/// across restarts), or a fresh self-signed pair covering the listen host.
/// Generation is reserved for a non-loopback listen; a loopback listen
/// without any material is served plaintext (`None`).
///
/// # Errors
///
/// Returns [`SiteTlsError`] when any tier fails: unreadable or invalid PEM
/// material, a certificate/key mismatch, generation failure, or persistence
/// failure.
fn acquire_tls(
    paths: &RuntimePaths,
    listen: &ListenAddress,
    address: SocketAddr,
    provided: Option<(&Path, &Path)>,
) -> Result<Option<SiteTls>, SiteTlsError> {
    if provided.is_some() || !address.ip().is_loopback() || persisted_pair_exists(paths) {
        // Explicit material, or a non-loopback listen (which must be HTTPS),
        // or an already persisted pair: HTTPS material is expected, and a
        // missing pair is generated and persisted.
        SiteTls::load_or_generate(paths, listen, provided).map(Some)
    } else {
        // A loopback listen without any TLS material: the loopback
        // plaintext posture.
        Ok(None)
    }
}

/// Whether both halves of a previously generated pair exist below `tls/`.
///
/// Both files must be present: a half-written or broken pair must not count
/// as a full pair (which would otherwise trigger generation for a loopback
/// listen).
fn persisted_pair_exists(paths: &RuntimePaths) -> bool {
    paths.tls_directory().join("cert.pem").is_file()
        && paths.tls_directory().join("key.pem").is_file()
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
    /// The TLS material is acquired before the policy decision: the
    /// CLI-provided pair, the pair persisted below `tls/`, or — for a
    /// non-loopback listen — a freshly generated self-signed pair. Every
    /// non-loopback listen therefore serves HTTPS (the 0.6.0 acceptance
    /// "非 HTTPS 不允许远程登录"), with the certificate fingerprint printed
    /// at startup for out-of-band verification; only a loopback listen
    /// without any TLS material serves plaintext.
    ///
    /// # Errors
    ///
    /// Returns [`SiteRunError::Config`] when a non-loopback listen ends up
    /// without TLS material (the fail-closed fallback),
    /// [`SiteRunError::Bind`] or [`SiteRunError::LocalAddress`] for socket
    /// failures, and [`SiteRunError::Tls`] when the TLS material cannot be
    /// prepared.
    pub async fn bind(
        paths: &RuntimePaths,
        options: &SiteRunOptions,
    ) -> Result<Self, SiteRunError> {
        let listener = TcpListener::bind((options.listen.host().to_owned(), options.listen.port()))
            .await
            .map_err(SiteRunError::Bind)?;
        let address = listener.local_addr().map_err(SiteRunError::LocalAddress)?;
        let tls = acquire_tls(
            paths,
            &options.listen,
            address,
            options.cert.as_deref().zip(options.key.as_deref()),
        )
        .map_err(SiteRunError::Tls)?;
        // The policy is decided on the acquired material rather than on
        // whether the CLI supplied a certificate, so a non-loopback listen
        // always ends up HTTPS (self-signed material is generated when
        // absent). Reaching the error arm means a non-loopback listen ended
        // up without TLS material — the fail-closed fallback.
        match listener_policy(address, tls.is_some())? {
            ListenerPolicy::Https | ListenerPolicy::LoopbackPlaintext => {}
        }
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
    /// drain — bounded by `drain_timeout` (N2-2). Every handler is capped at
    /// the same bound (a slower request is aborted with a 408); once the
    /// shutdown future resolves, the in-flight requests get the remaining
    /// grace to finish, and the server then force-closes the connections it
    /// is still waiting on and completes the stop, so a slow client can
    /// never stall the shutdown forever. The certificate fingerprint is
    /// printed once, at startup.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bound listener fails while serving.
    #[allow(clippy::too_many_arguments)]
    pub async fn serve_until<Services, Gateway, Time, Shutdown>(
        self,
        posture: DeploymentPosture,
        policy: AuthPolicy,
        services: Arc<Services>,
        gateway: Arc<Gateway>,
        clock: Time,
        shutdown: Shutdown,
        drain_timeout: Duration,
    ) -> io::Result<()>
    where
        Services: ProductServices + AuthServices + CenterServices + 'static,
        Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
        Time: Clock + Clone + 'static,
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let url = self.url();
        // The posture decides the console route surface (audit follow-up
        // F2): the Site posture serves the Edge surface, and the Center
        // posture serves the aggregation surface — one listener type, two
        // surfaces.
        let router = router_with_auth(
            WebProductInfo::new(env!("CARGO_PKG_VERSION"), NV_REDFISH_DEVELOPMENT_BASELINE),
            AuditActor::LocalOperator,
            posture,
            policy,
            services,
            gateway,
            clock,
        )
        // N2-2: every handler is capped at the same bound as the shutdown
        // drain, so a slow request is aborted with a 408 instead of
        // outliving the drain against the closing store.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            drain_timeout,
        ))
        .into_make_service_with_connect_info::<SocketAddr>();
        // The drain signal fires exactly when the graceful shutdown future
        // resolves — the moment hyper stops accepting and begins draining
        // the in-flight connections — so the bounded-drain race measures
        // the drain itself, never the serving lifetime. The two listener
        // paths produce different serve future types, so the future is
        // boxed once, at startup, for the shared bounded-drain runner.
        let (drain_signal_sender, drain_signal_receiver) = oneshot::channel();
        let graceful = async move {
            shutdown.await;
            let _ = drain_signal_sender.send(());
        };
        let serve: std::pin::Pin<Box<dyn Future<Output = io::Result<()>> + Send>> =
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
                Box::pin(
                    axum::serve(listener, router)
                        .with_graceful_shutdown(graceful)
                        .into_future(),
                )
            } else {
                println!("Rutilus Site is listening at {url} (loopback plaintext)");
                Box::pin(
                    axum::serve(self.listener, router)
                        .with_graceful_shutdown(graceful)
                        .into_future(),
                )
            };
        serve_with_bounded_drain(serve, drain_signal_receiver, drain_timeout).await
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
                    tracing::error!("Site accept failed: {error}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, self.acceptor.accept(stream)).await {
                Ok(Ok(stream)) => return (stream, address),
                Ok(Err(error)) => {
                    tracing::error!("Site TLS handshake failed from {address}: {error}");
                }
                Err(_) => {
                    // Dropping the timed-out future closes the stalled
                    // connection, so the accept loop proceeds.
                    tracing::error!("Site TLS handshake timed out from {address}");
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
/// `retention` is the configured telemetry history window (default seven
/// days) the background sampling loop prunes with; the CLI's
/// `--telemetry-retention-days` value reaches the prune verbatim through
/// this parameter.
///
/// # Errors
///
/// Returns [`SiteRunError`] while preserving both server and close failures
/// if they occur during the same shutdown.
#[instrument(skip_all, fields(data_directory = %paths.data_directory().display()))]
pub async fn run_site<Stop>(
    paths: &RuntimePaths,
    options: &SiteRunOptions,
    retention: TelemetryRetention,
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
    // 0.7.0 S7: the center sync engine starts when the site is bound. The
    // assembly happens once, before the server starts; a bound site whose
    // material is broken logs the failure and keeps running local-only
    // (§15.3 local autonomy — a center problem never takes the site down).
    let center_sync = match assemble_center_sync(&services_for_server.store, paths).await {
        Ok(bundle) => bundle,
        Err(error) => {
            tracing::error!("the site's center material is broken: {error}");
            None
        }
    };
    if center_sync.is_some() {
        println!("Rutilus Site is bound to the center; starting the center sync");
    }
    // The engine runs on its own stop signal, and the wrapper joins it on
    // every shutdown path — including a server failure — before `SQLite`
    // closes, so the engine's state reference is released in time.
    let run_result = async {
        let (engine_stop_signal, engine_stop_watch) = scheduler::StopSignal::new();
        let engine_task = center_sync.map(|bundle| {
            spawn_center_sync(
                bundle,
                Arc::clone(&services_for_server),
                engine_stop_watch,
                CenterSyncRuntimeOptions::default(),
            )
        });
        let services_result = run_background_services(
            instance.state(),
            gateway,
            retention,
            move |policy, stop_watch, scheduler_done_receiver| {
                binding.serve_until(
                    DeploymentPosture::Site,
                    policy,
                    services_for_server,
                    gateway_for_server,
                    SystemClock,
                    async move {
                        let mut stop = stop_watch;
                        stop.stopped().await;
                        let _ = scheduler_done_receiver.await;
                    },
                    GRACEFUL_DRAIN_TIMEOUT,
                )
            },
            stop,
        )
        .await;
        engine_stop_signal.signal();
        if let Some(engine_task) = engine_task {
            // The engine task's own error paths are logged inside it; a
            // `JoinError` here means the task panicked, and the shutdown
            // join is the only observation point left.
            if let Err(error) = engine_task.await {
                tracing::error!("the center sync engine task failed: {error}");
            }
        }
        services_result
    }
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

/// The site-side center-sync material (0.7.0 S7): the delivered binding
/// result persisted below `<data>/tls/`.
///
/// The one-time binding flow returns the issued client pair and the center's
/// §10.4 trust material to the operator; the site persists them as:
///
/// - `site-client.crt` / `site-client.key` — the issued client pair (the
///   exact PEM bytes of the binding result);
/// - `center-ca.crt` — the center CA certificate (the trust anchor);
/// - `center-pin.txt` — the pinned center server certificate fingerprint
///   (§10.4 explicit trust).
///
/// The site's own `center_bindings` row (written by the site-side bind
/// flow) records the center address and the site identity fingerprint; the
/// runtime cross-checks the loaded client certificate's private-arc
/// extension against that record, mirroring the center's own admission
/// check.
const SITE_CLIENT_CERT_FILE: &str = "site-client.crt";
const SITE_CLIENT_KEY_FILE: &str = "site-client.key";
const CENTER_CA_CERT_FILE: &str = "center-ca.crt";
const CENTER_PIN_FILE: &str = "center-pin.txt";

/// How often the site re-reads its binding while the sync engine runs; a
/// revoked binding stops the engine (the site keeps running locally).
const BINDING_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// The site's center-sync runtime timing bounds (tests use a short binding
/// poll instead of the production 30-second one).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterSyncRuntimeOptions {
    /// How often the runtime re-reads the site's binding while the sync
    /// engine runs.
    pub binding_poll_interval: Duration,
    /// The engine's own timing bounds, including the `not-bound`
    /// convergence count (audit follow-up F4). Tests shorten the reconnect
    /// backoff and the refusal count instead of the production values.
    pub engine: CenterSyncOptions,
}

impl Default for CenterSyncRuntimeOptions {
    fn default() -> Self {
        Self {
            binding_poll_interval: BINDING_POLL_INTERVAL,
            engine: CenterSyncOptions::default(),
        }
    }
}

/// One assembled site-to-center sync bundle: the transport configuration
/// and the site's own instance identity.
#[derive(Clone, Debug)]
pub struct CenterSyncBundle {
    config: CenterClientConfig,
    instance: SiteInstance,
}

impl CenterSyncBundle {
    #[must_use]
    pub const fn new(config: CenterClientConfig, instance: SiteInstance) -> Self {
        Self { config, instance }
    }

    /// The transport configuration of the site-to-center connection.
    #[must_use]
    pub const fn config(&self) -> &CenterClientConfig {
        &self.config
    }

    /// The site's own instance identity.
    #[must_use]
    pub const fn instance(&self) -> &SiteInstance {
        &self.instance
    }
}

/// A controlled failure while assembling the site's center-sync material.
#[derive(Debug, Error)]
pub enum CenterSyncMaterialError {
    #[error("the center address on the binding is not a host:port pair: {0}")]
    CenterAddress(#[source] ListenAddressError),
    #[error("failed to read the site client certificate {path}: {source}")]
    ClientCertificate {
        path: PathBuf,
        #[source]
        source: TlsMaterialError,
    },
    #[error("failed to read the site client key {path}: {source}")]
    ClientKey {
        path: PathBuf,
        #[source]
        source: TlsMaterialError,
    },
    #[error("failed to read the center CA certificate {path}: {source}")]
    CenterCa {
        path: PathBuf,
        #[source]
        source: TlsMaterialError,
    },
    #[error("failed to read the center pin file {path}: {source}")]
    CenterPin {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("the center pin file {0} does not carry a certificate fingerprint: {1}")]
    PinShape(
        PathBuf,
        #[source] rutilus_domain::CertificateFingerprintParseError,
    ),
    #[error("the site client certificate cannot be read: {0}")]
    Certificate(#[from] crate::x509::DerReadError),
    #[error(
        "the loaded client certificate carries no site-identity extension; it was not issued by a center"
    )]
    NotCenterIssued,
    #[error(
        "the loaded client certificate's site identity disagrees with the binding record; the material was replaced"
    )]
    FingerprintMismatch,
    #[error("the site is bound but its center material is incomplete")]
    IncompleteMaterial,
    #[error("the instance repository failed: {0}")]
    Instance(#[source] InstanceRepositoryError),
    #[error("the binding repository failed: {0}")]
    Binding(#[source] CenterBindingRepositoryError),
}

/// Loads the site's center binding and TLS material, returning the sync
/// bundle when the site is bound (§15.1, 0.7.0 S7).
///
/// A site without its own instance row, without a binding, or with a
/// pending or revoked binding runs local-only (`Ok(None)`). A bound site
/// whose material is incomplete or disagrees with its binding record is a
/// broken handoff: [`CenterSyncMaterialError`] is returned and the runtime
/// keeps the site local while logging the failure — local autonomy
/// (§15.3) never lets a center problem take the site down.
///
/// # Errors
///
/// Returns [`CenterSyncMaterialError`] for a broken material set: a
/// half-written pair, a missing center trust file, an unparseable pin, or
/// a client certificate that does not carry — or disagrees with — the
/// binding's site identity.
pub(crate) async fn assemble_center_sync(
    store: &SqliteStore,
    paths: &RuntimePaths,
) -> Result<Option<CenterSyncBundle>, CenterSyncMaterialError> {
    let instances = store
        .list_instances()
        .await
        .map_err(CenterSyncMaterialError::Instance)?;
    let Some(instance) = instances
        .into_iter()
        .find(|instance| instance.kind() == InstanceKind::Site)
    else {
        // The site's own identity row does not exist; it was never bound.
        return Ok(None);
    };
    let Some(binding) = store
        .find_binding_by_site(instance.id())
        .await
        .map_err(CenterSyncMaterialError::Binding)?
    else {
        return Ok(None);
    };
    if binding.state() != CenterBindingState::Bound {
        // A pending or revoked binding does not start the engine.
        return Ok(None);
    }
    let bundle = load_bundle_material(paths, &instance, &binding)?;
    Ok(Some(bundle))
}

/// The outcome of one local unbind (audit follow-up F4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnbindOutcome {
    /// The site's binding was revoked and its center material removed.
    Unbound,
    /// The site had no binding in force; nothing changed.
    AlreadyUnbound,
}

/// A controlled failure while unbinding the site from its center (audit
/// follow-up F4).
#[derive(Debug, Error)]
pub enum UnbindError {
    /// The instance could not be opened (including "another process owns
    /// the instance" — the unbind is an offline command like backup).
    #[error("failed to open the site instance: {0}")]
    Open(#[source] StandaloneInstanceError),
    /// The instance repository failed; carries its own error.
    #[error("the instance repository failed: {0}")]
    Instance(#[source] InstanceRepositoryError),
    /// The binding repository failed; carries its own error.
    #[error("the binding repository failed: {0}")]
    Binding(#[source] CenterBindingRepositoryError),
    /// One center material file could not be removed.
    #[error("failed to remove the center material at {path}: {source}")]
    RemoveMaterial {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The instance could not be closed after the unbind.
    #[error("failed to close the site instance: {0}")]
    Close(#[source] StandaloneInstanceCloseError),
    /// The unbind and the instance close both failed.
    #[error("the unbind failed ({run}) and the instance close failed ({close})")]
    RunAndClose {
        run: Box<Self>,
        close: StandaloneInstanceCloseError,
    },
}

/// Revokes the site's local center binding and removes its center material
/// (audit follow-up F4): the offline operator path that ends the site's
/// center relationship without the center.
///
/// The command opens the instance like every offline command (backup,
/// restore), so it refuses to run while the site console owns the runtime
/// lock. A site without a binding row, or with an already-revoked binding,
/// reports [`UnbindOutcome::AlreadyUnbound`] without touching the material
/// — the unbind is idempotent.
///
/// The running site converges through the engine instead: the center's
/// `not-bound` refusal revokes the local row and stops the engine, and the
/// CLI unbind exists for the operator who ends the relationship locally.
///
/// # Errors
///
/// Returns [`UnbindError`] when the instance cannot be opened or closed,
/// a repository fails, or one material file cannot be removed.
pub async fn unbind_from_center(
    paths: &RuntimePaths,
    unlock: Option<&StandaloneUnlock>,
) -> Result<UnbindOutcome, UnbindError> {
    let instance = if let Some(passphrase) = unlock {
        StandaloneInstance::open(paths, passphrase)
            .await
            .map_err(UnbindError::Open)?
    } else {
        let store = SystemSecretStore::new();
        StandaloneInstance::open_system(paths, &store)
            .await
            .map_err(UnbindError::Open)?
    };
    let run_result = async {
        let state = instance.state();
        let instances = state
            .store
            .list_instances()
            .await
            .map_err(UnbindError::Instance)?;
        let Some(instance_row) = instances
            .into_iter()
            .find(|instance| instance.kind() == InstanceKind::Site)
        else {
            // The site's own identity row does not exist; it was never bound.
            return Ok(UnbindOutcome::AlreadyUnbound);
        };
        let Some(binding) = state
            .store
            .find_binding_by_site(instance_row.id())
            .await
            .map_err(UnbindError::Binding)?
        else {
            return Ok(UnbindOutcome::AlreadyUnbound);
        };
        if binding.state() == CenterBindingState::Revoked {
            return Ok(UnbindOutcome::AlreadyUnbound);
        }
        state
            .store
            .revoke_binding(binding.id())
            .await
            .map_err(UnbindError::Binding)?;
        for file in [
            SITE_CLIENT_CERT_FILE,
            SITE_CLIENT_KEY_FILE,
            CENTER_CA_CERT_FILE,
            CENTER_PIN_FILE,
        ] {
            let path = paths.tls_directory().join(file);
            if path.exists() {
                std::fs::remove_file(&path)
                    .map_err(|source| UnbindError::RemoveMaterial { path, source })?;
            }
        }
        Ok(UnbindOutcome::Unbound)
    }
    .await;
    let close_result = instance.close().await;
    match (run_result, close_result) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(source), Ok(())) => Err(source),
        (Ok(_), Err(close)) => Err(UnbindError::Close(close)),
        (Err(run), Err(close)) => Err(UnbindError::RunAndClose {
            run: Box::new(run),
            close,
        }),
    }
}

/// Loads and validates the four material files of one bound site.
fn load_bundle_material(
    paths: &RuntimePaths,
    instance: &SiteInstance,
    binding: &CenterBinding,
) -> Result<CenterSyncBundle, CenterSyncMaterialError> {
    let client_cert_path = paths.tls_directory().join(SITE_CLIENT_CERT_FILE);
    let client_key_path = paths.tls_directory().join(SITE_CLIENT_KEY_FILE);
    let center_ca_path = paths.tls_directory().join(CENTER_CA_CERT_FILE);
    let center_pin_path = paths.tls_directory().join(CENTER_PIN_FILE);
    let present = [
        client_cert_path.is_file(),
        client_key_path.is_file(),
        center_ca_path.is_file(),
        center_pin_path.is_file(),
    ];
    if !present.iter().all(|present| *present) {
        if present.iter().all(|present| !*present) {
            // Never-bound material: the site is bound in the database but
            // the handoff files were never delivered. A bound site without
            // material cannot connect; the runtime logs and stays local.
            return Err(CenterSyncMaterialError::IncompleteMaterial);
        }
        // A half-written set is a broken handoff, never silently ignored.
        return Err(CenterSyncMaterialError::IncompleteMaterial);
    }
    let client_certificate = read_certificate(&client_cert_path).map_err(|source| {
        CenterSyncMaterialError::ClientCertificate {
            path: client_cert_path,
            source,
        }
    })?;
    let client_key = read_private_key(&client_key_path).map_err(|source| {
        CenterSyncMaterialError::ClientKey {
            path: client_key_path,
            source,
        }
    })?;
    validate_key_matches_cert(&client_certificate, &client_key)
        .map_err(|_| CenterSyncMaterialError::IncompleteMaterial)?;
    let center_ca =
        read_certificate(&center_ca_path).map_err(|source| CenterSyncMaterialError::CenterCa {
            path: center_ca_path,
            source,
        })?;
    let pin_text = std::fs::read_to_string(&center_pin_path).map_err(|source| {
        CenterSyncMaterialError::CenterPin {
            path: center_pin_path.clone(),
            source,
        }
    })?;
    let pinned_fingerprint = pin_text
        .trim()
        .parse::<CertificateFingerprint>()
        .map_err(|source| CenterSyncMaterialError::PinShape(center_pin_path, source))?;
    // The cross-check mirrors the center's own admission (S3b audit item
    // 1): the certificate's private-arc extension must carry the site
    // identity the binding recorded. A certificate without the extension
    // was not issued by a center.
    let bound_fingerprint = crate::x509::site_identity_fingerprint(&client_certificate)?;
    let Some(bound_fingerprint) = bound_fingerprint else {
        return Err(CenterSyncMaterialError::NotCenterIssued);
    };
    if let Some(recorded) = binding.site_cert_fingerprint()
        && recorded != bound_fingerprint
    {
        return Err(CenterSyncMaterialError::FingerprintMismatch);
    }
    let center = ListenAddress::parse(binding.center_url())
        .map_err(CenterSyncMaterialError::CenterAddress)?;
    let config = CenterClientConfig::new(
        center,
        center_ca,
        pinned_fingerprint,
        client_certificate,
        client_key,
        instance.id(),
        instance.display_name().to_owned(),
    )
    .map_err(|_| CenterSyncMaterialError::IncompleteMaterial)?;
    Ok(CenterSyncBundle::new(config, instance.clone()))
}

/// Spawns the site-to-center sync engine over one assembled bundle and
/// returns the task handle.
///
/// The engine runs until the shared stop watch fires or the site's binding
/// is revoked (re-read on the poll interval). The runtime joins the handle
/// on every shutdown path before `SQLite` closes, so no engine task ever
/// touches the store after shutdown begins.
pub(crate) fn spawn_center_sync(
    bundle: CenterSyncBundle,
    state: Arc<StandaloneState>,
    stop: scheduler::StopWatch,
    options: CenterSyncRuntimeOptions,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run_center_sync_task(bundle, state, stop, options))
}

/// The engine task body: the §15.4 sync loop with the binding-revocation
/// watch as its stop condition.
#[instrument(skip_all)]
async fn run_center_sync_task(
    bundle: CenterSyncBundle,
    state: Arc<StandaloneState>,
    mut stop: scheduler::StopWatch,
    options: CenterSyncRuntimeOptions,
) {
    let engine = CenterSync::new(
        bundle.config(),
        &state.store,
        &state.store,
        &state.store,
        &state.store,
        &state.store,
        SystemClock,
        bundle.instance().id(),
        options.engine,
    );
    let poll = options.binding_poll_interval;
    let binding_site = bundle.instance().id();
    let store = &state.store;
    let outcome = engine
        .run(async move {
            tokio::select! {
                () = stop.stopped() => {}
                () = binding_revoked(store, binding_site, poll) => {
                    // The watch logged the true reason (audit follow-up
                    // E3-1): only a row observed in a non-`Bound` state
                    // resolves it.
                }
            }
        })
        .await;
    match outcome {
        Ok(()) => {}
        Err(CenterSyncError::NotBound) => {
            // Audit follow-up F4: the center consistently refused the site
            // as `not-bound` — its binding is not in force on the center
            // (revoked or re-bound there). The engine already stopped; the
            // local binding row is revoked so the site converges: a later
            // restart stays local-only, exactly like a locally revoked
            // binding. The material files are left in place (harmless; a
            // future bind overwrites them).
            tracing::warn!("the center refused the site as not bound; revoking the local binding");
            let Ok(Some(binding)) = store.find_binding_by_site(binding_site).await else {
                return;
            };
            if let Err(error) = store.revoke_binding(binding.id()).await {
                tracing::error!("failed to revoke the local binding: {error}");
            }
        }
        Err(CenterSyncError::IdentityMismatch) => {
            // Audit follow-up E3-2 (C5-10): the center consistently
            // refused the site as an `identity-mismatch` — the `Hello`'s
            // declared instance identity disagrees with the center's
            // binding record for the presented certificate. Unlike
            // `not-bound`, the binding IS in force on the center, so the
            // local row must NOT be revoked (that would tear down a valid
            // binding); the mismatch is a configuration error no retry can
            // heal — the engine stopped so the site is not alerting every
            // backoff — and the repair path is to re-bind the site to the
            // center. The site keeps running locally until then.
            tracing::error!(
                "the center refused the site as an identity mismatch: the site's instance \
                 identity does not match the center's binding for its certificate; re-bind \
                 the site to the center (the local binding is left in place)"
            );
        }
        Err(error) => {
            tracing::error!("the center sync engine stopped with an error: {error}");
        }
    }
}

/// Resolves when the site's binding is no longer `Bound` (audit follow-up
/// E3-1).
///
/// Only a row that still exists in a different state is a true revocation:
/// a vanished row and a failed store read are transient — the row may be
/// mid-write on the bind path or the store may be wedged — and stopping
/// the sync engine on either would strand a bound site. The watch keeps
/// polling through them, with a warn naming the true reason, and only a
/// row observed in a non-`Bound` state stops the engine.
async fn binding_revoked(store: &SqliteStore, site: InstanceId, poll: Duration) {
    loop {
        match store.find_binding_by_site(site).await {
            Ok(Some(binding)) if binding.state() == CenterBindingState::Bound => {}
            Ok(Some(binding)) => {
                // The row still exists and is no longer `Bound`: the
                // binding was revoked on this site. Only this shape stops
                // the engine.
                tracing::warn!(
                    "the site's center binding is {}; stopping the center sync",
                    binding.state()
                );
                return;
            }
            Ok(None) => {
                // The row vanished: transient by the same rule as a failed
                // read — the bind path writes the row before the engine
                // starts, so a missing row means an external change, never
                // a revocation verdict.
                tracing::warn!(
                    "the site's center binding row is missing; keeping the center sync running"
                );
            }
            Err(error) => {
                // A failed store read must not be mistaken for a
                // revocation: a wedged store would otherwise stop the sync
                // engine of a still-bound site.
                tracing::warn!(
                    "the binding watch could not read the site's center binding: {error}; \
                     keeping the center sync running"
                );
            }
        }
        tokio::time::sleep(poll).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, error::Error, net::Ipv4Addr, sync::Mutex};

    use rutilus_application::CenterSessionRegistry;
    use rutilus_domain::{
        BINDING_CODE_TTL, BindingCode, CenterBinding, CenterBindingId, CertificateFingerprint,
        InstanceId, InstanceKind, SiteInstance,
    };
    use rutilus_platform::{RuntimeLock, RuntimePaths};
    use rutilus_security::MasterKey;

    use rutilus_application::CenterSessionAdmission;
    use tokio::net::TcpListener;

    use super::*;
    use crate::{CenterAcceptor, CenterAcceptorError, CenterAcceptorOptions, CenterCa};

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

    /// Probes one free port on the given host and returns it.
    async fn free_port(host: Ipv4Addr) -> io::Result<u16> {
        let listener = TcpListener::bind((host, 0)).await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    /// A Site bind failed because a racer grabbed the probed port between
    /// the probe and the bind; the retry loop moves on to a fresh port.
    fn is_raced_site_bind(error: &SiteRunError) -> bool {
        matches!(
            error,
            SiteRunError::Bind(inner) if inner.kind() == io::ErrorKind::AddrInUse
        )
    }

    /// A center acceptor bind failed because a racer grabbed the probed
    /// port between the probe and the bind; the retry loop moves on to a
    /// fresh port.
    fn is_raced_center_bind(error: &CenterAcceptorError) -> bool {
        matches!(
            error,
            CenterAcceptorError::Bind(inner) if inner.kind() == io::ErrorKind::AddrInUse
        )
    }

    /// Binds a Site listener on a free port on `host` (with the given
    /// explicit certificate pair, when any). The probe inside `free_port`
    /// is released before this bind, so a racer may grab the port in
    /// between; the attempt is then retried on a fresh port instead of
    /// failing the test. Returns the binding and the port it bound.
    async fn bind_site(
        paths: &RuntimePaths,
        host: Ipv4Addr,
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
    ) -> Result<(SiteBinding, u16), Box<dyn Error>> {
        loop {
            let port = free_port(host).await?;
            let listen = parse_listen(&format!("{host}:{port}"))?;
            let options = SiteRunOptions::new(listen, cert.clone(), key.clone())?;
            match SiteBinding::bind(paths, &options).await {
                Ok(binding) => return Ok((binding, port)),
                Err(error) if is_raced_site_bind(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// The production-reachable end-to-end path: a non-loopback listen
    /// without CLI material generates and persists a self-signed pair and
    /// serves HTTPS, and a later boot reuses the persisted identity.
    #[tokio::test]
    async fn non_loopback_bind_generates_persists_and_reuses_self_signed()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (first, first_port) = bind_site(&paths, Ipv4Addr::UNSPECIFIED, None, None).await?;
        assert_eq!(first.url(), format!("https://0.0.0.0:{first_port}/"));
        let first_tls = first.tls.ok_or_else(|| {
            io::Error::other("the non-loopback bind generated a self-signed pair")
        })?;
        assert_eq!(first_tls.fingerprint().split(':').count(), 32);
        assert!(paths.tls_directory().join("cert.pem").is_file());
        assert!(paths.tls_directory().join("key.pem").is_file());

        // A second boot on a fresh port reuses the persisted identity.
        let (second, _) = bind_site(&paths, Ipv4Addr::UNSPECIFIED, None, None).await?;
        let second_tls = second
            .tls
            .ok_or_else(|| io::Error::other("the second boot reused the persisted pair"))?;
        assert_eq!(first_tls.fingerprint(), second_tls.fingerprint());
        Ok(())
    }

    /// A loopback listen without any TLS material is the plaintext posture,
    /// and no certificate pair is generated for it.
    #[tokio::test]
    async fn loopback_bind_without_material_is_plaintext_and_generates_nothing()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let (binding, port) = bind_site(&paths, Ipv4Addr::LOCALHOST, None, None).await?;
        assert!(binding.tls.is_none());
        assert_eq!(binding.url(), format!("http://127.0.0.1:{port}/"));
        assert!(!paths.tls_directory().join("cert.pem").is_file());
        assert!(!paths.tls_directory().join("key.pem").is_file());
        Ok(())
    }

    /// A loopback listen still reuses a pair persisted below `tls/` (the
    /// persisted tier precedes the loopback plaintext posture).
    #[tokio::test]
    async fn loopback_bind_reuses_a_persisted_pair() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let seed_listen = parse_listen("127.0.0.1:8443")?;
        let seeded = SiteTls::load_or_generate(&paths, &seed_listen, None)?;

        let (binding, port) = bind_site(&paths, Ipv4Addr::LOCALHOST, None, None).await?;
        assert_eq!(binding.url(), format!("https://127.0.0.1:{port}/"));
        let tls = binding
            .tls
            .ok_or_else(|| io::Error::other("the persisted pair is reused on loopback"))?;
        assert_eq!(tls.fingerprint(), seeded.fingerprint());
        Ok(())
    }

    /// An explicitly provided pair is served over HTTPS even on loopback.
    #[tokio::test]
    async fn explicitly_provided_pair_serves_https_even_on_loopback() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        // Seed a pair, then copy it to explicit CLI-style paths.
        let seed_listen = parse_listen("127.0.0.1:8443")?;
        let seeded = SiteTls::load_or_generate(&paths, &seed_listen, None)?;
        let cert_path = directory.path().join("explicit-cert.pem");
        let key_path = directory.path().join("explicit-key.pem");
        std::fs::copy(paths.tls_directory().join("cert.pem"), &cert_path)?;
        std::fs::copy(paths.tls_directory().join("key.pem"), &key_path)?;

        let (binding, port) =
            bind_site(&paths, Ipv4Addr::LOCALHOST, Some(cert_path), Some(key_path)).await?;
        assert_eq!(binding.url(), format!("https://127.0.0.1:{port}/"));
        let tls = binding
            .tls
            .ok_or_else(|| io::Error::other("the provided pair is served"))?;
        assert_eq!(tls.fingerprint(), seeded.fingerprint());
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

    /// A test instance state over one migrated store.
    async fn test_state(paths: &RuntimePaths) -> Result<Arc<StandaloneState>, Box<dyn Error>> {
        let master_key = Arc::new(MasterKey::generate()?);
        let store =
            SqliteStore::open_with_command_key(paths.database_path(), Arc::clone(&master_key))
                .await?;
        let runtime_lock = RuntimeLock::acquire(paths.runtime_lock_path())?;
        Ok(Arc::new(StandaloneState {
            store,
            master_key,
            _runtime_lock: runtime_lock,
            audit_tail: Arc::new(Mutex::new(VecDeque::new())),
            registry: Arc::new(CenterSessionRegistry::new()),
            center_issuer: Mutex::new(None),
        }))
    }

    /// Seeds one bound site: the site's own instance row, a `Bound` binding
    /// naming `127.0.0.1:1` (an unreachable center for the engine tests),
    /// and the four delivered material files below `tls/`.
    async fn seed_bound_site(
        store: &SqliteStore,
        paths: &RuntimePaths,
    ) -> Result<(InstanceId, CenterBindingId, CertificateFingerprint), Box<dyn Error>> {
        let now = OffsetDateTime::now_utc();
        let instance = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        store.create_instance(&instance).await?;
        let site_fingerprint = CertificateFingerprint::from_bytes([0x42; 32]);
        let code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let mut binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            "127.0.0.1:1".to_owned(),
            instance.id(),
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        binding.bind(Some(site_fingerprint), now)?;
        let binding_id = binding.id();
        store.create_binding(&binding).await?;
        let ca = CenterCa::generate_or_load(paths)?;
        let issued = ca.issue_site_certificate(instance.id(), site_fingerprint)?;
        let (cert_pem, key_pem) = issued.pem_pair();
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_CERT_FILE), cert_pem)?;
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_KEY_FILE), key_pem)?;
        std::fs::write(
            paths.tls_directory().join(CENTER_CA_CERT_FILE),
            pem_encode("CERTIFICATE", ca.certificate().as_ref()),
        )?;
        std::fs::write(
            paths.tls_directory().join(CENTER_PIN_FILE),
            CertificateFingerprint::from_bytes([0xAA; 32]).to_string(),
        )?;
        Ok((instance.id(), binding_id, site_fingerprint))
    }

    #[tokio::test]
    async fn assembly_returns_no_bundle_for_an_unbound_site() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let state = test_state(&paths).await?;

        // No instance row at all: never bound.
        assert!(assemble_center_sync(&state.store, &paths).await?.is_none());

        // An instance row without a binding: never bound.
        let now = OffsetDateTime::now_utc();
        state
            .store
            .create_instance(&SiteInstance::new(
                InstanceId::generate(),
                "Test Site".to_owned(),
                InstanceKind::Site,
                now,
            ))
            .await?;
        assert!(assemble_center_sync(&state.store, &paths).await?.is_none());

        // A pending binding does not start the engine.
        let instance = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        state.store.create_instance(&instance).await?;
        let code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            "127.0.0.1:1".to_owned(),
            instance.id(),
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        state.store.create_binding(&binding).await?;
        assert!(assemble_center_sync(&state.store, &paths).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn assembly_loads_the_bundle_of_a_bound_site() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let state = test_state(&paths).await?;
        let (instance_id, _, _) = seed_bound_site(&state.store, &paths).await?;

        let bundle = assemble_center_sync(&state.store, &paths)
            .await?
            .ok_or("a bound site must assemble a bundle")?;
        assert_eq!(bundle.instance().id(), instance_id);
        assert_eq!(bundle.instance().display_name(), "Test Site");
        assert_eq!(bundle.config().center_address().to_string(), "127.0.0.1:1");
        Ok(())
    }

    #[tokio::test]
    async fn assembly_refuses_a_bound_site_with_broken_material() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let state = test_state(&paths).await?;
        let (_, _, _) = seed_bound_site(&state.store, &paths).await?;

        // A replaced client pair whose extension disagrees with the
        // binding record is refused (the material was swapped).
        let ca = CenterCa::generate_or_load(&paths)?;
        let foreign = ca.issue_site_certificate(
            InstanceId::generate(),
            CertificateFingerprint::from_bytes([0x99; 32]),
        )?;
        let (cert_pem, key_pem) = foreign.pem_pair();
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_CERT_FILE), cert_pem)?;
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_KEY_FILE), key_pem)?;
        assert!(matches!(
            assemble_center_sync(&state.store, &paths).await,
            Err(CenterSyncMaterialError::FingerprintMismatch)
        ));

        // A missing pin file is a broken handoff.
        std::fs::remove_file(paths.tls_directory().join(CENTER_PIN_FILE))?;
        assert!(matches!(
            assemble_center_sync(&state.store, &paths).await,
            Err(CenterSyncMaterialError::IncompleteMaterial)
        ));

        // A half-written client pair is a broken handoff, never silently
        // ignored.
        std::fs::remove_file(paths.tls_directory().join(SITE_CLIENT_KEY_FILE))?;
        assert!(matches!(
            assemble_center_sync(&state.store, &paths).await,
            Err(CenterSyncMaterialError::IncompleteMaterial)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn the_sync_engine_stops_on_the_stop_signal_and_after_revocation()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let state = test_state(&paths).await?;
        let (_, binding_id, _) = seed_bound_site(&state.store, &paths).await?;
        let bundle = assemble_center_sync(&state.store, &paths)
            .await?
            .ok_or("a bound site must assemble a bundle")?;
        let options = CenterSyncRuntimeOptions {
            binding_poll_interval: Duration::from_millis(20),
            ..CenterSyncRuntimeOptions::default()
        };

        // The engine stops on the stop signal (the center at 127.0.0.1:1
        // is unreachable; the connect loop exits on stop).
        let (stop_signal, stop_watch) = scheduler::StopSignal::new();
        let task = spawn_center_sync(bundle.clone(), Arc::clone(&state), stop_watch, options);
        stop_signal.signal();
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .map_err(|_| io::Error::other("the engine did not stop in time"))??;

        // The binding-revocation watch stops a running engine: revoke the
        // binding while the engine runs and join it.
        let (revoke_signal, revoke_watch) = scheduler::StopSignal::new();
        let task = spawn_center_sync(bundle, Arc::clone(&state), revoke_watch, options);
        tokio::time::sleep(Duration::from_millis(50)).await;
        state.store.revoke_binding(binding_id).await?;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .map_err(|_| io::Error::other("the engine did not stop after the revocation"))??;
        let _ = revoke_signal;
        Ok(())
    }

    #[tokio::test]
    async fn the_binding_watch_ignores_transient_rows_and_stops_on_a_true_revocation()
    -> Result<(), Box<dyn Error>> {
        // Audit follow-up E3-1: a missing binding row and a still-bound
        // row keep the watch polling — only a row observed in a
        // non-`Bound` state stops it — so a transient store read (or a
        // row the bind path has not written yet) can never strand a
        // bound site with a stopped sync engine.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let site = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        state.store.create_instance(&site).await?;
        let poll = Duration::from_millis(10);

        // No binding row yet: the vanished row is transient, so the watch
        // keeps polling instead of stopping the engine.
        let watch = binding_revoked(&state.store, site.id(), poll);
        tokio::pin!(watch);
        let result = tokio::time::timeout(Duration::from_millis(60), &mut watch).await;
        assert!(
            result.is_err(),
            "a missing binding row must not stop the watch"
        );

        // The bind path writes the row as `Bound`: the watch keeps
        // polling.
        let code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let mut binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            "127.0.0.1:8443".to_owned(),
            site.id(),
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        binding.bind(Some(CertificateFingerprint::from_bytes([0x42; 32])), now)?;
        let binding_id = binding.id();
        state.store.create_binding(&binding).await?;
        let result = tokio::time::timeout(Duration::from_millis(60), &mut watch).await;
        assert!(result.is_err(), "a bound row must not stop the watch");

        // The true revocation stops the watch.
        state.store.revoke_binding(binding_id).await?;
        let result = tokio::time::timeout(Duration::from_secs(5), &mut watch).await;
        result.map_err(|_| io::Error::other("the watch did not stop after the revocation"))?;
        Ok(())
    }

    // The mismatch script is one continuous scenario — the center side,
    // the mismatched site material, the engine run, and the binding
    // assertion — so it stays in one test (the same lint allowance as the
    // not-bound convergence test).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn identity_mismatch_refusals_stop_the_engine_without_revoking_the_local_binding()
    -> Result<(), Box<dyn Error>> {
        // Audit follow-up E3-2 (C5-10): the center's binding for the
        // presented certificate is in force, but the `Hello` declares a
        // different instance identity — the certificate was issued for
        // another instance than the site now runs as. The center refuses
        // with `identity-mismatch`; the site stops retrying after the
        // configured consecutive refusals (no more alerting every
        // backoff) and — unlike `not-bound` — leaves its local binding
        // untouched: the binding IS in force, only a re-bind heals the
        // mismatch.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("site"))?;
        let center_paths = RuntimePaths::from_root(directory.path().join("center"))?;

        // The center side: an acceptor whose admission finds the site's
        // fingerprint bound to a different instance than the site
        // declares.
        let ca = Arc::new(CenterCa::generate_or_load(&paths)?);
        let acceptor = loop {
            let port = free_port(Ipv4Addr::LOCALHOST).await?;
            let listen = ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
            match CenterAcceptor::bind_with_ca(
                &paths,
                &listen,
                Arc::clone(&ca),
                CenterAcceptorOptions {
                    handshake_timeout: Duration::from_secs(5),
                    idle_timeout: Duration::from_secs(5),
                },
            )
            .await
            {
                Ok(acceptor) => break acceptor,
                Err(error) if is_raced_center_bind(&error) => {}
                Err(error) => return Err(error.into()),
            }
        };
        let acceptor_address = acceptor.address().to_string();
        let acceptor_fingerprint = acceptor.server_fingerprint();
        let center_state = test_state(&center_paths).await?;
        let now = OffsetDateTime::now_utc();
        // The binding record the certificate resolves to: bound, in force,
        // but naming a different site than the one the `Hello` declares.
        let bound_instance = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        center_state.store.create_instance(&bound_instance).await?;
        let site_fingerprint = CertificateFingerprint::from_bytes([0x42; 32]);
        let code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let mut binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            acceptor_address.clone(),
            bound_instance.id(),
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        binding.bind(Some(site_fingerprint), now)?;
        center_state.store.create_binding(&binding).await?;
        let center_state_for_accept = Arc::clone(&center_state);
        let accept_task = tokio::spawn(async move {
            let mut acceptor = acceptor;
            let admission = CenterSessionAdmission::new(&center_state_for_accept.store);
            loop {
                // Every connection here is refused with the
                // `identity-mismatch` answer; the loop keeps accepting the
                // site's retries until the site stops.
                let _ = acceptor.accept_with_admission(&admission).await;
            }
        });

        // The site side: a bound local row, with the delivered material
        // issued for the CENTER's bound instance — the certificate and the
        // site's declared identity disagree exactly like a re-bound or
        // recreated site.
        let state = test_state(&paths).await?;
        let local_instance = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        state.store.create_instance(&local_instance).await?;
        let local_code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let mut local_binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            acceptor_address.clone(),
            local_instance.id(),
            &local_code,
            now + BINDING_CODE_TTL,
            now,
        );
        local_binding.bind(Some(site_fingerprint), now)?;
        state.store.create_binding(&local_binding).await?;
        let issued = ca.issue_site_certificate(bound_instance.id(), site_fingerprint)?;
        let (cert_pem, key_pem) = issued.pem_pair();
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_CERT_FILE), cert_pem)?;
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_KEY_FILE), key_pem)?;
        std::fs::write(
            paths.tls_directory().join(CENTER_CA_CERT_FILE),
            pem_encode("CERTIFICATE", ca.certificate().as_ref()),
        )?;
        std::fs::write(
            paths.tls_directory().join(CENTER_PIN_FILE),
            acceptor_fingerprint.to_string(),
        )?;
        let bundle = assemble_center_sync(&state.store, &paths)
            .await?
            .ok_or("a bound site must assemble a bundle")?;
        let options = CenterSyncRuntimeOptions {
            binding_poll_interval: Duration::from_millis(20),
            engine: CenterSyncOptions {
                heartbeat_interval: Duration::from_millis(20),
                reconnect_after: Duration::from_millis(50),
                flush_limit: 64,
                event_batch_limit: 256,
                artifact_chunk_bytes: 64,
                not_bound_abort_after: Some(2),
                identity_mismatch_abort_after: Some(2),
            },
        };
        let (_stop_signal, stop_watch) = scheduler::StopSignal::new();
        let task = spawn_center_sync(bundle, Arc::clone(&state), stop_watch, options);
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .map_err(|_| io::Error::other("the engine did not stop in time"))??;

        // The engine stopped on its own and the local row was left in
        // place: the mismatch never converges the binding.
        let local = state
            .store
            .find_binding_by_site(local_instance.id())
            .await?
            .ok_or("the local binding row must remain")?;
        assert_eq!(local.state(), CenterBindingState::Bound);
        accept_task.abort();
        Ok(())
    }

    /// Seeds one bound site whose binding names the given center address
    /// and whose material pins the given center server fingerprint (audit
    /// follow-up F4 — the convergence test needs a real, reachable center,
    /// so the pin must be the acceptor's actual fingerprint).
    async fn seed_bound_site_to_center(
        store: &SqliteStore,
        paths: &RuntimePaths,
        center_address: &str,
        center_fingerprint: CertificateFingerprint,
    ) -> Result<(InstanceId, CenterBindingId, CertificateFingerprint), Box<dyn Error>> {
        let now = OffsetDateTime::now_utc();
        let instance = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        store.create_instance(&instance).await?;
        let site_fingerprint = CertificateFingerprint::from_bytes([0x42; 32]);
        let code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let mut binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            center_address.to_owned(),
            instance.id(),
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        binding.bind(Some(site_fingerprint), now)?;
        let binding_id = binding.id();
        store.create_binding(&binding).await?;
        let ca = CenterCa::generate_or_load(paths)?;
        let issued = ca.issue_site_certificate(instance.id(), site_fingerprint)?;
        let (cert_pem, key_pem) = issued.pem_pair();
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_CERT_FILE), cert_pem)?;
        std::fs::write(paths.tls_directory().join(SITE_CLIENT_KEY_FILE), key_pem)?;
        std::fs::write(
            paths.tls_directory().join(CENTER_CA_CERT_FILE),
            pem_encode("CERTIFICATE", ca.certificate().as_ref()),
        )?;
        std::fs::write(
            paths.tls_directory().join(CENTER_PIN_FILE),
            center_fingerprint.to_string(),
        )?;
        Ok((instance.id(), binding_id, site_fingerprint))
    }

    #[tokio::test]
    async fn the_unbind_command_revokes_the_binding_and_removes_the_material()
    -> Result<(), Box<dyn Error>> {
        // Audit follow-up F4: the offline operator path ends the site's
        // center relationship — the local binding row is revoked and the
        // four delivered material files are removed; an already-unbound
        // site reports idempotently.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = StandaloneUnlock::existing(SecretString::from(
            "correct local unlock phrase".to_owned(),
        ))?;
        crate::initialize_standalone(&paths, &unlock).await?;
        {
            let instance = StandaloneInstance::open(&paths, &unlock).await?;
            let (_, _, _) = seed_bound_site(&instance.state().store, &paths).await?;
            instance.close().await?;
        }
        assert!(paths.tls_directory().join(SITE_CLIENT_CERT_FILE).is_file());
        assert!(paths.tls_directory().join(CENTER_PIN_FILE).is_file());

        assert_eq!(
            unbind_from_center(&paths, Some(&unlock)).await?,
            UnbindOutcome::Unbound
        );
        for file in [
            SITE_CLIENT_CERT_FILE,
            SITE_CLIENT_KEY_FILE,
            CENTER_CA_CERT_FILE,
            CENTER_PIN_FILE,
        ] {
            assert!(
                !paths.tls_directory().join(file).exists(),
                "the unbind must remove {file}"
            );
        }
        // The unbind is idempotent: a second run reports already unbound.
        assert_eq!(
            unbind_from_center(&paths, Some(&unlock)).await?,
            UnbindOutcome::AlreadyUnbound
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_not_bound_refusal_from_the_center_converges_the_local_binding()
    -> Result<(), Box<dyn Error>> {
        // Audit follow-up F4: the center revoked the binding on its side;
        // the site's next connection is answered with the `not-bound`
        // negotiation refusal, and after the configured number of
        // consecutive refusals the site revokes its local row and the
        // engine stops — the center-revocation convergence path.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("site"))?;
        let center_paths = RuntimePaths::from_root(directory.path().join("center"))?;

        // The center side: an acceptor whose admission refuses the site
        // because its binding is revoked there. The probe port is
        // released before this bind, so a racer may grab it; the bind is
        // then retried on a fresh port.
        let ca = Arc::new(CenterCa::generate_or_load(&paths)?);
        let acceptor = loop {
            let port = free_port(Ipv4Addr::LOCALHOST).await?;
            let listen = ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
            match CenterAcceptor::bind_with_ca(
                &paths,
                &listen,
                Arc::clone(&ca),
                CenterAcceptorOptions {
                    handshake_timeout: Duration::from_secs(5),
                    idle_timeout: Duration::from_secs(5),
                },
            )
            .await
            {
                Ok(acceptor) => break acceptor,
                Err(error) if is_raced_center_bind(&error) => {}
                Err(error) => return Err(error.into()),
            }
        };
        // The address and the pin material are captured before the
        // acceptor moves into the accept task.
        let acceptor_address = acceptor.address().to_string();
        let acceptor_fingerprint = acceptor.server_fingerprint();
        let center_state = test_state(&center_paths).await?;
        let now = OffsetDateTime::now_utc();
        let center_instance = SiteInstance::new(
            InstanceId::generate(),
            "Test Site".to_owned(),
            InstanceKind::Site,
            now,
        );
        center_state.store.create_instance(&center_instance).await?;
        let site_fingerprint = CertificateFingerprint::from_bytes([0x42; 32]);
        let code: BindingCode = "23456789ABCDEFGHJKLM".parse()?;
        let mut revoked = CenterBinding::new_pending(
            CenterBindingId::generate(),
            acceptor_address.clone(),
            center_instance.id(),
            &code,
            now + BINDING_CODE_TTL,
            now,
        );
        revoked.bind(Some(site_fingerprint), now)?;
        revoked.revoke()?;
        center_state.store.create_binding(&revoked).await?;
        let center_state_for_accept = Arc::clone(&center_state);
        let accept_task = tokio::spawn(async move {
            let mut acceptor = acceptor;
            let admission = CenterSessionAdmission::new(&center_state_for_accept.store);
            loop {
                // Every connection here is refused with the `not-bound`
                // answer; the loop keeps accepting the site's retries.
                let _ = acceptor.accept_with_admission(&admission).await;
            }
        });

        // The site side: a bound local row and the delivered material,
        // pinned to the acceptor's real fingerprint.
        let state = test_state(&paths).await?;
        let (site_id, _, _) = seed_bound_site_to_center(
            &state.store,
            &paths,
            &acceptor_address,
            acceptor_fingerprint,
        )
        .await?;
        let bundle = assemble_center_sync(&state.store, &paths)
            .await?
            .ok_or("a bound site must assemble a bundle")?;
        let options = CenterSyncRuntimeOptions {
            binding_poll_interval: Duration::from_millis(20),
            engine: CenterSyncOptions {
                heartbeat_interval: Duration::from_millis(20),
                reconnect_after: Duration::from_millis(50),
                flush_limit: 64,
                event_batch_limit: 256,
                artifact_chunk_bytes: 64,
                not_bound_abort_after: Some(2),
                identity_mismatch_abort_after: Some(2),
            },
        };
        let (_stop_signal, stop_watch) = scheduler::StopSignal::new();
        let task = spawn_center_sync(bundle, Arc::clone(&state), stop_watch, options);
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .map_err(|_| io::Error::other("the engine did not converge in time"))??;

        // The engine stopped on its own and the local row converged.
        let local = state
            .store
            .find_binding_by_site(site_id)
            .await?
            .ok_or("the local binding row must remain")?;
        assert_eq!(local.state(), CenterBindingState::Revoked);
        accept_task.abort();
        Ok(())
    }
}
