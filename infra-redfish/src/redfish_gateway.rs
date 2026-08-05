use std::{
    error::Error as StdError,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use nv_redfish::{
    ServiceRoot,
    bmc_http::{
        BmcCredentials, CacheSettings, HttpBmc,
        reqwest::{BmcError, Client as NvHttpClient},
    },
};
use reqwest::{Client as ReqwestClient, StatusCode, redirect::Policy as RedirectPolicy};
use rustls::{
    ClientConfig, DigitallySignedStruct, SignatureScheme,
    client::{
        Resumption, WebPkiServerVerifier,
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    },
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use rutilus_domain::{
    CertificateFingerprint, CredentialUsername, EndpointAddress, TlsIdentityChanged, TlsTrust,
};
use secrecy::{ExposeSecret, SecretString};
use serde_json::error::Category as JsonErrorCategory;
use thiserror::Error;

use crate::{TlsCertificateObservation, TlsProbe, TlsProbeError, TlsProbeInitError};

const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = concat!("rutilus/", env!("CARGO_PKG_VERSION"));

type UpstreamBmc = HttpBmc<NvHttpClient>;
type UpstreamServiceRootError = nv_redfish::Error<UpstreamBmc>;

/// The sole product boundary for credential-free TLS observation and typed
/// Redfish access.
#[derive(Clone, Debug)]
pub struct RedfishGateway {
    tls: TlsProbe,
}

impl RedfishGateway {
    /// Loads platform trust once for both certificate observation and trusted
    /// Redfish connections.
    ///
    /// # Errors
    ///
    /// Returns [`TlsProbeInitError`] when platform trust cannot be loaded or
    /// configured safely.
    pub async fn from_system_roots() -> Result<Self, TlsProbeInitError> {
        Ok(Self {
            tls: TlsProbe::from_system_roots().await?,
        })
    }

    /// Observes a leaf certificate without credentials or application data.
    ///
    /// # Errors
    ///
    /// Returns [`TlsProbeError`] for target, network, TLS, timeout, or
    /// certificate-state failures.
    pub async fn observe_tls(
        &self,
        address: &EndpointAddress,
    ) -> Result<TlsCertificateObservation, TlsProbeError> {
        self.tls.probe(address).await
    }

    /// Authenticates only through a connection bound to the persisted TLS
    /// decision, reads the standard Redfish Service Root through the public
    /// `nv-redfish` API, and drops the transient client and credentials before
    /// returning.
    ///
    /// HTTP redirects and system proxy discovery are disabled so credentials
    /// cannot leave the validated endpoint origin. TLS session resumption is
    /// also disabled so every new connection presents and checks a certificate.
    ///
    /// # Errors
    ///
    /// Returns [`RedfishServiceRootError`] with distinct TLS identity,
    /// certificate, authentication, authorization, network, response, and
    /// schema failure categories.
    pub async fn read_service_root(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
    ) -> Result<ServiceRootSummary, RedfishServiceRootError> {
        let (tls_config, identity) = self
            .tls
            .trust_bound_client_config(trust)
            .map_err(RedfishServiceRootError::TlsConfiguration)?;
        let transport = ReqwestClient::builder()
            .use_preconfigured_tls(tls_config)
            .redirect(RedirectPolicy::none())
            .no_proxy()
            .https_only(true)
            .connect_timeout(HTTP_CONNECT_TIMEOUT)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .pool_max_idle_per_host(0)
            .user_agent(USER_AGENT)
            .build()
            .map_err(RedfishServiceRootError::ClientBuild)?;
        let http = NvHttpClient::with_client(transport);
        let credentials = BmcCredentials::new(
            username.as_str().to_owned(),
            password.expose_secret().to_owned(),
        );
        let bmc = Arc::new(HttpBmc::new(
            http,
            address.as_url().clone(),
            credentials,
            CacheSettings::with_capacity(0),
        ));

        match ServiceRoot::new(bmc).await {
            Ok(root) => Ok(ServiceRootSummary::from_root(&root)),
            Err(source) => Err(classify_service_root_error(source, &identity, trust)),
        }
    }
}

/// Stable product projection of the standard Redfish Service Root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceRootSummary {
    vendor: Option<String>,
    product: Option<String>,
    redfish_version: Option<String>,
}

impl ServiceRootSummary {
    fn from_root<B: nv_redfish::Bmc>(root: &ServiceRoot<B>) -> Self {
        Self {
            vendor: root.vendor().map(|value| value.into_inner().to_owned()),
            product: root.product().map(|value| value.into_inner().to_owned()),
            redfish_version: root
                .redfish_version()
                .map(|value| value.into_inner().to_owned()),
        }
    }

    /// Returns the optional Redfish service vendor.
    #[must_use]
    pub fn vendor(&self) -> Option<&str> {
        self.vendor.as_deref()
    }

    /// Returns the optional Redfish service product.
    #[must_use]
    pub fn product(&self) -> Option<&str> {
        self.product.as_deref()
    }

    /// Returns the optional advertised Redfish protocol version.
    #[must_use]
    pub fn redfish_version(&self) -> Option<&str> {
        self.redfish_version.as_deref()
    }
}

/// A controlled failure while reading an authenticated Redfish Service Root.
#[derive(Debug, Error)]
pub enum RedfishServiceRootError {
    #[error("failed to configure trust-bound Rustls: {0}")]
    TlsConfiguration(#[source] rustls::Error),
    #[error("failed to build the bounded Redfish HTTP transport: {0}")]
    ClientBuild(#[source] reqwest::Error),
    #[error("TLS identity observation state is unavailable: {0}")]
    TlsIdentityState(#[source] TlsIdentityStateError),
    #[error("{0}")]
    TlsIdentityChanged(#[source] TlsIdentityChanged),
    #[error("the persisted certificate identity was retained but TLS validation rejected it")]
    TlsRejected {
        #[source]
        source: BmcError,
    },
    #[error("BMC authentication failed")]
    AuthenticationFailed {
        #[source]
        source: BmcError,
    },
    #[error("BMC credentials are valid but lack permission to read the Service Root")]
    PermissionDenied {
        #[source]
        source: BmcError,
    },
    #[error("the target did not expose the standard Redfish Service Root")]
    NotRedfishService {
        #[source]
        source: BmcError,
    },
    #[error("the Redfish Service Root was incompatible with the compiled schema")]
    SchemaIncompatible {
        #[source]
        source: UpstreamServiceRootError,
    },
    #[error("the Redfish Service Root request timed out")]
    NetworkTimeout {
        #[source]
        source: BmcError,
    },
    #[error("the Redfish Service Root could not be reached")]
    Network {
        #[source]
        source: BmcError,
    },
    #[error("the BMC returned an unsuccessful Redfish response")]
    RemoteResponse {
        #[source]
        source: BmcError,
    },
    #[error("the public nv-redfish Service Root operation failed: {0}")]
    Upstream(#[source] UpstreamServiceRootError),
}

/// TLS identity evidence could not be retained because its synchronization
/// state was poisoned.
#[derive(Clone, Copy, Debug, Error)]
#[error("TLS identity synchronization failed")]
pub struct TlsIdentityStateError;

fn classify_service_root_error(
    source: UpstreamServiceRootError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> RedfishServiceRootError {
    match identity.take_change(trust) {
        Ok(Some(changed)) => return RedfishServiceRootError::TlsIdentityChanged(changed),
        Err(source) => return RedfishServiceRootError::TlsIdentityState(source),
        Ok(None) => {}
    }

    let tls_rejected = identity.validation_rejected();
    match source {
        nv_redfish::Error::Bmc(source) if tls_rejected => {
            RedfishServiceRootError::TlsRejected { source }
        }
        nv_redfish::Error::Json(_) => RedfishServiceRootError::SchemaIncompatible { source },
        nv_redfish::Error::Bmc(source) => classify_bmc_error(source),
        source => RedfishServiceRootError::Upstream(source),
    }
}

fn classify_bmc_error(source: BmcError) -> RedfishServiceRootError {
    match &source {
        BmcError::InvalidResponse { status, .. } if *status == StatusCode::UNAUTHORIZED => {
            RedfishServiceRootError::AuthenticationFailed { source }
        }
        BmcError::InvalidResponse { status, .. } if *status == StatusCode::FORBIDDEN => {
            RedfishServiceRootError::PermissionDenied { source }
        }
        BmcError::InvalidResponse { status, .. } if *status == StatusCode::NOT_FOUND => {
            RedfishServiceRootError::NotRedfishService { source }
        }
        BmcError::JsonError(_) | BmcError::DecodeError(_) => {
            RedfishServiceRootError::SchemaIncompatible {
                source: nv_redfish::Error::Bmc(source),
            }
        }
        BmcError::ReqwestError(error)
            if matches!(
                json_error_category(error),
                Some(JsonErrorCategory::Syntax | JsonErrorCategory::Eof)
            ) =>
        {
            RedfishServiceRootError::NotRedfishService { source }
        }
        BmcError::ReqwestError(error) if error.is_decode() => {
            RedfishServiceRootError::SchemaIncompatible {
                source: nv_redfish::Error::Bmc(source),
            }
        }
        BmcError::ReqwestError(error) if error.is_timeout() => {
            RedfishServiceRootError::NetworkTimeout { source }
        }
        BmcError::ReqwestError(_) => RedfishServiceRootError::Network { source },
        _ => RedfishServiceRootError::RemoteResponse { source },
    }
}

fn json_error_category(error: &reqwest::Error) -> Option<JsonErrorCategory> {
    let mut source: Option<&(dyn StdError + 'static)> = Some(error);
    while let Some(current) = source {
        if let Some(error) = current.downcast_ref::<serde_json::Error>() {
            return Some(error.classify());
        }
        source = current.source();
    }
    None
}

impl TlsProbe {
    fn trust_bound_client_config(
        &self,
        trust: &TlsTrust,
    ) -> Result<(ClientConfig, IdentityMonitor), rustls::Error> {
        let identity = IdentityMonitor::default();
        let guard = IdentityGuard {
            expected: trust.certificate().fingerprint(),
            monitor: identity.clone(),
        };
        let verifier: Arc<dyn ServerCertVerifier> = match trust {
            TlsTrust::SystemCa { .. } => Arc::new(SystemCaIdentityVerifier {
                guard,
                system_verifier: Arc::clone(&self.system_verifier),
            }),
            TlsTrust::PinnedCertificate { .. } => Arc::new(PinnedCertificateVerifier {
                guard,
                algorithms: self.provider.signature_verification_algorithms,
            }),
        };
        let mut config = ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        config.resumption = Resumption::disabled();
        Ok((config, identity))
    }
}

#[derive(Clone, Default)]
struct IdentityMonitor {
    observed_change: Arc<Mutex<Option<CertificateFingerprint>>>,
    validation_rejected: Arc<AtomicBool>,
}

impl fmt::Debug for IdentityMonitor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityMonitor")
            .finish_non_exhaustive()
    }
}

impl IdentityMonitor {
    fn record_change(&self, observed: CertificateFingerprint) -> Result<(), TlsIdentityStateError> {
        let mut state = self
            .observed_change
            .lock()
            .map_err(|_| TlsIdentityStateError)?;
        if state.is_none() {
            *state = Some(observed);
        }
        Ok(())
    }

    fn take_change(
        &self,
        trust: &TlsTrust,
    ) -> Result<Option<TlsIdentityChanged>, TlsIdentityStateError> {
        let observed = self
            .observed_change
            .lock()
            .map_err(|_| TlsIdentityStateError)?
            .take();
        Ok(observed.and_then(|observed| trust.verify_fingerprint(observed).err()))
    }

    fn record_validation_rejection(&self) {
        self.validation_rejected.store(true, Ordering::Release);
    }

    fn validation_rejected(&self) -> bool {
        self.validation_rejected.load(Ordering::Acquire)
    }
}

struct IdentityGuard {
    expected: CertificateFingerprint,
    monitor: IdentityMonitor,
}

impl IdentityGuard {
    fn verify(&self, certificate: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let observed = CertificateFingerprint::from_certificate_der(certificate.as_ref());
        if observed == self.expected {
            return Ok(());
        }
        self.monitor
            .record_change(observed)
            .map_err(|source| rustls::Error::General(source.to_string()))?;
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn retain_validation_result<T>(
        &self,
        result: Result<T, rustls::Error>,
    ) -> Result<T, rustls::Error> {
        if matches!(&result, Err(rustls::Error::InvalidCertificate(_))) {
            self.monitor.record_validation_rejection();
        }
        result
    }
}

struct SystemCaIdentityVerifier {
    guard: IdentityGuard,
    system_verifier: Arc<WebPkiServerVerifier>,
}

impl fmt::Debug for SystemCaIdentityVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemCaIdentityVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for SystemCaIdentityVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.guard.verify(end_entity)?;
        self.guard
            .retain_validation_result(self.system_verifier.verify_server_cert(
                end_entity,
                intermediates,
                server_name,
                ocsp_response,
                now,
            ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.guard
            .retain_validation_result(self.system_verifier.verify_tls12_signature(
                message,
                certificate,
                signature,
            ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.guard
            .retain_validation_result(self.system_verifier.verify_tls13_signature(
                message,
                certificate,
                signature,
            ))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.system_verifier.supported_verify_schemes()
    }
}

/// Exact SHA-256 pinning replaces CA, hostname, and validity checks only after
/// an explicit trust decision. Rustls still validates the TLS `CertificateVerify`
/// signature and Finished message, proving possession of the pinned key.
struct PinnedCertificateVerifier {
    guard: IdentityGuard,
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedCertificateVerifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedCertificateVerifier")
            .field("algorithms", &self.algorithms)
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.guard.verify(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.guard.retain_validation_result(verify_tls12_signature(
            message,
            certificate,
            signature,
            &self.algorithms,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.guard.retain_validation_result(verify_tls13_signature(
            message,
            certificate,
            signature,
            &self.algorithms,
        ))
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, net::SocketAddr};

    use rcgen::{CertifiedKey, generate_simple_self_signed};
    use rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    };
    use rutilus_domain::{TlsCertificate, TlsTrust};
    use time::OffsetDateTime;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::JoinHandle,
        time::timeout,
    };
    use tokio_rustls::TlsAcceptor;

    use super::*;

    const SERVICE_ROOT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/",
        "Id":"RootService",
        "Name":"Root Service",
        "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
        "RedfishVersion":"1.20.0",
        "Vendor":"Rutilus Test",
        "Product":"Fixture BMC"
    }"#;

    #[tokio::test]
    async fn reads_service_root_through_system_ca_and_public_nv_redfish_api()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start("200 OK", SERVICE_ROOT_BODY).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let summary = gateway
            .read_service_root(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(summary.vendor(), Some("Rutilus Test"));
        assert_eq!(summary.product(), Some("Fixture BMC"));
        assert_eq!(summary.redfish_version(), Some("1.20.0"));
        let request = String::from_utf8(server.finish().await?)?;
        assert!(request.starts_with("GET /redfish/v1 HTTP/1.1\r\n"));
        let authorization = request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then_some(value.trim())
        });
        assert_eq!(authorization, Some("Basic YWRtaW46cGFzc3dvcmQ="));
        assert!(!request.contains("password"));
        Ok(())
    }

    #[tokio::test]
    async fn explicit_pin_can_authenticate_a_known_hostname_mismatch() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start("200 OK", SERVICE_ROOT_BODY).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = pinned_trust(&server.certificate)?;
        let address = endpoint_address(server.socket, "127.0.0.1")?;

        let summary = gateway
            .read_service_root(
                &address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(summary.vendor(), Some("Rutilus Test"));
        assert!(!server.finish().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn changed_pin_is_typed_and_sends_no_credentials() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start("200 OK", SERVICE_ROOT_BODY).await?;
        let expected = generate_simple_self_signed([String::from("localhost")])?;
        let expected = expected.cert.der().clone();
        let gateway = gateway_with_root(expected.clone())?;
        let trust = pinned_trust(&expected)?;

        let result = gateway
            .read_service_root(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("must-not-leave-client"),
            )
            .await;

        match result {
            Err(RedfishServiceRootError::TlsIdentityChanged(changed)) => {
                assert_eq!(
                    changed.expected(),
                    CertificateFingerprint::from_certificate_der(expected.as_ref())
                );
                assert_eq!(
                    changed.observed(),
                    CertificateFingerprint::from_certificate_der(server.certificate.as_ref())
                );
            }
            result => {
                return Err(io::Error::other(format!(
                    "expected typed TLS identity change, got {result:?}"
                ))
                .into());
            }
        }
        assert!(server.finish().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn system_ca_retains_hostname_validation_and_sends_no_credentials()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start("200 OK", SERVICE_ROOT_BODY).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;
        let address = endpoint_address(server.socket, "127.0.0.1")?;

        let result = gateway
            .read_service_root(
                &address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("must-not-leave-client"),
            )
            .await;

        assert!(matches!(
            result,
            Err(RedfishServiceRootError::TlsRejected { .. })
        ));
        assert!(server.finish().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_authentication_non_redfish_and_schema_failure()
    -> Result<(), Box<dyn Error>> {
        let unauthorized = TestRedfishServer::start("401 Unauthorized", "{}").await?;
        let unauthorized_gateway = gateway_with_root(unauthorized.certificate.clone())?;
        let unauthorized_trust = system_ca_trust(&unauthorized.certificate)?;
        let authentication = unauthorized_gateway
            .read_service_root(
                &unauthorized.address,
                &unauthorized_trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("wrong"),
            )
            .await;
        assert!(matches!(
            authentication,
            Err(RedfishServiceRootError::AuthenticationFailed { .. })
        ));
        assert!(!unauthorized.finish().await?.is_empty());

        let non_redfish = TestRedfishServer::start("200 OK", "not-json").await?;
        let non_redfish_gateway = gateway_with_root(non_redfish.certificate.clone())?;
        let non_redfish_trust = system_ca_trust(&non_redfish.certificate)?;
        let incompatible_service = non_redfish_gateway
            .read_service_root(
                &non_redfish.address,
                &non_redfish_trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;
        assert!(matches!(
            incompatible_service,
            Err(RedfishServiceRootError::NotRedfishService { .. })
        ));
        assert!(!non_redfish.finish().await?.is_empty());

        let incompatible = TestRedfishServer::start("200 OK", "{}").await?;
        let incompatible_gateway = gateway_with_root(incompatible.certificate.clone())?;
        let incompatible_trust = system_ca_trust(&incompatible.certificate)?;
        let schema = incompatible_gateway
            .read_service_root(
                &incompatible.address,
                &incompatible_trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;
        if !matches!(
            schema,
            Err(RedfishServiceRootError::SchemaIncompatible { .. })
        ) {
            return Err(
                io::Error::other(format!("expected incompatible schema, got {schema:?}")).into(),
            );
        }
        assert!(!incompatible.finish().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_permission_and_missing_service_root() -> Result<(), Box<dyn Error>> {
        let forbidden = TestRedfishServer::start("403 Forbidden", "{}").await?;
        let forbidden_gateway = gateway_with_root(forbidden.certificate.clone())?;
        let forbidden_trust = system_ca_trust(&forbidden.certificate)?;
        let permission = forbidden_gateway
            .read_service_root(
                &forbidden.address,
                &forbidden_trust,
                &CredentialUsername::parse("reader")?,
                &SecretString::from("password"),
            )
            .await;
        assert!(matches!(
            permission,
            Err(RedfishServiceRootError::PermissionDenied { .. })
        ));
        assert!(!forbidden.finish().await?.is_empty());

        let missing = TestRedfishServer::start("404 Not Found", "{}").await?;
        let missing_gateway = gateway_with_root(missing.certificate.clone())?;
        let missing_trust = system_ca_trust(&missing.certificate)?;
        let not_redfish = missing_gateway
            .read_service_root(
                &missing.address,
                &missing_trust,
                &CredentialUsername::parse("reader")?,
                &SecretString::from("password"),
            )
            .await;
        assert!(matches!(
            not_redfish,
            Err(RedfishServiceRootError::NotRedfishService { .. })
        ));
        assert!(!missing.finish().await?.is_empty());
        Ok(())
    }

    fn gateway_with_root(
        certificate: CertificateDer<'static>,
    ) -> Result<RedfishGateway, Box<dyn Error>> {
        let mut roots = RootCertStore::empty();
        roots.add(certificate)?;
        Ok(RedfishGateway {
            tls: TlsProbe::from_root_store(roots, HTTP_CONNECT_TIMEOUT, HTTP_REQUEST_TIMEOUT)?,
        })
    }

    fn system_ca_trust(certificate: &CertificateDer<'_>) -> Result<TlsTrust, Box<dyn Error>> {
        Ok(TlsTrust::SystemCa {
            certificate: TlsCertificate::from_der(certificate.as_ref().to_vec())?,
            verified_at: OffsetDateTime::now_utc(),
        })
    }

    fn pinned_trust(certificate: &CertificateDer<'_>) -> Result<TlsTrust, Box<dyn Error>> {
        Ok(TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(certificate.as_ref().to_vec())?,
            trusted_at: OffsetDateTime::now_utc(),
        })
    }

    struct TestRedfishServer {
        address: EndpointAddress,
        socket: SocketAddr,
        certificate: CertificateDer<'static>,
        task: JoinHandle<Result<Vec<u8>, io::Error>>,
    }

    impl TestRedfishServer {
        async fn start(status: &str, body: &str) -> Result<Self, Box<dyn Error>> {
            let CertifiedKey { cert, signing_key } =
                generate_simple_self_signed([String::from("localhost")])?;
            let certificate = cert.der().clone();
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key)?;
            let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
            let socket = listener.local_addr()?;
            let acceptor = TlsAcceptor::from(Arc::new(config));
            let response = http_response(status, body);
            let task = tokio::spawn(run_server(listener, acceptor, response));
            Ok(Self {
                address: endpoint_address(socket, "localhost")?,
                socket,
                certificate,
                task,
            })
        }

        async fn finish(self) -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(self.task.await??)
        }
    }

    fn endpoint_address(socket: SocketAddr, host: &str) -> Result<EndpointAddress, Box<dyn Error>> {
        Ok(EndpointAddress::parse(&format!(
            "https://{host}:{}",
            socket.port()
        ))?)
    }

    fn http_response(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    async fn run_server(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        response: Vec<u8>,
    ) -> Result<Vec<u8>, io::Error> {
        let (tcp, _) = listener.accept().await?;
        let Ok(mut stream) = timeout(Duration::from_secs(5), acceptor.accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test TLS handshake"))?
        else {
            return Ok(Vec::new());
        };
        let request = read_request_headers(&mut stream).await?;
        stream.write_all(&response).await?;
        stream.shutdown().await?;
        Ok(request)
    }

    async fn read_request_headers(
        stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> Result<Vec<u8>, io::Error> {
        const MAX_REQUEST_BYTES: usize = 16 * 1024;
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            let bytes = timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test HTTP request"))??;
            if bytes == 0 {
                return Ok(request);
            }
            request.extend_from_slice(&chunk[..bytes]);
            if request.len() > MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test HTTP request headers exceeded limit",
                ));
            }
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                return Ok(request);
            }
        }
    }
}
