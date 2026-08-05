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
    Resource as NvResource, ServiceRoot,
    bmc_http::{
        BmcCredentials, CacheSettings, HttpBmc,
        reqwest::{BmcError, Client as NvHttpClient},
    },
    core::EntityTypeRef as _,
    session_service::{Session, SessionCreate},
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
    CapabilityState, CertificateFingerprint, CredentialUsername, EndpointAddress,
    EndpointCapability, EndpointCapabilityObservation, ResourceEtag, ResourceEtagError,
    ResourceFeature, ResourceODataId, ResourceODataIdError, ResourceSnapshotPayload,
    ResourceSnapshotPayloadError, TlsIdentityChanged, TlsTrust,
};
use secrecy::{ExposeSecret, SecretString};
use serde::Serialize;
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
        let (bmc, _, identity) = self.authenticated_bmc(address, trust, username, password)?;

        match ServiceRoot::new(bmc).await {
            Ok(root) => Ok(ServiceRootSummary::from_root(&root)),
            Err(source) => Err(classify_service_root_error(source, &identity, trust)),
        }
    }

    /// Reads the Service Root and probes the 0.1 core capabilities through
    /// public, typed `nv-redfish` navigation methods.
    ///
    /// When `SessionService` is usable, the gateway creates an operation-scoped
    /// Session, authenticates subsequent reads with its in-memory token, and
    /// actively deletes the Session before returning. An unavailable or
    /// unauthorized `SessionService` falls back to Basic authentication and is
    /// retained as an explicit capability state.
    ///
    /// Capability reads are sequential. A TLS identity or validation failure
    /// stops the probe immediately, while endpoint-local authorization,
    /// availability, and schema failures become explicit capability states so
    /// one limited feature does not erase the usable remainder.
    ///
    /// # Errors
    ///
    /// Returns [`RedfishServiceRootError`] when the trusted transport cannot be
    /// created, the Service Root itself cannot be read, or TLS safety changes
    /// during any capability request.
    pub async fn probe_core_capabilities(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
    ) -> Result<CoreEndpointDiscovery, RedfishServiceRootError> {
        let (bmc, http, identity) = self.authenticated_bmc(address, trust, username, password)?;
        let root = ServiceRoot::new(bmc)
            .await
            .map_err(|source| classify_service_root_error(source, &identity, trust))?;
        let authenticated = establish_preferred_authentication(
            root, http, address, username, password, &identity, trust,
        )
        .await?;
        let service_root = ServiceRootSummary::from_root(&authenticated.root);
        let result = async {
            let systems =
                classify_capability_probe(authenticated.root.systems().await, &identity, trust)?;
            let chassis =
                classify_capability_probe(authenticated.root.chassis().await, &identity, trust)?;
            let managers =
                classify_capability_probe(authenticated.root.managers().await, &identity, trust)?;

            Ok(CoreEndpointDiscovery {
                service_root,
                capabilities: [
                    EndpointCapabilityObservation::new(
                        EndpointCapability::SessionService,
                        authenticated.session_state,
                    ),
                    EndpointCapabilityObservation::new(EndpointCapability::Systems, systems),
                    EndpointCapabilityObservation::new(EndpointCapability::Chassis, chassis),
                    EndpointCapabilityObservation::new(EndpointCapability::Managers, managers),
                ],
            })
        }
        .await;
        finish_redfish_operation(result, authenticated.session, &identity, trust).await
    }

    /// Reads the complete advertised 0.1 core resource surface through public,
    /// typed `nv-redfish` navigation and returns bounded domain projections.
    ///
    /// Collection links and member identifiers always come from the decoded
    /// Service Root and collection types; the gateway never constructs a BMC
    /// resource URI. An error aborts the complete read so the application
    /// cannot commit a partial refresh Generation. Session tokens are scoped
    /// to this call, kept only in memory, and actively cleaned up.
    ///
    /// # Errors
    ///
    /// Returns [`CoreResourceReadError`] when trusted Redfish access fails or
    /// a decoded resource cannot be represented by the domain snapshot model.
    pub async fn read_core_resources(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
    ) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
        let (bmc, http, identity) = self.authenticated_bmc(address, trust, username, password)?;
        let root = ServiceRoot::new(bmc)
            .await
            .map_err(|source| classify_service_root_error(source, &identity, trust))?;
        let authenticated = establish_preferred_authentication(
            root, http, address, username, password, &identity, trust,
        )
        .await?;
        let result = read_authenticated_core_resources(&authenticated.root, &identity, trust).await;
        finish_core_resource_read(result, authenticated.session, &identity, trust).await
    }

    fn authenticated_bmc(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
    ) -> Result<(Arc<UpstreamBmc>, NvHttpClient, IdentityMonitor), RedfishServiceRootError> {
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
        let bmc = build_bmc(address, http.clone(), credentials);
        Ok((bmc, http, identity))
    }
}

async fn read_authenticated_core_resources(
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let mut resources = vec![service_root_projection(root)?];

    if let Some(collection) = root
        .systems()
        .await
        .map_err(|source| classify_service_root_error(source, identity, trust))?
    {
        let members = collection
            .members()
            .await
            .map_err(|source| classify_service_root_error(source, identity, trust))?;
        resources.reserve(members.len());
        for system in members {
            resources.push(computer_system_projection(&system)?);
        }
    }

    if let Some(collection) = root
        .chassis()
        .await
        .map_err(|source| classify_service_root_error(source, identity, trust))?
    {
        let members = collection
            .members()
            .await
            .map_err(|source| classify_service_root_error(source, identity, trust))?;
        resources.reserve(members.len());
        for chassis in members {
            resources.push(chassis_projection(&chassis)?);
        }
    }

    if let Some(collection) = root
        .managers()
        .await
        .map_err(|source| classify_service_root_error(source, identity, trust))?
    {
        let members = collection
            .members()
            .await
            .map_err(|source| classify_service_root_error(source, identity, trust))?;
        resources.reserve(members.len());
        for manager in members {
            resources.push(manager_projection(&manager)?);
        }
    }

    Ok(resources)
}

fn build_bmc(
    address: &EndpointAddress,
    http: NvHttpClient,
    credentials: BmcCredentials,
) -> Arc<UpstreamBmc> {
    Arc::new(HttpBmc::new(
        http,
        address.as_url().clone(),
        credentials,
        CacheSettings::with_capacity(0),
    ))
}

struct AuthenticatedRoot {
    root: ServiceRoot<UpstreamBmc>,
    session: Option<Session<UpstreamBmc>>,
    session_state: CapabilityState,
}

async fn establish_preferred_authentication(
    root: ServiceRoot<UpstreamBmc>,
    http: NvHttpClient,
    address: &EndpointAddress,
    username: &CredentialUsername,
    password: &SecretString,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<AuthenticatedRoot, RedfishServiceRootError> {
    let service = match root.session_service().await {
        Ok(Some(service)) => service,
        Ok(None) => {
            return Ok(AuthenticatedRoot {
                root,
                session: None,
                session_state: CapabilityState::NotAdvertised,
            });
        }
        Err(source) => {
            let session_state = session_fallback_state(source, identity, trust)?;
            return Ok(AuthenticatedRoot {
                root,
                session: None,
                session_state,
            });
        }
    };
    if matches!(service.raw().service_enabled, Some(Some(false))) {
        return Ok(AuthenticatedRoot {
            root,
            session: None,
            session_state: CapabilityState::TemporarilyUnavailable,
        });
    }
    let sessions = match service.sessions().await {
        Ok(Some(sessions)) => sessions,
        Ok(None) => {
            return Ok(AuthenticatedRoot {
                root,
                session: None,
                session_state: CapabilityState::TemporarilyUnavailable,
            });
        }
        Err(source) => {
            let session_state = session_fallback_state(source, identity, trust)?;
            return Ok(AuthenticatedRoot {
                root,
                session: None,
                session_state,
            });
        }
    };
    let create = SessionCreate::builder(
        username.as_str().to_owned(),
        password.expose_secret().to_owned(),
    )
    .build();
    let session = match sessions.create_session(&create).await {
        Ok(session) => session,
        Err(source) => {
            let session_state = session_fallback_state(source, identity, trust)?;
            return Ok(AuthenticatedRoot {
                root,
                session: None,
                session_state,
            });
        }
    };
    let Some(token) = session
        .auth_token()
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
    else {
        cleanup_session(Some(session), identity, trust).await?;
        return Ok(AuthenticatedRoot {
            root,
            session: None,
            session_state: CapabilityState::SchemaIncompatible,
        });
    };
    let token_bmc = build_bmc(address, http, BmcCredentials::token(token));
    Ok(AuthenticatedRoot {
        root: root.replace_bmc(token_bmc),
        session: Some(session),
        session_state: CapabilityState::Supported,
    })
}

fn session_fallback_state(
    source: UpstreamServiceRootError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CapabilityState, RedfishServiceRootError> {
    classify_capability_probe::<()>(Err(source), identity, trust)
}

async fn cleanup_session(
    session: Option<Session<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<(), RedfishServiceRootError> {
    let Some(session) = session else {
        return Ok(());
    };
    if session.delete().await.is_ok() {
        return Ok(());
    }
    // Do not retain the upstream deletion error: a vendor may put opaque
    // credentials in its Location URI, which the error chain could expose.
    match identity.take_change(trust) {
        Ok(Some(changed)) => Err(RedfishServiceRootError::TlsIdentityChanged(changed)),
        Err(source) => Err(RedfishServiceRootError::TlsIdentityState(source)),
        Ok(None) if identity.validation_rejected() => {
            Err(RedfishServiceRootError::SessionCleanupTlsRejected)
        }
        Ok(None) => Err(RedfishServiceRootError::SessionCleanupFailed),
    }
}

async fn finish_redfish_operation<T>(
    operation: Result<T, RedfishServiceRootError>,
    session: Option<Session<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<T, RedfishServiceRootError> {
    let cleanup = cleanup_session(session, identity, trust).await;
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup),
        (Err(operation), Err(cleanup)) => {
            Err(RedfishServiceRootError::OperationAndSessionCleanupFailed {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            })
        }
    }
}

async fn finish_core_resource_read(
    operation: Result<Vec<CoreResourceProjection>, CoreResourceReadError>,
    session: Option<Session<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let cleanup = cleanup_session(session, identity, trust).await;
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup.into()),
        (Err(operation), Err(cleanup)) => Err(CoreResourceReadError::ReadAndSessionCleanupFailed {
            read: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// One typed Redfish resource ready for the application refresh boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreResourceProjection {
    feature: ResourceFeature,
    odata_id: ResourceODataId,
    etag: Option<ResourceEtag>,
    payload: ResourceSnapshotPayload,
}

impl CoreResourceProjection {
    /// Returns the typed feature that produced this resource.
    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
    }

    /// Borrows the exact identifier discovered through typed navigation.
    #[must_use]
    pub const fn odata_id(&self) -> &ResourceODataId {
        &self.odata_id
    }

    /// Borrows the optional entity tag retained by the upstream schema.
    #[must_use]
    pub const fn etag(&self) -> Option<&ResourceEtag> {
        self.etag.as_ref()
    }

    /// Borrows the canonical JSON projection created from typed fields.
    #[must_use]
    pub const fn payload(&self) -> &ResourceSnapshotPayload {
        &self.payload
    }
}

/// Service metadata and the usable state of every 0.1 core capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreEndpointDiscovery {
    service_root: ServiceRootSummary,
    capabilities: [EndpointCapabilityObservation; 4],
}

impl CoreEndpointDiscovery {
    /// Borrows the stable Service Root projection.
    #[must_use]
    pub const fn service_root(&self) -> &ServiceRootSummary {
        &self.service_root
    }

    /// Borrows all core observations in stable capability order.
    #[must_use]
    pub const fn capabilities(&self) -> &[EndpointCapabilityObservation; 4] {
        &self.capabilities
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

#[derive(Serialize)]
struct CommonResourcePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description", skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

impl CommonResourcePayload {
    fn from_resource(resource: &impl NvResource) -> Self {
        Self {
            id: resource.id().to_string(),
            name: resource.name().to_string(),
            description: resource.description().map(|value| value.to_string()),
        }
    }
}

#[derive(Serialize)]
struct ResourceStatusPayload {
    #[serde(rename = "State", skip_serializing_if = "Option::is_none")]
    state: Option<nv_redfish::schema::resource::State>,
    #[serde(rename = "Health", skip_serializing_if = "Option::is_none")]
    health: Option<nv_redfish::schema::resource::Health>,
    #[serde(rename = "HealthRollup", skip_serializing_if = "Option::is_none")]
    health_rollup: Option<nv_redfish::schema::resource::Health>,
}

impl ResourceStatusPayload {
    fn from_status(status: &nv_redfish::schema::resource::Status) -> Self {
        Self {
            state: status.state.as_ref().copied().flatten(),
            health: status.health.as_ref().copied().flatten(),
            health_rollup: status.health_rollup.as_ref().copied().flatten(),
        }
    }
}

#[derive(Serialize)]
struct ServiceRootPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Vendor", skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    #[serde(rename = "Product", skip_serializing_if = "Option::is_none")]
    product: Option<String>,
    #[serde(rename = "RedfishVersion", skip_serializing_if = "Option::is_none")]
    redfish_version: Option<String>,
}

#[derive(Serialize)]
struct ComputerSystemPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "SystemType", skip_serializing_if = "Option::is_none")]
    system_type: Option<nv_redfish::schema::computer_system::SystemType>,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "PartNumber", skip_serializing_if = "Option::is_none")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(rename = "SKU", skip_serializing_if = "Option::is_none")]
    sku: Option<String>,
    #[serde(rename = "HostName", skip_serializing_if = "Option::is_none")]
    host_name: Option<String>,
    #[serde(rename = "BiosVersion", skip_serializing_if = "Option::is_none")]
    bios_version: Option<String>,
    #[serde(rename = "PowerState", skip_serializing_if = "Option::is_none")]
    power_state: Option<nv_redfish::schema::resource::PowerState>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

#[derive(Serialize)]
struct ChassisPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ChassisType")]
    chassis_type: nv_redfish::schema::chassis::ChassisType,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "PartNumber", skip_serializing_if = "Option::is_none")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(rename = "SKU", skip_serializing_if = "Option::is_none")]
    sku: Option<String>,
    #[serde(rename = "AssetTag", skip_serializing_if = "Option::is_none")]
    asset_tag: Option<String>,
    #[serde(rename = "PowerState", skip_serializing_if = "Option::is_none")]
    power_state: Option<nv_redfish::schema::resource::PowerState>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

#[derive(Serialize)]
struct ManagerPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ManagerType", skip_serializing_if = "Option::is_none")]
    manager_type: Option<nv_redfish::schema::manager::ManagerType>,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "PartNumber", skip_serializing_if = "Option::is_none")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(rename = "FirmwareVersion", skip_serializing_if = "Option::is_none")]
    firmware_version: Option<String>,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(rename = "PowerState", skip_serializing_if = "Option::is_none")]
    power_state: Option<nv_redfish::schema::resource::PowerState>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

fn service_root_projection(
    root: &ServiceRoot<UpstreamBmc>,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ServiceRootPayload {
        resource: CommonResourcePayload::from_resource(root),
        vendor: root.vendor().map(|value| value.to_string()),
        product: root.product().map(|value| value.to_string()),
        redfish_version: root.redfish_version().map(|value| value.to_string()),
    };
    build_core_projection(
        ResourceFeature::ServiceRoot,
        root,
        root.root.etag(),
        &payload,
    )
}

fn computer_system_projection(
    system: &nv_redfish::computer_system::ComputerSystem<UpstreamBmc>,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let raw = system.raw();
    let hardware = system.hardware_id();
    let payload = ComputerSystemPayload {
        resource: CommonResourcePayload::from_resource(system),
        system_type: raw.system_type,
        manufacturer: hardware.manufacturer.map(|value| value.to_string()),
        model: hardware.model.map(|value| value.to_string()),
        part_number: hardware.part_number.map(|value| value.to_string()),
        serial_number: hardware.serial_number.map(|value| value.to_string()),
        sku: system.sku().map(|value| value.to_string()),
        host_name: optional_nullable_text(raw.host_name.as_ref()),
        bios_version: optional_nullable_text(raw.bios_version.as_ref()),
        power_state: system.power_state(),
        status: raw.status.as_ref().map(ResourceStatusPayload::from_status),
    };
    build_core_projection(ResourceFeature::Systems, system, raw.etag(), &payload)
}

fn chassis_projection(
    chassis: &nv_redfish::chassis::Chassis<UpstreamBmc>,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let raw = chassis.raw();
    let hardware = chassis.hardware_id();
    let payload = ChassisPayload {
        resource: CommonResourcePayload::from_resource(chassis),
        chassis_type: raw.chassis_type,
        manufacturer: hardware.manufacturer.map(|value| value.to_string()),
        model: hardware.model.map(|value| value.to_string()),
        part_number: hardware.part_number.map(|value| value.to_string()),
        serial_number: hardware.serial_number.map(|value| value.to_string()),
        sku: optional_nullable_text(raw.sku.as_ref()),
        asset_tag: optional_nullable_text(raw.asset_tag.as_ref()),
        power_state: raw.power_state.as_ref().copied().flatten(),
        status: raw.status.as_ref().map(ResourceStatusPayload::from_status),
    };
    build_core_projection(ResourceFeature::Chassis, chassis, raw.etag(), &payload)
}

fn manager_projection(
    manager: &nv_redfish::manager::Manager<UpstreamBmc>,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let raw = manager.raw();
    let payload = ManagerPayload {
        resource: CommonResourcePayload::from_resource(manager),
        manager_type: raw.manager_type,
        manufacturer: optional_nullable_text(raw.manufacturer.as_ref()),
        model: optional_nullable_text(raw.model.as_ref()),
        part_number: optional_nullable_text(raw.part_number.as_ref()),
        serial_number: optional_nullable_text(raw.serial_number.as_ref()),
        firmware_version: optional_nullable_text(raw.firmware_version.as_ref()),
        version: optional_nullable_text(raw.version.as_ref()),
        power_state: raw.power_state.as_ref().copied().flatten(),
        status: raw.status.as_ref().map(ResourceStatusPayload::from_status),
    };
    build_core_projection(ResourceFeature::Managers, manager, raw.etag(), &payload)
}

fn optional_nullable_text(value: Option<&Option<String>>) -> Option<String> {
    value.and_then(Option::as_ref).cloned()
}

fn build_core_projection(
    feature: ResourceFeature,
    resource: &impl NvResource,
    etag: Option<&nv_redfish::core::ODataETag>,
    payload: &impl Serialize,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let odata_id = ResourceODataId::parse(&resource.odata_id().to_string())
        .map_err(|source| CoreResourceReadError::InvalidODataId { feature, source })?;
    let etag = etag
        .map(|value| ResourceEtag::parse(&value.to_string()))
        .transpose()
        .map_err(|source| CoreResourceReadError::InvalidEtag { feature, source })?;
    let json = serde_json::to_string(payload)
        .map_err(|source| CoreResourceReadError::SerializePayload { feature, source })?;
    let payload = ResourceSnapshotPayload::parse(&json)
        .map_err(|source| CoreResourceReadError::InvalidPayload { feature, source })?;
    Ok(CoreResourceProjection {
        feature,
        odata_id,
        etag,
        payload,
    })
}

/// A controlled failure while reading a complete typed core resource set.
#[derive(Debug, Error)]
pub enum CoreResourceReadError {
    #[error(transparent)]
    Redfish(Box<RedfishServiceRootError>),
    #[error("{feature} returned an invalid @odata.id: {source}")]
    InvalidODataId {
        feature: ResourceFeature,
        #[source]
        source: ResourceODataIdError,
    },
    #[error("{feature} returned an invalid ETag: {source}")]
    InvalidEtag {
        feature: ResourceFeature,
        #[source]
        source: ResourceEtagError,
    },
    #[error("failed to serialize the typed {feature} projection: {source}")]
    SerializePayload {
        feature: ResourceFeature,
        #[source]
        source: serde_json::Error,
    },
    #[error("the typed {feature} projection is not a valid snapshot payload: {source}")]
    InvalidPayload {
        feature: ResourceFeature,
        #[source]
        source: ResourceSnapshotPayloadError,
    },
    #[error(
        "typed core read and transient Session cleanup both failed; read: {read}; cleanup: {cleanup}"
    )]
    ReadAndSessionCleanupFailed {
        read: Box<CoreResourceReadError>,
        cleanup: Box<RedfishServiceRootError>,
    },
}

impl From<RedfishServiceRootError> for CoreResourceReadError {
    fn from(source: RedfishServiceRootError) -> Self {
        Self::Redfish(Box::new(source))
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
    #[error("BMC credentials are valid but lack permission for the requested Redfish resource")]
    PermissionDenied {
        #[source]
        source: BmcError,
    },
    #[error("the target did not expose the standard Redfish Service Root")]
    NotRedfishService {
        #[source]
        source: BmcError,
    },
    #[error("the Redfish response was incompatible with the compiled schema")]
    SchemaIncompatible {
        #[source]
        source: UpstreamServiceRootError,
    },
    #[error("the Redfish request timed out")]
    NetworkTimeout {
        #[source]
        source: BmcError,
    },
    #[error("the Redfish resource could not be reached")]
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
    #[error("TLS validation rejected transient Session cleanup")]
    SessionCleanupTlsRejected,
    #[error("transient Redfish Session cleanup failed")]
    SessionCleanupFailed,
    #[error(
        "Redfish operation and transient Session cleanup both failed; operation: {operation}; cleanup: {cleanup}"
    )]
    OperationAndSessionCleanupFailed {
        operation: Box<RedfishServiceRootError>,
        cleanup: Box<RedfishServiceRootError>,
    },
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

fn classify_capability_probe<T>(
    result: Result<Option<T>, UpstreamServiceRootError>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CapabilityState, RedfishServiceRootError> {
    let source = match result {
        Ok(Some(_)) => return Ok(CapabilityState::Supported),
        Ok(None) => return Ok(CapabilityState::NotAdvertised),
        Err(source) => source,
    };

    match classify_service_root_error(source, identity, trust) {
        RedfishServiceRootError::AuthenticationFailed { .. }
        | RedfishServiceRootError::PermissionDenied { .. } => Ok(CapabilityState::Unauthorized),
        RedfishServiceRootError::SchemaIncompatible { .. } => {
            Ok(CapabilityState::SchemaIncompatible)
        }
        RedfishServiceRootError::NotRedfishService { .. }
        | RedfishServiceRootError::NetworkTimeout { .. }
        | RedfishServiceRootError::Network { .. }
        | RedfishServiceRootError::RemoteResponse { .. }
        | RedfishServiceRootError::Upstream(_) => Ok(CapabilityState::TemporarilyUnavailable),
        source @ (RedfishServiceRootError::TlsConfiguration(_)
        | RedfishServiceRootError::ClientBuild(_)
        | RedfishServiceRootError::TlsIdentityState(_)
        | RedfishServiceRootError::TlsIdentityChanged(_)
        | RedfishServiceRootError::TlsRejected { .. }
        | RedfishServiceRootError::SessionCleanupTlsRejected
        | RedfishServiceRootError::SessionCleanupFailed
        | RedfishServiceRootError::OperationAndSessionCleanupFailed { .. }) => Err(source),
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

    const INVALID_SERVICE_ROOT_ID_BODY: &str = r#"{
        "@odata.id":" /redfish/v1/",
        "Id":"RootService",
        "Name":"Root Service",
        "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}}
    }"#;

    const CORE_SERVICE_ROOT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/",
        "@odata.etag":"W/\"root-1\"",
        "Id":"RootService",
        "Name":"Root Service",
        "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
        "RedfishVersion":"1.20.0",
        "Vendor":"Rutilus Test",
        "Product":"Fixture BMC",
        "SessionService":{"@odata.id":"/redfish/v1/SessionService"},
        "Systems":{"@odata.id":"/redfish/v1/Systems"},
        "Chassis":{"@odata.id":"/redfish/v1/Chassis"},
        "Managers":{"@odata.id":"/redfish/v1/Managers"}
    }"#;

    const SYSTEMS_SERVICE_ROOT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/",
        "Id":"RootService",
        "Name":"Root Service",
        "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
        "Systems":{"@odata.id":"/redfish/v1/Systems"}
    }"#;

    const SESSION_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/SessionService",
        "Id":"SessionService",
        "Name":"Session Service",
        "ServiceEnabled":true,
        "Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}
    }"#;

    const SESSIONS_BODY: &str = r##"{
        "@odata.type":"#SessionCollection.SessionCollection",
        "@odata.id":"/redfish/v1/SessionService/Sessions",
        "Name":"Session Collection",
        "Members":[]
    }"##;

    const SESSION_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/SessionService/Sessions/1",
        "Id":"1",
        "Name":"Rutilus Session",
        "UserName":"admin",
        "Password":null
    }"#;

    const SYSTEMS_BODY: &str = r##"{
        "@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",
        "@odata.id":"/redfish/v1/Systems",
        "Name":"Computer System Collection",
        "Members":[]
    }"##;

    const CHASSIS_BODY: &str = r##"{
        "@odata.type":"#ChassisCollection.ChassisCollection",
        "@odata.id":"/redfish/v1/Chassis",
        "Name":"Chassis Collection",
        "Members":[]
    }"##;

    const MANAGERS_BODY: &str = r##"{
        "@odata.type":"#ManagerCollection.ManagerCollection",
        "@odata.id":"/redfish/v1/Managers",
        "Name":"Manager Collection",
        "Members":[]
    }"##;

    const SYSTEMS_WITH_MEMBER_BODY: &str = r##"{
        "@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",
        "@odata.id":"/redfish/v1/Systems",
        "Name":"Computer System Collection",
        "Members":[{"@odata.id":"/redfish/v1/Systems/1"}]
    }"##;

    const SYSTEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "Description":"Primary compute system",
        "SystemType":"Physical",
        "Manufacturer":"Rutilus Test",
        "Model":"Model S",
        "PartNumber":"SYS-PART-1",
        "SerialNumber":"SYS-1",
        "SKU":"SYS-SKU-1",
        "HostName":"compute-1",
        "BiosVersion":"2.3.4",
        "PowerState":"On",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"#;

    const CHASSIS_WITH_MEMBER_BODY: &str = r##"{
        "@odata.type":"#ChassisCollection.ChassisCollection",
        "@odata.id":"/redfish/v1/Chassis",
        "Name":"Chassis Collection",
        "Members":[{"@odata.id":"/redfish/v1/Chassis/1"}]
    }"##;

    const CHASSIS_MEMBER_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "@odata.etag":"W/\"chassis-1\"",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Manufacturer":"Rutilus Test",
        "Model":"Model C",
        "PartNumber":"CHA-PART-1",
        "SerialNumber":"CHA-1",
        "SKU":"CHA-SKU-1",
        "AssetTag":"RACK-01",
        "PowerState":"On",
        "Status":{"State":"Enabled","Health":"Warning","HealthRollup":"OK"}
    }"#;

    const MANAGERS_WITH_MEMBER_BODY: &str = r##"{
        "@odata.type":"#ManagerCollection.ManagerCollection",
        "@odata.id":"/redfish/v1/Managers",
        "Name":"Manager Collection",
        "Members":[{"@odata.id":"/redfish/v1/Managers/1"}]
    }"##;

    const MANAGER_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Manufacturer":"Rutilus Test",
        "Model":"Model M",
        "PartNumber":"MGR-PART-1",
        "SerialNumber":"MGR-1",
        "FirmwareVersion":"1.2.3",
        "Version":"4.5.6",
        "PowerState":"On",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"#;

    const CORE_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Chassis",
        "/redfish/v1/Managers",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    const BASIC_FALLBACK_REQUEST_PATHS: [&str; 5] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/Systems",
        "/redfish/v1/Chassis",
        "/redfish/v1/Managers",
    ];

    const SESSION_CREATE_FALLBACK_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Chassis",
        "/redfish/v1/Managers",
    ];

    const INVALID_SESSION_TOKEN_FALLBACK_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions/1",
        "/redfish/v1/Systems",
        "/redfish/v1/Chassis",
        "/redfish/v1/Managers",
    ];

    const FAILED_RESOURCE_AND_CLEANUP_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    const CORE_RESOURCE_REQUEST_PATHS: [&str; 11] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

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
    async fn probes_every_advertised_core_capability_through_typed_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(&[
            ("200 OK", SYSTEMS_BODY),
            ("200 OK", CHASSIS_BODY),
            ("200 OK", MANAGERS_BODY),
        ]))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let discovery = gateway
            .probe_core_capabilities(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(discovery.service_root().vendor(), Some("Rutilus Test"));
        assert_eq!(
            discovery.capabilities(),
            &[
                EndpointCapabilityObservation::new(
                    EndpointCapability::SessionService,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Chassis,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Managers,
                    CapabilityState::Supported,
                ),
            ]
        );
        assert_session_requests(&server.finish_all().await?, &CORE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn reports_unadvertised_core_capabilities_without_guessing_paths()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start("200 OK", SERVICE_ROOT_BODY).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let discovery = gateway
            .probe_core_capabilities(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert!(
            discovery
                .capabilities()
                .iter()
                .all(|observation| observation.state() == CapabilityState::NotAdvertised)
        );
        assert_authenticated_requests(&server.finish_all().await?, &["/redfish/v1"])?;
        Ok(())
    }

    #[tokio::test]
    async fn isolates_limited_capabilities_and_continues_typed_probe() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_sequence(&[
            ("200 OK", CORE_SERVICE_ROOT_BODY),
            ("403 Forbidden", "{}"),
            ("200 OK", "{}"),
            ("404 Not Found", "{}"),
            ("200 OK", MANAGERS_BODY),
        ])
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let discovery = gateway
            .probe_core_capabilities(
                &server.address,
                &trust,
                &CredentialUsername::parse("limited-reader")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(
            discovery.capabilities(),
            &[
                EndpointCapabilityObservation::new(
                    EndpointCapability::SessionService,
                    CapabilityState::Unauthorized,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::SchemaIncompatible,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Chassis,
                    CapabilityState::TemporarilyUnavailable,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Managers,
                    CapabilityState::Supported,
                ),
            ]
        );
        assert_authenticated_requests(&server.finish_all().await?, &BASIC_FALLBACK_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn records_unavailable_session_creation_and_falls_back_to_basic()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(vec![
            http_response("200 OK", CORE_SERVICE_ROOT_BODY),
            http_response("200 OK", SESSION_SERVICE_BODY),
            http_response("200 OK", SESSIONS_BODY),
            http_response("501 Not Implemented", "{}"),
            http_response("200 OK", SYSTEMS_BODY),
            http_response("200 OK", CHASSIS_BODY),
            http_response("200 OK", MANAGERS_BODY),
        ])
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let discovery = gateway
            .probe_core_capabilities(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(
            discovery.capabilities(),
            &[
                EndpointCapabilityObservation::new(
                    EndpointCapability::SessionService,
                    CapabilityState::TemporarilyUnavailable,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Chassis,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Managers,
                    CapabilityState::Supported,
                ),
            ]
        );
        assert_session_creation_fallback_requests(
            &server.finish_all().await?,
            &SESSION_CREATE_FALLBACK_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn reports_sanitized_transient_session_cleanup_failure() -> Result<(), Box<dyn Error>> {
        let mut responses = session_response_sequence(&[
            ("200 OK", SYSTEMS_BODY),
            ("200 OK", CHASSIS_BODY),
            ("200 OK", MANAGERS_BODY),
        ]);
        if let Some(cleanup) = responses.last_mut() {
            *cleanup = http_response("500 Internal Server Error", "{}");
        }
        let server = TestRedfishServer::start_raw_sequence(responses).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .probe_core_capabilities(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        let Err(error) = result else {
            return Err(io::Error::other("Session cleanup failure was accepted").into());
        };
        assert!(matches!(
            error,
            RedfishServiceRootError::SessionCleanupFailed
        ));
        let rendered = format!("{error}\n{error:?}");
        assert!(!rendered.contains("test-session-token"));
        assert!(!rendered.contains("password"));
        assert_session_requests(&server.finish_all().await?, &CORE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn cleans_invalid_session_token_then_records_schema_fallback()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(vec![
            http_response("200 OK", CORE_SERVICE_ROOT_BODY),
            http_response("200 OK", SESSION_SERVICE_BODY),
            http_response("200 OK", SESSIONS_BODY),
            http_response_with_headers(
                "201 Created",
                SESSION_BODY,
                &[
                    ("X-Auth-Token", ""),
                    ("Location", "/redfish/v1/SessionService/Sessions/1"),
                ],
            ),
            http_response("204 No Content", ""),
            http_response("200 OK", SYSTEMS_BODY),
            http_response("200 OK", CHASSIS_BODY),
            http_response("200 OK", MANAGERS_BODY),
        ])
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let discovery = gateway
            .probe_core_capabilities(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(
            discovery.capabilities(),
            &[
                EndpointCapabilityObservation::new(
                    EndpointCapability::SessionService,
                    CapabilityState::SchemaIncompatible,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Chassis,
                    CapabilityState::Supported,
                ),
                EndpointCapabilityObservation::new(
                    EndpointCapability::Managers,
                    CapabilityState::Supported,
                ),
            ]
        );
        assert_invalid_session_token_fallback_requests(
            &server.finish_all().await?,
            &INVALID_SESSION_TOKEN_FALLBACK_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_complete_core_resources_through_typed_navigation() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(&[
            ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
            ("200 OK", SYSTEM_BODY),
            ("200 OK", CHASSIS_WITH_MEMBER_BODY),
            ("200 OK", CHASSIS_MEMBER_BODY),
            ("200 OK", MANAGERS_WITH_MEMBER_BODY),
            ("200 OK", MANAGER_BODY),
        ]))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let resources = gateway
            .read_core_resources(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(resources.len(), 4);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Chassis,
                ResourceFeature::Managers,
            ]
        );
        assert_projection(
            &resources[0],
            "/redfish/v1/",
            "W/\"root-1\"",
            "Vendor",
            "Rutilus Test",
        )?;
        assert_projection(
            &resources[1],
            "/redfish/v1/Systems/1",
            "W/\"system-1\"",
            "SystemType",
            "Physical",
        )?;
        assert_projection(
            &resources[2],
            "/redfish/v1/Chassis/1",
            "W/\"chassis-1\"",
            "ChassisType",
            "RackMount",
        )?;
        assert_projection(
            &resources[3],
            "/redfish/v1/Managers/1",
            "W/\"manager-1\"",
            "ManagerType",
            "BMC",
        )?;
        let system_payload: serde_json::Value =
            serde_json::from_str(resources[1].payload().as_str())?;
        assert_eq!(system_payload["PowerState"], "On");
        assert_eq!(system_payload["Status"]["Health"], "OK");
        assert_eq!(system_payload["BiosVersion"], "2.3.4");
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_only_service_root_when_core_collections_are_not_advertised()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start("200 OK", SERVICE_ROOT_BODY).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let resources = gateway
            .read_core_resources(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].feature(), ResourceFeature::ServiceRoot);
        assert_authenticated_requests(&server.finish_all().await?, &["/redfish/v1"])?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_invalid_typed_resource_metadata_without_normalizing_it()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start("200 OK", INVALID_SERVICE_ROOT_ID_BODY).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .read_core_resources(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        assert!(matches!(
            result,
            Err(CoreResourceReadError::InvalidODataId {
                feature: ResourceFeature::ServiceRoot,
                source: ResourceODataIdError::SurroundingWhitespace,
            })
        ));
        assert_authenticated_requests(&server.finish_all().await?, &["/redfish/v1"])?;
        Ok(())
    }

    #[tokio::test]
    async fn aborts_complete_resource_read_on_incompatible_member_schema()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_sequence(&[
            ("200 OK", SYSTEMS_SERVICE_ROOT_BODY),
            ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
            ("200 OK", "{}"),
        ])
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .read_core_resources(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        assert!(matches!(
            result,
            Err(CoreResourceReadError::Redfish(source))
                if matches!(*source, RedfishServiceRootError::SchemaIncompatible { .. })
        ));
        assert_authenticated_requests(
            &server.finish_all().await?,
            &[
                "/redfish/v1",
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
            ],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn preserves_resource_and_sanitized_session_cleanup_failures()
    -> Result<(), Box<dyn Error>> {
        let mut responses =
            session_response_sequence(&[("200 OK", SYSTEMS_WITH_MEMBER_BODY), ("200 OK", "{}")]);
        if let Some(cleanup) = responses.last_mut() {
            *cleanup = http_response("500 Internal Server Error", "{}");
        }
        let server = TestRedfishServer::start_raw_sequence(responses).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .read_core_resources(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        let Err(CoreResourceReadError::ReadAndSessionCleanupFailed { read, cleanup }) = result
        else {
            return Err(io::Error::other(
                "resource and Session cleanup failures were not both retained",
            )
            .into());
        };
        assert!(matches!(
            read.as_ref(),
            CoreResourceReadError::Redfish(source)
                if matches!(source.as_ref(), RedfishServiceRootError::SchemaIncompatible { .. })
        ));
        assert!(matches!(
            cleanup.as_ref(),
            RedfishServiceRootError::SessionCleanupFailed
        ));
        let rendered = format!("{read}\n{read:?}\n{cleanup}\n{cleanup:?}");
        assert!(!rendered.contains("test-session-token"));
        assert!(!rendered.contains("password"));
        assert_session_requests(
            &server.finish_all().await?,
            &FAILED_RESOURCE_AND_CLEANUP_REQUEST_PATHS,
        )?;
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

    fn assert_authenticated_requests(
        requests: &[Vec<u8>],
        expected_paths: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(requests.len(), expected_paths.len());
        for (request, expected_path) in requests.iter().zip(expected_paths) {
            let request = std::str::from_utf8(request)?;
            assert!(request.starts_with(&format!("GET {expected_path} HTTP/1.1\r\n")));
            let authorization = request.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("authorization")
                    .then_some(value.trim())
            });
            assert!(authorization.is_some_and(|value| value.starts_with("Basic ")));
            assert!(!request.contains("password"));
        }
        Ok(())
    }

    fn assert_session_requests(
        requests: &[Vec<u8>],
        expected_paths: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(requests.len(), expected_paths.len());
        let last = requests.len().saturating_sub(1);
        for (index, (request, expected_path)) in requests.iter().zip(expected_paths).enumerate() {
            let request = std::str::from_utf8(request)?;
            let expected_method = match index {
                3 => "POST",
                value if value == last => "DELETE",
                _ => "GET",
            };
            assert!(
                request.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1\r\n"))
            );
            let authorization = request_header(request, "authorization");
            let token = request_header(request, "x-auth-token");
            match index {
                3 => {
                    assert!(authorization.is_none());
                    assert!(token.is_none());
                }
                4.. if index < last => {
                    assert!(authorization.is_none());
                    assert_eq!(token, Some("test-session-token"));
                }
                _ => {
                    assert!(authorization.is_some_and(|value| value.starts_with("Basic ")));
                    assert!(token.is_none());
                }
            }
            if index != 3 {
                assert!(!request.contains("password"));
            }
        }
        Ok(())
    }

    fn assert_session_creation_fallback_requests(
        requests: &[Vec<u8>],
        expected_paths: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(requests.len(), expected_paths.len());
        for (index, (request, expected_path)) in requests.iter().zip(expected_paths).enumerate() {
            let request = std::str::from_utf8(request)?;
            let expected_method = if index == 3 { "POST" } else { "GET" };
            assert!(
                request.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1\r\n"))
            );
            let authorization = request_header(request, "authorization");
            let token = request_header(request, "x-auth-token");
            if index == 3 {
                assert!(authorization.is_none());
            } else {
                assert!(authorization.is_some_and(|value| value.starts_with("Basic ")));
                assert!(!request.contains("password"));
            }
            assert!(token.is_none());
        }
        Ok(())
    }

    fn assert_invalid_session_token_fallback_requests(
        requests: &[Vec<u8>],
        expected_paths: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(requests.len(), expected_paths.len());
        for (index, (request, expected_path)) in requests.iter().zip(expected_paths).enumerate() {
            let request = std::str::from_utf8(request)?;
            let expected_method = match index {
                3 => "POST",
                4 => "DELETE",
                _ => "GET",
            };
            assert!(
                request.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1\r\n"))
            );
            let authorization = request_header(request, "authorization");
            if index == 3 {
                assert!(authorization.is_none());
            } else {
                assert!(authorization.is_some_and(|value| value.starts_with("Basic ")));
                assert!(!request.contains("password"));
            }
            assert!(request_header(request, "x-auth-token").is_none());
        }
        Ok(())
    }

    fn request_header<'a>(request: &'a str, expected_name: &str) -> Option<&'a str> {
        request.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case(expected_name)
                .then_some(value.trim())
        })
    }

    fn session_response_sequence(after_session: &[(&str, &str)]) -> Vec<Vec<u8>> {
        let mut responses = vec![
            http_response("200 OK", CORE_SERVICE_ROOT_BODY),
            http_response("200 OK", SESSION_SERVICE_BODY),
            http_response("200 OK", SESSIONS_BODY),
            http_response_with_headers(
                "201 Created",
                SESSION_BODY,
                &[
                    ("X-Auth-Token", "test-session-token"),
                    ("Location", "/redfish/v1/SessionService/Sessions/1"),
                ],
            ),
        ];
        responses.extend(
            after_session
                .iter()
                .map(|(status, body)| http_response(status, body)),
        );
        responses.push(http_response("204 No Content", ""));
        responses
    }

    fn assert_projection(
        projection: &CoreResourceProjection,
        expected_odata_id: &str,
        expected_etag: &str,
        field: &str,
        expected_value: &str,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(projection.odata_id().as_str(), expected_odata_id);
        assert_eq!(
            projection.etag().map(ResourceEtag::as_str),
            Some(expected_etag)
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload[field], expected_value);
        Ok(())
    }

    struct TestRedfishServer {
        address: EndpointAddress,
        socket: SocketAddr,
        certificate: CertificateDer<'static>,
        task: JoinHandle<Result<Vec<Vec<u8>>, io::Error>>,
    }

    impl TestRedfishServer {
        async fn start(status: &str, body: &str) -> Result<Self, Box<dyn Error>> {
            Self::start_sequence(&[(status, body)]).await
        }

        async fn start_sequence(responses: &[(&str, &str)]) -> Result<Self, Box<dyn Error>> {
            Self::start_raw_sequence(
                responses
                    .iter()
                    .map(|(status, body)| http_response(status, body))
                    .collect(),
            )
            .await
        }

        async fn start_raw_sequence(responses: Vec<Vec<u8>>) -> Result<Self, Box<dyn Error>> {
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
            let task = tokio::spawn(run_server_sequence(listener, acceptor, responses));
            Ok(Self {
                address: endpoint_address(socket, "localhost")?,
                socket,
                certificate,
                task,
            })
        }

        async fn finish(self) -> Result<Vec<u8>, Box<dyn Error>> {
            let mut requests = self.finish_all().await?;
            if requests.len() != 1 {
                return Err(io::Error::other(format!(
                    "expected one test request, got {}",
                    requests.len()
                ))
                .into());
            }
            requests
                .pop()
                .ok_or_else(|| io::Error::other("test request was not captured").into())
        }

        async fn finish_all(self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
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
        http_response_with_headers(status, body, &[])
    }

    fn http_response_with_headers(status: &str, body: &str, headers: &[(&str, &str)]) -> Vec<u8> {
        let mut response_headers = String::new();
        for (name, value) in headers {
            response_headers.push_str(name);
            response_headers.push_str(": ");
            response_headers.push_str(value);
            response_headers.push_str("\r\n");
        }
        format!(
            "HTTP/1.1 {status}\r\n{response_headers}Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    async fn run_server_sequence(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        responses: Vec<Vec<u8>>,
    ) -> Result<Vec<Vec<u8>>, io::Error> {
        let mut requests = Vec::with_capacity(responses.len());
        for response in responses {
            let (tcp, _) = timeout(Duration::from_secs(5), listener.accept())
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test TCP accept"))??;
            let Ok(mut stream) = timeout(Duration::from_secs(5), acceptor.accept(tcp))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test TLS handshake"))?
            else {
                requests.push(Vec::new());
                continue;
            };
            let request = read_request_headers(&mut stream).await?;
            stream.write_all(&response).await?;
            stream.shutdown().await?;
            requests.push(request);
        }
        Ok(requests)
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
