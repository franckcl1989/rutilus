use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
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
    chassis::{Chassis, ChassisCollection, NetworkAdapter},
    computer_system::{ComputerSystem, SystemCollection},
    core::{EntityTypeRef, NavProperty},
    manager::{Manager, ManagerCollection},
    schema::{
        chassis::Chassis as ChassisSchema,
        chassis_collection::ChassisCollection as ChassisCollectionSchema,
        computer_system::ComputerSystem as ComputerSystemSchema,
        computer_system_collection::ComputerSystemCollection as ComputerSystemCollectionSchema,
        ethernet_interface::EthernetInterface as EthernetInterfaceSchema,
        ethernet_interface_collection::EthernetInterfaceCollection as EthernetInterfaceCollectionSchema,
        manager::Manager as ManagerSchema,
        manager_collection::ManagerCollection as ManagerCollectionSchema,
        memory::Memory as MemorySchema,
        memory_collection::MemoryCollection as MemoryCollectionSchema,
        network_adapter::NetworkAdapter as NetworkAdapterSchema,
        network_adapter_collection::NetworkAdapterCollection as NetworkAdapterCollectionSchema,
        processor::Processor as ProcessorSchema,
        processor_collection::ProcessorCollection as ProcessorCollectionSchema,
        resource::Resource as ResourceSchema, storage::Storage as StorageSchema,
        storage_collection::StorageCollection as StorageCollectionSchema,
    },
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
use serde::{Deserialize, Serialize};
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

    /// Reads the Service Root and probes the complete §2.1 standard feature
    /// surface (30 capabilities) through public, typed `nv-redfish`
    /// navigation methods.
    ///
    /// When `SessionService` is usable, the gateway creates an operation-scoped
    /// Session, authenticates subsequent reads with its in-memory token, and
    /// actively deletes the Session before returning. An unavailable or
    /// unauthorized `SessionService` falls back to Basic authentication and is
    /// retained as an explicit capability state.
    ///
    /// Root-level services are probed directly from the Service Root. The
    /// Systems, Chassis, and Managers collections are probed once and their
    /// typed members then carry the member-scoped feature probes (BIOS,
    /// processors, power, thermal, network protocol, and so on). Member
    /// probing stops at the first observation that is not `NotAdvertised`,
    /// because advertisement is an endpoint-level property that later members
    /// cannot change. When no member can be inspected (empty collection or
    /// member fetch failure), member-scoped features inherit the collection's
    /// observation gap instead of guessing at links that were never decoded.
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
        let root = ServiceRoot::new(Arc::clone(&bmc))
            .await
            .map_err(|source| classify_service_root_error(source, &identity, trust))?;
        let authenticated = establish_preferred_authentication(
            root,
            SessionSetup {
                bmc,
                http,
                address,
                username,
                password,
            },
            &identity,
            trust,
        )
        .await?;
        let service_root = ServiceRootSummary::from_root(&authenticated.root);
        let result = async {
            let systems =
                probe_collection(authenticated.root.systems().await, &identity, trust).await?;
            let chassis =
                probe_collection(authenticated.root.chassis().await, &identity, trust).await?;
            let managers =
                probe_collection(authenticated.root.managers().await, &identity, trust).await?;
            let observations = CapabilityObservations {
                session: authenticated.session_state,
                systems: systems.state,
                chassis: chassis.state,
                managers: managers.state,
                root: probe_root_services(&authenticated.root, &identity, trust).await?,
                systems_features: probe_system_features(&systems, &identity, trust).await?,
                chassis_features: probe_chassis_features(&chassis, &identity, trust).await?,
                manager_features: probe_manager_features(&managers, &identity, trust).await?,
            };
            Ok(CoreEndpointDiscovery {
                service_root,
                capabilities: build_observations(observations),
            })
        }
        .await;
        finish_redfish_operation(result, authenticated.session, &identity, trust).await
    }

    /// Reads the complete advertised core resource surface (the 0.1
    /// ServiceRoot/Systems/Chassis/Managers triad plus the 0.2 Processors,
    /// Memory, Storage, `NetworkAdapters`, and `EthernetInterfaces` families)
    /// through public, typed `nv-redfish` navigation and returns bounded
    /// domain projections.
    ///
    /// Collection links and member identifiers always come from the decoded
    /// Service Root and collection types; the gateway never constructs a BMC
    /// resource URI. Member-granular failures are skippable (§0.2.0
    /// acceptance): one member that cannot be fetched or represented is left
    /// behind without disabling its collection or the rest of the read.
    /// Service Root and collection-document failures still abort the complete
    /// read so the application cannot commit a partial refresh Generation.
    /// Session tokens are scoped to this call, kept only in memory, and
    /// actively cleaned up.
    ///
    /// # Errors
    ///
    /// Returns [`CoreResourceReadError`] when trusted Redfish access fails or
    /// the Service Root cannot be represented by the domain snapshot model.
    pub async fn read_core_resources(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
    ) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
        let (bmc, http, identity) = self.authenticated_bmc(address, trust, username, password)?;
        let root = ServiceRoot::new(Arc::clone(&bmc))
            .await
            .map_err(|source| classify_service_root_error(source, &identity, trust))?;
        let authenticated = establish_preferred_authentication(
            root,
            SessionSetup {
                bmc,
                http,
                address,
                username,
                password,
            },
            &identity,
            trust,
        )
        .await?;
        let result = read_authenticated_core_resources(
            authenticated.bmc.as_ref(),
            &authenticated.root,
            &identity,
            trust,
        )
        .await;
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

/// Reads the authenticated resource surface through the transport the
/// Session logic selected, so the token never leaks into the Basic path.
///
/// Members are fetched one at a time from the decoded collection documents
/// instead of through the `nv-redfish` wholesale accessors, because the
/// wholesale accessors abort on the first undecodable member. Fetching
/// individually is what makes the §0.2.0 member-skip acceptance implementable.
async fn read_authenticated_core_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let mut resources = vec![service_root_projection(root)?];
    resources.extend(read_systems_resources(bmc, root, identity, trust).await?);
    resources.extend(read_chassis_resources(bmc, root, identity, trust).await?);
    resources.extend(read_manager_resources(bmc, root, identity, trust).await?);
    Ok(resources)
}

/// Reads the Systems collection and, for every decoded System member, its
/// Processors, Memory, and Storage collections, so the 0.2 families follow
/// their parent through the same typed navigation.
///
/// A missing Systems link leaves the whole family absent without an error
/// ("资源存在才呈现"); a failed Systems collection document aborts the read
/// with the existing classified error semantics. Only individual members are
/// skippable.
async fn read_systems_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(systems) = root.root.systems.as_ref() else {
        return Ok(Vec::new());
    };
    let collection = systems
        .get(bmc)
        .await
        .map_err(|source| collection_failure(source, identity, trust))?;
    let mut resources = Vec::new();
    for member in &collection.members {
        let Some(system) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        let Some(system_projection) = member_projection(computer_system_projection(&system))?
        else {
            continue;
        };
        resources.push(system_projection);
        resources.extend(
            read_collection_resources(
                system.processors.as_ref(),
                bmc,
                identity,
                trust,
                processor_projection,
            )
            .await?,
        );
        resources.extend(
            read_collection_resources(
                system.memory.as_ref(),
                bmc,
                identity,
                trust,
                memory_projection,
            )
            .await?,
        );
        resources.extend(
            read_collection_resources(
                system.storage.as_ref(),
                bmc,
                identity,
                trust,
                storage_projection,
            )
            .await?,
        );
    }
    Ok(resources)
}

/// Reads the Chassis collection and, for every decoded Chassis member, its
/// `NetworkAdapters` collection, so the 0.2 network family follows its parent
/// through the same typed navigation.
///
/// A missing Chassis link leaves the whole family absent without an error; a
/// failed Chassis collection document aborts the read with the existing
/// classified error semantics. Only individual members are skippable.
async fn read_chassis_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(chassis) = root.root.chassis.as_ref() else {
        return Ok(Vec::new());
    };
    let collection = chassis
        .get(bmc)
        .await
        .map_err(|source| collection_failure(source, identity, trust))?;
    let mut resources = Vec::new();
    for member in &collection.members {
        let Some(chassis) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        let Some(projection) = member_projection(chassis_projection(&chassis))? else {
            continue;
        };
        resources.push(projection);
        resources.extend(
            read_collection_resources(
                chassis.network_adapters.as_ref(),
                bmc,
                identity,
                trust,
                network_adapter_projection,
            )
            .await?,
        );
    }
    Ok(resources)
}

/// Reads the Managers collection and, for every decoded Manager member, its
/// `EthernetInterfaces` collection, so the 0.2 network family follows its
/// parent through the same typed navigation.
///
/// A missing Managers link leaves the whole family absent without an error; a
/// failed Managers collection document aborts the read with the existing
/// classified error semantics. Only individual members are skippable.
async fn read_manager_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(managers) = root.root.managers.as_ref() else {
        return Ok(Vec::new());
    };
    let collection = managers
        .get(bmc)
        .await
        .map_err(|source| collection_failure(source, identity, trust))?;
    let mut resources = Vec::new();
    for member in &collection.members {
        let Some(manager) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        let Some(projection) = member_projection(manager_projection(&manager))? else {
            continue;
        };
        resources.push(projection);
        resources.extend(
            read_collection_resources(
                manager.ethernet_interfaces.as_ref(),
                bmc,
                identity,
                trust,
                ethernet_interface_projection,
            )
            .await?,
        );
    }
    Ok(resources)
}

/// A decoded Redfish collection schema that exposes its member navigation
/// properties, so members can be fetched individually and one failing member
/// cannot erase its peers.
trait MemberCollection: EntityTypeRef + for<'de> Deserialize<'de> + 'static {
    type Member: EntityTypeRef + for<'de> Deserialize<'de> + 'static;

    fn members(&self) -> &[NavProperty<Self::Member>];
}

impl MemberCollection for ComputerSystemCollectionSchema {
    type Member = ComputerSystemSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for ChassisCollectionSchema {
    type Member = ChassisSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for ManagerCollectionSchema {
    type Member = ManagerSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for ProcessorCollectionSchema {
    type Member = ProcessorSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for MemoryCollectionSchema {
    type Member = MemorySchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for StorageCollectionSchema {
    type Member = StorageSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for NetworkAdapterCollectionSchema {
    type Member = NetworkAdapterSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for EthernetInterfaceCollectionSchema {
    type Member = EthernetInterfaceSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

/// Projects one typed collection with per-member skip semantics.
///
/// A missing link or an empty collection produces no snapshots, because a
/// family the endpoint does not advertise must not be presented as existing.
/// A failed collection document keeps the existing classified read-error
/// semantics, so the refresh Generation stays all-or-nothing.
async fn read_collection_resources<C, M>(
    nav: Option<&NavProperty<C>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    project: impl Fn(&M) -> Result<CoreResourceProjection, CoreResourceReadError>,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError>
where
    C: MemberCollection<Member = M>,
    M: EntityTypeRef + for<'de> Deserialize<'de> + 'static,
{
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let collection = nav
        .get(bmc)
        .await
        .map_err(|source| collection_failure(source, identity, trust))?;
    let mut resources = Vec::new();
    for member in collection.members() {
        let Some(member) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(project(&member))? {
            resources.push(projection);
        }
    }
    Ok(resources)
}

/// Fetches one member through its typed navigation property.
///
/// A member-level failure is endpoint-local and must not erase the readable
/// remainder of its collection (§0.2.0 acceptance), so endpoint-local errors
/// skip the member. TLS-safety errors always abort: a changed or rejected
/// identity is never swallowed by a member-scoped skip.
async fn fetch_member<T>(
    nav: &NavProperty<T>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<Arc<T>>, CoreResourceReadError>
where
    T: EntityTypeRef + for<'de> Deserialize<'de> + 'static,
{
    match nav.get(bmc).await {
        Ok(member) => Ok(Some(member)),
        Err(source) => {
            skip_member_failure(source, identity, trust)?;
            Ok(None)
        }
    }
}

/// Decides whether one member-level fetch failure is skippable.
///
/// Reuses the capability classifier's Ok/Err split: endpoint-local states
/// (unauthorized, permission, schema, availability) leave the member behind,
/// while TLS-safety failures abort the complete read.
fn skip_member_failure(
    source: BmcError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<(), CoreResourceReadError> {
    match classify_capability_error(nv_redfish::Error::Bmc(source), identity, trust) {
        Ok(_) => Ok(()),
        Err(source) => Err(source.into()),
    }
}

/// Resolves one member projection, skipping representation failures.
///
/// A decoded member that cannot be represented (invalid @odata.id or
/// `ETag`, oversized payload) is skipped like an undecodable member: it is
/// one odd member, not an endpoint-wide condition. Transport failures cannot
/// occur inside the synchronous projection and abort defensively.
fn member_projection(
    result: Result<CoreResourceProjection, CoreResourceReadError>,
) -> Result<Option<CoreResourceProjection>, CoreResourceReadError> {
    match result {
        Ok(projection) => Ok(Some(projection)),
        Err(
            CoreResourceReadError::InvalidODataId { .. }
            | CoreResourceReadError::InvalidEtag { .. }
            | CoreResourceReadError::SerializePayload { .. }
            | CoreResourceReadError::InvalidPayload { .. },
        ) => Ok(None),
        Err(source) => Err(source),
    }
}

/// Classifies one collection-document fetch failure as a complete-read error.
///
/// Collection-document failures keep the existing read error semantics (the
/// whole read aborts) instead of the member-skip semantics, because a
/// collection is the unit the read iterates, not a single observation.
fn collection_failure(
    source: BmcError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> CoreResourceReadError {
    classify_service_root_error(nv_redfish::Error::Bmc(source), identity, trust).into()
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
    /// The transport `root` actually reads through: the token Session
    /// transport when one was established, the Basic transport otherwise.
    /// Resource reads navigate through this transport directly, so it must
    /// stay paired with the root that published the decoded links.
    bmc: Arc<UpstreamBmc>,
    session: Option<Session<UpstreamBmc>>,
    session_state: CapabilityState,
}

/// The endpoint-bound Basic transport and credentials used to establish the
/// preferred Session transport, and kept as the fallback when a Session
/// cannot be established.
struct SessionSetup<'a> {
    bmc: Arc<UpstreamBmc>,
    http: NvHttpClient,
    address: &'a EndpointAddress,
    username: &'a CredentialUsername,
    password: &'a SecretString,
}

async fn establish_preferred_authentication(
    root: ServiceRoot<UpstreamBmc>,
    setup: SessionSetup<'_>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<AuthenticatedRoot, RedfishServiceRootError> {
    let SessionSetup {
        bmc,
        http,
        address,
        username,
        password,
    } = setup;
    let service = match root.session_service().await {
        Ok(Some(service)) => service,
        Ok(None) => {
            return Ok(AuthenticatedRoot {
                root,
                bmc,
                session: None,
                session_state: CapabilityState::NotAdvertised,
            });
        }
        Err(source) => {
            let session_state = session_fallback_state(source, identity, trust)?;
            return Ok(AuthenticatedRoot {
                root,
                bmc,
                session: None,
                session_state,
            });
        }
    };
    if matches!(service.raw().service_enabled, Some(Some(false))) {
        return Ok(AuthenticatedRoot {
            root,
            bmc,
            session: None,
            session_state: CapabilityState::TemporarilyUnavailable,
        });
    }
    let sessions = match service.sessions().await {
        Ok(Some(sessions)) => sessions,
        Ok(None) => {
            return Ok(AuthenticatedRoot {
                root,
                bmc,
                session: None,
                session_state: CapabilityState::TemporarilyUnavailable,
            });
        }
        Err(source) => {
            let session_state = session_fallback_state(source, identity, trust)?;
            return Ok(AuthenticatedRoot {
                root,
                bmc,
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
                bmc,
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
            bmc,
            session: None,
            session_state: CapabilityState::SchemaIncompatible,
        });
    };
    let token_bmc = build_bmc(address, http, BmcCredentials::token(token));
    let bmc = Arc::clone(&token_bmc);
    Ok(AuthenticatedRoot {
        root: root.replace_bmc(token_bmc),
        bmc,
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

/// Service metadata and the usable state of every §2.1 standard capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreEndpointDiscovery {
    service_root: ServiceRootSummary,
    capabilities: Vec<EndpointCapabilityObservation>,
}

impl CoreEndpointDiscovery {
    /// Borrows the stable Service Root projection.
    #[must_use]
    pub const fn service_root(&self) -> &ServiceRootSummary {
        &self.service_root
    }

    /// Borrows all capability observations in §2.1 inventory order.
    ///
    /// The vector always carries exactly one observation per compiled standard
    /// feature; [`super::probe_core_capabilities`] constructs it exhaustively
    /// so a future capability cannot silently drop out of discovery.
    #[must_use]
    pub fn capabilities(&self) -> &[EndpointCapabilityObservation] {
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

    /// Builds the common projection from a decoded schema base instead of an
    /// `nv-redfish` wrapper type, because members fetched individually for
    /// per-member skip semantics are raw schemas, not wrappers.
    fn from_schema_base(base: &ResourceSchema) -> Self {
        Self {
            id: base.id.clone(),
            name: base.name.clone(),
            description: base.description.as_ref().and_then(Option::as_ref).cloned(),
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

/// The §0.2.0 `processors` family projection.
///
/// The field set is exactly the `ProcessorPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time.
#[derive(Serialize)]
struct ProcessorPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ProcessorType", skip_serializing_if = "Option::is_none")]
    processor_type: Option<nv_redfish::schema::processor::ProcessorType>,
    #[serde(rename = "Socket", skip_serializing_if = "Option::is_none")]
    socket: Option<String>,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "TotalCores", skip_serializing_if = "Option::is_none")]
    total_cores: Option<i64>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `memory` family projection.
///
/// The field set is exactly the `MemoryPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time.
#[derive(Serialize)]
struct MemoryPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "MemoryDeviceType", skip_serializing_if = "Option::is_none")]
    memory_device_type: Option<nv_redfish::schema::memory::MemoryDeviceType>,
    #[serde(rename = "CapacityMiB", skip_serializing_if = "Option::is_none")]
    capacity_mib: Option<i64>,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `storages` family projection.
///
/// The field set is exactly the `StoragePayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. `ControllerCount` and
/// `DriveCount` are derived from the `StorageControllers` and `Drives`
/// navigations of the typed schema and stay numeric so the console can render
/// counts without re-parsing text.
#[derive(Serialize)]
struct StoragePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ControllerCount", skip_serializing_if = "Option::is_none")]
    controller_count: Option<usize>,
    #[serde(rename = "DriveCount", skip_serializing_if = "Option::is_none")]
    drive_count: Option<usize>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `network-adapters` family projection.
///
/// The field set is exactly the `NetworkAdapterPayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. Only the direct
/// `Manufacturer`, `Model`, and `Status` properties of the adapter resource
/// are projectable; `FirmwareVersion` exists only inside `Controllers[]` and
/// is deliberately not flattened here.
#[derive(Serialize)]
struct NetworkAdapterPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `ethernet-interfaces` family projection.
///
/// The field set is exactly the `EthernetInterfacePayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. Only the direct
/// `MACAddress`, `SpeedMbps`, `InterfaceEnabled`, and `Status` properties are
/// projectable; `SpeedMbps` stays numeric so the console can render the link
/// speed without re-parsing text.
#[derive(Serialize)]
struct EthernetInterfacePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "MACAddress", skip_serializing_if = "Option::is_none")]
    mac_address: Option<String>,
    #[serde(rename = "SpeedMbps", skip_serializing_if = "Option::is_none")]
    speed_mbps: Option<i64>,
    #[serde(rename = "InterfaceEnabled", skip_serializing_if = "Option::is_none")]
    interface_enabled: Option<bool>,
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
        root.odata_id(),
        root.root.etag(),
        &payload,
    )
}

fn computer_system_projection(
    system: &ComputerSystemSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ComputerSystemPayload {
        resource: CommonResourcePayload::from_schema_base(&system.base),
        system_type: system.system_type,
        manufacturer: optional_nullable_text(system.manufacturer.as_ref()),
        model: optional_nullable_text(system.model.as_ref()),
        part_number: optional_nullable_text(system.part_number.as_ref()),
        serial_number: optional_nullable_text(system.serial_number.as_ref()),
        sku: optional_nullable_text(system.sku.as_ref()),
        host_name: optional_nullable_text(system.host_name.as_ref()),
        bios_version: optional_nullable_text(system.bios_version.as_ref()),
        power_state: system.power_state.as_ref().copied().flatten(),
        status: system
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Systems,
        system.odata_id(),
        system.etag(),
        &payload,
    )
}

fn chassis_projection(
    chassis: &ChassisSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ChassisPayload {
        resource: CommonResourcePayload::from_schema_base(&chassis.base),
        chassis_type: chassis.chassis_type,
        manufacturer: optional_nullable_text(chassis.manufacturer.as_ref()),
        model: optional_nullable_text(chassis.model.as_ref()),
        part_number: optional_nullable_text(chassis.part_number.as_ref()),
        serial_number: optional_nullable_text(chassis.serial_number.as_ref()),
        sku: optional_nullable_text(chassis.sku.as_ref()),
        asset_tag: optional_nullable_text(chassis.asset_tag.as_ref()),
        power_state: chassis.power_state.as_ref().copied().flatten(),
        status: chassis
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Chassis,
        chassis.odata_id(),
        chassis.etag(),
        &payload,
    )
}

fn manager_projection(
    manager: &ManagerSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ManagerPayload {
        resource: CommonResourcePayload::from_schema_base(&manager.base),
        manager_type: manager.manager_type,
        manufacturer: optional_nullable_text(manager.manufacturer.as_ref()),
        model: optional_nullable_text(manager.model.as_ref()),
        part_number: optional_nullable_text(manager.part_number.as_ref()),
        serial_number: optional_nullable_text(manager.serial_number.as_ref()),
        firmware_version: optional_nullable_text(manager.firmware_version.as_ref()),
        version: optional_nullable_text(manager.version.as_ref()),
        power_state: manager.power_state.as_ref().copied().flatten(),
        status: manager
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Managers,
        manager.odata_id(),
        manager.etag(),
        &payload,
    )
}

fn processor_projection(
    processor: &ProcessorSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ProcessorPayload {
        resource: CommonResourcePayload::from_schema_base(&processor.base),
        processor_type: processor.processor_type.as_ref().copied().flatten(),
        socket: optional_nullable_text(processor.socket.as_ref()),
        manufacturer: optional_nullable_text(processor.manufacturer.as_ref()),
        model: optional_nullable_text(processor.model.as_ref()),
        total_cores: processor.total_cores.as_ref().copied().flatten(),
        status: processor
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Processors,
        processor.odata_id(),
        processor.etag(),
        &payload,
    )
}

fn memory_projection(
    memory: &MemorySchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = MemoryPayload {
        resource: CommonResourcePayload::from_schema_base(&memory.base),
        memory_device_type: memory.memory_device_type.as_ref().copied().flatten(),
        capacity_mib: memory.capacity_mi_b.as_ref().copied().flatten(),
        manufacturer: optional_nullable_text(memory.manufacturer.as_ref()),
        model: optional_nullable_text(memory.model.as_ref()),
        status: memory
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Memory,
        memory.odata_id(),
        memory.etag(),
        &payload,
    )
}

fn storage_projection(
    storage: &StorageSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = StoragePayload {
        resource: CommonResourcePayload::from_schema_base(&storage.base),
        controller_count: storage.storage_controllers.as_ref().map(Vec::len),
        drive_count: storage.drives.as_ref().map(Vec::len),
        status: storage
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Storages,
        storage.odata_id(),
        storage.etag(),
        &payload,
    )
}

fn network_adapter_projection(
    adapter: &NetworkAdapterSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NetworkAdapterPayload {
        resource: CommonResourcePayload::from_schema_base(&adapter.base),
        manufacturer: optional_nullable_text(adapter.manufacturer.as_ref()),
        model: optional_nullable_text(adapter.model.as_ref()),
        status: adapter
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::NetworkAdapters,
        adapter.odata_id(),
        adapter.etag(),
        &payload,
    )
}

fn ethernet_interface_projection(
    interface: &EthernetInterfaceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = EthernetInterfacePayload {
        resource: CommonResourcePayload::from_schema_base(&interface.base),
        mac_address: optional_nullable_text(interface.mac_address.as_ref()),
        speed_mbps: interface.speed_mbps.as_ref().copied().flatten(),
        interface_enabled: interface.interface_enabled.as_ref().copied().flatten(),
        status: interface
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::EthernetInterfaces,
        interface.odata_id(),
        interface.etag(),
        &payload,
    )
}

fn optional_nullable_text(value: Option<&Option<String>>) -> Option<String> {
    value.and_then(Option::as_ref).cloned()
}

fn build_core_projection(
    feature: ResourceFeature,
    odata_id: &nv_redfish::core::ODataId,
    etag: Option<&nv_redfish::core::ODataETag>,
    payload: &impl Serialize,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let odata_id = ResourceODataId::parse(&odata_id.to_string())
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
    match result {
        Ok(Some(_)) => Ok(CapabilityState::Supported),
        Ok(None) => Ok(CapabilityState::NotAdvertised),
        Err(source) => classify_capability_error(source, identity, trust),
    }
}

/// Classifies one typed navigation failure into a capability state.
///
/// TLS-safety failures stay hard errors so a capability probe can never paper
/// over a changed identity; everything else becomes the state the capability
/// ledger persists.
fn classify_capability_error(
    source: UpstreamServiceRootError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CapabilityState, RedfishServiceRootError> {
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

/// One probed collection: its own capability state plus the typed members
/// that carry the member-scoped feature probes.
struct ProbedCollection<Member> {
    state: CapabilityState,
    members: Option<Vec<Member>>,
    nested_state: CapabilityState,
}

/// Access to the typed members of one `nv-redfish` collection wrapper.
trait CollectionMembers {
    type Member;

    async fn fetch_members(&self) -> Result<Vec<Self::Member>, UpstreamServiceRootError>;
}

impl CollectionMembers for SystemCollection<UpstreamBmc> {
    type Member = ComputerSystem<UpstreamBmc>;

    async fn fetch_members(&self) -> Result<Vec<Self::Member>, UpstreamServiceRootError> {
        self.members().await
    }
}

impl CollectionMembers for ChassisCollection<UpstreamBmc> {
    type Member = Chassis<UpstreamBmc>;

    async fn fetch_members(&self) -> Result<Vec<Self::Member>, UpstreamServiceRootError> {
        self.members().await
    }
}

impl CollectionMembers for ManagerCollection<UpstreamBmc> {
    type Member = Manager<UpstreamBmc>;

    async fn fetch_members(&self) -> Result<Vec<Self::Member>, UpstreamServiceRootError> {
        self.members().await
    }
}

/// Fetches one typed collection once and retains its members for the nested
/// capability probes, so member-scoped links are discovered through decoded
/// members instead of guessed paths.
///
/// When the collection is advertised but its members cannot be fetched, the
/// member-scoped features inherit the classified member failure: they are
/// observable in principle, so `NotAdvertised` would be a guess.
async fn probe_collection<C: CollectionMembers>(
    result: Result<Option<C>, UpstreamServiceRootError>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<ProbedCollection<C::Member>, RedfishServiceRootError> {
    let (state, collection) = match result {
        Ok(Some(collection)) => (CapabilityState::Supported, Some(collection)),
        Ok(None) => (CapabilityState::NotAdvertised, None),
        Err(source) => {
            let state = classify_capability_error(source, identity, trust)?;
            return Ok(ProbedCollection {
                state,
                members: None,
                nested_state: state,
            });
        }
    };
    let Some(collection) = collection else {
        return Ok(ProbedCollection {
            state,
            members: None,
            nested_state: state,
        });
    };
    match collection.fetch_members().await {
        Ok(members) => Ok(ProbedCollection {
            state,
            members: Some(members),
            nested_state: CapabilityState::NotAdvertised,
        }),
        Err(source) => {
            let nested_state = classify_capability_error(source, identity, trust)?;
            Ok(ProbedCollection {
                state,
                members: None,
                nested_state,
            })
        }
    }
}

/// Probes one member-scoped feature through every decoded member of a
/// collection.
///
/// The first observation that is not `NotAdvertised` decides the endpoint
/// state: advertisement is an endpoint-level property, so later members cannot
/// change it, and stopping early keeps the probe bounded on dense services.
async fn probe_nested<T, U>(
    collection: &ProbedCollection<T>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    accessor: impl for<'a> Fn(
        &'a T,
    ) -> Pin<
        Box<dyn Future<Output = Result<Option<U>, UpstreamServiceRootError>> + Send + 'a>,
    >,
) -> Result<CapabilityState, RedfishServiceRootError> {
    let Some(members) = &collection.members else {
        return Ok(collection.nested_state);
    };
    for member in members {
        let observed = classify_capability_probe(accessor(member).await, identity, trust)?;
        if observed != CapabilityState::NotAdvertised {
            return Ok(observed);
        }
    }
    Ok(CapabilityState::NotAdvertised)
}

/// Probes a member-scoped feature that has no `nv-redfish` fetch accessor by
/// inspecting the typed navigation field of every decoded member.
///
/// The schema already decoded together with the member, so a present link is
/// `Supported` and a missing link is `NotAdvertised` without an extra request;
/// a decode failure cannot occur here because it would have failed the member
/// fetch itself.
fn probe_nested_presence<T>(
    collection: &ProbedCollection<T>,
    advertised: impl Fn(&T) -> bool,
) -> CapabilityState {
    match &collection.members {
        Some(members) if members.iter().any(advertised) => CapabilityState::Supported,
        Some(_) => CapabilityState::NotAdvertised,
        None => collection.nested_state,
    }
}

/// Probes the power-supplies capability through the modern `PowerSubsystem`
/// surface.
///
/// The `nv-redfish` accessor returns an empty vector both when the
/// `PowerSubsystem` link is missing and when no supply exists, so the typed
/// link is checked first to keep `NotAdvertised` distinguishable from a
/// decoded-but-empty subsystem.
async fn probe_power_supplies(
    collection: &ProbedCollection<Chassis<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CapabilityState, RedfishServiceRootError> {
    let Some(members) = &collection.members else {
        return Ok(collection.nested_state);
    };
    for chassis in members {
        if chassis.raw().power_subsystem.is_none() {
            continue;
        }
        return classify_capability_probe(
            chassis.power_supplies().await.map(Some),
            identity,
            trust,
        );
    }
    Ok(CapabilityState::NotAdvertised)
}

/// Probes the Chassis network-adapters collection and retains the decoded
/// adapters, because the network-device-functions capability lives one level
/// deeper on those adapters and re-fetching them would double the probe.
async fn probe_network_adapters(
    collection: &ProbedCollection<Chassis<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<(CapabilityState, Option<Vec<NetworkAdapter<UpstreamBmc>>>), RedfishServiceRootError> {
    let Some(members) = &collection.members else {
        return Ok((collection.nested_state, None));
    };
    for chassis in members {
        match chassis.network_adapters().await {
            Ok(Some(adapters)) => return Ok((CapabilityState::Supported, Some(adapters))),
            Ok(None) => {}
            Err(source) => {
                let state = classify_capability_error(source, identity, trust)?;
                return Ok((state, None));
            }
        }
    }
    Ok((CapabilityState::NotAdvertised, None))
}

/// Probes network-device-functions through the adapters already fetched by
/// [`probe_network_adapters`].
async fn probe_adapter_functions(
    adapters: &[NetworkAdapter<UpstreamBmc>],
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CapabilityState, RedfishServiceRootError> {
    for adapter in adapters {
        let observed =
            classify_capability_probe(adapter.network_device_functions().await, identity, trust)?;
        if observed != CapabilityState::NotAdvertised {
            return Ok(observed);
        }
    }
    Ok(CapabilityState::NotAdvertised)
}

/// The observed states of the services linked directly from the Service Root.
struct RootServiceProbe {
    accounts: CapabilityState,
    event_service: CapabilityState,
    task_service: CapabilityState,
    telemetry_service: CapabilityState,
    update_service: CapabilityState,
    power_equipment: CapabilityState,
}

/// The observed states of the features carried by `ComputerSystem` members.
struct SystemFeatureProbe {
    bios: CapabilityState,
    boot_options: CapabilityState,
    secure_boot: CapabilityState,
    processors: CapabilityState,
    memory: CapabilityState,
    storages: CapabilityState,
    pcie_devices: CapabilityState,
}

/// The observed states of the features carried by `Chassis` members.
struct ChassisFeatureProbe {
    assembly: CapabilityState,
    power: CapabilityState,
    thermal: CapabilityState,
    sensors: CapabilityState,
    controls: CapabilityState,
    power_supplies: CapabilityState,
    network_adapters: CapabilityState,
    network_device_functions: CapabilityState,
    environment_metrics: CapabilityState,
}

/// The observed states of the features carried by `Manager` members.
struct ManagerFeatureProbe {
    ethernet_interfaces: CapabilityState,
    host_interfaces: CapabilityState,
    manager_network_protocol: CapabilityState,
    log_services: CapabilityState,
}

/// Every probed state grouped by origin, so the §2.1 observation vector can
/// be assembled exhaustively without a 30-field hand-written tuple.
struct CapabilityObservations {
    session: CapabilityState,
    systems: CapabilityState,
    chassis: CapabilityState,
    managers: CapabilityState,
    root: RootServiceProbe,
    systems_features: SystemFeatureProbe,
    chassis_features: ChassisFeatureProbe,
    manager_features: ManagerFeatureProbe,
}

async fn probe_root_services(
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<RootServiceProbe, RedfishServiceRootError> {
    Ok(RootServiceProbe {
        accounts: classify_capability_probe(root.account_service().await, identity, trust)?,
        event_service: classify_capability_probe(root.event_service().await, identity, trust)?,
        task_service: classify_capability_probe(root.task_service().await, identity, trust)?,
        telemetry_service: classify_capability_probe(
            root.telemetry_service().await,
            identity,
            trust,
        )?,
        update_service: classify_capability_probe(root.update_service().await, identity, trust)?,
        power_equipment: classify_capability_probe(root.power_equipment().await, identity, trust)?,
    })
}

async fn probe_system_features(
    systems: &ProbedCollection<ComputerSystem<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<SystemFeatureProbe, RedfishServiceRootError> {
    Ok(SystemFeatureProbe {
        bios: probe_nested(systems, identity, trust, |system| Box::pin(system.bios())).await?,
        boot_options: probe_nested(systems, identity, trust, |system| {
            Box::pin(system.boot_options())
        })
        .await?,
        secure_boot: probe_nested(systems, identity, trust, |system| {
            Box::pin(system.secure_boot())
        })
        .await?,
        processors: probe_nested(systems, identity, trust, |system| {
            Box::pin(system.processors())
        })
        .await?,
        memory: probe_nested(systems, identity, trust, |system| {
            Box::pin(system.memory_modules())
        })
        .await?,
        storages: probe_nested(systems, identity, trust, |system| {
            Box::pin(system.storage_controllers())
        })
        .await?,
        pcie_devices: probe_nested_presence(systems, |system| system.raw().pcie_devices.is_some()),
    })
}

async fn probe_chassis_features(
    chassis: &ProbedCollection<Chassis<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<ChassisFeatureProbe, RedfishServiceRootError> {
    let (network_adapters, adapter_members) =
        probe_network_adapters(chassis, identity, trust).await?;
    let network_device_functions = match &adapter_members {
        Some(adapters) => probe_adapter_functions(adapters, identity, trust).await?,
        None => network_adapters,
    };
    Ok(ChassisFeatureProbe {
        assembly: probe_nested(chassis, identity, trust, |chassis| {
            Box::pin(chassis.assembly())
        })
        .await?,
        power: probe_nested(chassis, identity, trust, |chassis| {
            Box::pin(chassis.power())
        })
        .await?,
        thermal: probe_nested(chassis, identity, trust, |chassis| {
            Box::pin(chassis.thermal())
        })
        .await?,
        sensors: probe_nested(chassis, identity, trust, |chassis| {
            Box::pin(chassis.sensor_links())
        })
        .await?,
        controls: probe_nested(chassis, identity, trust, |chassis| {
            Box::pin(chassis.controls())
        })
        .await?,
        power_supplies: probe_power_supplies(chassis, identity, trust).await?,
        network_adapters,
        network_device_functions,
        environment_metrics: probe_nested_presence(chassis, |chassis| {
            chassis.raw().environment_metrics.is_some()
        }),
    })
}

async fn probe_manager_features(
    managers: &ProbedCollection<Manager<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<ManagerFeatureProbe, RedfishServiceRootError> {
    Ok(ManagerFeatureProbe {
        ethernet_interfaces: probe_nested(managers, identity, trust, |manager| {
            Box::pin(manager.ethernet_interfaces())
        })
        .await?,
        host_interfaces: probe_nested(managers, identity, trust, |manager| {
            Box::pin(manager.host_interfaces())
        })
        .await?,
        manager_network_protocol: probe_nested(managers, identity, trust, |manager| {
            Box::pin(manager.network_protocol())
        })
        .await?,
        log_services: probe_nested(managers, identity, trust, |manager| {
            Box::pin(manager.log_services())
        })
        .await?,
    })
}

/// Assembles the §2.1 inventory in design-document order.
///
/// Every field of [`CapabilityObservations`] maps to exactly one entry, so a
/// future capability cannot silently drop out of discovery.
fn build_observations(states: CapabilityObservations) -> Vec<EndpointCapabilityObservation> {
    let CapabilityObservations {
        session,
        systems,
        chassis,
        managers,
        root,
        systems_features,
        chassis_features,
        manager_features,
    } = states;
    vec![
        EndpointCapabilityObservation::new(EndpointCapability::Accounts, root.accounts),
        EndpointCapabilityObservation::new(EndpointCapability::Assembly, chassis_features.assembly),
        EndpointCapabilityObservation::new(EndpointCapability::Bios, systems_features.bios),
        EndpointCapabilityObservation::new(
            EndpointCapability::BootOptions,
            systems_features.boot_options,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::Chassis, chassis),
        EndpointCapabilityObservation::new(EndpointCapability::Systems, systems),
        EndpointCapabilityObservation::new(EndpointCapability::Controls, chassis_features.controls),
        EndpointCapabilityObservation::new(
            EndpointCapability::EnvironmentMetrics,
            chassis_features.environment_metrics,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::EthernetInterfaces,
            manager_features.ethernet_interfaces,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::EventService, root.event_service),
        EndpointCapabilityObservation::new(
            EndpointCapability::HostInterfaces,
            manager_features.host_interfaces,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::LogServices,
            manager_features.log_services,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::ManagerNetworkProtocol,
            manager_features.manager_network_protocol,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::Managers, managers),
        EndpointCapabilityObservation::new(EndpointCapability::Memory, systems_features.memory),
        EndpointCapabilityObservation::new(
            EndpointCapability::NetworkAdapters,
            chassis_features.network_adapters,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::NetworkDeviceFunctions,
            chassis_features.network_device_functions,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::PcieDevices,
            systems_features.pcie_devices,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::Power, chassis_features.power),
        EndpointCapabilityObservation::new(
            EndpointCapability::PowerEquipment,
            root.power_equipment,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::PowerSupplies,
            chassis_features.power_supplies,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::Processors,
            systems_features.processors,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::SecureBoot,
            systems_features.secure_boot,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::Sensors, chassis_features.sensors),
        EndpointCapabilityObservation::new(EndpointCapability::SessionService, session),
        EndpointCapabilityObservation::new(EndpointCapability::Storages, systems_features.storages),
        EndpointCapabilityObservation::new(EndpointCapability::TaskService, root.task_service),
        EndpointCapabilityObservation::new(
            EndpointCapability::TelemetryService,
            root.telemetry_service,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::Thermal, chassis_features.thermal),
        EndpointCapabilityObservation::new(EndpointCapability::UpdateService, root.update_service),
    ]
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

    /// A System member that advertises the 0.2 Processors and Memory
    /// collections, so the resource read can navigate into both families.
    const SYSTEM_WITH_COMPONENTS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "Description":"Primary compute system",
        "SystemType":"Physical",
        "Manufacturer":"Rutilus Test",
        "Model":"Model S",
        "Processors":{"@odata.id":"/redfish/v1/Systems/1/Processors"},
        "Memory":{"@odata.id":"/redfish/v1/Systems/1/Memory"}
    }"#;

    const SYSTEMS_WITH_TWO_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",
        "@odata.id":"/redfish/v1/Systems",
        "Name":"Computer System Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Systems/1"},
            {"@odata.id":"/redfish/v1/Systems/2"}
        ]
    }"##;

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

    const FULL_SERVICE_ROOT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/",
        "Id":"RootService",
        "Name":"Root Service",
        "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
        "RedfishVersion":"1.20.0",
        "Vendor":"Rutilus Test",
        "Product":"Fixture BMC",
        "SessionService":{"@odata.id":"/redfish/v1/SessionService"},
        "Systems":{"@odata.id":"/redfish/v1/Systems"},
        "Chassis":{"@odata.id":"/redfish/v1/Chassis"},
        "Managers":{"@odata.id":"/redfish/v1/Managers"},
        "AccountService":{"@odata.id":"/redfish/v1/AccountService"},
        "Tasks":{"@odata.id":"/redfish/v1/TaskService"},
        "EventService":{"@odata.id":"/redfish/v1/EventService"},
        "TelemetryService":{"@odata.id":"/redfish/v1/TelemetryService"},
        "UpdateService":{"@odata.id":"/redfish/v1/UpdateService"},
        "PowerEquipment":{"@odata.id":"/redfish/v1/PowerEquipment"}
    }"#;

    const FULL_SYSTEMS_BODY: &str = r##"{
        "@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",
        "@odata.id":"/redfish/v1/Systems",
        "Name":"Computer System Collection",
        "Members":[{"@odata.id":"/redfish/v1/Systems/1"}]
    }"##;

    const FULL_SYSTEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Bios":{"@odata.id":"/redfish/v1/Systems/1/Bios"},
        "Boot":{"BootOptions":{"@odata.id":"/redfish/v1/Systems/1/BootOptions"}},
        "SecureBoot":{"@odata.id":"/redfish/v1/Systems/1/SecureBoot"},
        "Processors":{"@odata.id":"/redfish/v1/Systems/1/Processors"},
        "Memory":{"@odata.id":"/redfish/v1/Systems/1/Memory"},
        "Storage":{"@odata.id":"/redfish/v1/Systems/1/Storage"},
        "PCIeDevices":[{"@odata.id":"/redfish/v1/Systems/1/PCIeDevices/1"}]
    }"#;

    const FULL_CHASSIS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Assembly":{"@odata.id":"/redfish/v1/Chassis/1/Assembly"},
        "Power":{"@odata.id":"/redfish/v1/Chassis/1/Power"},
        "Thermal":{"@odata.id":"/redfish/v1/Chassis/1/Thermal"},
        "Sensors":{"@odata.id":"/redfish/v1/Chassis/1/Sensors"},
        "Controls":{"@odata.id":"/redfish/v1/Chassis/1/Controls"},
        "PowerSubsystem":{"@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem"},
        "NetworkAdapters":{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters"},
        "EnvironmentMetrics":{"@odata.id":"/redfish/v1/Chassis/1/EnvironmentMetrics"}
    }"#;

    const FULL_MANAGER_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "EthernetInterfaces":{"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces"},
        "HostInterfaces":{"@odata.id":"/redfish/v1/Managers/1/HostInterfaces"},
        "NetworkProtocol":{"@odata.id":"/redfish/v1/Managers/1/NetworkProtocol"},
        "LogServices":{"@odata.id":"/redfish/v1/Managers/1/LogServices"}
    }"#;

    const ACCOUNT_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/AccountService",
        "Id":"AccountService",
        "Name":"Account Service"
    }"#;

    const EVENT_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/EventService",
        "Id":"EventService",
        "Name":"Event Service"
    }"#;

    const TASK_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/TaskService",
        "Id":"TaskService",
        "Name":"Task Service",
        "Tasks":{"@odata.id":"/redfish/v1/TaskService/Tasks"}
    }"#;

    const TELEMETRY_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/TelemetryService",
        "Id":"TelemetryService",
        "Name":"Telemetry Service"
    }"#;

    const UPDATE_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/UpdateService",
        "Id":"UpdateService",
        "Name":"Update Service"
    }"#;

    const POWER_EQUIPMENT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/PowerEquipment",
        "Id":"PowerEquipment",
        "Name":"Power Equipment"
    }"#;

    const BIOS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Bios",
        "Id":"Bios",
        "Name":"BIOS"
    }"#;

    const BOOT_OPTIONS_BODY: &str = r##"{
        "@odata.type":"#BootOptionCollection.BootOptionCollection",
        "@odata.id":"/redfish/v1/Systems/1/BootOptions",
        "Name":"Boot Option Collection",
        "Members":[]
    }"##;

    const SECURE_BOOT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/SecureBoot",
        "Id":"SecureBoot",
        "Name":"Secure Boot"
    }"#;

    const PROCESSORS_BODY: &str = r##"{
        "@odata.type":"#ProcessorCollection.ProcessorCollection",
        "@odata.id":"/redfish/v1/Systems/1/Processors",
        "Name":"Processor Collection",
        "Members":[]
    }"##;

    const PROCESSORS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#ProcessorCollection.ProcessorCollection",
        "@odata.id":"/redfish/v1/Systems/1/Processors",
        "Name":"Processor Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Systems/1/Processors/CPU1"},
            {"@odata.id":"/redfish/v1/Systems/1/Processors/CPU2"}
        ]
    }"##;

    const PROCESSOR_ONE_BODY: &str = r##"{
        "@odata.type":"#Processor.v1_15_0.Processor",
        "@odata.id":"/redfish/v1/Systems/1/Processors/CPU1",
        "@odata.etag":"W/\"cpu-1\"",
        "Id":"CPU1",
        "Name":"Processor One",
        "Description":"Primary compute processor",
        "ProcessorType":"CPU",
        "Socket":"LGA4189",
        "Manufacturer":"Rutilus Test",
        "Model":"Model P",
        "TotalCores":64,
        "TotalThreads":128,
        "MaxSpeedMHz":3200,
        "PartNumber":"CPU-PART-1",
        "SerialNumber":"CPU-1",
        "Version":"3.0.0",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    const PROCESSOR_TWO_BODY: &str = r##"{
        "@odata.type":"#Processor.v1_15_0.Processor",
        "@odata.id":"/redfish/v1/Systems/1/Processors/CPU2",
        "@odata.etag":"W/\"cpu-2\"",
        "Id":"CPU2",
        "Name":"Processor Two",
        "ProcessorType":"CPU",
        "Socket":"LGA4189",
        "Manufacturer":"Rutilus Test",
        "Model":"Model P2",
        "TotalCores":32,
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    const MEMORY_BODY: &str = r##"{
        "@odata.type":"#MemoryCollection.MemoryCollection",
        "@odata.id":"/redfish/v1/Systems/1/Memory",
        "Name":"Memory Collection",
        "Members":[]
    }"##;

    const MEMORY_WITH_MEMBER_BODY: &str = r##"{
        "@odata.type":"#MemoryCollection.MemoryCollection",
        "@odata.id":"/redfish/v1/Systems/1/Memory",
        "Name":"Memory Collection",
        "Members":[{"@odata.id":"/redfish/v1/Systems/1/Memory/DIMM1"}]
    }"##;

    const MEMORY_DIMM_ONE_BODY: &str = r##"{
        "@odata.type":"#Memory.v1_17_0.Memory",
        "@odata.id":"/redfish/v1/Systems/1/Memory/DIMM1",
        "@odata.etag":"W/\"dimm-1\"",
        "Id":"DIMM1",
        "Name":"Memory Module One",
        "Description":"Main memory module",
        "MemoryType":"DRAM",
        "MemoryDeviceType":"DDR4",
        "CapacityMiB":32768,
        "DataWidthBits":64,
        "BusWidthBits":72,
        "Manufacturer":"Rutilus Test",
        "Model":"Model MEM",
        "PartNumber":"MEM-PART-1",
        "SerialNumber":"MEM-1",
        "DeviceLocator":"A1",
        "RankCount":2,
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    const STORAGE_BODY: &str = r##"{
        "@odata.type":"#StorageCollection.StorageCollection",
        "@odata.id":"/redfish/v1/Systems/1/Storage",
        "Name":"Storage Collection",
        "Members":[]
    }"##;

    /// A System member that advertises only the 0.2 Storage family, so the
    /// family read tests exercise one navigation per parent instead of the
    /// combined Processors/Memory fixture.
    const SYSTEM_WITH_STORAGE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "Description":"Primary compute system",
        "SystemType":"Physical",
        "Manufacturer":"Rutilus Test",
        "Model":"Model S",
        "Storage":{"@odata.id":"/redfish/v1/Systems/1/Storage"}
    }"#;

    const STORAGE_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#StorageCollection.StorageCollection",
        "@odata.id":"/redfish/v1/Systems/1/Storage",
        "Name":"Storage Collection",
        "Members":[{"@odata.id":"/redfish/v1/Systems/1/Storage/1"}]
    }"##;

    const STORAGE_WITH_TWO_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#StorageCollection.StorageCollection",
        "@odata.id":"/redfish/v1/Systems/1/Storage",
        "Name":"Storage Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Systems/1/Storage/1"},
            {"@odata.id":"/redfish/v1/Systems/1/Storage/2"}
        ]
    }"##;

    /// The Storage member projection carries only the two collection counts
    /// and the status; the drives and controllers are counted from the typed
    /// navigation arrays without fetching them.
    const STORAGE_SUBSYSTEM_BODY: &str = r##"{
        "@odata.type":"#Storage.v1_17_0.Storage",
        "@odata.id":"/redfish/v1/Systems/1/Storage/1",
        "@odata.etag":"W/\"storage-1\"",
        "Id":"1",
        "Name":"Storage Subsystem One",
        "Description":"Primary storage subsystem",
        "StorageControllers":[
            {"@odata.id":"/redfish/v1/Systems/1/Storage/1/Controllers/0"},
            {"@odata.id":"/redfish/v1/Systems/1/Storage/1/Controllers/1"}
        ],
        "Drives":[
            {"@odata.id":"/redfish/v1/Systems/1/Storage/1/Drives/0"},
            {"@odata.id":"/redfish/v1/Systems/1/Storage/1/Drives/1"}
        ],
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A Chassis member that advertises the 0.2 `NetworkAdapters` family.
    const CHASSIS_WITH_NETWORK_ADAPTERS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "@odata.etag":"W/\"chassis-1\"",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "NetworkAdapters":{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters"}
    }"#;

    /// The full `NetworkAdapter` member projection the family read asserts,
    /// with every optional inventory field the schema carries populated.
    const NETWORK_ADAPTER_FULL_BODY: &str = r##"{
        "@odata.type":"#NetworkAdapter.v1_11_0.NetworkAdapter",
        "@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1",
        "@odata.etag":"W/\"nic-1\"",
        "Id":"1",
        "Name":"Adapter One",
        "Description":"Primary network adapter",
        "Manufacturer":"Rutilus Test",
        "Model":"Model NIC",
        "PartNumber":"NIC-PART-1",
        "SerialNumber":"NIC-1",
        "SKU":"NIC-SKU-1",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A Manager member that advertises the 0.2 `EthernetInterfaces` family.
    const MANAGER_WITH_ETHERNET_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "EthernetInterfaces":{"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces"}
    }"#;

    const ETHERNET_INTERFACES_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#EthernetInterfaceCollection.EthernetInterfaceCollection",
        "@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces",
        "Name":"Ethernet Interface Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/1"},
            {"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/2"}
        ]
    }"##;

    /// The full `EthernetInterface` member projection with every optional
    /// field the schema carries populated.
    const ETHERNET_INTERFACE_ONE_BODY: &str = r##"{
        "@odata.type":"#EthernetInterface.v1_6_0.EthernetInterface",
        "@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/1",
        "@odata.etag":"W/\"eth-1\"",
        "Id":"1",
        "Name":"Ethernet Interface One",
        "Description":"Management network interface",
        "InterfaceEnabled":true,
        "PermanentMACAddress":"AA:BB:CC:DD:EE:01",
        "MACAddress":"AA:BB:CC:DD:EE:01",
        "SpeedMbps":1000,
        "MTUSize":1500,
        "HostName":"bmc-mgmt",
        "FQDN":"bmc-mgmt.example.test",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A minimal `EthernetInterface` member: absent optional fields must be
    /// omitted from the projection, never emitted as null.
    const ETHERNET_INTERFACE_TWO_BODY: &str = r##"{
        "@odata.type":"#EthernetInterface.v1_6_0.EthernetInterface",
        "@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/2",
        "@odata.etag":"W/\"eth-2\"",
        "Id":"2",
        "Name":"Ethernet Interface Two",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    const ASSEMBLY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1/Assembly",
        "Id":"Assembly",
        "Name":"Assembly"
    }"#;

    const POWER_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1/Power",
        "Id":"Power",
        "Name":"Power"
    }"#;

    const THERMAL_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1/Thermal",
        "Id":"Thermal",
        "Name":"Thermal"
    }"#;

    const SENSORS_BODY: &str = r##"{
        "@odata.type":"#SensorCollection.SensorCollection",
        "@odata.id":"/redfish/v1/Chassis/1/Sensors",
        "Name":"Sensor Collection",
        "Members":[]
    }"##;

    const CONTROLS_BODY: &str = r##"{
        "@odata.type":"#ControlCollection.ControlCollection",
        "@odata.id":"/redfish/v1/Chassis/1/Controls",
        "Name":"Control Collection",
        "Members":[]
    }"##;

    const POWER_SUBSYSTEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem",
        "Id":"PowerSubsystem",
        "Name":"Power Subsystem",
        "PowerSupplies":{"@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies"}
    }"#;

    const POWER_SUPPLIES_BODY: &str = r##"{
        "@odata.type":"#PowerSupplyCollection.PowerSupplyCollection",
        "@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies",
        "Name":"Power Supply Collection",
        "Members":[]
    }"##;

    const NETWORK_ADAPTERS_BODY: &str = r##"{
        "@odata.type":"#NetworkAdapterCollection.NetworkAdapterCollection",
        "@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters",
        "Name":"Network Adapter Collection",
        "Members":[{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1"}]
    }"##;

    const NETWORK_ADAPTER_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1",
        "Id":"1",
        "Name":"Adapter One",
        "NetworkDeviceFunctions":{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions"}
    }"#;

    const NETWORK_DEVICE_FUNCTIONS_BODY: &str = r##"{
        "@odata.type":"#NetworkDeviceFunctionCollection.NetworkDeviceFunctionCollection",
        "@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions",
        "Name":"Network Device Function Collection",
        "Members":[]
    }"##;

    const ETHERNET_INTERFACES_BODY: &str = r##"{
        "@odata.type":"#EthernetInterfaceCollection.EthernetInterfaceCollection",
        "@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces",
        "Name":"Ethernet Interface Collection",
        "Members":[]
    }"##;

    const HOST_INTERFACES_BODY: &str = r##"{
        "@odata.type":"#HostInterfaceCollection.HostInterfaceCollection",
        "@odata.id":"/redfish/v1/Managers/1/HostInterfaces",
        "Name":"Host Interface Collection",
        "Members":[]
    }"##;

    const NETWORK_PROTOCOL_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/NetworkProtocol",
        "Id":"NetworkProtocol",
        "Name":"Manager Network Protocol"
    }"#;

    const LOG_SERVICES_BODY: &str = r##"{
        "@odata.type":"#LogServiceCollection.LogServiceCollection",
        "@odata.id":"/redfish/v1/Managers/1/LogServices",
        "Name":"Log Service Collection",
        "Members":[]
    }"##;

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

    const FAILED_RESOURCE_AND_CLEANUP_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
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

    /// The request order for one System member that carries populated
    /// Processors and Memory collections: the families are read right after
    /// their parent, before the sibling collections.
    const CORE_RESOURCE_WITH_COMPONENTS_REQUEST_PATHS: [&str; 16] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Processors",
        "/redfish/v1/Systems/1/Processors/CPU1",
        "/redfish/v1/Systems/1/Processors/CPU2",
        "/redfish/v1/Systems/1/Memory",
        "/redfish/v1/Systems/1/Memory/DIMM1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when both component collections are advertised but
    /// empty: the collection documents are still read, no member is.
    const EMPTY_COMPONENT_REQUEST_PATHS: [&str; 13] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Processors",
        "/redfish/v1/Systems/1/Memory",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when members fail at every level: the failing
    /// member URIs are still requested (that is how the skip is observed),
    /// then the next member or collection is attempted.
    const MEMBER_SKIP_REQUEST_PATHS: [&str; 17] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Processors",
        "/redfish/v1/Systems/1/Processors/CPU1",
        "/redfish/v1/Systems/1/Processors/CPU2",
        "/redfish/v1/Systems/1/Memory",
        "/redfish/v1/Systems/1/Memory/DIMM1",
        "/redfish/v1/Systems/2",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one member per core collection when every 0.2
    /// family is populated: Storage follows its System member, `NetworkAdapters`
    /// follows its Chassis member, `EthernetInterfaces` follows its Manager
    /// member.
    const FAMILY_RESOURCE_REQUEST_PATHS: [&str; 18] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Storage",
        "/redfish/v1/Systems/1/Storage/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/NetworkAdapters",
        "/redfish/v1/Chassis/1/NetworkAdapters/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/Managers/1/EthernetInterfaces",
        "/redfish/v1/Managers/1/EthernetInterfaces/1",
        "/redfish/v1/Managers/1/EthernetInterfaces/2",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the Storage collection is advertised but empty
    /// and the Chassis and Manager members advertise no network links: the
    /// empty collection document is still read, no member is.
    const EMPTY_FAMILY_REQUEST_PATHS: [&str; 12] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Storage",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the second Storage member is undecodable: its
    /// URI is still requested (that is how the skip is observed), then the
    /// remaining families complete.
    const FAMILY_MEMBER_SKIP_REQUEST_PATHS: [&str; 19] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Storage",
        "/redfish/v1/Systems/1/Storage/1",
        "/redfish/v1/Systems/1/Storage/2",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/NetworkAdapters",
        "/redfish/v1/Chassis/1/NetworkAdapters/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/Managers/1/EthernetInterfaces",
        "/redfish/v1/Managers/1/EthernetInterfaces/1",
        "/redfish/v1/Managers/1/EthernetInterfaces/2",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// Every request the complete 30-feature probe makes against a fixture
    /// that advertises all root services and one member per core collection.
    /// Order mirrors the probe sequence in `probe_core_capabilities`.
    const FULL_PROBE_REQUEST_PATHS: [&str; 37] = [
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
        "/redfish/v1/AccountService",
        "/redfish/v1/EventService",
        "/redfish/v1/TaskService",
        "/redfish/v1/TelemetryService",
        "/redfish/v1/UpdateService",
        "/redfish/v1/PowerEquipment",
        "/redfish/v1/Systems/1/Bios",
        "/redfish/v1/Systems/1/BootOptions",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Systems/1/Processors",
        "/redfish/v1/Systems/1/Memory",
        "/redfish/v1/Systems/1/Storage",
        "/redfish/v1/Chassis/1/NetworkAdapters",
        "/redfish/v1/Chassis/1/NetworkAdapters/1",
        "/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions",
        "/redfish/v1/Chassis/1/Assembly",
        "/redfish/v1/Chassis/1/Power",
        "/redfish/v1/Chassis/1/Thermal",
        "/redfish/v1/Chassis/1/Sensors",
        "/redfish/v1/Chassis/1/Controls",
        "/redfish/v1/Chassis/1/PowerSubsystem",
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies",
        "/redfish/v1/Managers/1/EthernetInterfaces",
        "/redfish/v1/Managers/1/HostInterfaces",
        "/redfish/v1/Managers/1/NetworkProtocol",
        "/redfish/v1/Managers/1/LogServices",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The §2.1 standard-feature inventory in design-document order, mirrored
    /// from `rutilus_domain` so discovery can prove it covers every capability
    /// exactly once.
    const CAPABILITY_INVENTORY_ORDER: [EndpointCapability; 30] = [
        EndpointCapability::Accounts,
        EndpointCapability::Assembly,
        EndpointCapability::Bios,
        EndpointCapability::BootOptions,
        EndpointCapability::Chassis,
        EndpointCapability::Systems,
        EndpointCapability::Controls,
        EndpointCapability::EnvironmentMetrics,
        EndpointCapability::EthernetInterfaces,
        EndpointCapability::EventService,
        EndpointCapability::HostInterfaces,
        EndpointCapability::LogServices,
        EndpointCapability::ManagerNetworkProtocol,
        EndpointCapability::Managers,
        EndpointCapability::Memory,
        EndpointCapability::NetworkAdapters,
        EndpointCapability::NetworkDeviceFunctions,
        EndpointCapability::PcieDevices,
        EndpointCapability::Power,
        EndpointCapability::PowerEquipment,
        EndpointCapability::PowerSupplies,
        EndpointCapability::Processors,
        EndpointCapability::SecureBoot,
        EndpointCapability::Sensors,
        EndpointCapability::SessionService,
        EndpointCapability::Storages,
        EndpointCapability::TaskService,
        EndpointCapability::TelemetryService,
        EndpointCapability::Thermal,
        EndpointCapability::UpdateService,
    ];

    /// Builds the exact discovery vector a probe must return for one fixture
    /// class, so every capability test asserts the full §2.1 inventory in
    /// order instead of a hand-written subset.
    fn expected_capabilities(states: CapabilityObservations) -> Vec<EndpointCapabilityObservation> {
        let CapabilityObservations {
            session,
            systems,
            chassis,
            managers,
            root,
            systems_features,
            chassis_features,
            manager_features,
        } = states;
        let expected = [
            (EndpointCapability::Accounts, root.accounts),
            (EndpointCapability::Assembly, chassis_features.assembly),
            (EndpointCapability::Bios, systems_features.bios),
            (
                EndpointCapability::BootOptions,
                systems_features.boot_options,
            ),
            (EndpointCapability::Chassis, chassis),
            (EndpointCapability::Systems, systems),
            (EndpointCapability::Controls, chassis_features.controls),
            (
                EndpointCapability::EnvironmentMetrics,
                chassis_features.environment_metrics,
            ),
            (
                EndpointCapability::EthernetInterfaces,
                manager_features.ethernet_interfaces,
            ),
            (EndpointCapability::EventService, root.event_service),
            (
                EndpointCapability::HostInterfaces,
                manager_features.host_interfaces,
            ),
            (
                EndpointCapability::LogServices,
                manager_features.log_services,
            ),
            (
                EndpointCapability::ManagerNetworkProtocol,
                manager_features.manager_network_protocol,
            ),
            (EndpointCapability::Managers, managers),
            (EndpointCapability::Memory, systems_features.memory),
            (
                EndpointCapability::NetworkAdapters,
                chassis_features.network_adapters,
            ),
            (
                EndpointCapability::NetworkDeviceFunctions,
                chassis_features.network_device_functions,
            ),
            (
                EndpointCapability::PcieDevices,
                systems_features.pcie_devices,
            ),
            (EndpointCapability::Power, chassis_features.power),
            (EndpointCapability::PowerEquipment, root.power_equipment),
            (
                EndpointCapability::PowerSupplies,
                chassis_features.power_supplies,
            ),
            (EndpointCapability::Processors, systems_features.processors),
            (EndpointCapability::SecureBoot, systems_features.secure_boot),
            (EndpointCapability::Sensors, chassis_features.sensors),
            (EndpointCapability::SessionService, session),
            (EndpointCapability::Storages, systems_features.storages),
            (EndpointCapability::TaskService, root.task_service),
            (EndpointCapability::TelemetryService, root.telemetry_service),
            (EndpointCapability::Thermal, chassis_features.thermal),
            (EndpointCapability::UpdateService, root.update_service),
        ];
        assert_eq!(expected.len(), CAPABILITY_INVENTORY_ORDER.len());
        for (observation, expected_capability) in expected.iter().zip(CAPABILITY_INVENTORY_ORDER) {
            assert_eq!(observation.0, expected_capability);
        }
        expected
            .into_iter()
            .map(|(capability, state)| EndpointCapabilityObservation::new(capability, state))
            .collect()
    }

    /// Assigns one uniform state to every feature inside a probe group, for
    /// fixtures whose collections and member-scoped links share one fate.
    fn uniform_group(
        session: CapabilityState,
        core: CapabilityState,
        root_services: CapabilityState,
        nested: CapabilityState,
    ) -> CapabilityObservations {
        CapabilityObservations {
            session,
            systems: core,
            chassis: core,
            managers: core,
            root: RootServiceProbe {
                accounts: root_services,
                event_service: root_services,
                task_service: root_services,
                telemetry_service: root_services,
                update_service: root_services,
                power_equipment: root_services,
            },
            systems_features: SystemFeatureProbe {
                bios: nested,
                boot_options: nested,
                secure_boot: nested,
                processors: nested,
                memory: nested,
                storages: nested,
                pcie_devices: nested,
            },
            chassis_features: ChassisFeatureProbe {
                assembly: nested,
                power: nested,
                thermal: nested,
                sensors: nested,
                controls: nested,
                power_supplies: nested,
                network_adapters: nested,
                network_device_functions: nested,
                environment_metrics: nested,
            },
            manager_features: ManagerFeatureProbe {
                ethernet_interfaces: nested,
                host_interfaces: nested,
                manager_network_protocol: nested,
                log_services: nested,
            },
        }
    }

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
    async fn probes_every_advertised_capability_through_typed_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", FULL_SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", FULL_CHASSIS_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", FULL_MANAGER_BODY),
                ("200 OK", ACCOUNT_SERVICE_BODY),
                ("200 OK", EVENT_SERVICE_BODY),
                ("200 OK", TASK_SERVICE_BODY),
                ("200 OK", TELEMETRY_SERVICE_BODY),
                ("200 OK", UPDATE_SERVICE_BODY),
                ("200 OK", POWER_EQUIPMENT_BODY),
                ("200 OK", BIOS_BODY),
                ("200 OK", BOOT_OPTIONS_BODY),
                ("200 OK", SECURE_BOOT_BODY),
                ("200 OK", PROCESSORS_BODY),
                ("200 OK", MEMORY_BODY),
                ("200 OK", STORAGE_BODY),
                ("200 OK", NETWORK_ADAPTERS_BODY),
                ("200 OK", NETWORK_ADAPTER_BODY),
                ("200 OK", NETWORK_DEVICE_FUNCTIONS_BODY),
                ("200 OK", ASSEMBLY_BODY),
                ("200 OK", POWER_BODY),
                ("200 OK", THERMAL_BODY),
                ("200 OK", SENSORS_BODY),
                ("200 OK", CONTROLS_BODY),
                ("200 OK", POWER_SUBSYSTEM_BODY),
                ("200 OK", POWER_SUPPLIES_BODY),
                ("200 OK", ETHERNET_INTERFACES_BODY),
                ("200 OK", HOST_INTERFACES_BODY),
                ("200 OK", NETWORK_PROTOCOL_BODY),
                ("200 OK", LOG_SERVICES_BODY),
            ],
        ))
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
            expected_capabilities(uniform_group(
                CapabilityState::Supported,
                CapabilityState::Supported,
                CapabilityState::Supported,
                CapabilityState::Supported,
            ))
        );
        assert_session_requests(&server.finish_all().await?, &FULL_PROBE_REQUEST_PATHS)?;
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

        assert_eq!(
            discovery.capabilities(),
            expected_capabilities(uniform_group(
                CapabilityState::NotAdvertised,
                CapabilityState::NotAdvertised,
                CapabilityState::NotAdvertised,
                CapabilityState::NotAdvertised,
            ))
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
            expected_capabilities(CapabilityObservations {
                session: CapabilityState::Unauthorized,
                systems: CapabilityState::SchemaIncompatible,
                chassis: CapabilityState::TemporarilyUnavailable,
                managers: CapabilityState::Supported,
                root: RootServiceProbe {
                    accounts: CapabilityState::NotAdvertised,
                    event_service: CapabilityState::NotAdvertised,
                    task_service: CapabilityState::NotAdvertised,
                    telemetry_service: CapabilityState::NotAdvertised,
                    update_service: CapabilityState::NotAdvertised,
                    power_equipment: CapabilityState::NotAdvertised,
                },
                systems_features: SystemFeatureProbe {
                    bios: CapabilityState::SchemaIncompatible,
                    boot_options: CapabilityState::SchemaIncompatible,
                    secure_boot: CapabilityState::SchemaIncompatible,
                    processors: CapabilityState::SchemaIncompatible,
                    memory: CapabilityState::SchemaIncompatible,
                    storages: CapabilityState::SchemaIncompatible,
                    pcie_devices: CapabilityState::SchemaIncompatible,
                },
                chassis_features: ChassisFeatureProbe {
                    assembly: CapabilityState::TemporarilyUnavailable,
                    power: CapabilityState::TemporarilyUnavailable,
                    thermal: CapabilityState::TemporarilyUnavailable,
                    sensors: CapabilityState::TemporarilyUnavailable,
                    controls: CapabilityState::TemporarilyUnavailable,
                    power_supplies: CapabilityState::TemporarilyUnavailable,
                    network_adapters: CapabilityState::TemporarilyUnavailable,
                    network_device_functions: CapabilityState::TemporarilyUnavailable,
                    environment_metrics: CapabilityState::TemporarilyUnavailable,
                },
                manager_features: ManagerFeatureProbe {
                    ethernet_interfaces: CapabilityState::NotAdvertised,
                    host_interfaces: CapabilityState::NotAdvertised,
                    manager_network_protocol: CapabilityState::NotAdvertised,
                    log_services: CapabilityState::NotAdvertised,
                },
            })
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
            expected_capabilities(uniform_group(
                CapabilityState::TemporarilyUnavailable,
                CapabilityState::Supported,
                CapabilityState::NotAdvertised,
                CapabilityState::NotAdvertised,
            ))
        );
        assert_session_creation_fallback_requests(
            &server.finish_all().await?,
            &SESSION_CREATE_FALLBACK_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn reports_sanitized_transient_session_cleanup_failure() -> Result<(), Box<dyn Error>> {
        let mut responses = session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_BODY),
                ("200 OK", CHASSIS_BODY),
                ("200 OK", MANAGERS_BODY),
            ],
        );
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
            expected_capabilities(uniform_group(
                CapabilityState::SchemaIncompatible,
                CapabilityState::Supported,
                CapabilityState::NotAdvertised,
                CapabilityState::NotAdvertised,
            ))
        );
        assert_invalid_session_token_fallback_requests(
            &server.finish_all().await?,
            &INVALID_SESSION_TOKEN_FALLBACK_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn member_schema_failure_is_inherited_by_member_scoped_features()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", "{}"),
                ("200 OK", CHASSIS_BODY),
                ("200 OK", MANAGERS_BODY),
            ],
        ))
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
            expected_capabilities(CapabilityObservations {
                session: CapabilityState::Supported,
                systems: CapabilityState::Supported,
                chassis: CapabilityState::Supported,
                managers: CapabilityState::Supported,
                root: RootServiceProbe {
                    accounts: CapabilityState::NotAdvertised,
                    event_service: CapabilityState::NotAdvertised,
                    task_service: CapabilityState::NotAdvertised,
                    telemetry_service: CapabilityState::NotAdvertised,
                    update_service: CapabilityState::NotAdvertised,
                    power_equipment: CapabilityState::NotAdvertised,
                },
                systems_features: SystemFeatureProbe {
                    bios: CapabilityState::SchemaIncompatible,
                    boot_options: CapabilityState::SchemaIncompatible,
                    secure_boot: CapabilityState::SchemaIncompatible,
                    processors: CapabilityState::SchemaIncompatible,
                    memory: CapabilityState::SchemaIncompatible,
                    storages: CapabilityState::SchemaIncompatible,
                    pcie_devices: CapabilityState::SchemaIncompatible,
                },
                chassis_features: ChassisFeatureProbe {
                    assembly: CapabilityState::NotAdvertised,
                    power: CapabilityState::NotAdvertised,
                    thermal: CapabilityState::NotAdvertised,
                    sensors: CapabilityState::NotAdvertised,
                    controls: CapabilityState::NotAdvertised,
                    power_supplies: CapabilityState::NotAdvertised,
                    network_adapters: CapabilityState::NotAdvertised,
                    network_device_functions: CapabilityState::NotAdvertised,
                    environment_metrics: CapabilityState::NotAdvertised,
                },
                manager_features: ManagerFeatureProbe {
                    ethernet_interfaces: CapabilityState::NotAdvertised,
                    host_interfaces: CapabilityState::NotAdvertised,
                    manager_network_protocol: CapabilityState::NotAdvertised,
                    log_services: CapabilityState::NotAdvertised,
                },
            })
        );
        assert_session_requests(
            &server.finish_all().await?,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Chassis",
                "/redfish/v1/Managers",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;
        Ok(())
    }

    #[test]
    fn capability_state_derivation_maps_links_and_schema_failures() -> Result<(), Box<dyn Error>> {
        let identity = IdentityMonitor::default();
        let trust = pinned_trust(
            generate_simple_self_signed([String::from("localhost")])?
                .cert
                .der(),
        )?;

        assert_eq!(
            classify_capability_probe::<()>(Ok(Some(())), &identity, &trust)?,
            CapabilityState::Supported
        );
        assert_eq!(
            classify_capability_probe::<()>(Ok(None), &identity, &trust)?,
            CapabilityState::NotAdvertised
        );
        let schema_error = match serde_json::from_str::<()>("{") {
            Ok(()) => return Err(io::Error::other("invalid JSON unexpectedly parsed").into()),
            Err(source) => source,
        };
        assert_eq!(
            classify_capability_probe::<()>(
                Err(nv_redfish::Error::Json(schema_error)),
                &identity,
                &trust,
            )?,
            CapabilityState::SchemaIncompatible
        );
        Ok(())
    }

    #[test]
    fn presence_probe_derives_state_from_decoded_members() {
        let collection = ProbedCollection {
            state: CapabilityState::Supported,
            members: Some(vec![1_u8, 2]),
            nested_state: CapabilityState::NotAdvertised,
        };
        assert_eq!(
            probe_nested_presence(&collection, |member| *member == 2),
            CapabilityState::Supported
        );
        assert_eq!(
            probe_nested_presence(&collection, |member| *member == 3),
            CapabilityState::NotAdvertised
        );
        let unobservable = ProbedCollection {
            state: CapabilityState::SchemaIncompatible,
            members: None,
            nested_state: CapabilityState::SchemaIncompatible,
        };
        assert_eq!(
            probe_nested_presence(&unobservable, |_member: &u8| true),
            CapabilityState::SchemaIncompatible
        );
    }

    #[tokio::test]
    async fn nested_probe_stops_at_the_first_decisive_member() -> Result<(), Box<dyn Error>> {
        let identity = IdentityMonitor::default();
        let trust = pinned_trust(
            generate_simple_self_signed([String::from("localhost")])?
                .cert
                .der(),
        )?;
        let collection = ProbedCollection {
            state: CapabilityState::Supported,
            members: Some(vec![0_u8, 1, 2]),
            nested_state: CapabilityState::NotAdvertised,
        };

        let state = probe_nested(&collection, &identity, &trust, |member| {
            Box::pin(async move {
                match member {
                    0 => Ok(None),
                    _ => Ok(Some(())),
                }
            })
        })
        .await?;
        assert_eq!(state, CapabilityState::Supported);

        let absent = probe_nested(&collection, &identity, &trust, |_member| {
            Box::pin(async { Ok(None::<()>) })
        })
        .await?;
        assert_eq!(absent, CapabilityState::NotAdvertised);

        let unobservable = ProbedCollection {
            state: CapabilityState::TemporarilyUnavailable,
            members: None,
            nested_state: CapabilityState::TemporarilyUnavailable,
        };
        let inherited = probe_nested(&unobservable, &identity, &trust, |_member: &u8| {
            Box::pin(async { Ok(None::<()>) })
        })
        .await?;
        assert_eq!(inherited, CapabilityState::TemporarilyUnavailable);
        Ok(())
    }

    #[tokio::test]
    async fn reads_complete_core_resources_through_typed_navigation() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
            ],
        ))
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
    async fn reads_processors_and_memory_through_typed_system_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_COMPONENTS_BODY),
                ("200 OK", PROCESSORS_WITH_MEMBERS_BODY),
                ("200 OK", PROCESSOR_ONE_BODY),
                ("200 OK", PROCESSOR_TWO_BODY),
                ("200 OK", MEMORY_WITH_MEMBER_BODY),
                ("200 OK", MEMORY_DIMM_ONE_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
            ],
        ))
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

        assert_eq!(resources.len(), 7);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Processors,
                ResourceFeature::Processors,
                ResourceFeature::Memory,
                ResourceFeature::Chassis,
                ResourceFeature::Managers,
            ]
        );
        assert_projection(
            &resources[2],
            "/redfish/v1/Systems/1/Processors/CPU1",
            "W/\"cpu-1\"",
            "ProcessorType",
            "CPU",
        )?;
        assert_projection(
            &resources[3],
            "/redfish/v1/Systems/1/Processors/CPU2",
            "W/\"cpu-2\"",
            "Model",
            "Model P2",
        )?;
        assert_projection(
            &resources[4],
            "/redfish/v1/Systems/1/Memory/DIMM1",
            "W/\"dimm-1\"",
            "MemoryDeviceType",
            "DDR4",
        )?;
        let processor_payload: serde_json::Value =
            serde_json::from_str(resources[2].payload().as_str())?;
        assert_eq!(processor_payload["TotalCores"], 64);
        assert_eq!(processor_payload["Socket"], "LGA4189");
        assert_eq!(processor_payload["Status"]["Health"], "OK");
        let memory_payload: serde_json::Value =
            serde_json::from_str(resources[4].payload().as_str())?;
        assert_eq!(memory_payload["CapacityMiB"], 32768);
        assert_eq!(memory_payload["Manufacturer"], "Rutilus Test");
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_COMPONENTS_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn empty_component_collections_produce_no_component_snapshots()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_COMPONENTS_BODY),
                ("200 OK", PROCESSORS_BODY),
                ("200 OK", MEMORY_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
            ],
        ))
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
        assert_session_requests(&server.finish_all().await?, &EMPTY_COMPONENT_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_failing_members_without_aborting_the_read() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_TWO_MEMBERS_BODY),
                ("200 OK", SYSTEM_WITH_COMPONENTS_BODY),
                ("200 OK", PROCESSORS_WITH_MEMBERS_BODY),
                ("200 OK", PROCESSOR_ONE_BODY),
                ("200 OK", "{}"),
                ("200 OK", MEMORY_WITH_MEMBER_BODY),
                ("200 OK", MEMORY_DIMM_ONE_BODY),
                ("200 OK", "{}"),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", "{}"),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
            ],
        ))
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

        // Systems/2, CPU2, and Chassis/1 all return undecodable bodies and
        // are skipped; every other member still produces a snapshot.
        assert_eq!(resources.len(), 5);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Processors,
                ResourceFeature::Memory,
                ResourceFeature::Managers,
            ]
        );
        assert_session_requests(&server.finish_all().await?, &MEMBER_SKIP_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_storage_network_and_ethernet_families_through_typed_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_STORAGE_BODY),
                ("200 OK", STORAGE_WITH_MEMBERS_BODY),
                ("200 OK", STORAGE_SUBSYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_NETWORK_ADAPTERS_BODY),
                ("200 OK", NETWORK_ADAPTERS_BODY),
                ("200 OK", NETWORK_ADAPTER_FULL_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_ETHERNET_BODY),
                ("200 OK", ETHERNET_INTERFACES_WITH_MEMBERS_BODY),
                ("200 OK", ETHERNET_INTERFACE_ONE_BODY),
                ("200 OK", ETHERNET_INTERFACE_TWO_BODY),
            ],
        ))
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

        assert_eq!(resources.len(), 8);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Storages,
                ResourceFeature::Chassis,
                ResourceFeature::NetworkAdapters,
                ResourceFeature::Managers,
                ResourceFeature::EthernetInterfaces,
                ResourceFeature::EthernetInterfaces,
            ]
        );
        assert_projection(
            &resources[2],
            "/redfish/v1/Systems/1/Storage/1",
            "W/\"storage-1\"",
            "Id",
            "1",
        )?;
        let storage_payload: serde_json::Value =
            serde_json::from_str(resources[2].payload().as_str())?;
        assert_eq!(storage_payload["ControllerCount"], 2);
        assert_eq!(storage_payload["DriveCount"], 2);
        assert_eq!(storage_payload["Status"]["Health"], "OK");
        // Only the contract fields may leave the gateway; the decoded schema
        // fields that are not part of the contract must stay out of the
        // snapshot or the strict application decoder rejects it.
        assert_eq!(storage_payload.get("EncryptionMode"), None);
        assert_projection(
            &resources[4],
            "/redfish/v1/Chassis/1/NetworkAdapters/1",
            "W/\"nic-1\"",
            "Model",
            "Model NIC",
        )?;
        let adapter_payload: serde_json::Value =
            serde_json::from_str(resources[4].payload().as_str())?;
        assert_eq!(adapter_payload["Manufacturer"], "Rutilus Test");
        assert_eq!(adapter_payload["Status"]["State"], "Enabled");
        assert_eq!(adapter_payload.get("PartNumber"), None);
        assert_eq!(adapter_payload.get("SerialNumber"), None);
        assert_eq!(adapter_payload.get("SKU"), None);
        assert_projection(
            &resources[6],
            "/redfish/v1/Managers/1/EthernetInterfaces/1",
            "W/\"eth-1\"",
            "MACAddress",
            "AA:BB:CC:DD:EE:01",
        )?;
        let interface_payload: serde_json::Value =
            serde_json::from_str(resources[6].payload().as_str())?;
        assert_eq!(interface_payload["InterfaceEnabled"], true);
        assert_eq!(interface_payload["SpeedMbps"], 1000);
        assert_eq!(interface_payload["Status"]["Health"], "OK");
        assert_eq!(interface_payload.get("PermanentMACAddress"), None);
        assert_eq!(interface_payload.get("MTUSize"), None);
        assert_eq!(interface_payload.get("HostName"), None);
        assert_eq!(interface_payload.get("FQDN"), None);
        // The second interface carries none of the optional contract fields:
        // they are omitted from the projection, not emitted as null, so the
        // strict application decoder accepts the snapshot.
        let minimal_payload: serde_json::Value =
            serde_json::from_str(resources[7].payload().as_str())?;
        assert_eq!(minimal_payload.get("MACAddress"), None);
        assert_eq!(minimal_payload.get("SpeedMbps"), None);
        assert_eq!(minimal_payload.get("InterfaceEnabled"), None);
        assert_session_requests(&server.finish_all().await?, &FAMILY_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn empty_advertised_families_produce_no_member_snapshots() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_STORAGE_BODY),
                ("200 OK", STORAGE_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
            ],
        ))
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

        // The advertised-but-empty Storage collection produces no snapshot,
        // and the Chassis and Manager members without network links produce
        // none either ("资源存在才呈现").
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
        assert_session_requests(&server.finish_all().await?, &EMPTY_FAMILY_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_one_undecodable_family_member_without_aborting_the_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_STORAGE_BODY),
                ("200 OK", STORAGE_WITH_TWO_MEMBERS_BODY),
                ("200 OK", STORAGE_SUBSYSTEM_BODY),
                ("200 OK", "{}"),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_NETWORK_ADAPTERS_BODY),
                ("200 OK", NETWORK_ADAPTERS_BODY),
                ("200 OK", NETWORK_ADAPTER_FULL_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_ETHERNET_BODY),
                ("200 OK", ETHERNET_INTERFACES_WITH_MEMBERS_BODY),
                ("200 OK", ETHERNET_INTERFACE_ONE_BODY),
                ("200 OK", ETHERNET_INTERFACE_TWO_BODY),
            ],
        ))
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

        // Storage/2 returns an undecodable body and is skipped; the first
        // Storage member and the complete network families still produce
        // snapshots (§0.2.0 acceptance).
        assert_eq!(resources.len(), 8);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Storages,
                ResourceFeature::Chassis,
                ResourceFeature::NetworkAdapters,
                ResourceFeature::Managers,
                ResourceFeature::EthernetInterfaces,
                ResourceFeature::EthernetInterfaces,
            ]
        );
        assert_eq!(
            resources[2].odata_id().as_str(),
            "/redfish/v1/Systems/1/Storage/1"
        );
        assert_session_requests(
            &server.finish_all().await?,
            &FAMILY_MEMBER_SKIP_REQUEST_PATHS,
        )?;
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
    async fn skips_incompatible_member_schema_without_aborting_the_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_sequence(&[
            ("200 OK", SYSTEMS_SERVICE_ROOT_BODY),
            ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
            ("200 OK", "{}"),
        ])
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

        // The undecodable member is left behind; the Service Root snapshot
        // still completes, so the endpoint stays usable (§0.2.0 acceptance).
        assert_eq!(resources.len(), 1);
        assert_eq!(resources[0].feature(), ResourceFeature::ServiceRoot);
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
    async fn aborts_complete_resource_read_on_incompatible_collection_document()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", "{}"),
            ],
        ))
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

        // A failed Chassis collection document is a collection-level failure,
        // not a member-level one: it keeps the existing read error semantics
        // so a refresh Generation is never partial.
        assert!(matches!(
            result,
            Err(CoreResourceReadError::Redfish(source))
                if matches!(*source, RedfishServiceRootError::SchemaIncompatible { .. })
        ));
        assert_session_requests(
            &server.finish_all().await?,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Chassis",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn preserves_resource_and_sanitized_session_cleanup_failures()
    -> Result<(), Box<dyn Error>> {
        let mut responses = session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", "{}"),
            ],
        );
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

    fn session_response_sequence(
        service_root_body: &str,
        after_session: &[(&str, &str)],
    ) -> Vec<Vec<u8>> {
        let mut responses = vec![
            http_response("200 OK", service_root_body),
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
