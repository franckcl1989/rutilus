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
    Bmc as _, Resource as NvResource, ServiceRoot,
    bmc_http::{
        BmcCredentials, CacheSettings, HttpBmc,
        reqwest::{BmcError, Client as NvHttpClient},
    },
    chassis::{Chassis, ChassisCollection, NetworkAdapter},
    computer_system::{ComputerSystem, SystemCollection},
    core::{EntityTypeRef, ModificationResponse, NavProperty, ODataId, ReferenceLeaf, ToSnakeCase},
    manager::{Manager, ManagerCollection},
    schema::{
        assembly::Assembly as AssemblySchema,
        assembly::AssemblyData as AssemblyDataSchema,
        bios::Bios as BiosSchema,
        boot_option::BootOption as BootOptionSchema,
        boot_option_collection::BootOptionCollection as BootOptionCollectionSchema,
        chassis::Chassis as ChassisSchema,
        chassis_collection::ChassisCollection as ChassisCollectionSchema,
        computer_system::{
            BootUpdate as BootUpdateSchema, ComputerSystem as ComputerSystemSchema,
            ComputerSystemUpdate as ComputerSystemUpdateSchema,
        },
        computer_system_collection::ComputerSystemCollection as ComputerSystemCollectionSchema,
        control::Control as ControlSchema,
        control_collection::ControlCollection as ControlCollectionSchema,
        ethernet_interface::EthernetInterface as EthernetInterfaceSchema,
        ethernet_interface_collection::EthernetInterfaceCollection as EthernetInterfaceCollectionSchema,
        event_service::EventService as EventServiceSchema,
        host_interface::HostInterface as HostInterfaceSchema,
        host_interface_collection::HostInterfaceCollection as HostInterfaceCollectionSchema,
        log_service::LogService as LogServiceSchema,
        log_service_collection::LogServiceCollection as LogServiceCollectionSchema,
        manager::Manager as ManagerSchema,
        manager_account::ManagerAccount as ManagerAccountSchema,
        manager_account_collection::ManagerAccountCollection as ManagerAccountCollectionSchema,
        manager_collection::ManagerCollection as ManagerCollectionSchema,
        manager_network_protocol::ManagerNetworkProtocol as ManagerNetworkProtocolSchema,
        memory::Memory as MemorySchema,
        memory_collection::MemoryCollection as MemoryCollectionSchema,
        metric_definition::MetricDefinition as MetricDefinitionSchema,
        metric_definition_collection::MetricDefinitionCollection as MetricDefinitionCollectionSchema,
        metric_report::MetricReport as MetricReportSchema,
        metric_report_collection::MetricReportCollection as MetricReportCollectionSchema,
        network_adapter::NetworkAdapter as NetworkAdapterSchema,
        network_adapter_collection::NetworkAdapterCollection as NetworkAdapterCollectionSchema,
        pcie_device::PcieDevice as PcieDeviceSchema,
        power::Power as PowerSchema,
        processor::Processor as ProcessorSchema,
        processor_collection::ProcessorCollection as ProcessorCollectionSchema,
        resource::Resource as ResourceSchema,
        resource::ResourceCollection as ResourceCollectionSchema,
        secure_boot::SecureBoot as SecureBootSchema,
        secure_boot::SecureBootUpdate as SecureBootUpdateSchema,
        sensor::Sensor as SensorSchema,
        sensor_collection::SensorCollection as SensorCollectionSchema,
        software_inventory::SoftwareInventory as SoftwareInventorySchema,
        software_inventory_collection::SoftwareInventoryCollection as SoftwareInventoryCollectionSchema,
        storage::Storage as StorageSchema,
        storage_collection::StorageCollection as StorageCollectionSchema,
        task::Task as TaskSchema,
        task_collection::TaskCollection as TaskCollectionSchema,
        task_service::TaskService as TaskServiceSchema,
        telemetry_service::TelemetryService as TelemetryServiceSchema,
        thermal::Thermal as ThermalSchema,
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
    BootCommand, BootSource, BootSourceOverrideEnabled, BootSourceOverrideMode, CapabilityState,
    CertificateFingerprint, ChassisCommand, CreateSubscription, CredentialUsername,
    DeleteSubscription, EndpointAddress, EndpointCapability, EndpointCapabilityObservation,
    EventCommand, EventDestinationProtocol, EventType, ManagerCommand, RedfishCommand,
    ResetKeysType, ResetType, ResourceEtag, ResourceEtagError, ResourceFeature, ResourceODataId,
    ResourceODataIdError, ResourceSnapshotPayload, ResourceSnapshotPayloadError, SecureBootCommand,
    SetBootSourceOverride, SystemCommand, TlsIdentityChanged, TlsTrust,
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
    /// Memory, Storage, `NetworkAdapters`, `EthernetInterfaces`, `Accounts`,
    /// `Bios`, `BootOptions`, `SecureBoot`, `Power`, `Thermal`, `Sensors`,
    /// `Controls`, `LogServices`, `ManagerNetworkProtocol`, `HostInterfaces`,
    /// `SoftwareInventory`, `EventService`, `EventSubscription`,
    /// `TelemetryService`, `MetricDefinition`, `MetricReport`, `TaskService`,
    /// and `Task` families) through public, typed `nv-redfish` navigation and
    /// returns bounded domain projections.
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

    /// Executes one typed write command against the endpoint (§13.3 step 7)
    /// exclusively through the public `nv-redfish` typed API (§7.4): the
    /// `Bmc::action`, `Bmc::update`, `Bmc::create`, and `Bmc::delete` methods
    /// — never a raw `reqwest` request.
    ///
    /// The command families map onto the typed write surface as follows:
    ///
    /// - `System`, `Manager`, and `Chassis` resets run the `Reset` action
    ///   decoded from the endpoint's first advertised member of the family
    ///   (§13.3 step 2: a missing family link or missing action rejects the
    ///   command before any write is sent);
    /// - `Boot` patches the system's `Boot` properties through the compiled
    ///   `ComputerSystemUpdate`/`BootUpdate` schema types;
    /// - `SecureBoot` `Enable`/`Disable` patch the `SecureBootEnable`
    ///   property — the standard CSDL exposes no Enable/Disable actions, only
    ///   `ResetKeys` — and `ResetKeys` runs the decoded
    ///   `#SecureBoot.ResetKeys` action;
    /// - `Event` `CreateSubscription` posts the CSDL `EventDestination`
    ///   shape onto the decoded `Subscriptions` link, and
    ///   `DeleteSubscription` deletes the link URI extended by the typed
    ///   subscription id (the one URI the command payload contributes; the
    ///   product never accepts BMC URLs from outside, §15.6).
    ///
    /// The transient Session lifecycle is identical to the read surfaces: a
    /// Session is established when usable, every member fetch and the write
    /// authenticate with its token, and the Session is deleted before
    /// returning. The §13.4 `ETag` precondition is a later iteration — the
    /// typed `update` sends the transport's existence-only `If-Match: *` —
    /// and a `202` response is reported as
    /// [`CommandExecutionError::AsyncTaskAccepted`], never as acceptance:
    /// the gateway itself never polls Tasks, so the application adapter maps
    /// that error onto the `AsyncTaskAccepted` outcome the Task monitor
    /// polls (§13.6).
    ///
    /// # Errors
    ///
    /// Returns [`CommandExecutionError`] for a provable rejection
    /// ([`CommandExecutionError::Rejected`]), a client-side failure that
    /// provably prevented dispatch, a dispatched write whose outcome cannot
    /// be proven (§13.5), or a `202` Task acceptance. Only the outcome-class
    /// failures must drive the operation to `Unknown`; every other error
    /// proves the write was not executed.
    pub async fn execute_command(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
        command: &RedfishCommand,
    ) -> Result<CommandExecutionOutcome, CommandExecutionError> {
        let (bmc, http, identity) = self
            .authenticated_bmc(address, trust, username, password)
            .map_err(CommandExecutionError::from)?;
        let root = match ServiceRoot::new(Arc::clone(&bmc)).await {
            Ok(root) => root,
            Err(source) => {
                return Err(classify_command_preparation_error(source, &identity, trust));
            }
        };
        let authenticated = match establish_preferred_authentication(
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
        .await
        {
            Ok(authenticated) => authenticated,
            Err(source) => return Err(source.into()),
        };
        let result = execute_authenticated_command(
            authenticated.bmc.as_ref(),
            &authenticated.root,
            &identity,
            trust,
            command,
        )
        .await;
        finish_command_execution(result, authenticated.session, &identity, trust).await
    }

    /// Re-reads the target of one previously accepted write command and
    /// checks the expected result (§13.3 steps 9–10).
    ///
    /// Only `Accepted` operations reach the verifier, so every failure here
    /// proves nothing about the write: the scheduler records `Unknown`
    /// (§13.5) instead of a failure. The expected result is derived from the
    /// command itself:
    ///
    /// - `Event` `CreateSubscription` — the re-read `Subscriptions`
    ///   collection must contain a member whose `Destination` matches the
    ///   command payload; an absent destination is `Mismatched`.
    /// - `Event` `DeleteSubscription` — the subscription id must be absent
    ///   from the re-read collection (matched by the member `@odata.id` tail
    ///   segment, the same identity the deletion payload uses).
    /// - Reset, Boot, and Secure Boot commands — "accepted" verification:
    ///   the target resource must re-read without error, and the verifier
    ///   returns `Confirmed` without asserting the physical effect (power
    ///   state, boot override, key state), which takes effect asynchronously
    ///   on most BMCs; claiming the effect from a successful read would
    ///   fabricate a result. This is the same honest re-read pattern §13.6
    ///   recovery uses.
    ///
    /// The re-reads go through the same typed navigation and Session
    /// lifecycle as the write itself, and the endpoint's own URI structure is
    /// never guessed (§11.1): subscriptions are re-read through the decoded
    /// `EventService` `Subscriptions` link, and targets through the decoded
    /// collection members.
    ///
    /// # Errors
    ///
    /// Returns [`CommandVerificationError`] when the target cannot be
    /// re-read at all — a failed re-read proves nothing about the write, so
    /// the scheduler records `Unknown` (§13.5).
    pub async fn verify_command(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
        command: &RedfishCommand,
    ) -> Result<CommandVerificationOutcome, CommandVerificationError> {
        let (bmc, http, identity) = self
            .authenticated_bmc(address, trust, username, password)
            .map_err(CommandVerificationError::from)?;
        let root = match ServiceRoot::new(Arc::clone(&bmc)).await {
            Ok(root) => root,
            Err(source) => {
                return Err(CommandVerificationError::from(classify_service_root_error(
                    source, &identity, trust,
                )));
            }
        };
        let authenticated = match establish_preferred_authentication(
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
        .await
        {
            Ok(authenticated) => authenticated,
            Err(source) => return Err(source.into()),
        };
        let result = verify_authenticated_command(
            authenticated.bmc.as_ref(),
            &authenticated.root,
            &identity,
            trust,
            command,
        )
        .await;
        finish_command_verification(result, authenticated.session, &identity, trust).await
    }

    /// Reads one Redfish `Task` resource by its `@odata.id` (§13.6) through
    /// the public, typed `nv-redfish` API — the same `Bmc::get` navigation
    /// the core resource read uses, never a raw HTTP request (§7.4).
    ///
    /// The Task URI comes from the BMC itself — the `Location` header of the
    /// `202` acceptance or the `TaskMonitor` property of a Task document —
    /// and is validated as an exact identifier before it reaches this method
    /// (§15.6: the product never accepts BMC URLs from outside). The typed
    /// `Bmc::get` resolves the identifier against the endpoint origin with
    /// redirects, proxies, and cleartext disabled, so a stored identifier
    /// cannot escape the endpoint's own service.
    ///
    /// The transient Session lifecycle is identical to the read surfaces: a
    /// Session is established when usable, the Task read authenticates with
    /// its token, and the Session is deleted before returning. When the Task
    /// document advertises a `TaskMonitor` URI, the observation carries it so
    /// the §13.6 monitor can poll the monitor instead of the Task; the
    /// `Retry-After` header of `TaskMonitor` responses is not part of the
    /// `Task_v1` CSDL and the typed API does not expose it, so the polling
    /// cadence stays a scheduler decision until a raw-header iteration.
    ///
    /// # Errors
    ///
    /// Returns [`TaskReadError`] with a distinct disappearance
    /// ([`TaskReadError::TaskGone`]) and the shared read classification
    /// (authentication, permission, schema, timeout, network, response,
    /// preparation) for everything else. `TaskGone` means the BMC no longer
    /// tracks the Task: the §13.6 recovery must re-verify the operation
    /// target instead of continuing the poll.
    pub async fn read_task(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
        task_uri: &ResourceODataId,
    ) -> Result<TaskObservation, TaskReadError> {
        let (bmc, http, identity) = self
            .authenticated_bmc(address, trust, username, password)
            .map_err(TaskReadError::from)?;
        let root = match ServiceRoot::new(Arc::clone(&bmc)).await {
            Ok(root) => root,
            Err(source) => {
                return Err(TaskReadError::from(classify_service_root_error(
                    source, &identity, trust,
                )));
            }
        };
        let authenticated = match establish_preferred_authentication(
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
        .await
        {
            Ok(authenticated) => authenticated,
            Err(source) => return Err(TaskReadError::from(source)),
        };
        let result =
            read_authenticated_task(authenticated.bmc.as_ref(), task_uri, &identity, trust).await;
        finish_task_read(result, authenticated.session, &identity, trust).await
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
    resources.extend(read_account_resources(bmc, root, identity, trust).await?);
    resources.extend(read_software_inventory_resources(bmc, root, identity, trust).await?);
    resources.extend(read_event_service_resources(bmc, root, identity, trust).await?);
    resources.extend(read_telemetry_service_resources(bmc, root, identity, trust).await?);
    resources.extend(read_task_service_resources(bmc, root, identity, trust).await?);
    Ok(resources)
}

/// Reads the Systems collection and, for every decoded System member, its
/// `Bios`, `BootOptions`, and `SecureBoot` configuration surfaces plus the
/// `Processors`, `Memory`, `Storage`, and `PcieDevices` families, so the 0.2
/// families follow their parent through the same typed navigation.
///
/// A missing Systems link leaves the whole family absent without an error
/// ("资源存在才呈现"); a failed Systems collection document aborts the read
/// with the existing classified error semantics. Only individual members and
/// singletons are skippable.
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
            read_singleton_resources(system.bios.as_ref(), bmc, identity, trust, bios_projection)
                .await?,
        );
        resources.extend(
            read_collection_resources(
                system
                    .boot
                    .as_ref()
                    .and_then(|boot| boot.boot_options.as_ref()),
                bmc,
                identity,
                trust,
                boot_option_projection,
            )
            .await?,
        );
        resources.extend(
            read_singleton_resources(
                system.secure_boot.as_ref(),
                bmc,
                identity,
                trust,
                secure_boot_projection,
            )
            .await?,
        );
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
        resources.extend(
            read_nav_link_members(
                system.pcie_devices.as_deref(),
                bmc,
                identity,
                trust,
                pcie_device_projection,
            )
            .await?,
        );
    }
    Ok(resources)
}

/// Reads the Chassis collection and, for every decoded Chassis member, its
/// `NetworkAdapters` collection plus the `Power` and `Thermal` telemetry
/// singletons, the `Sensors` and `Controls` telemetry collections, and the
/// `Assembly` document, so the 0.2 telemetry and assembly surfaces follow
/// their parent through the same typed navigation.
///
/// A missing Chassis link leaves the whole family absent without an error; a
/// failed Chassis collection document aborts the read with the existing
/// classified error semantics. Only individual members and singletons are
/// skippable.
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
        resources.extend(
            read_singleton_resources(
                chassis.power.as_ref(),
                bmc,
                identity,
                trust,
                power_projection,
            )
            .await?,
        );
        resources.extend(
            read_singleton_resources(
                chassis.thermal.as_ref(),
                bmc,
                identity,
                trust,
                thermal_projection,
            )
            .await?,
        );
        resources.extend(
            read_collection_resources(
                chassis.sensors.as_ref(),
                bmc,
                identity,
                trust,
                sensor_projection,
            )
            .await?,
        );
        resources.extend(
            read_collection_resources(
                chassis.controls.as_ref(),
                bmc,
                identity,
                trust,
                control_projection,
            )
            .await?,
        );
        resources.extend(
            read_assembly_resources(chassis.assembly.as_ref(), bmc, identity, trust).await?,
        );
    }
    Ok(resources)
}

/// Reads the Managers collection and, for every decoded Manager member, its
/// `EthernetInterfaces`, `LogServices`, and `HostInterfaces` collections plus
/// the `NetworkProtocol` singleton, so the 0.2 Manager-facing families follow
/// their parent through the same typed navigation.
///
/// A missing Managers link leaves the whole family absent without an error; a
/// failed Managers collection document aborts the read with the existing
/// classified error semantics. Only individual members and the
/// `NetworkProtocol` singleton are skippable.
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
        resources.extend(
            read_collection_resources(
                manager.log_services.as_ref(),
                bmc,
                identity,
                trust,
                log_service_projection,
            )
            .await?,
        );
        resources.extend(
            read_singleton_resources(
                manager.network_protocol.as_ref(),
                bmc,
                identity,
                trust,
                manager_network_protocol_projection,
            )
            .await?,
        );
        resources.extend(
            read_collection_resources(
                manager.host_interfaces.as_ref(),
                bmc,
                identity,
                trust,
                host_interface_projection,
            )
            .await?,
        );
    }
    Ok(resources)
}

/// Reads the `Accounts` family through the root-level `AccountService` link,
/// so account members are discovered from the decoded Service Root instead of
/// a guessed path.
///
/// The `AccountService` document itself is a singleton and follows the
/// singleton decision: a missing link leaves the family absent and a failed
/// document is skipped with the member-level semantics instead of aborting
/// the read. The `Accounts` collection below it keeps the normal collection
/// semantics: a failed collection document aborts, only individual members
/// are skippable.
async fn read_account_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(account_service) = root.root.account_service.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(service) = fetch_member(account_service, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_collection_resources(
        service.accounts.as_ref(),
        bmc,
        identity,
        trust,
        manager_account_projection,
    )
    .await
}

/// Reads the `SoftwareInventory` family through the root-level
/// `UpdateService` link, so members are discovered from the decoded Service
/// Root instead of a guessed path.
///
/// The `UpdateService` document itself is a singleton and follows the
/// singleton decision exactly like `AccountService`: a missing link leaves
/// the family absent and a failed document is skipped with the member-level
/// semantics instead of aborting the read. The `SoftwareInventory` collection
/// below it keeps the normal collection semantics: a failed collection
/// document aborts, only individual members are skippable.
async fn read_software_inventory_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(update_service) = root.root.update_service.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(service) = fetch_member(update_service, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_collection_resources(
        service.software_inventory.as_ref(),
        bmc,
        identity,
        trust,
        software_inventory_projection,
    )
    .await
}

/// Reads the root-level `EventService` singleton and, through its
/// `Subscriptions` link, every `EventSubscription` member, so the §2.1
/// `event-service` read surface follows its service through the decoded
/// Service Root instead of a guessed path.
///
/// Unlike `AccountService` and `UpdateService`, the service document itself
/// is part of the read surface (`event-service` is a projected feature, not
/// only a navigation hub), so it is projected with the singleton decision
/// exactly like `Bios`: a missing link leaves the family absent
/// ("资源存在才呈现"), a failed document is skipped with the member-level
/// semantics, and a representation failure skips only the singleton. The
/// `Subscriptions` collection below it keeps the normal collection
/// semantics: a failed collection document aborts, only individual members
/// are skippable.
async fn read_event_service_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(event_service) = root.root.event_service.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(service) = fetch_member(event_service, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    if let Some(projection) = member_projection(event_service_projection(&service))? {
        resources.push(projection);
    }
    resources.extend(
        read_event_subscription_resources(service.subscriptions.as_ref(), bmc, identity, trust)
            .await?,
    );
    Ok(resources)
}

/// Reads the `EventSubscription` members of the root-level `EventService`
/// through the decoded `Subscriptions` collection link.
///
/// The `EventDestinationCollection` and `EventDestination` entity types are
/// not compiled into nv-redfish 0.13 — the `Subscriptions` navigation is a
/// bare [`ReferenceLeaf`] — so this is the one read surface that decodes its
/// collection and member documents through the minimal local schemas
/// declared below instead of the compiled tree. The fetch and failure
/// semantics stay identical to every other collection: a missing link leaves
/// the family absent, a failed collection document aborts the read with the
/// existing classified error (the read iterates the collection, it does not
/// observe it), and only individual members are skippable.
async fn read_event_subscription_resources(
    subscriptions: Option<&ReferenceLeaf>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(subscriptions) = subscriptions else {
        return Ok(Vec::new());
    };
    let collection = bmc
        .get::<EventSubscriptionCollectionSchema>(&subscriptions.odata_id)
        .await
        .map_err(|source| collection_failure(source, identity, trust))?;
    let mut resources = Vec::new();
    for member in collection.members() {
        let Some(member) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(event_subscription_projection(&member))? {
            resources.push(projection);
        }
    }
    Ok(resources)
}

/// Reads the root-level `TelemetryService` singleton and, through its
/// `MetricDefinitions` and `MetricReports` links, every metric definition
/// and metric report member, so the §2.1 `telemetry-service` read surface
/// follows its service through the decoded Service Root.
///
/// The `TelemetryService` document itself is a singleton and follows the
/// singleton decision exactly like `EventService`: a missing link leaves the
/// family absent, a failed document is skipped with the member-level
/// semantics, and a representation failure skips only the singleton. Both
/// collections below it keep the normal collection semantics: a failed
/// collection document aborts, only individual members are skippable.
async fn read_telemetry_service_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(telemetry_service) = root.root.telemetry_service.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(service) = fetch_member(telemetry_service, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    if let Some(projection) = member_projection(telemetry_service_projection(&service))? {
        resources.push(projection);
    }
    resources.extend(
        read_collection_resources(
            service.metric_definitions.as_ref(),
            bmc,
            identity,
            trust,
            metric_definition_projection,
        )
        .await?,
    );
    resources.extend(
        read_collection_resources(
            service.metric_reports.as_ref(),
            bmc,
            identity,
            trust,
            metric_report_projection,
        )
        .await?,
    );
    Ok(resources)
}

/// Reads the root-level `TaskService` singleton and, through its `Tasks`
/// link, every `Task` member, so the §2.1 `task-service` read surface
/// follows its service through the decoded Service Root.
///
/// The `TaskService` document itself is a singleton and follows the
/// singleton decision exactly like `EventService`: a missing link leaves the
/// family absent, a failed document is skipped with the member-level
/// semantics, and a representation failure skips only the singleton. The
/// `Tasks` collection below it keeps the normal collection semantics: a
/// failed collection document aborts, only individual members are skippable.
async fn read_task_service_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(task_service) = root.root.tasks.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(service) = fetch_member(task_service, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    if let Some(projection) = member_projection(task_service_projection(&service))? {
        resources.push(projection);
    }
    resources.extend(
        read_collection_resources(
            service.tasks.as_ref(),
            bmc,
            identity,
            trust,
            task_projection,
        )
        .await?,
    );
    Ok(resources)
}

/// Reads the `Assembly` document of every Chassis member and projects one
/// snapshot per `AssemblyData` member embedded in it.
///
/// The `Assembly` document is a singleton: a missing link leaves the family
/// absent and a failed document is skipped with the member-level semantics,
/// because there is no collection document to abort the read over. Each
/// `AssemblyData` member is then fetched individually, so one undecodable
/// member cannot erase its peers.
async fn read_assembly_resources(
    assembly: Option<&NavProperty<AssemblySchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(assembly) = assembly else {
        return Ok(Vec::new());
    };
    let Some(assembly) = fetch_member(assembly, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_nav_link_members(
        assembly.assemblies.as_deref(),
        bmc,
        identity,
        trust,
        assembly_data_projection,
    )
    .await
}

/// Projects the members of an in-document array of typed navigation links
/// with the same per-member skip semantics as a collection, because the array
/// is the whole family surface and there is no collection document to abort
/// the read over.
///
/// `PCIeDevices` on a System and `Assemblies` inside the Assembly document
/// are both arrays of links instead of collection resources: a missing or
/// empty array produces no snapshots ("资源存在才呈现"), and every member is
/// fetched individually so one undecodable member cannot erase its peers.
async fn read_nav_link_members<T>(
    links: Option<&[NavProperty<T>]>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    project: impl Fn(&T) -> Result<CoreResourceProjection, CoreResourceReadError>,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError>
where
    T: EntityTypeRef + for<'de> Deserialize<'de> + 'static,
{
    let Some(links) = links else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    for link in links {
        let Some(member) = fetch_member(link, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(project(&member))? {
            resources.push(projection);
        }
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

impl MemberCollection for LogServiceCollectionSchema {
    type Member = LogServiceSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for HostInterfaceCollectionSchema {
    type Member = HostInterfaceSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for ManagerAccountCollectionSchema {
    type Member = ManagerAccountSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for BootOptionCollectionSchema {
    type Member = BootOptionSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for SensorCollectionSchema {
    type Member = SensorSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for ControlCollectionSchema {
    type Member = ControlSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for SoftwareInventoryCollectionSchema {
    type Member = SoftwareInventorySchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for MetricDefinitionCollectionSchema {
    type Member = MetricDefinitionSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for MetricReportCollectionSchema {
    type Member = MetricReportSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for TaskCollectionSchema {
    type Member = TaskSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for EventSubscriptionCollectionSchema {
    type Member = EventSubscriptionSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

/// The `EventDestination_v1` member schema of the `EventService`
/// `Subscriptions` collection, declared locally because the
/// `EventDestination` entity type is not compiled into nv-redfish 0.13 (the
/// `Subscriptions` navigation is a bare [`ReferenceLeaf`]).
///
/// Only the contract fields are decoded. The subscription filtering and
/// delivery fields (`HttpHeaders`, `MessageIds`, `RegistryPrefixes`,
/// `ResourceTypes`, `DeliveryRetryPolicy`, and the origin-condition options)
/// stay out of this minimal schema: they are not part of the projection
/// contract, and an unknown key is ignored by the flattened base instead of
/// failing the member decode. The string fields stay plain `Option`s with a
/// missing-field default: serde maps both a missing property and an explicit
/// null to `None`, so the projection sees exactly the same absent value the
/// compiled double-optional shape would produce, without the clippy-forbidden
/// `Option<Option<T>>` pair that only read-write schemas need.
#[derive(Deserialize)]
struct EventSubscriptionSchema {
    #[serde(flatten)]
    base: ResourceSchema,
    #[serde(rename = "Destination", default)]
    destination: Option<String>,
    #[serde(rename = "Protocol", default)]
    protocol: Option<String>,
    #[serde(rename = "Context", default)]
    context: Option<String>,
    #[serde(rename = "EventTypes", default)]
    event_types: Option<Vec<nv_redfish::schema::event::EventType>>,
    #[serde(rename = "Status", default)]
    status: Option<nv_redfish::schema::resource::Status>,
}

impl EntityTypeRef for EventSubscriptionSchema {
    fn odata_id(&self) -> &nv_redfish::core::ODataId {
        self.base.odata_id()
    }

    fn etag(&self) -> Option<&nv_redfish::core::ODataETag> {
        self.base.etag()
    }
}

/// The `EventDestinationCollection` document schema of the `EventService`
/// `Subscriptions` link, declared locally for the same reason as
/// [`EventSubscriptionSchema`]: the collection entity type is not compiled
/// into nv-redfish 0.13.
///
/// The shape mirrors the compiled collection types exactly: the shared
/// `ResourceCollection` base carries the identity metadata and `Members`
/// carries the typed navigation links, so the collection document decodes
/// from the same wire form as every compiled collection.
#[derive(Deserialize)]
struct EventSubscriptionCollectionSchema {
    #[serde(flatten)]
    base: ResourceCollectionSchema,
    #[serde(rename = "Members", default)]
    members: Vec<NavProperty<EventSubscriptionSchema>>,
}

impl EntityTypeRef for EventSubscriptionCollectionSchema {
    fn odata_id(&self) -> &nv_redfish::core::ODataId {
        self.base.odata_id()
    }

    fn etag(&self) -> Option<&nv_redfish::core::ODataETag> {
        self.base.etag()
    }
}

/// The typed `POST` payload of one event subscription creation.
///
/// `EventDestination` is not compiled into nv-redfish 0.13 (the
/// `Subscriptions` navigation is a bare [`ReferenceLeaf`], which is why
/// [`EventSubscriptionSchema`] is declared locally too), so the create body
/// is declared here with the exact `EventDestination_v1` CSDL property
/// names. The protocol and event-type member sets come from the domain
/// projections, whose const member-set tests pin the CSDL enumerations —
/// reusing the domain types keeps the wire values under the same pinned
/// contract instead of duplicating the member sets in this crate.
#[derive(Serialize)]
struct EventDestinationCreateBody {
    #[serde(rename = "Destination")]
    destination: String,
    #[serde(rename = "Protocol")]
    protocol: EventDestinationProtocol,
    #[serde(rename = "EventTypes")]
    event_types: Vec<EventType>,
}

/// The wire response projection of one created event subscription.
///
/// Vendor create responses differ — the full `EventDestination` document, a
/// `Location`-only reference, or no body at all — so every field stays
/// optional and the projection accepts all of them. The outcome contract
/// needs only the acceptance; the created `@odata.id` is decoded but not
/// consumed yet, because the subscription-lifecycle iterations that follow
/// (verification, Task recovery) read it from this projection.
#[derive(Deserialize)]
struct EventDestinationWriteSchema {
    #[serde(rename = "@odata.id", default)]
    #[allow(dead_code)]
    odata_id: Option<String>,
}

/// Projects one advertised singleton with the member-level skip semantics.
///
/// `Bios` and `SecureBoot` are singletons, not collections, so they share
/// the fetch and representation skip rules of a single member: a missing
/// link leaves the family absent ("资源存在才呈现"), a failed fetch is
/// endpoint-local and skips only that singleton, and a failed projection
/// skips it as well. There is no collection document to abort the read over.
async fn read_singleton_resources<T>(
    nav: Option<&NavProperty<T>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    project: impl Fn(&T) -> Result<CoreResourceProjection, CoreResourceReadError>,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError>
where
    T: EntityTypeRef + for<'de> Deserialize<'de> + 'static,
{
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(resource) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    Ok(member_projection(project(&resource))?.into_iter().collect())
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

/// Reads one Task document through the transport the Session logic selected.
///
/// The Task URI is fetched directly with `Bmc::get`, so the read depends on
/// no collection navigation: the §13.6 recovery scan re-reads the exact URI
/// the BMC returned, whether it identifies the Task or its `TaskMonitor`.
async fn read_authenticated_task(
    bmc: &UpstreamBmc,
    task_uri: &ResourceODataId,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<TaskObservation, TaskReadError> {
    let odata_id = ODataId::from(task_uri.as_str().to_owned());
    match bmc.get::<TaskSchema>(&odata_id).await {
        Ok(task) => Ok(TaskObservation::from_task(&task, task_uri)),
        Err(source) => Err(classify_task_fetch_error(
            nv_redfish::Error::Bmc(source),
            task_uri,
            identity,
            trust,
        )),
    }
}

/// Classifies one Task-document fetch failure (§13.6).
///
/// A `404` from the Task URI itself means the BMC deleted or overwrote the
/// Task (`TaskService` auto-deletes completed tasks): the monitor must stop
/// polling and re-verify the operation target, because the write may already
/// have completed. TLS-safety failures keep precedence over the status so a
/// changed or rejected identity is never misread as a vanished Task, and
/// every other failure keeps the shared read classification (authentication,
/// permission, schema, timeout, network, response) for the monitor to decide
/// between retry and surface.
fn classify_task_fetch_error(
    source: UpstreamServiceRootError,
    task_uri: &ResourceODataId,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> TaskReadError {
    match identity.take_change(trust) {
        Ok(Some(changed)) => {
            return TaskReadError::ReadFailed {
                task_uri: task_uri.clone(),
                source: Box::new(RedfishServiceRootError::TlsIdentityChanged(changed)),
            };
        }
        Err(source) => {
            return TaskReadError::ReadFailed {
                task_uri: task_uri.clone(),
                source: Box::new(RedfishServiceRootError::TlsIdentityState(source)),
            };
        }
        Ok(None) => {}
    }
    match source {
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { status, .. })
            if status == StatusCode::NOT_FOUND && !identity.validation_rejected() =>
        {
            TaskReadError::TaskGone {
                task_uri: task_uri.clone(),
                source,
            }
        }
        source => TaskReadError::ReadFailed {
            task_uri: task_uri.clone(),
            source: Box::new(classify_service_root_error(source, identity, trust)),
        },
    }
}

async fn finish_task_read(
    operation: Result<TaskObservation, TaskReadError>,
    session: Option<Session<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<TaskObservation, TaskReadError> {
    let cleanup = cleanup_session(session, identity, trust).await;
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(operation), Ok(())) => Err(operation),
        (Ok(_), Err(cleanup)) => Err(cleanup.into()),
        (Err(operation), Err(cleanup)) => Err(TaskReadError::ReadAndSessionCleanupFailed {
            read: Box::new(operation),
            cleanup: Box::new(cleanup),
        }),
    }
}

/// Dispatches one typed write command through the authenticated transport.
///
/// The match is exhaustive over every §7.5 family, so adding a command
/// family fails to compile until a typed execution path exists here.
async fn execute_authenticated_command(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    command: &RedfishCommand,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    match command {
        RedfishCommand::System(SystemCommand::Reset(reset_type)) => {
            execute_system_reset(bmc, root, identity, trust, *reset_type).await
        }
        RedfishCommand::Manager(ManagerCommand::Reset(reset_type)) => {
            execute_manager_reset(bmc, root, identity, trust, *reset_type).await
        }
        RedfishCommand::Chassis(ChassisCommand::Reset(reset_type)) => {
            execute_chassis_reset(bmc, root, identity, trust, *reset_type).await
        }
        RedfishCommand::Boot(BootCommand::SetBootSourceOverride(override_value)) => {
            execute_boot_override(bmc, root, identity, trust, override_value).await
        }
        RedfishCommand::SecureBoot(SecureBootCommand::Enable) => {
            execute_secure_boot_enable(bmc, root, identity, trust, true).await
        }
        RedfishCommand::SecureBoot(SecureBootCommand::Disable) => {
            execute_secure_boot_enable(bmc, root, identity, trust, false).await
        }
        RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(kind)) => {
            execute_secure_boot_reset_keys(bmc, root, identity, trust, *kind).await
        }
        RedfishCommand::Event(EventCommand::CreateSubscription(payload)) => {
            execute_create_subscription(bmc, root, identity, trust, payload).await
        }
        RedfishCommand::Event(EventCommand::DeleteSubscription(payload)) => {
            execute_delete_subscription(bmc, root, identity, trust, payload).await
        }
    }
}

/// Fetches the first advertised member of one core collection.
///
/// The write surfaces of this iteration are endpoint-scoped: a command acts
/// on the endpoint's primary resource of the family — the first member of
/// the decoded collection. The persisted `Operation` already carries
/// `TargetId`s, but mapping a target identity to a specific member is the
/// engine's later iteration; the endpoint-scoped rule is documented here so
/// the resolution stays deterministic until then. Member links always come
/// from the decoded collection document, never from a guessed path (§11.1).
///
/// A missing link or an empty collection is `None`: the family is simply not
/// advertised ("资源存在才呈现"), which the callers surface as
/// [`CommandRejection::CapabilityUnavailable`].
async fn first_collection_member<C>(
    nav: Option<&NavProperty<C>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<Arc<C::Member>>, CommandExecutionError>
where
    C: MemberCollection,
{
    let Some(collection_nav) = nav else {
        return Ok(None);
    };
    let collection = collection_nav
        .get(bmc)
        .await
        .map_err(|source| command_preparation_error(source, identity, trust))?;
    let Some(member_nav) = collection.members().first() else {
        return Ok(None);
    };
    let member = member_nav
        .get(bmc)
        .await
        .map_err(|source| command_preparation_error(source, identity, trust))?;
    Ok(Some(member))
}

/// Executes a `System` reset through the decoded `#ComputerSystem.Reset`
/// action (§13.3 step 7).
///
/// The action is invoked through the `Bmc::action` typed API with the
/// compiled `ComputerSystemResetAction` parameter type; the wrapper
/// convenience method (`ComputerSystem::reset`) is not used because it
/// requires the upstream `ActionError` bound that the HTTP BMC error type
/// does not satisfy — the underlying `Bmc::action` has no such bound.
async fn execute_system_reset(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    reset_type: ResetType,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(system) =
        first_collection_member(root.root.systems.as_ref(), bmc, identity, trust).await?
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let Some(action) = system
        .actions
        .as_ref()
        .and_then(|actions| actions.reset.as_ref())
    else {
        // §13.3 step 2: the decoded system does not advertise the Reset
        // action, so the command is provably unsupported on this endpoint.
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let params = nv_redfish::schema::computer_system::ComputerSystemResetAction {
        reset_type: Some(map_reset_type(reset_type)),
    };
    let response = match bmc
        .action::<nv_redfish::schema::computer_system::ComputerSystemResetAction, ()>(
            action, &params,
        )
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Executes a `Manager` reset through the decoded `#Manager.Reset` action.
async fn execute_manager_reset(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    reset_type: ResetType,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(manager) =
        first_collection_member(root.root.managers.as_ref(), bmc, identity, trust).await?
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let Some(action) = manager
        .actions
        .as_ref()
        .and_then(|actions| actions.reset.as_ref())
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let params = nv_redfish::schema::manager::ManagerResetAction {
        reset_type: Some(map_reset_type(reset_type)),
    };
    let response = match bmc
        .action::<nv_redfish::schema::manager::ManagerResetAction, ()>(action, &params)
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Executes a `Chassis` reset through the decoded `#Chassis.Reset` action.
async fn execute_chassis_reset(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    reset_type: ResetType,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(chassis) =
        first_collection_member(root.root.chassis.as_ref(), bmc, identity, trust).await?
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let Some(action) = chassis
        .actions
        .as_ref()
        .and_then(|actions| actions.reset.as_ref())
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let params = nv_redfish::schema::chassis::ChassisResetAction {
        reset_type: Some(map_reset_type(reset_type)),
    };
    let response = match bmc
        .action::<nv_redfish::schema::chassis::ChassisResetAction, ()>(action, &params)
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Executes a boot source override as a typed `Boot` property `PATCH`.
///
/// The update carries the three CSDL properties
/// (`BootSourceOverrideTarget`, `BootSourceOverrideEnabled`,
/// `BootSourceOverrideMode`) through the compiled
/// [`ComputerSystemUpdateSchema`]/[`BootUpdateSchema`] types, so the wire
/// payload is produced by the upstream schema, not by a hand-written JSON
/// request (§7.4). The response is projected as a [`NavProperty`] so both a
/// full resource body and a `204` are handled; a body that decodes to
/// neither classifies as an outcome-unknown error because the write itself
/// was accepted by the success status (§13.5).
async fn execute_boot_override(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    override_value: &SetBootSourceOverride,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(system) =
        first_collection_member(root.root.systems.as_ref(), bmc, identity, trust).await?
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    if system.boot.is_none() {
        // §13.3 step 2: the decoded system carries no `Boot` object, so a
        // boot override is provably unsupported on this endpoint.
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    }
    let update = ComputerSystemUpdateSchema::default().with_boot(
        BootUpdateSchema::default()
            .with_boot_source_override_target(map_boot_source(override_value.source()))
            .with_boot_source_override_enabled(map_boot_override_enabled(override_value.enabled()))
            .with_boot_source_override_mode(map_boot_override_mode(override_value.mode())),
    );
    let response = match bmc
        .update::<ComputerSystemUpdateSchema, NavProperty<ComputerSystemSchema>>(
            system.odata_id(),
            None,
            &update,
        )
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Executes a `SecureBoot` enable or disable as a typed
/// `SecureBootEnable` property `PATCH`.
///
/// The standard `SecureBoot` CSDL defines no Enable/Disable actions — the
/// member is a `SecureBootEnable` boolean property — so the domain's
/// `Enable`/`Disable` commands map onto the compiled
/// [`SecureBootUpdateSchema`] type exactly like the boot override maps onto
/// its update type.
async fn execute_secure_boot_enable(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    enabled: bool,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(secure_boot) = secure_boot_document(bmc, root, identity, trust).await? else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let update = SecureBootUpdateSchema::default().with_secure_boot_enable(enabled);
    let response = match bmc
        .update::<SecureBootUpdateSchema, NavProperty<SecureBootSchema>>(
            secure_boot.odata_id(),
            None,
            &update,
        )
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Executes a Secure Boot key reset through the decoded
/// `#SecureBoot.ResetKeys` action.
async fn execute_secure_boot_reset_keys(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    kind: ResetKeysType,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(secure_boot) = secure_boot_document(bmc, root, identity, trust).await? else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let Some(action) = secure_boot
        .actions
        .as_ref()
        .and_then(|actions| actions.reset_keys.as_ref())
    else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let params = nv_redfish::schema::secure_boot::SecureBootResetKeysAction {
        reset_keys_type: Some(map_reset_keys_type(kind)),
    };
    let response = match bmc
        .action::<nv_redfish::schema::secure_boot::SecureBootResetKeysAction, ()>(action, &params)
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Fetches the typed `SecureBoot` document of the endpoint's first system.
///
/// The document is fetched through the system's decoded `SecureBoot`
/// navigation property, so the `PATCH`/action target URI is never guessed
/// (§11.1). A missing system or a missing `SecureBoot` link is `None`.
async fn secure_boot_document(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<Arc<SecureBootSchema>>, CommandExecutionError> {
    let Some(system) =
        first_collection_member(root.root.systems.as_ref(), bmc, identity, trust).await?
    else {
        return Ok(None);
    };
    let Some(secure_boot_nav) = system.secure_boot.as_ref() else {
        return Ok(None);
    };
    let secure_boot = secure_boot_nav
        .get(bmc)
        .await
        .map_err(|source| command_preparation_error(source, identity, trust))?;
    Ok(Some(secure_boot))
}

/// Executes an event subscription creation as a typed `POST`.
///
/// The create targets the decoded `Subscriptions` link of the `EventService`
/// document — never a constructed collection path (§11.1) — and the body is
/// the local CSDL projection of the `EventDestination` shape (see
/// [`EventDestinationCreateBody`]). The response projection keeps every
/// field optional because vendor create responses differ (full document,
/// `Location`-only reference, or no body); the outcome contract needs only
/// the acceptance.
async fn execute_create_subscription(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    payload: &CreateSubscription,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(event_service) = event_service_document(bmc, root, identity, trust).await? else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let Some(subscriptions) = event_service.subscriptions.as_ref() else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let create = EventDestinationCreateBody {
        destination: payload.destination().to_owned(),
        protocol: payload.protocol(),
        event_types: payload.event_types().to_vec(),
    };
    let response = match bmc
        .create::<EventDestinationCreateBody, EventDestinationWriteSchema>(
            &subscriptions.odata_id,
            &create,
        )
        .await
    {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Executes an event subscription deletion as a typed `DELETE`.
///
/// The deletion target is the decoded `Subscriptions` collection URI
/// extended by the typed subscription id — the one URI segment the command
/// payload contributes. This is a product-internal operation on a typed
/// subscription id (§15.6: the Center never hands down BMC URLs; the product
/// maps its own persisted subscription identity onto the collection). The id
/// is validated as a single safe path segment first so a corrupt or hostile
/// id cannot escape the collection.
async fn execute_delete_subscription(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    payload: &DeleteSubscription,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(subscription_id) = validate_subscription_id(payload.subscription_id()) else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::InvalidCommandPayload,
        ));
    };
    let Some(event_service) = event_service_document(bmc, root, identity, trust).await? else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let Some(subscriptions) = event_service.subscriptions.as_ref() else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let uri = ODataId::from(format!("{}/{}", subscriptions.odata_id, subscription_id));
    let response = match bmc.delete::<EventSubscriptionSchema>(&uri).await {
        Ok(response) => response,
        Err(source) => {
            return Err(classify_command_write_error(
                nv_redfish::Error::Bmc(source),
                identity,
                trust,
            ));
        }
    };
    outcome_from_modification(response)
}

/// Fetches the typed `EventService` document through its root navigation
/// property; a missing link is `None`.
async fn event_service_document(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<Arc<EventServiceSchema>>, CommandExecutionError> {
    let Some(event_service) = root.root.event_service.as_ref() else {
        return Ok(None);
    };
    let service = event_service
        .get(bmc)
        .await
        .map_err(|source| command_preparation_error(source, identity, trust))?;
    Ok(Some(service))
}

/// Validates a subscription id as a single safe URI path segment.
///
/// The id is joined onto the decoded `Subscriptions` collection URI to form
/// the deletion target, so only one plain segment may participate: the
/// charset is ASCII alphanumerics, `-`, and `_`, which excludes the
/// separators and escape characters (`/`, `\`, `?`, `#`, `%`) and the dot
/// segments (`.`, `..`) that could redirect the request outside the
/// collection, and excludes whitespace and control characters that could
/// smuggle request structure.
fn validate_subscription_id(value: &str) -> Option<&str> {
    let safe = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    safe.then_some(value)
}

/// Projects one typed modification response onto the outcome space.
///
/// A fully handled synchronous success (`200`/`201`/`204` body handled) is
/// [`CommandExecutionOutcome::Accepted`] — the target still must be verified
/// (§13.3 steps 9–10). A `202` Task acceptance is deliberately not
/// acceptance: the gateway itself never polls Tasks, so it surfaces the
/// acceptance as [`CommandExecutionError::AsyncTaskAccepted`] whose verdict
/// is outcome-unknown at this boundary — the BMC accepted the write and the
/// application adapter maps the error onto the `AsyncTaskAccepted` outcome
/// the Task monitor polls (§13.6).
fn outcome_from_modification<T>(
    response: ModificationResponse<T>,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    match response {
        ModificationResponse::Entity(_) | ModificationResponse::Empty => {
            Ok(CommandExecutionOutcome::Accepted)
        }
        ModificationResponse::Task(task) => Err(CommandExecutionError::AsyncTaskAccepted {
            task_location: task.location.0,
        }),
    }
}

/// Completes one command execution with the transient Session lifecycle.
///
/// A known write outcome always stands: when the write itself produced a
/// result (acceptance or provable rejection), a Session cleanup failure
/// cannot change what the BMC did, and shadowing the outcome with a
/// session-hygiene error would push a known result into the §13.5 `Unknown`
/// class and block the verification step the operation model expects after a
/// proven outcome. When the write itself failed AND cleanup failed, both
/// failures are preserved so the classification of the write still decides
/// the verdict.
async fn finish_command_execution(
    outcome: Result<CommandExecutionOutcome, CommandExecutionError>,
    session: Option<Session<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let cleanup = cleanup_session(session, identity, trust).await;
    match cleanup {
        Ok(()) => outcome,
        Err(cleanup) => match outcome {
            // A known write outcome stands despite the hygiene failure.
            Ok(value) => Ok(value),
            Err(operation) => Err(CommandExecutionError::OperationAndSessionCleanupFailed {
                operation: Box::new(operation),
                cleanup: Box::new(cleanup),
            }),
        },
    }
}

/// Dispatches one post-execution verification re-read (§13.3 steps 9–10).
///
/// The match is exhaustive over every §7.5 family, so adding a command
/// family fails to compile until a verification path exists here.
async fn verify_authenticated_command(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    command: &RedfishCommand,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    match command {
        // Both families verify by re-reading the endpoint's first system
        // ("accepted" semantics).
        RedfishCommand::System(SystemCommand::Reset(_))
        | RedfishCommand::Boot(BootCommand::SetBootSourceOverride(_)) => {
            verify_system_readable(bmc, root, identity, trust).await
        }
        RedfishCommand::Manager(ManagerCommand::Reset(_)) => {
            verify_manager_readable(bmc, root, identity, trust).await
        }
        RedfishCommand::Chassis(ChassisCommand::Reset(_)) => {
            verify_chassis_readable(bmc, root, identity, trust).await
        }
        RedfishCommand::SecureBoot(_) => {
            verify_secure_boot_readable(bmc, root, identity, trust).await
        }
        RedfishCommand::Event(EventCommand::CreateSubscription(payload)) => {
            verify_subscription_created(bmc, root, identity, trust, payload).await
        }
        RedfishCommand::Event(EventCommand::DeleteSubscription(payload)) => {
            verify_subscription_deleted(bmc, root, identity, trust, payload).await
        }
    }
}

/// Re-reads the endpoint's first member of a core collection for
/// verification.
///
/// This mirrors [`first_collection_member`] with the verification error
/// contract: every re-read failure becomes [`CommandVerificationError`],
/// because after an accepted write any unreadable target leaves the outcome
/// unprovable (§13.5) regardless of why the re-read failed.
async fn verify_first_collection_member<C>(
    nav: Option<&NavProperty<C>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<Arc<C::Member>>, CommandVerificationError>
where
    C: MemberCollection,
{
    let Some(collection_nav) = nav else {
        return Ok(None);
    };
    let collection = collection_nav
        .get(bmc)
        .await
        .map_err(|source| command_verification_read_error(source, identity, trust))?;
    let Some(member_nav) = collection.members().first() else {
        return Ok(None);
    };
    let member = member_nav
        .get(bmc)
        .await
        .map_err(|source| command_verification_read_error(source, identity, trust))?;
    Ok(Some(member))
}

/// Classifies one verification re-read failure.
///
/// Every failure class converges on [`CommandVerificationError::ReReadFailed`]
/// with the classified source preserved: the verifier only runs after an
/// accepted write, so an authentication refusal, a transport failure, and a
/// schema incompatibility all prove the same thing — nothing — and the
/// scheduler records `Unknown` (§13.5).
fn command_verification_read_error(
    source: BmcError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> CommandVerificationError {
    CommandVerificationError::ReReadFailed(Box::new(classify_service_root_error(
        nv_redfish::Error::Bmc(source),
        identity,
        trust,
    )))
}

/// "Accepted" verification of a `System` Reset or Boot command: the
/// endpoint's first system must re-read without error. The physical effect
/// is deliberately not asserted (see [`RedfishGateway::verify_command`]).
async fn verify_system_readable(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    match verify_first_collection_member(root.root.systems.as_ref(), bmc, identity, trust).await? {
        Some(_) => Ok(CommandVerificationOutcome::Confirmed),
        None => Err(CommandVerificationError::CapabilityUnavailable),
    }
}

/// "Accepted" verification of a `Manager` Reset command: the endpoint's
/// first manager must re-read without error.
async fn verify_manager_readable(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    match verify_first_collection_member(root.root.managers.as_ref(), bmc, identity, trust).await? {
        Some(_) => Ok(CommandVerificationOutcome::Confirmed),
        None => Err(CommandVerificationError::CapabilityUnavailable),
    }
}

/// "Accepted" verification of a `Chassis` Reset command: the endpoint's
/// first chassis must re-read without error.
async fn verify_chassis_readable(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    match verify_first_collection_member(root.root.chassis.as_ref(), bmc, identity, trust).await? {
        Some(_) => Ok(CommandVerificationOutcome::Confirmed),
        None => Err(CommandVerificationError::CapabilityUnavailable),
    }
}

/// "Accepted" verification of a Secure Boot command: the `SecureBoot`
/// document must re-read without error through the system's decoded
/// navigation property.
async fn verify_secure_boot_readable(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    let Some(system) =
        verify_first_collection_member(root.root.systems.as_ref(), bmc, identity, trust).await?
    else {
        return Err(CommandVerificationError::CapabilityUnavailable);
    };
    let Some(secure_boot_nav) = system.secure_boot.as_ref() else {
        return Err(CommandVerificationError::CapabilityUnavailable);
    };
    let _secure_boot = secure_boot_nav
        .get(bmc)
        .await
        .map_err(|source| command_verification_read_error(source, identity, trust))?;
    Ok(CommandVerificationOutcome::Confirmed)
}

/// Verifies a subscription creation: the re-read `Subscriptions` collection
/// must contain a member whose `Destination` matches the command payload.
///
/// The destination is matched by exact string equality against the decoded
/// `Destination` property — the property the create posted. A member that
/// cannot be fetched makes the check inconclusive and is an error (never a
/// `Mismatched`): skipping it could hide the proof of the write (§13.5).
async fn verify_subscription_created(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    payload: &CreateSubscription,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    let subscriptions = re_read_subscriptions(bmc, root, identity, trust).await?;
    for member_nav in subscriptions.members() {
        let member = member_nav
            .get(bmc)
            .await
            .map_err(|source| command_verification_read_error(source, identity, trust))?;
        if member.destination.as_deref() == Some(payload.destination()) {
            return Ok(CommandVerificationOutcome::Confirmed);
        }
    }
    Ok(CommandVerificationOutcome::Mismatched)
}

/// Verifies a subscription deletion: the subscription id must be absent from
/// the re-read `Subscriptions` collection.
///
/// Members are matched by the `@odata.id` tail segment — the same identity
/// the deletion payload names (the id is the last path segment of the
/// subscription's `@odata.id`). A member that cannot be fetched makes the
/// check inconclusive and is an error, for the same reason as in
/// [`verify_subscription_created`].
async fn verify_subscription_deleted(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    payload: &DeleteSubscription,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    let subscriptions = re_read_subscriptions(bmc, root, identity, trust).await?;
    for member_nav in subscriptions.members() {
        let member = member_nav
            .get(bmc)
            .await
            .map_err(|source| command_verification_read_error(source, identity, trust))?;
        if member.odata_id().last_segment() == Some(payload.subscription_id()) {
            return Ok(CommandVerificationOutcome::Mismatched);
        }
    }
    Ok(CommandVerificationOutcome::Confirmed)
}

/// Re-reads the `EventSubscriptions` collection through the decoded
/// `EventService` `Subscriptions` link (§11.1: no guessed path).
async fn re_read_subscriptions(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Arc<EventSubscriptionCollectionSchema>, CommandVerificationError> {
    let Some(event_service) = root.root.event_service.as_ref() else {
        return Err(CommandVerificationError::CapabilityUnavailable);
    };
    let service = event_service
        .get(bmc)
        .await
        .map_err(|source| command_verification_read_error(source, identity, trust))?;
    let Some(subscriptions) = service.subscriptions.as_ref() else {
        return Err(CommandVerificationError::CapabilityUnavailable);
    };
    bmc.get::<EventSubscriptionCollectionSchema>(&subscriptions.odata_id)
        .await
        .map_err(|source| command_verification_read_error(source, identity, trust))
}

/// Completes one verification re-read with the transient Session lifecycle.
///
/// A known verification outcome stands despite a Session cleanup failure,
/// for the same reason the write outcome stands: the re-read evidence is a
/// fact about the BMC, and degrading it would push a proven result into the
/// §13.5 `Unknown` class. When the re-read itself failed AND cleanup failed,
/// both failures are preserved.
async fn finish_command_verification(
    outcome: Result<CommandVerificationOutcome, CommandVerificationError>,
    session: Option<Session<UpstreamBmc>>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    let cleanup = cleanup_session(session, identity, trust).await;
    match cleanup {
        Ok(()) => outcome,
        Err(cleanup) => match outcome {
            Ok(value) => Ok(value),
            Err(verification) => Err(
                CommandVerificationError::VerificationAndSessionCleanupFailed {
                    verification: Box::new(verification),
                    cleanup: Box::new(cleanup),
                },
            ),
        },
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

/// The typed observation of one Redfish `Task` resource (§13.6).
///
/// This is the §7.2 projection the Task monitor consumes: `nv-redfish` types
/// never cross the gateway. `task_state` and `task_status` carry the
/// product's stable snake-case codes — the exact `nv-redfish`
/// `to_snake_case` values the `remote_tasks` persistence contract pins — so
/// the operation engine maps them onto its `RemoteTaskState` enumeration
/// without depending on `nv-redfish`. A wire value this build cannot
/// classify surfaces as `unsupported_value` instead of failing the read:
/// unknown states are an observation, not an endpoint condition.
///
/// `percent_complete` collapses the schema's nullable double-option onto
/// `None` when the BMC omits or nulls it, matching the core resource
/// projection. A `TaskMonitor` URI or `ETag` the gateway cannot represent as
/// exact text is left behind rather than failing the observation — one odd
/// value does not erase the rest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskObservation {
    task_uri: ResourceODataId,
    task_monitor: Option<ResourceODataId>,
    etag: Option<ResourceEtag>,
    task_state: Option<String>,
    task_status: Option<String>,
    percent_complete: Option<i64>,
    messages: Vec<TaskMessageObservation>,
}

impl TaskObservation {
    fn from_task(task: &TaskSchema, task_uri: &ResourceODataId) -> Self {
        Self {
            task_uri: task_uri.clone(),
            task_monitor: task
                .task_monitor
                .as_deref()
                .and_then(|uri| ResourceODataId::parse(uri).ok()),
            etag: task
                .etag()
                .and_then(|value| ResourceEtag::parse(&value.to_string()).ok()),
            task_state: task
                .task_state
                .map(|state| state.to_snake_case().to_owned()),
            task_status: task
                .task_status
                .map(|status| status.to_snake_case().to_owned()),
            percent_complete: task.percent_complete.as_ref().copied().flatten(),
            messages: task
                .messages
                .as_ref()
                .map(|messages| {
                    messages
                        .iter()
                        .map(TaskMessageObservation::from_message)
                        .collect()
                })
                .unwrap_or_default(),
        }
    }

    /// Borrows the exact Task identifier the BMC returned.
    #[must_use]
    pub const fn task_uri(&self) -> &ResourceODataId {
        &self.task_uri
    }

    /// Borrows the `TaskMonitor` URI the Task document advertises, when the
    /// BMC provided one the gateway can represent as exact text.
    #[must_use]
    pub const fn task_monitor(&self) -> Option<&ResourceODataId> {
        self.task_monitor.as_ref()
    }

    /// Borrows the optional entity tag of the Task document.
    #[must_use]
    pub const fn etag(&self) -> Option<&ResourceEtag> {
        self.etag.as_ref()
    }

    /// Borrows the stable code of the last observed `TaskState`
    /// (`running`, `completed`, …; `unsupported_value` for a wire value this
    /// build cannot classify).
    #[must_use]
    pub fn task_state(&self) -> Option<&str> {
        self.task_state.as_deref()
    }

    /// Borrows the stable code of the last observed `TaskStatus` health
    /// (`ok`, `warning`, `critical`, `unsupported_value`).
    #[must_use]
    pub fn task_status(&self) -> Option<&str> {
        self.task_status.as_deref()
    }

    /// Returns the last observed completion percentage (0–100), when the
    /// BMC provided one.
    #[must_use]
    pub const fn percent_complete(&self) -> Option<i64> {
        self.percent_complete
    }

    /// Borrows every message the Task document reports, in wire order; the
    /// §13.6 `LastMessage` contract consumes the last one.
    #[must_use]
    pub fn messages(&self) -> &[TaskMessageObservation] {
        &self.messages
    }
}

/// One Redfish `Task` message, projected for the §13.6 `LastMessage`
/// contract.
///
/// The `MessageId` is required by the CSDL; the human-readable `Message` and
/// the registry `Severity` are optional on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskMessageObservation {
    message_id: String,
    message: Option<String>,
    severity: Option<String>,
}

impl TaskMessageObservation {
    fn from_message(message: &nv_redfish::schema::message::Message) -> Self {
        Self {
            message_id: message.message_id.clone(),
            message: message.message.clone(),
            severity: message.severity.clone(),
        }
    }

    /// Borrows the message registry identifier (`Base.1.0.Progress`, …).
    #[must_use]
    pub fn message_id(&self) -> &str {
        &self.message_id
    }

    /// Borrows the optional human-readable message text.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Borrows the optional registry severity text (`OK`, `Warning`, …).
    #[must_use]
    pub fn severity(&self) -> Option<&str> {
        self.severity.as_deref()
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

/// The §0.2.0 `log-services` family projection.
///
/// The field set is exactly the `LogServicePayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. Only the direct
/// `ServiceEnabled`, `MaxNumberOfRecords`, and `Status` properties are
/// projectable: `OverWritePolicy`, `LogEntryType`, and the `Entries`
/// log-entry collection stay out because the API surface projects metadata
/// only and reading entries is deferred to a later iteration.
#[derive(Serialize)]
struct LogServicePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ServiceEnabled", skip_serializing_if = "Option::is_none")]
    service_enabled: Option<bool>,
    #[serde(rename = "MaxNumberOfRecords", skip_serializing_if = "Option::is_none")]
    max_number_of_records: Option<i64>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `manager-network-protocol` family projection.
///
/// The field set is exactly the `ManagerNetworkProtocolPayload` the
/// application boundary decodes with `deny_unknown_fields`, so an extra field
/// here would make every stored snapshot unreadable at projection time. Only
/// the direct `HostName`, `FQDN`, and `Status` properties are projectable:
/// the per-protocol settings (`HTTP`, `HTTPS`, `SSH`, ...) are nested
/// `Protocol` objects whose set grows with every schema release, so they stay
/// out exactly like `NetworkAdapter`'s `Controllers[]` array.
#[derive(Serialize)]
struct ManagerNetworkProtocolPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "HostName", skip_serializing_if = "Option::is_none")]
    host_name: Option<String>,
    #[serde(rename = "FQDN", skip_serializing_if = "Option::is_none")]
    fqdn: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `host-interfaces` family projection.
///
/// The field set is exactly the `HostInterfacePayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The direct
/// `InterfaceEnabled` and `Status` properties are projectable and
/// `HostInterfaceType` is retained in the persisted payload but stays
/// internal (the API surface exposes only `InterfaceEnabled` and `Status`).
/// The host-facing ethernet links (`HostEthernetInterfaces`,
/// `ManagerEthernetInterface`) and the authentication-mode and
/// credential-bootstrapping sections stay out.
#[derive(Serialize)]
struct HostInterfacePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "InterfaceEnabled", skip_serializing_if = "Option::is_none")]
    interface_enabled: Option<bool>,
    #[serde(rename = "HostInterfaceType", skip_serializing_if = "Option::is_none")]
    host_interface_type: Option<nv_redfish::schema::host_interface::HostInterfaceType>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `accounts` family projection.
///
/// The field set is exactly the `AccountPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. The direct
/// `UserName`, `RoleId`, `Enabled`, `Locked`, and `AccountTypes` properties
/// of the `ManagerAccount` schema are all projectable; `UserName` and
/// `AccountTypes` are retained in the persisted payload but stay internal
/// (the API surface exposes only `Enabled`, `RoleId`, and `Locked`). The
/// password lifecycle fields (`PasswordExpiration`, `AccountExpiration`,
/// `PasswordChangeRequired`) and SNMP/OEM sections stay out, and the schema
/// declares no `Status` property.
#[derive(Serialize)]
struct AccountsPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "UserName", skip_serializing_if = "Option::is_none")]
    user_name: Option<String>,
    #[serde(rename = "RoleId", skip_serializing_if = "Option::is_none")]
    role_id: Option<String>,
    #[serde(rename = "Enabled", skip_serializing_if = "Option::is_none")]
    enabled: Option<bool>,
    #[serde(rename = "Locked", skip_serializing_if = "Option::is_none")]
    locked: Option<bool>,
    #[serde(rename = "AccountTypes", skip_serializing_if = "Option::is_none")]
    account_types: Option<Vec<nv_redfish::schema::manager_account::AccountTypes>>,
}

/// The §0.2.0 `pcie-devices` family projection.
///
/// The field set is exactly the `PcieDevicePayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. The direct
/// `DeviceType`, `Manufacturer`, `Model`, and `Status` properties of the
/// `PCIeDevice` schema are all projectable; `DeviceType` keeps the typed
/// enumeration value so the console renders the device class without
/// re-parsing text. `SlotType` entered `PCIeDevice_v1` only in `v1_9_0` and
/// the schema compiles no `SlotType` property, so it stays out of this
/// strictly projectable field set.
#[derive(Serialize)]
struct PcieDevicePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DeviceType", skip_serializing_if = "Option::is_none")]
    device_type: Option<nv_redfish::schema::pcie_device::DeviceType>,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `assembly` family projection.
///
/// The field set is exactly the `AssemblyPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. The direct `Producer`
/// and `Status` properties of the `AssemblyData` member schema are the whole
/// projectable surface: the type of an assembly is expressed through the
/// `PhysicalContext` property, which stays out of this first strictly
/// projectable field set.
#[derive(Serialize)]
struct AssemblyDataPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Producer", skip_serializing_if = "Option::is_none")]
    producer: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `software-inventory` family projection.
///
/// The field set is exactly the `SoftwareInventoryPayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The direct
/// `SoftwareId`, `Version`, `ReleaseDate`, and `Status` properties of the
/// `SoftwareInventory` schema are all projectable; `ReleaseDate` keeps the
/// RFC 3339 timestamp of the compiled `Edm.DateTimeOffset` type so the
/// console renders the release date without re-parsing text.
#[derive(Serialize)]
struct SoftwareInventoryPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "SoftwareId", skip_serializing_if = "Option::is_none")]
    software_id: Option<String>,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(rename = "ReleaseDate", skip_serializing_if = "Option::is_none")]
    release_date: Option<nv_redfish::schema::edm::DateTimeOffset>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `event-service` singleton projection.
///
/// The field set is exactly the `EventService` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The direct
/// `ServiceEnabled` and `Status` properties of the `EventService` schema are
/// the whole projectable surface: the retry policy (`DeliveryRetryAttempts`,
/// `DeliveryRetryIntervalSeconds`), the SMTP delivery settings, and the
/// SSE endpoint describe event delivery plumbing rather than a
/// console-rendered posture and stay out.
#[derive(Serialize)]
struct EventServicePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ServiceEnabled", skip_serializing_if = "Option::is_none")]
    service_enabled: Option<bool>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `event-subscription` family projection.
///
/// The field set is exactly the `EventSubscription` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The direct
/// `Destination`, `Protocol`, `Context`, and `EventTypes` properties and the
/// `Status` property are the projectable surface; `protocol` keeps the
/// `EventDestinationProtocol` enumeration value as the wire string and
/// `event_types` the `EventTypes` array of `EventType` values, so the
/// console renders both without re-parsing text. `HttpHeaders` and the
/// `MessageIds`/`RegistryPrefixes`/`ResourceTypes` filters stay out.
#[derive(Serialize)]
struct EventSubscriptionPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Destination", skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    #[serde(rename = "Protocol", skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(rename = "Context", skip_serializing_if = "Option::is_none")]
    context: Option<String>,
    #[serde(rename = "EventTypes", skip_serializing_if = "Option::is_none")]
    event_types: Option<Vec<nv_redfish::schema::event::EventType>>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `telemetry-service` singleton projection.
///
/// The field set is exactly the `TelemetryService` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The api
/// contract exposes only the `Status` property of the `TelemetryService`
/// schema, so `ServiceEnabled` — although the compiled schema carries it —
/// must not be projected, and the service-capacity fields (`MaxReports`,
/// `MinCollectionInterval`, `SupportedCollectionFunctions`) stay out for the
/// telemetry-history iteration.
#[derive(Serialize)]
struct TelemetryServicePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `metric-definition` family projection.
///
/// The field set is exactly the `MetricDefinition` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The direct
/// `Units` text and the `MetricType` enumeration (retained as the wire
/// string) are the whole projectable surface; `MetricDataType`, `Precision`,
/// the reading ranges, and the calculation properties describe measurement
/// semantics that the telemetry-history iteration will render, and the
/// schema declares no `Status` property.
#[derive(Serialize)]
struct MetricDefinitionPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Units", skip_serializing_if = "Option::is_none")]
    units: Option<String>,
    #[serde(rename = "MetricType", skip_serializing_if = "Option::is_none")]
    metric_type: Option<nv_redfish::schema::metric_definition::MetricType>,
}

/// The §0.2.0 `metric-report` family projection.
///
/// The field set is exactly the `MetricReport` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. Only metadata
/// is projected: `metric_values_count` is derived from the length of the
/// `MetricValues` array, which is decoded by the schema but deliberately
/// never projected — each `MetricValue` entry is a timestamped reading, the
/// telemetry history of the 0.4.0 iteration, and carrying unbounded value
/// arrays now would defeat the strict decoder alignment. The `Timestamp`,
/// `Context`, and `ReportSequence` metadata and the (schema-absent) `Status`
/// stay out too, so the projection carries only the derived count.
#[derive(Serialize)]
struct MetricReportPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "MetricValuesCount", skip_serializing_if = "Option::is_none")]
    metric_values_count: Option<usize>,
}

/// The §0.2.0 `task-service` singleton projection.
///
/// The field set is exactly the `TaskService` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The direct
/// `ServiceEnabled`, `CompletedTaskOverWritePolicy`, and `Status` properties
/// are the projectable surface; the overwrite policy keeps the `OverWritePolicy`
/// enumeration value so the console renders it without re-parsing text.
/// `DateTime` and `LifeCycleEventOnTaskStateChange` describe service plumbing
/// rather than a console-rendered surface and stay out.
#[derive(Serialize)]
struct TaskServicePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ServiceEnabled", skip_serializing_if = "Option::is_none")]
    service_enabled: Option<bool>,
    #[serde(
        rename = "CompletedTaskOverWritePolicy",
        skip_serializing_if = "Option::is_none"
    )]
    completed_task_over_write_policy: Option<nv_redfish::schema::task_service::OverWritePolicy>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `task` family projection.
///
/// The field set is exactly the `Task` variant the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. The direct
/// `TaskState`, `TaskStatus`, `PercentComplete`, `StartTime`, and `EndTime`
/// properties are the projectable surface: `task_state` keeps the `TaskState`
/// enumeration and `task_status` the `Resource.Health` enumeration as wire
/// strings, `percent_complete` stays numeric, and `start_time`/`end_time`
/// keep the RFC 3339 timestamps of the compiled `Edm.DateTimeOffset` type.
/// `Messages` and the `Payload`/`TaskMonitor` links stay out, and the schema
/// declares no `Status` property.
#[derive(Serialize)]
struct TaskPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "TaskState", skip_serializing_if = "Option::is_none")]
    task_state: Option<nv_redfish::schema::task::TaskState>,
    #[serde(rename = "TaskStatus", skip_serializing_if = "Option::is_none")]
    task_status: Option<nv_redfish::schema::resource::Health>,
    #[serde(rename = "PercentComplete", skip_serializing_if = "Option::is_none")]
    percent_complete: Option<i64>,
    #[serde(rename = "StartTime", skip_serializing_if = "Option::is_none")]
    start_time: Option<nv_redfish::schema::edm::DateTimeOffset>,
    #[serde(rename = "EndTime", skip_serializing_if = "Option::is_none")]
    end_time: Option<nv_redfish::schema::edm::DateTimeOffset>,
}

/// The §0.2.0 `bios` family projection.
///
/// The field set is exactly the `BiosPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. Only the metadata
/// properties of the `Bios` schema are projectable: `AttributeRegistry`
/// names the attribute registry and `ResetBiosToDefaultsPending` exposes the
/// pending-reset flag. The full `Attributes` map is deliberately not
/// projected, so a BIOS attribute change cannot invalidate the snapshot
/// contract, and the schema declares no `Status` property.
#[derive(Serialize)]
struct BiosPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "AttributeRegistry", skip_serializing_if = "Option::is_none")]
    attribute_registry: Option<String>,
    #[serde(
        rename = "ResetBiosToDefaultsPending",
        skip_serializing_if = "Option::is_none"
    )]
    reset_bios_to_defaults_pending: Option<bool>,
}

/// The §0.2.0 `boot-options` family projection.
///
/// The field set is exactly the `BootOptionPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. The direct
/// `BootOptionReference`, `DisplayName`, `BootOptionEnabled`,
/// `UefiDevicePath`, and `Alias` properties of the `BootOption` schema are
/// all projectable; `BootOptionReference` and `Alias` are retained in the
/// persisted payload but stay internal (the API surface exposes only
/// `DisplayName`, `BootOptionEnabled`, and `UefiDevicePath`). `Alias` keeps
/// the typed `BootSource` value so the console renders the boot source
/// without re-parsing text, and the schema declares no `Status` property.
#[derive(Serialize)]
struct BootOptionsPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(
        rename = "BootOptionReference",
        skip_serializing_if = "Option::is_none"
    )]
    boot_option_reference: Option<String>,
    #[serde(rename = "DisplayName", skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    #[serde(rename = "BootOptionEnabled", skip_serializing_if = "Option::is_none")]
    boot_option_enabled: Option<bool>,
    #[serde(rename = "UefiDevicePath", skip_serializing_if = "Option::is_none")]
    uefi_device_path: Option<String>,
    #[serde(rename = "Alias", skip_serializing_if = "Option::is_none")]
    alias: Option<nv_redfish::schema::computer_system::BootSource>,
}

/// The §0.2.0 `secure-boot` family projection.
///
/// The field set is exactly the `SecureBootPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. The direct
/// `SecureBootEnable`, `SecureBootCurrentBoot`, and `SecureBootMode`
/// properties of the `SecureBoot` schema are all projectable;
/// `SecureBootCurrentBoot` is retained in the persisted payload but stays
/// internal (the API surface exposes only `SecureBootEnable` and
/// `SecureBootMode`). The `SecureBootDatabases` link stays out, and the
/// schema declares no `Status` property.
#[derive(Serialize)]
struct SecureBootPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "SecureBootEnable", skip_serializing_if = "Option::is_none")]
    secure_boot_enable: Option<bool>,
    #[serde(
        rename = "SecureBootCurrentBoot",
        skip_serializing_if = "Option::is_none"
    )]
    secure_boot_current_boot: Option<nv_redfish::schema::secure_boot::SecureBootCurrentBootType>,
    #[serde(rename = "SecureBootMode", skip_serializing_if = "Option::is_none")]
    secure_boot_mode: Option<nv_redfish::schema::secure_boot::SecureBootModeType>,
}

/// The §0.2.0 `power` singleton projection.
///
/// The field set is exactly the `PowerPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. `Power_v1` itself
/// declares no `Status` property and no reading or metadata properties:
/// consumption and capacity readings (`PowerConsumedWatts`,
/// `PowerCapacityWatts`) exist only on the `PowerControl` and `PowerSupply`
/// types, whose nested reading arrays deliberately stay out of the snapshot,
/// so the projection carries no details at all.
#[derive(Serialize)]
struct PowerPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
}

/// The §0.2.0 `thermal` singleton projection.
///
/// The field set is exactly the `ThermalPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. Only `Status` exists
/// on the `Thermal` resource itself: `TemperatureCelsius` exists only on
/// `Temperatures` members and fan readings only on `Fans` members, so those
/// nested reading arrays stay out of the strictly projectable field set.
#[derive(Serialize)]
struct ThermalPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `sensors` family projection.
///
/// The field set is exactly the `SensorPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. `reading_type` keeps
/// the typed `ReadingType` value, `reading` the current `Reading` value, and
/// `reading_units` the `ReadingUnits` text, so the console renders the
/// measurement without re-parsing text; the threshold, calibration, and
/// range bags stay out.
#[derive(Serialize)]
struct SensorPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Reading", skip_serializing_if = "Option::is_none")]
    reading: Option<f64>,
    #[serde(rename = "ReadingUnits", skip_serializing_if = "Option::is_none")]
    reading_units: Option<String>,
    #[serde(rename = "ReadingType", skip_serializing_if = "Option::is_none")]
    reading_type: Option<nv_redfish::schema::sensor::ReadingType>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `controls` family projection.
///
/// The field set is exactly the `ControlPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. `control_type` keeps
/// the typed `ControlType` value and `set_point` the current `SetPoint`
/// reading, so the console renders the control surface without re-parsing
/// text; the setting ranges and update schedule stay out.
#[derive(Serialize)]
struct ControlPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ControlType", skip_serializing_if = "Option::is_none")]
    control_type: Option<nv_redfish::schema::control::ControlType>,
    #[serde(rename = "SetPoint", skip_serializing_if = "Option::is_none")]
    set_point: Option<f64>,
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

fn log_service_projection(
    service: &LogServiceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = LogServicePayload {
        resource: CommonResourcePayload::from_schema_base(&service.base),
        service_enabled: service.service_enabled.as_ref().copied().flatten(),
        max_number_of_records: service.max_number_of_records,
        status: service
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::LogServices,
        service.odata_id(),
        service.etag(),
        &payload,
    )
}

fn manager_network_protocol_projection(
    protocol: &ManagerNetworkProtocolSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ManagerNetworkProtocolPayload {
        resource: CommonResourcePayload::from_schema_base(&protocol.base),
        host_name: optional_nullable_text(protocol.host_name.as_ref()),
        fqdn: optional_nullable_text(protocol.fqdn.as_ref()),
        status: protocol
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::ManagerNetworkProtocol,
        protocol.odata_id(),
        protocol.etag(),
        &payload,
    )
}

fn host_interface_projection(
    interface: &HostInterfaceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = HostInterfacePayload {
        resource: CommonResourcePayload::from_schema_base(&interface.base),
        interface_enabled: interface.interface_enabled.as_ref().copied().flatten(),
        host_interface_type: interface.host_interface_type.as_ref().copied().flatten(),
        status: interface
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::HostInterfaces,
        interface.odata_id(),
        interface.etag(),
        &payload,
    )
}

fn manager_account_projection(
    account: &ManagerAccountSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = AccountsPayload {
        resource: CommonResourcePayload::from_schema_base(&account.base),
        user_name: account.user_name.clone(),
        role_id: account.role_id.clone(),
        enabled: account.enabled.as_ref().copied(),
        locked: account.locked.as_ref().copied(),
        account_types: account.account_types.clone(),
    };
    build_core_projection(
        ResourceFeature::Accounts,
        account.odata_id(),
        account.etag(),
        &payload,
    )
}

fn pcie_device_projection(
    device: &PcieDeviceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = PcieDevicePayload {
        resource: CommonResourcePayload::from_schema_base(&device.base),
        device_type: device.device_type,
        manufacturer: optional_nullable_text(device.manufacturer.as_ref()),
        model: optional_nullable_text(device.model.as_ref()),
        status: device
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::PcieDevices,
        device.odata_id(),
        device.etag(),
        &payload,
    )
}

fn assembly_data_projection(
    data: &AssemblyDataSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = AssemblyDataPayload {
        resource: CommonResourcePayload {
            // `AssemblyData` is a referenceable member: the schema declares
            // no `Id` property, so the required `MemberId` array index is
            // the member's stable identifier, and `Name` is optional while
            // the common projection requires a string, so an unnamed member
            // falls back to the empty string instead of producing an
            // undecodable snapshot.
            id: data.base.member_id.clone(),
            name: data
                .name
                .as_ref()
                .and_then(Option::as_ref)
                .cloned()
                .unwrap_or_default(),
            description: data.description.as_ref().and_then(Option::as_ref).cloned(),
        },
        producer: optional_nullable_text(data.producer.as_ref()),
        status: data.status.as_ref().map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Assembly,
        data.odata_id(),
        data.etag(),
        &payload,
    )
}

fn software_inventory_projection(
    item: &SoftwareInventorySchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = SoftwareInventoryPayload {
        resource: CommonResourcePayload::from_schema_base(&item.base),
        software_id: item.software_id.clone(),
        version: optional_nullable_text(item.version.as_ref()),
        release_date: item.release_date.as_ref().and_then(Option::as_ref).copied(),
        status: item.status.as_ref().map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::SoftwareInventory,
        item.odata_id(),
        item.etag(),
        &payload,
    )
}

fn event_service_projection(
    service: &EventServiceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = EventServicePayload {
        resource: CommonResourcePayload::from_schema_base(&service.base),
        service_enabled: service.service_enabled.as_ref().copied().flatten(),
        status: service
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::EventService,
        service.odata_id(),
        service.etag(),
        &payload,
    )
}

fn event_subscription_projection(
    subscription: &EventSubscriptionSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = EventSubscriptionPayload {
        resource: CommonResourcePayload::from_schema_base(&subscription.base),
        destination: subscription.destination.clone(),
        protocol: subscription.protocol.clone(),
        context: subscription.context.clone(),
        event_types: subscription.event_types.clone(),
        status: subscription
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::EventSubscription,
        subscription.odata_id(),
        subscription.etag(),
        &payload,
    )
}

fn telemetry_service_projection(
    service: &TelemetryServiceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = TelemetryServicePayload {
        resource: CommonResourcePayload::from_schema_base(&service.base),
        status: service
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::TelemetryService,
        service.odata_id(),
        service.etag(),
        &payload,
    )
}

fn metric_definition_projection(
    definition: &MetricDefinitionSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = MetricDefinitionPayload {
        resource: CommonResourcePayload::from_schema_base(&definition.base),
        units: optional_nullable_text(definition.units.as_ref()),
        metric_type: definition.metric_type.as_ref().copied().flatten(),
    };
    build_core_projection(
        ResourceFeature::MetricDefinition,
        definition.odata_id(),
        definition.etag(),
        &payload,
    )
}

fn metric_report_projection(
    report: &MetricReportSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = MetricReportPayload {
        resource: CommonResourcePayload::from_schema_base(&report.base),
        metric_values_count: report.metric_values.as_ref().map(Vec::len),
    };
    build_core_projection(
        ResourceFeature::MetricReport,
        report.odata_id(),
        report.etag(),
        &payload,
    )
}

fn task_service_projection(
    service: &TaskServiceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = TaskServicePayload {
        resource: CommonResourcePayload::from_schema_base(&service.base),
        service_enabled: service.service_enabled.as_ref().copied().flatten(),
        completed_task_over_write_policy: service.completed_task_over_write_policy,
        status: service
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::TaskService,
        service.odata_id(),
        service.etag(),
        &payload,
    )
}

fn task_projection(task: &TaskSchema) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = TaskPayload {
        resource: CommonResourcePayload::from_schema_base(&task.base),
        task_state: task.task_state,
        task_status: task.task_status,
        percent_complete: task.percent_complete.as_ref().copied().flatten(),
        start_time: task.start_time,
        end_time: task.end_time,
    };
    build_core_projection(
        ResourceFeature::Task,
        task.odata_id(),
        task.etag(),
        &payload,
    )
}

fn bios_projection(bios: &BiosSchema) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = BiosPayload {
        resource: CommonResourcePayload::from_schema_base(&bios.base),
        attribute_registry: optional_nullable_text(bios.attribute_registry.as_ref()),
        reset_bios_to_defaults_pending: bios
            .reset_bios_to_defaults_pending
            .as_ref()
            .copied()
            .flatten(),
    };
    build_core_projection(
        ResourceFeature::Bios,
        bios.odata_id(),
        bios.etag(),
        &payload,
    )
}

fn boot_option_projection(
    option: &BootOptionSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = BootOptionsPayload {
        resource: CommonResourcePayload::from_schema_base(&option.base),
        boot_option_reference: option.boot_option_reference.clone(),
        display_name: optional_nullable_text(option.display_name.as_ref()),
        boot_option_enabled: option.boot_option_enabled.as_ref().copied().flatten(),
        uefi_device_path: optional_nullable_text(option.uefi_device_path.as_ref()),
        alias: option.alias.as_ref().copied().flatten(),
    };
    build_core_projection(
        ResourceFeature::BootOptions,
        option.odata_id(),
        option.etag(),
        &payload,
    )
}

fn secure_boot_projection(
    secure_boot: &SecureBootSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = SecureBootPayload {
        resource: CommonResourcePayload::from_schema_base(&secure_boot.base),
        secure_boot_enable: secure_boot.secure_boot_enable.as_ref().copied().flatten(),
        secure_boot_current_boot: secure_boot
            .secure_boot_current_boot
            .as_ref()
            .copied()
            .flatten(),
        secure_boot_mode: secure_boot.secure_boot_mode.as_ref().copied().flatten(),
    };
    build_core_projection(
        ResourceFeature::SecureBoot,
        secure_boot.odata_id(),
        secure_boot.etag(),
        &payload,
    )
}

fn power_projection(power: &PowerSchema) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = PowerPayload {
        resource: CommonResourcePayload::from_schema_base(&power.base),
    };
    build_core_projection(
        ResourceFeature::Power,
        power.odata_id(),
        power.etag(),
        &payload,
    )
}

fn thermal_projection(
    thermal: &ThermalSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ThermalPayload {
        resource: CommonResourcePayload::from_schema_base(&thermal.base),
        status: thermal
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Thermal,
        thermal.odata_id(),
        thermal.etag(),
        &payload,
    )
}

fn sensor_projection(
    sensor: &SensorSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = SensorPayload {
        resource: CommonResourcePayload::from_schema_base(&sensor.base),
        reading: sensor.reading.as_ref().copied().flatten(),
        reading_units: sensor
            .reading_units
            .as_ref()
            .and_then(Option::as_ref)
            .cloned(),
        reading_type: sensor.reading_type.as_ref().copied().flatten(),
        status: sensor
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Sensors,
        sensor.odata_id(),
        sensor.etag(),
        &payload,
    )
}

fn control_projection(
    control: &ControlSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = ControlPayload {
        resource: CommonResourcePayload::from_schema_base(&control.base),
        control_type: control.control_type.as_ref().copied().flatten(),
        set_point: control.set_point.as_ref().copied().flatten(),
        status: control
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::Controls,
        control.odata_id(),
        control.etag(),
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

/// The provable outcome of one dispatched write command (§13.3 step 7).
///
/// The application boundary consumes this through `CommandOutcome`:
/// [`Self::Accepted`] maps to the application `Accepted` outcome, every
/// provable refusal is [`CommandExecutionError::Rejected`], and every
/// failure whose outcome cannot be proven (§13.5) is one of the
/// outcome-unknown error variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandExecutionOutcome {
    /// The BMC accepted the write: a synchronous success response
    /// (`200`/`201`/`204`) was received and fully handled (§13.3 step 8).
    /// A success status alone is not business success — the target still
    /// must be re-read and verified (§13.3 steps 9–10). A `202` Task
    /// acceptance is deliberately NOT this variant: the gateway never polls
    /// Tasks, so a `202` surfaces as
    /// [`CommandExecutionError::AsyncTaskAccepted`] and the application
    /// adapter maps it onto the async outcome the Task monitor polls.
    Accepted,
}

/// The provable reason a command was not executed.
///
/// Every reason here proves the BMC never executed the write, so the
/// operation scheduler records `Failed` (§13.5). The reason is the
/// classification contract between the gateway and the application
/// boundary; the vendor response bodies behind a rejection are deliberately
/// not embedded — they can carry arbitrary vendor content, and the reason
/// is what the boundary consumes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandRejection {
    /// Authentication failed (`401`): the credentials were refused.
    AuthenticationFailed,
    /// The credentials are valid but lack permission for the write (`403`).
    PermissionDenied,
    /// The endpoint does not expose the resource, link, or action the
    /// command needs (§13.3 step 2: the gateway-side capability check).
    CapabilityUnavailable,
    /// The command payload cannot be represented safely on the wire (for
    /// example a subscription id that would escape its collection URI).
    InvalidCommandPayload,
    /// The BMC refused the write with another client error (`4xx`), proving
    /// the request was not executed.
    RefusedByBmc,
    /// The endpoint could not be reached or decoded before the write was
    /// dispatched (failed root/session/target reads), proving the write was
    /// never sent.
    EndpointUnavailable,
}

impl fmt::Display for CommandRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::PermissionDenied => "permission denied",
            Self::CapabilityUnavailable => "capability unavailable",
            Self::InvalidCommandPayload => "invalid command payload",
            Self::RefusedByBmc => "refused by the BMC",
            Self::EndpointUnavailable => "endpoint unavailable",
        })
    }
}

/// A controlled failure while executing one typed write command.
///
/// The variants are the §13.5 classification surface for the application
/// boundary: [`Self::outcome_is_unknown`] separates the failures that prove
/// the write was never executed from the failures after which the BMC may
/// already have applied the write. Only the outcome-unknown class may drive
/// an operation to `Unknown`; everything else records `Failed`.
#[derive(Debug, Error)]
pub enum CommandExecutionError {
    #[error("the BMC provably refused the command: {0}")]
    Rejected(CommandRejection),
    #[error("the command was not dispatched because of a client-side failure: {0}")]
    NotDispatched(#[source] Box<RedfishServiceRootError>),
    #[error("the write request was dispatched but its outcome cannot be proven: {0}")]
    OutcomeUnknown(#[source] Box<RedfishServiceRootError>),
    #[error(
        "the BMC accepted the write as an asynchronous Task at {task_location}; the gateway itself never polls Tasks, so the application adapter hands the Task to the monitor"
    )]
    AsyncTaskAccepted {
        /// The `Location` of the accepted Task; the application adapter
        /// validates and persists it, and the Task monitor resumes polling
        /// from it (§13.6).
        task_location: nv_redfish::core::ODataId,
    },
    #[error(
        "the write failed and the transient Session cleanup failed; operation: {operation}; cleanup: {cleanup}"
    )]
    OperationAndSessionCleanupFailed {
        operation: Box<CommandExecutionError>,
        #[source]
        cleanup: Box<RedfishServiceRootError>,
    },
}

impl CommandExecutionError {
    /// Reports whether the BMC may already have executed the write (§13.5).
    ///
    /// Only the outcome-unknown class (a dispatched write with a lost,
    /// dropped, timed-out, server-failed, or undecodable response, or a
    /// `202` Task acceptance) returns `true`; the operation scheduler must
    /// never blindly retry a write in this class.
    #[must_use]
    pub const fn outcome_is_unknown(&self) -> bool {
        match self {
            Self::OutcomeUnknown(_) | Self::AsyncTaskAccepted { .. } => true,
            Self::Rejected(_) | Self::NotDispatched(_) => false,
            Self::OperationAndSessionCleanupFailed { operation, .. } => {
                operation.outcome_is_unknown()
            }
        }
    }
}

impl From<RedfishServiceRootError> for CommandExecutionError {
    fn from(source: RedfishServiceRootError) -> Self {
        Self::NotDispatched(Box::new(source))
    }
}

/// The verdict of a post-execution target re-read (§13.3 steps 9–10).
///
/// The application boundary consumes this through `VerificationVerdict`:
/// `Confirmed` records the operation `Succeeded`, `Mismatched` records
/// `Failed` (the re-read proves the expected result is absent).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandVerificationOutcome {
    /// The re-read confirmed the expected result.
    Confirmed,
    /// The re-read proves the expected result is absent.
    Mismatched,
}

/// A controlled failure while re-reading the target of an accepted write.
///
/// Every failure in this boundary proves nothing about the write: the
/// verifier only runs after an `Accepted` dispatch, so a failed re-read
/// records `Unknown` (§13.5) instead of a failure, no matter why the
/// re-read failed.
#[derive(Debug, Error)]
pub enum CommandVerificationError {
    #[error("the verification re-read failed; this proves nothing about the write: {0}")]
    ReReadFailed(#[source] Box<RedfishServiceRootError>),
    #[error("the endpoint no longer advertises the resource the command targeted")]
    CapabilityUnavailable,
    #[error(
        "the verification re-read and the transient Session cleanup both failed; verification: {verification}; cleanup: {cleanup}"
    )]
    VerificationAndSessionCleanupFailed {
        verification: Box<CommandVerificationError>,
        #[source]
        cleanup: Box<RedfishServiceRootError>,
    },
}

impl From<RedfishServiceRootError> for CommandVerificationError {
    fn from(source: RedfishServiceRootError) -> Self {
        Self::ReReadFailed(Box::new(source))
    }
}

/// TLS identity evidence could not be retained because its synchronization
/// state was poisoned.
#[derive(Clone, Copy, Debug, Error)]
#[error("TLS identity synchronization failed")]
pub struct TlsIdentityStateError;

/// A controlled failure while observing one Redfish `Task` (§13.6).
///
/// [`Self::TaskGone`] is the recovery contract: the BMC no longer tracks the
/// Task (auto-delete or manual cleanup), so the monitor must stop polling and
/// re-verify the operation target — the write may already have completed.
/// Every other Task-document failure keeps the shared read classification
/// inside [`Self::ReadFailed`] so the monitor can separate transient causes
/// (timeout, network, remote response) and preparation failures — retry
/// later — from endpoint-local causes (authentication, permission, schema,
/// TLS) that must surface instead.
#[derive(Debug, Error)]
pub enum TaskReadError {
    #[error("the Task read failed before the Task request was sent: {0}")]
    Preparation(#[source] Box<RedfishServiceRootError>),
    #[error(
        "the Task at {task_uri} no longer exists (404): the BMC deleted or overwrote it, so the operation target must be re-verified instead of continuing the poll (§13.6)"
    )]
    TaskGone {
        task_uri: ResourceODataId,
        #[source]
        source: BmcError,
    },
    #[error("the Task at {task_uri} could not be read: {source}")]
    ReadFailed {
        task_uri: ResourceODataId,
        #[source]
        source: Box<RedfishServiceRootError>,
    },
    #[error(
        "Task read and transient Session cleanup both failed; read: {read}; cleanup: {cleanup}"
    )]
    ReadAndSessionCleanupFailed {
        read: Box<TaskReadError>,
        #[source]
        cleanup: Box<RedfishServiceRootError>,
    },
}

impl From<RedfishServiceRootError> for TaskReadError {
    fn from(source: RedfishServiceRootError) -> Self {
        Self::Preparation(Box::new(source))
    }
}

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

/// Classifies one failure that occurred before the write request was
/// dispatched (§13.3 steps 1–6).
///
/// Every failure in this phase proves the write was never sent, so none of
/// them is outcome-unknown (§13.5): authentication and permission failures
/// become their rejection reasons, unreachable or undecodable read surfaces
/// become [`CommandRejection::EndpointUnavailable`], and TLS-safety
/// failures become [`CommandExecutionError::NotDispatched`] because the
/// trust boundary broke before any write could go out.
fn classify_command_preparation_error(
    source: UpstreamServiceRootError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> CommandExecutionError {
    match classify_service_root_error(source, identity, trust) {
        RedfishServiceRootError::AuthenticationFailed { .. } => {
            CommandExecutionError::Rejected(CommandRejection::AuthenticationFailed)
        }
        RedfishServiceRootError::PermissionDenied { .. } => {
            CommandExecutionError::Rejected(CommandRejection::PermissionDenied)
        }
        RedfishServiceRootError::NotRedfishService { .. }
        | RedfishServiceRootError::NetworkTimeout { .. }
        | RedfishServiceRootError::Network { .. }
        | RedfishServiceRootError::RemoteResponse { .. }
        | RedfishServiceRootError::SchemaIncompatible { .. }
        | RedfishServiceRootError::Upstream(_) => {
            CommandExecutionError::Rejected(CommandRejection::EndpointUnavailable)
        }
        source @ (RedfishServiceRootError::TlsConfiguration(_)
        | RedfishServiceRootError::ClientBuild(_)
        | RedfishServiceRootError::TlsIdentityState(_)
        | RedfishServiceRootError::TlsIdentityChanged(_)
        | RedfishServiceRootError::TlsRejected { .. }
        | RedfishServiceRootError::SessionCleanupTlsRejected
        | RedfishServiceRootError::SessionCleanupFailed
        | RedfishServiceRootError::OperationAndSessionCleanupFailed { .. }) => {
            CommandExecutionError::NotDispatched(Box::new(source))
        }
    }
}

/// Converts one pre-dispatch `BmcError` into the error value the command
/// resolvers propagate through `map_err`.
fn command_preparation_error(
    source: BmcError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> CommandExecutionError {
    classify_command_preparation_error(nv_redfish::Error::Bmc(source), identity, trust)
}

/// Classifies one failure of the write request itself.
///
/// The classification mirrors §13.5 exactly: a received client error
/// response (`4xx`) proves the BMC refused the write and becomes a
/// rejection; a timeout, a dropped or lost response, a server-side failure
/// (`5xx`), an undecodable success payload, or a TLS-safety failure all
/// leave the request's outcome unprovable and become
/// [`CommandExecutionError::OutcomeUnknown`].
fn classify_command_write_error(
    source: UpstreamServiceRootError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> CommandExecutionError {
    match identity.take_change(trust) {
        Ok(Some(changed)) => {
            return CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::TlsIdentityChanged(changed),
            ));
        }
        Err(source) => {
            return CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::TlsIdentityState(source),
            ));
        }
        Ok(None) => {}
    }
    let tls_rejected = identity.validation_rejected();
    match source {
        nv_redfish::Error::Bmc(source) if tls_rejected => {
            CommandExecutionError::OutcomeUnknown(Box::new(RedfishServiceRootError::TlsRejected {
                source,
            }))
        }
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { status, .. }) => match status {
            StatusCode::UNAUTHORIZED => {
                CommandExecutionError::Rejected(CommandRejection::AuthenticationFailed)
            }
            StatusCode::FORBIDDEN => {
                CommandExecutionError::Rejected(CommandRejection::PermissionDenied)
            }
            value if value.is_client_error() => {
                CommandExecutionError::Rejected(CommandRejection::RefusedByBmc)
            }
            // A server-side failure while handling the write: the
            // request may already have been applied (§13.5).
            _ => CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::RemoteResponse { source },
            )),
        },
        nv_redfish::Error::Bmc(source @ (BmcError::JsonError(_) | BmcError::DecodeError(_))) => {
            CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::SchemaIncompatible {
                    source: nv_redfish::Error::Bmc(source),
                },
            ))
        }
        nv_redfish::Error::Bmc(BmcError::ReqwestError(error))
            if matches!(
                json_error_category(&error),
                Some(JsonErrorCategory::Syntax | JsonErrorCategory::Eof)
            ) =>
        {
            CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::NotRedfishService {
                    source: BmcError::ReqwestError(error),
                },
            ))
        }
        nv_redfish::Error::Bmc(BmcError::ReqwestError(error)) if error.is_decode() => {
            CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::SchemaIncompatible {
                    source: nv_redfish::Error::Bmc(BmcError::ReqwestError(error)),
                },
            ))
        }
        nv_redfish::Error::Bmc(source @ BmcError::ReqwestError(_)) => {
            // A timeout or a dropped connection after dispatch: the request
            // may already have been applied (§13.5).
            CommandExecutionError::OutcomeUnknown(Box::new(RedfishServiceRootError::Network {
                source,
            }))
        }
        nv_redfish::Error::ActionNotAvailable => {
            CommandExecutionError::Rejected(CommandRejection::CapabilityUnavailable)
        }
        source => CommandExecutionError::OutcomeUnknown(Box::new(
            RedfishServiceRootError::Upstream(source),
        )),
    }
}

/// Maps the domain `ResetType` projection onto the compiled CSDL
/// `ResetType` member set. The domain member set is pinned to the CSDL by
/// const tests, so this match cannot drift silently.
fn map_reset_type(value: ResetType) -> nv_redfish::schema::resource::ResetType {
    use nv_redfish::schema::resource::ResetType as NvResetType;
    match value {
        ResetType::On => NvResetType::On,
        ResetType::ForceOff => NvResetType::ForceOff,
        ResetType::GracefulShutdown => NvResetType::GracefulShutdown,
        ResetType::GracefulRestart => NvResetType::GracefulRestart,
        ResetType::ForceRestart => NvResetType::ForceRestart,
        ResetType::Nmi => NvResetType::Nmi,
        ResetType::ForceOn => NvResetType::ForceOn,
        ResetType::PushPowerButton => NvResetType::PushPowerButton,
        ResetType::PowerCycle => NvResetType::PowerCycle,
        ResetType::Suspend => NvResetType::Suspend,
        ResetType::Pause => NvResetType::Pause,
        ResetType::Resume => NvResetType::Resume,
        ResetType::FullPowerCycle => NvResetType::FullPowerCycle,
    }
}

/// Maps the domain `BootSource` projection onto the compiled CSDL
/// `BootSource` member set (including the `SDCard` wire name).
fn map_boot_source(value: BootSource) -> nv_redfish::schema::computer_system::BootSource {
    use nv_redfish::schema::computer_system::BootSource as NvBootSource;
    match value {
        BootSource::None => NvBootSource::None,
        BootSource::Pxe => NvBootSource::Pxe,
        BootSource::Floppy => NvBootSource::Floppy,
        BootSource::Cd => NvBootSource::Cd,
        BootSource::Usb => NvBootSource::Usb,
        BootSource::Hdd => NvBootSource::Hdd,
        BootSource::BiosSetup => NvBootSource::BiosSetup,
        BootSource::Utilities => NvBootSource::Utilities,
        BootSource::Diags => NvBootSource::Diags,
        BootSource::UefiShell => NvBootSource::UefiShell,
        BootSource::UefiTarget => NvBootSource::UefiTarget,
        BootSource::SdCard => NvBootSource::SdCard,
        BootSource::UefiHttp => NvBootSource::UefiHttp,
        BootSource::RemoteDrive => NvBootSource::RemoteDrive,
        BootSource::UefiBootNext => NvBootSource::UefiBootNext,
        BootSource::Recovery => NvBootSource::Recovery,
    }
}

/// Maps the domain override-enabled projection onto the compiled CSDL
/// member set.
fn map_boot_override_enabled(
    value: BootSourceOverrideEnabled,
) -> nv_redfish::schema::computer_system::BootSourceOverrideEnabled {
    use nv_redfish::schema::computer_system::BootSourceOverrideEnabled as NvEnabled;
    match value {
        BootSourceOverrideEnabled::Disabled => NvEnabled::Disabled,
        BootSourceOverrideEnabled::Once => NvEnabled::Once,
        BootSourceOverrideEnabled::Continuous => NvEnabled::Continuous,
    }
}

/// Maps the domain override-mode projection onto the compiled CSDL member
/// set (the CSDL member is the all-caps `UEFI`).
fn map_boot_override_mode(
    value: BootSourceOverrideMode,
) -> nv_redfish::schema::computer_system::BootSourceOverrideMode {
    use nv_redfish::schema::computer_system::BootSourceOverrideMode as NvMode;
    match value {
        BootSourceOverrideMode::Legacy => NvMode::Legacy,
        BootSourceOverrideMode::Uefi => NvMode::Uefi,
    }
}

/// Maps the domain `ResetKeysType` projection onto the compiled CSDL
/// member set (including the `DeletePK` wire name).
fn map_reset_keys_type(value: ResetKeysType) -> nv_redfish::schema::secure_boot::ResetKeysType {
    use nv_redfish::schema::secure_boot::ResetKeysType as NvResetKeysType;
    match value {
        ResetKeysType::ResetAllKeysToDefault => NvResetKeysType::ResetAllKeysToDefault,
        ResetKeysType::DeleteAllKeys => NvResetKeysType::DeleteAllKeys,
        ResetKeysType::DeletePk => NvResetKeysType::DeletePk,
    }
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

    /// A Service Root that also advertises the 0.2 `Accounts` family through
    /// the root-level `AccountService` link.
    const CORE_WITH_ACCOUNTS_SERVICE_ROOT_BODY: &str = r#"{
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
        "Managers":{"@odata.id":"/redfish/v1/Managers"},
        "AccountService":{"@odata.id":"/redfish/v1/AccountService"}
    }"#;

    /// The `AccountService` document that advertises the `Accounts`
    /// collection; the service-level password policy fields are decoded but
    /// stay outside the projection contract.
    const ACCOUNT_SERVICE_WITH_ACCOUNTS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/AccountService",
        "@odata.etag":"W/\"account-service-1\"",
        "Id":"AccountService",
        "Name":"Account Service",
        "Description":"Local account management",
        "ServiceEnabled":true,
        "MinPasswordLength":8,
        "Accounts":{"@odata.id":"/redfish/v1/AccountService/Accounts"}
    }"#;

    const ACCOUNTS_BODY: &str = r##"{
        "@odata.type":"#ManagerAccountCollection.ManagerAccountCollection",
        "@odata.id":"/redfish/v1/AccountService/Accounts",
        "Name":"Accounts Collection",
        "Members":[]
    }"##;

    const ACCOUNTS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#ManagerAccountCollection.ManagerAccountCollection",
        "@odata.id":"/redfish/v1/AccountService/Accounts",
        "Name":"Accounts Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/AccountService/Accounts/1"},
            {"@odata.id":"/redfish/v1/AccountService/Accounts/2"}
        ]
    }"##;

    /// The full `ManagerAccount` member projection with every optional
    /// contract field populated; the password lifecycle fields are decoded
    /// but stay outside the projection contract.
    const ACCOUNT_ONE_BODY: &str = r##"{
        "@odata.type":"#ManagerAccount.v1_12_0.ManagerAccount",
        "@odata.id":"/redfish/v1/AccountService/Accounts/1",
        "@odata.etag":"W/\"account-1\"",
        "Id":"1",
        "Name":"Account One",
        "Description":"Primary administrator account",
        "UserName":"admin",
        "RoleId":"Administrator",
        "Enabled":true,
        "Locked":false,
        "AccountTypes":["Redfish","IPMI"],
        "PasswordChangeRequired":false,
        "AccountExpiration":null
    }"##;

    /// A minimal `ManagerAccount` member: `AccountTypes` is `Redfish.Required`
    /// in the schema and must stay present to decode, while every optional
    /// field is absent so the projection omits it instead of emitting null.
    const ACCOUNT_TWO_BODY: &str = r##"{
        "@odata.type":"#ManagerAccount.v1_12_0.ManagerAccount",
        "@odata.id":"/redfish/v1/AccountService/Accounts/2",
        "@odata.etag":"W/\"account-2\"",
        "Id":"2",
        "Name":"Account Two",
        "UserName":"viewer",
        "AccountTypes":["Redfish"]
    }"##;

    /// A Service Root that also advertises the 0.2 `SoftwareInventory` family
    /// through the root-level `UpdateService` link.
    const CORE_WITH_UPDATE_SERVICE_ROOT_BODY: &str = r#"{
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
        "Managers":{"@odata.id":"/redfish/v1/Managers"},
        "UpdateService":{"@odata.id":"/redfish/v1/UpdateService"}
    }"#;

    /// The `UpdateService` document that advertises the `SoftwareInventory`
    /// collection; the update-operation fields are decoded but stay outside
    /// the projection contract.
    const UPDATE_SERVICE_WITH_INVENTORY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/UpdateService",
        "@odata.etag":"W/\"update-service-1\"",
        "Id":"UpdateService",
        "Name":"Update Service",
        "Description":"Firmware update service",
        "ServiceEnabled":true,
        "MaxImageSizeBytes":2147483648,
        "SoftwareInventory":{"@odata.id":"/redfish/v1/UpdateService/SoftwareInventory"}
    }"#;

    const SOFTWARE_INVENTORY_BODY: &str = r##"{
        "@odata.type":"#SoftwareInventoryCollection.SoftwareInventoryCollection",
        "@odata.id":"/redfish/v1/UpdateService/SoftwareInventory",
        "Name":"Software Inventory Collection",
        "Members":[]
    }"##;

    const SOFTWARE_INVENTORY_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#SoftwareInventoryCollection.SoftwareInventoryCollection",
        "@odata.id":"/redfish/v1/UpdateService/SoftwareInventory",
        "Name":"Software Inventory Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/UpdateService/SoftwareInventory/BIOS"},
            {"@odata.id":"/redfish/v1/UpdateService/SoftwareInventory/BMC"}
        ]
    }"##;

    /// The full `SoftwareInventory` member projection with every optional
    /// contract field populated; the update-lifecycle fields are decoded but
    /// stay outside the projection contract.
    const SOFTWARE_INVENTORY_BIOS_BODY: &str = r##"{
        "@odata.type":"#SoftwareInventory.v1_7_0.SoftwareInventory",
        "@odata.id":"/redfish/v1/UpdateService/SoftwareInventory/BIOS",
        "@odata.etag":"W/\"sw-1\"",
        "Id":"BIOS",
        "Name":"System BIOS",
        "Description":"Host firmware",
        "SoftwareId":"BIOS-2026-1",
        "Version":"2.7.0",
        "ReleaseDate":"2026-05-01T00:00:00Z",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "Updateable":true,
        "Manufacturer":"Vendor E",
        "LowestSupportedVersion":"2.0.0"
    }"##;

    /// A minimal `SoftwareInventory` member: every optional contract field
    /// is absent so the projection omits it instead of emitting null.
    const SOFTWARE_INVENTORY_BMC_BODY: &str = r##"{
        "@odata.type":"#SoftwareInventory.v1_7_0.SoftwareInventory",
        "@odata.id":"/redfish/v1/UpdateService/SoftwareInventory/BMC",
        "@odata.etag":"W/\"sw-2\"",
        "Id":"BMC",
        "Name":"BMC Firmware",
        "SoftwareId":"BMC-2026-1",
        "Version":"1.4.2"
    }"##;

    /// A Service Root that also advertises the 0.2 `EventService`,
    /// `TelemetryService`, and `TaskService` surfaces through their root-level
    /// links, so the service-family reads navigate from the decoded root.
    const CORE_WITH_SERVICES_ROOT_BODY: &str = r#"{
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
        "Managers":{"@odata.id":"/redfish/v1/Managers"},
        "EventService":{"@odata.id":"/redfish/v1/EventService"},
        "TelemetryService":{"@odata.id":"/redfish/v1/TelemetryService"},
        "Tasks":{"@odata.id":"/redfish/v1/TaskService"}
    }"#;

    /// The `EventService` document that advertises the `Subscriptions`
    /// collection; the event-delivery fields are decoded by the schema but
    /// stay outside the projection contract.
    const EVENT_SERVICE_WITH_SUBSCRIPTIONS_BODY: &str = r##"{
        "@odata.type":"#EventService.v1_7_0.EventService",
        "@odata.id":"/redfish/v1/EventService",
        "@odata.etag":"W/\"event-service-1\"",
        "Id":"EventService",
        "Name":"Event Service",
        "Description":"Event subscription and delivery",
        "ServiceEnabled":true,
        "DeliveryRetryAttempts":3,
        "DeliveryRetryIntervalSeconds":30,
        "ServerSentEventUri":"/redfish/v1/EventService/SSE",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "Subscriptions":{"@odata.id":"/redfish/v1/EventService/Subscriptions"}
    }"##;

    const EVENT_SUBSCRIPTIONS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#EventDestinationCollection.EventDestinationCollection",
        "@odata.id":"/redfish/v1/EventService/Subscriptions",
        "Name":"Event Subscription Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/EventService/Subscriptions/1"},
            {"@odata.id":"/redfish/v1/EventService/Subscriptions/2"}
        ]
    }"##;

    /// An advertised but empty `Subscriptions` collection, so the read proves
    /// that an empty subscription family produces no member snapshots.
    const EVENT_SUBSCRIPTIONS_BODY: &str = r##"{
        "@odata.type":"#EventDestinationCollection.EventDestinationCollection",
        "@odata.id":"/redfish/v1/EventService/Subscriptions",
        "Name":"Event Subscription Collection",
        "Members":[]
    }"##;

    /// The full `EventDestination` subscription member projection with every
    /// optional contract field populated; the delivery and filtering fields
    /// are decoded but stay outside the projection contract.
    const EVENT_SUBSCRIPTION_ONE_BODY: &str = r##"{
        "@odata.type":"#EventDestination.v1_14_0.EventDestination",
        "@odata.id":"/redfish/v1/EventService/Subscriptions/1",
        "@odata.etag":"W/\"subscription-1\"",
        "Id":"1",
        "Name":"Webhook Subscription One",
        "Description":"Primary webhook subscription",
        "Destination":"https://events.example.com/hook-1",
        "Protocol":"Redfish",
        "Context":"hook-one",
        "EventTypes":["StatusChange","Alert"],
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "HttpHeaders":[{"Key":"X-Example","Value":"1"}],
        "MessageIds":["Base.1.0.Success"]
    }"##;

    /// A minimal `EventDestination` subscription member: every optional
    /// contract field is absent so the projection omits it instead of
    /// emitting null.
    const EVENT_SUBSCRIPTION_TWO_BODY: &str = r##"{
        "@odata.type":"#EventDestination.v1_14_0.EventDestination",
        "@odata.id":"/redfish/v1/EventService/Subscriptions/2",
        "@odata.etag":"W/\"subscription-2\"",
        "Id":"2",
        "Name":"Webhook Subscription Two",
        "Destination":"https://events.example.com/hook-2"
    }"##;

    /// The `TelemetryService` document that advertises the `MetricDefinitions`
    /// and `MetricReports` collections. `ServiceEnabled` is present on the
    /// wire and decoded by the schema, but the api contract exposes only
    /// `Status`, so the projection must omit it (an extra key would make the
    /// stored snapshot unreadable to the strict application decoder).
    const TELEMETRY_SERVICE_WITH_LINKS_BODY: &str = r##"{
        "@odata.type":"#TelemetryService.v1_4_0.TelemetryService",
        "@odata.id":"/redfish/v1/TelemetryService",
        "@odata.etag":"W/\"telemetry-service-1\"",
        "Id":"TelemetryService",
        "Name":"Telemetry Service",
        "Description":"Telemetry collection and reporting",
        "ServiceEnabled":true,
        "MaxReports":256,
        "MinCollectionInterval":"PT1S",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "MetricDefinitions":{"@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions"},
        "MetricReports":{"@odata.id":"/redfish/v1/TelemetryService/MetricReports"}
    }"##;

    const METRIC_DEFINITIONS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#MetricDefinitionCollection.MetricDefinitionCollection",
        "@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions",
        "Name":"Metric Definition Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions/1"},
            {"@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions/2"}
        ]
    }"##;

    /// An advertised but empty `MetricDefinitions` collection, so the read
    /// proves that an empty definition family produces no member snapshots.
    const METRIC_DEFINITIONS_BODY: &str = r##"{
        "@odata.type":"#MetricDefinitionCollection.MetricDefinitionCollection",
        "@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions",
        "Name":"Metric Definition Collection",
        "Members":[]
    }"##;

    /// The full `MetricDefinition` member projection with every optional
    /// contract field populated; the measurement-semantics fields are decoded
    /// but stay outside the projection contract.
    const METRIC_DEFINITION_ONE_BODY: &str = r##"{
        "@odata.type":"#MetricDefinition.v1_2_0.MetricDefinition",
        "@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions/1",
        "@odata.etag":"W/\"metric-definition-1\"",
        "Id":"1",
        "Name":"Power Consumption",
        "Description":"Instantaneous power consumption",
        "MetricType":"Numeric",
        "MetricDataType":"Integer",
        "Units":"W",
        "Precision":1,
        "MetricProperties":["/redfish/v1/Chassis/1/Power#/0/PowerConsumedWatts"]
    }"##;

    /// A minimal `MetricDefinition` member carrying only the contract fields.
    const METRIC_DEFINITION_TWO_BODY: &str = r##"{
        "@odata.type":"#MetricDefinition.v1_2_0.MetricDefinition",
        "@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions/2",
        "@odata.etag":"W/\"metric-definition-2\"",
        "Id":"2",
        "Name":"Chassis Temperature",
        "MetricType":"Gauge",
        "Units":"Cel"
    }"##;

    const METRIC_REPORTS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#MetricReportCollection.MetricReportCollection",
        "@odata.id":"/redfish/v1/TelemetryService/MetricReports",
        "Name":"Metric Report Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/TelemetryService/MetricReports/1"},
            {"@odata.id":"/redfish/v1/TelemetryService/MetricReports/2"}
        ]
    }"##;

    /// An advertised but empty `MetricReports` collection, so the read proves
    /// that an empty report family produces no member snapshots.
    const METRIC_REPORTS_BODY: &str = r##"{
        "@odata.type":"#MetricReportCollection.MetricReportCollection",
        "@odata.id":"/redfish/v1/TelemetryService/MetricReports",
        "Name":"Metric Report Collection",
        "Members":[]
    }"##;

    /// A `MetricReports` collection with a single member, so the member-skip
    /// test observes one undecodable report without a second member to
    /// confuse the request-order assertion.
    const METRIC_REPORTS_WITH_ONE_MEMBER_BODY: &str = r##"{
        "@odata.type":"#MetricReportCollection.MetricReportCollection",
        "@odata.id":"/redfish/v1/TelemetryService/MetricReports",
        "Name":"Metric Report Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/TelemetryService/MetricReports/1"}
        ]
    }"##;

    /// The full `MetricReport` member fixture: the `MetricValues` array and
    /// the `Timestamp`/`Context` metadata are decoded by the schema, but the
    /// projection carries only the derived `MetricValuesCount`, so every
    /// value-array and metadata key must stay out of the snapshot. `Status`
    /// is not a `MetricReport_v1` property and must stay out as well.
    const METRIC_REPORT_ONE_BODY: &str = r##"{
        "@odata.type":"#MetricReport.v1_4_0.MetricReport",
        "@odata.id":"/redfish/v1/TelemetryService/MetricReports/1",
        "@odata.etag":"W/\"metric-report-1\"",
        "Id":"1",
        "Name":"Power Report",
        "Description":"Average platform power usage",
        "ReportSequence":"1",
        "Timestamp":"2026-08-01T09:30:00Z",
        "Context":"power-context",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "MetricValues":[
            {
                "MetricId":"AverageConsumedWatts",
                "MetricValue":"100",
                "Timestamp":"2026-08-01T09:30:00Z"
            },
            {
                "MetricId":"AverageConsumedWatts",
                "MetricValue":"94",
                "Timestamp":"2026-08-01T09:31:00Z"
            }
        ]
    }"##;

    /// A minimal `MetricReport` member with an empty `MetricValues` array, so
    /// the derived count is asserted as zero instead of absent.
    const METRIC_REPORT_TWO_BODY: &str = r##"{
        "@odata.type":"#MetricReport.v1_4_0.MetricReport",
        "@odata.id":"/redfish/v1/TelemetryService/MetricReports/2",
        "@odata.etag":"W/\"metric-report-2\"",
        "Id":"2",
        "Name":"Temperature Report",
        "MetricValues":[]
    }"##;

    /// The `TaskService` document that advertises the `Tasks` collection; the
    /// service-plumbing fields are decoded by the schema but stay outside the
    /// projection contract.
    const TASK_SERVICE_WITH_TASKS_BODY: &str = r##"{
        "@odata.type":"#TaskService.v1_2_0.TaskService",
        "@odata.id":"/redfish/v1/TaskService",
        "@odata.etag":"W/\"task-service-1\"",
        "Id":"TaskService",
        "Name":"Task Service",
        "Description":"Asynchronous task tracking",
        "ServiceEnabled":true,
        "CompletedTaskOverWritePolicy":"Oldest",
        "TaskAutoDeleteTimeoutMinutes":60,
        "DateTime":"2026-08-01T09:30:00Z",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "Tasks":{"@odata.id":"/redfish/v1/TaskService/Tasks"}
    }"##;

    const TASKS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#TaskCollection.TaskCollection",
        "@odata.id":"/redfish/v1/TaskService/Tasks",
        "Name":"Task Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/TaskService/Tasks/1"},
            {"@odata.id":"/redfish/v1/TaskService/Tasks/2"}
        ]
    }"##;

    /// An advertised but empty `Tasks` collection, so the read proves that an
    /// empty task family produces no member snapshots.
    const TASKS_BODY: &str = r##"{
        "@odata.type":"#TaskCollection.TaskCollection",
        "@odata.id":"/redfish/v1/TaskService/Tasks",
        "Name":"Task Collection",
        "Members":[]
    }"##;

    /// The full `Task` member projection with every optional contract field
    /// populated (the running task carries no `EndTime` yet); the task
    /// plumbing fields are decoded but stay outside the projection contract.
    const TASK_ONE_BODY: &str = r##"{
        "@odata.type":"#Task.v1_7_0.Task",
        "@odata.id":"/redfish/v1/TaskService/Tasks/1",
        "@odata.etag":"W/\"task-1\"",
        "Id":"1",
        "Name":"Firmware Update Task",
        "Description":"Applying firmware update",
        "TaskState":"Running",
        "TaskStatus":"OK",
        "PercentComplete":42,
        "StartTime":"2026-08-01T09:30:00Z",
        "TaskMonitor":"/redfish/v1/TaskService/Tasks/1/Monitor",
        "HidePayload":false
    }"##;

    /// A minimal completed `Task` member: every optional contract field that
    /// the endpoint omitted stays absent so the projection omits it instead
    /// of emitting null.
    const TASK_TWO_BODY: &str = r##"{
        "@odata.type":"#Task.v1_7_0.Task",
        "@odata.id":"/redfish/v1/TaskService/Tasks/2",
        "@odata.etag":"W/\"task-2\"",
        "Id":"2",
        "Name":"Firmware Update Task Two",
        "TaskState":"Completed",
        "TaskStatus":"OK",
        "PercentComplete":100,
        "StartTime":"2026-08-01T09:00:00Z",
        "EndTime":"2026-08-01T09:05:00Z"
    }"##;

    /// The running `Task` document the §13.6 monitor re-reads: every
    /// optional monitor contract field is populated, including the
    /// `TaskMonitor` URI and one progress message.
    const TASK_MONITOR_RUNNING_BODY: &str = r##"{
        "@odata.type":"#Task.v1_7_0.Task",
        "@odata.id":"/redfish/v1/TaskService/Tasks/1",
        "@odata.etag":"W/\"task-1\"",
        "Id":"1",
        "Name":"Firmware Update Task",
        "TaskState":"Running",
        "TaskStatus":"OK",
        "PercentComplete":42,
        "StartTime":"2026-08-01T09:30:00Z",
        "TaskMonitor":"/redfish/v1/TaskService/Tasks/1/Monitor",
        "Messages":[
            {"MessageId":"Base.1.0.Progress","Message":"Firmware update in progress","Severity":"OK"}
        ]
    }"##;

    /// A `Task` document whose `TaskState` is a wire value this build cannot
    /// classify and whose `PercentComplete` is explicitly null, so the
    /// observation surfaces the honest `unsupported_value` code and `None`
    /// instead of inventing a state.
    const TASK_WITH_UNKNOWN_STATE_BODY: &str = r##"{
        "@odata.type":"#Task.v1_7_0.Task",
        "@odata.id":"/redfish/v1/TaskService/Tasks/2",
        "@odata.etag":"W/\"task-2\"",
        "Id":"2",
        "Name":"Future State Task",
        "TaskState":"FutureState",
        "TaskStatus":"Critical",
        "PercentComplete":null
    }"##;

    /// A System member that advertises the 0.2 `PcieDevices` family as an
    /// in-document array of typed links, the presence-type shape the
    /// `ComputerSystem` schema uses instead of a collection resource.
    const SYSTEM_WITH_PCIE_DEVICES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "Description":"Primary compute system",
        "SystemType":"Physical",
        "Manufacturer":"Rutilus Test",
        "Model":"Model S",
        "PCIeDevices":[
            {"@odata.id":"/redfish/v1/Systems/1/PCIeDevices/GPU1"},
            {"@odata.id":"/redfish/v1/Systems/1/PCIeDevices/NIC1"}
        ]
    }"#;

    /// A System member that advertises an empty `PCIeDevices` link array, so
    /// the read proves the presence-type family produces nothing when the
    /// advertised surface has no members.
    const SYSTEM_WITH_EMPTY_PCIE_DEVICES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "PCIeDevices":[]
    }"#;

    /// The full `PCIeDevice` member projection with every optional contract
    /// field populated; the firmware and identity fields are decoded but stay
    /// outside the projection contract.
    const PCIE_DEVICE_GPU_BODY: &str = r##"{
        "@odata.type":"#PCIeDevice.v1_12_0.PCIeDevice",
        "@odata.id":"/redfish/v1/Systems/1/PCIeDevices/GPU1",
        "@odata.etag":"W/\"pcie-device-1\"",
        "Id":"GPU1",
        "Name":"PCIe Device One",
        "Description":"GPU accelerator",
        "DeviceType":"SingleFunction",
        "Manufacturer":"Vendor C",
        "Model":"PCIE-GEN4-X16",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "FirmwareVersion":"1.2.3",
        "SerialNumber":"PCI-SN-1",
        "SKU":"PCI-SKU-1"
    }"##;

    /// A minimal `PCIeDevice` member: every optional contract field is
    /// absent so the projection omits it instead of emitting null.
    const PCIE_DEVICE_NIC_BODY: &str = r##"{
        "@odata.type":"#PCIeDevice.v1_12_0.PCIeDevice",
        "@odata.id":"/redfish/v1/Systems/1/PCIeDevices/NIC1",
        "@odata.etag":"W/\"pcie-device-2\"",
        "Id":"NIC1",
        "Name":"PCIe Device Two",
        "DeviceType":"MultiFunction"
    }"##;

    /// A Chassis member that advertises the 0.2 `Assembly` document.
    const CHASSIS_WITH_ASSEMBLY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "@odata.etag":"W/\"chassis-1\"",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Assembly":{"@odata.id":"/redfish/v1/Chassis/1/Assembly"}
    }"#;

    /// The `Assembly` document that embeds the `Assemblies` link array; the
    /// document itself is not projected, only its members are.
    const ASSEMBLY_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#Assembly.v1_5_0.Assembly",
        "@odata.id":"/redfish/v1/Chassis/1/Assembly",
        "@odata.etag":"W/\"assembly-1\"",
        "Id":"Assembly",
        "Name":"Chassis Assembly",
        "Assemblies":[
            {"@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/0"},
            {"@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/1"}
        ]
    }"##;

    /// The full `AssemblyData` member projection with every optional contract
    /// field populated; the FRU identity fields are decoded but stay outside
    /// the projection contract.
    const ASSEMBLY_FAN_BODY: &str = r##"{
        "@odata.type":"#Assembly.v1_5_0.AssemblyData",
        "@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
        "@odata.etag":"W/\"assembly-data-0\"",
        "MemberId":"0",
        "Name":"Fan Assembly",
        "Description":"Cooling fan",
        "Producer":"Vendor D",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "Model":"FRU-MODEL-X",
        "SerialNumber":"FRU-1",
        "Version":"1.0"
    }"##;

    /// A minimal `AssemblyData` member: every optional contract field is
    /// absent so the projection omits it instead of emitting null.
    const ASSEMBLY_PSU_BODY: &str = r##"{
        "@odata.type":"#Assembly.v1_5_0.AssemblyData",
        "@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/1",
        "@odata.etag":"W/\"assembly-data-1\"",
        "MemberId":"1",
        "Name":"Power Supply Assembly",
        "Producer":"Vendor E"
    }"##;

    /// An `Assembly` document embedding a single `AssemblyData` member that
    /// carries no `Name` property, so the projection exercises the empty-name
    /// fallback of the common payload.
    const ASSEMBLY_WITH_UNNAMED_MEMBER_BODY: &str = r##"{
        "@odata.type":"#Assembly.v1_5_0.Assembly",
        "@odata.id":"/redfish/v1/Chassis/1/Assembly",
        "Id":"Assembly",
        "Name":"Chassis Assembly",
        "Assemblies":[
            {"@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/0"}
        ]
    }"##;

    /// A minimal `AssemblyData` member without the optional `Name` property:
    /// the schema decodes it, and the projection falls back to the empty
    /// string so the strict application decoder still reads the snapshot.
    const ASSEMBLY_UNNAMED_BODY: &str = r##"{
        "@odata.type":"#Assembly.v1_5_0.AssemblyData",
        "@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
        "@odata.etag":"W/\"assembly-data-0\"",
        "MemberId":"0",
        "Producer":"Vendor D",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A System member that advertises the 0.2 `Bios`, `BootOptions` (inside
    /// the `Boot` property), and `SecureBoot` configuration surfaces.
    const SYSTEM_WITH_CONFIG_FEATURES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "Description":"Primary compute system",
        "SystemType":"Physical",
        "Bios":{"@odata.id":"/redfish/v1/Systems/1/Bios"},
        "Boot":{"BootOptions":{"@odata.id":"/redfish/v1/Systems/1/BootOptions"}},
        "SecureBoot":{"@odata.id":"/redfish/v1/Systems/1/SecureBoot"}
    }"#;

    /// The full `Bios` singleton projection: `Attributes` is decoded by the
    /// schema but must stay out of the snapshot, because it is not part of
    /// the contract and the strict application decoder rejects it.
    const BIOS_FULL_BODY: &str = r##"{
        "@odata.type":"#Bios.v1_2_0.Bios",
        "@odata.id":"/redfish/v1/Systems/1/Bios",
        "@odata.etag":"W/\"bios-1\"",
        "Id":"Bios",
        "Name":"BIOS Configuration",
        "Description":"BIOS attribute registry",
        "AttributeRegistry":"BiosAttributeRegistryP11.v1_2_0",
        "ResetBiosToDefaultsPending":false,
        "Attributes":{"BootMode":"Uefi","QuietBoot":"Enabled"}
    }"##;

    const BOOT_OPTIONS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#BootOptionCollection.BootOptionCollection",
        "@odata.id":"/redfish/v1/Systems/1/BootOptions",
        "Name":"Boot Option Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Systems/1/BootOptions/1"},
            {"@odata.id":"/redfish/v1/Systems/1/BootOptions/2"}
        ]
    }"##;

    /// The full `BootOption` member projection with every optional contract
    /// field populated; `RelatedItem` is decoded but stays outside the
    /// projection contract.
    const BOOT_OPTION_ONE_BODY: &str = r##"{
        "@odata.type":"#BootOption.v1_1_0.BootOption",
        "@odata.id":"/redfish/v1/Systems/1/BootOptions/1",
        "@odata.etag":"W/\"boot-option-1\"",
        "Id":"1",
        "Name":"Boot Option One",
        "Description":"UEFI PXE boot option",
        "BootOptionReference":"Boot0001",
        "DisplayName":"UEFI PXE IP4 Intel",
        "BootOptionEnabled":true,
        "UefiDevicePath":"PciRoot(0x0)/Pci(0x1C,0x4)",
        "Alias":"Pxe",
        "RelatedItem":[{"@odata.id":"/redfish/v1/Systems/1"}]
    }"##;

    /// A minimal `BootOption` member carrying only the required
    /// `BootOptionReference`.
    const BOOT_OPTION_TWO_BODY: &str = r##"{
        "@odata.type":"#BootOption.v1_1_0.BootOption",
        "@odata.id":"/redfish/v1/Systems/1/BootOptions/2",
        "@odata.etag":"W/\"boot-option-2\"",
        "Id":"2",
        "Name":"Boot Option Two",
        "BootOptionReference":"Boot0002"
    }"##;

    /// The full `SecureBoot` singleton projection with every optional
    /// contract field populated; `SecureBootDatabases` stays outside the
    /// projection contract.
    const SECURE_BOOT_FULL_BODY: &str = r##"{
        "@odata.type":"#SecureBoot.v1_1_0.SecureBoot",
        "@odata.id":"/redfish/v1/Systems/1/SecureBoot",
        "@odata.etag":"W/\"secure-boot-1\"",
        "Id":"SecureBoot",
        "Name":"Secure Boot",
        "Description":"UEFI Secure Boot configuration",
        "SecureBootEnable":true,
        "SecureBootCurrentBoot":"Enabled",
        "SecureBootMode":"UserMode"
    }"##;

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

    /// A Manager member that advertises the 0.2 `LogServices`,
    /// `NetworkProtocol`, and `HostInterfaces` surfaces.
    const MANAGER_WITH_MANAGER_FAMILIES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "LogServices":{"@odata.id":"/redfish/v1/Managers/1/LogServices"},
        "NetworkProtocol":{"@odata.id":"/redfish/v1/Managers/1/NetworkProtocol"},
        "HostInterfaces":{"@odata.id":"/redfish/v1/Managers/1/HostInterfaces"}
    }"#;

    const LOG_SERVICES_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#LogServiceCollection.LogServiceCollection",
        "@odata.id":"/redfish/v1/Managers/1/LogServices",
        "Name":"Log Service Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Managers/1/LogServices/SEL"},
            {"@odata.id":"/redfish/v1/Managers/1/LogServices/Audit"}
        ]
    }"##;

    /// The full `LogService` member projection: the retention bound and the
    /// overwrite policy are decoded but only the contract fields may leave
    /// the gateway, and the linked `LogEntryCollection` is never fetched.
    const LOG_SERVICE_ONE_BODY: &str = r##"{
        "@odata.type":"#LogService.v1_9_0.LogService",
        "@odata.id":"/redfish/v1/Managers/1/LogServices/SEL",
        "@odata.etag":"W/\"log-service-1\"",
        "Id":"SEL",
        "Name":"System Event Log",
        "Description":"System event log service",
        "ServiceEnabled":true,
        "MaxNumberOfRecords":10000,
        "OverWritePolicy":"WrapsWhenFull",
        "LogEntryType":"SEL",
        "DateTime":"2026-08-05T10:11:12Z",
        "Entries":{"@odata.id":"/redfish/v1/Managers/1/LogServices/SEL/Entries"},
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A minimal `LogService` member: absent optional fields must be omitted
    /// from the projection, never emitted as null.
    const LOG_SERVICE_TWO_BODY: &str = r##"{
        "@odata.type":"#LogService.v1_9_0.LogService",
        "@odata.id":"/redfish/v1/Managers/1/LogServices/Audit",
        "@odata.etag":"W/\"log-service-2\"",
        "Id":"Audit",
        "Name":"Audit Log"
    }"##;

    /// The full `ManagerNetworkProtocol` singleton projection with the
    /// top-level metadata populated and the per-protocol settings nested in
    /// their own `Protocol` objects.
    const NETWORK_PROTOCOL_FULL_BODY: &str = r##"{
        "@odata.type":"#ManagerNetworkProtocol.v1_12_0.ManagerNetworkProtocol",
        "@odata.id":"/redfish/v1/Managers/1/NetworkProtocol",
        "@odata.etag":"W/\"network-protocol-1\"",
        "Id":"NetworkProtocol",
        "Name":"Manager Network Protocol",
        "Description":"Network services for this manager",
        "HostName":"bmc-rack-a",
        "FQDN":"bmc-rack-a.example.test",
        "HTTP":{"ProtocolEnabled":true,"Port":80},
        "HTTPS":{"ProtocolEnabled":true,"Port":443},
        "SSH":{"ProtocolEnabled":true,"Port":22},
        "SNMP":{"ProtocolEnabled":false,"Port":161},
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    const HOST_INTERFACES_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#HostInterfaceCollection.HostInterfaceCollection",
        "@odata.id":"/redfish/v1/Managers/1/HostInterfaces",
        "Name":"Host Interface Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Managers/1/HostInterfaces/1"},
            {"@odata.id":"/redfish/v1/Managers/1/HostInterfaces/2"}
        ]
    }"##;

    /// The full `HostInterface` member projection with every optional
    /// contract field populated; the host-facing ethernet links are decoded
    /// but stay outside the projection contract.
    const HOST_INTERFACE_ONE_BODY: &str = r##"{
        "@odata.type":"#HostInterface.v1_3_3.HostInterface",
        "@odata.id":"/redfish/v1/Managers/1/HostInterfaces/1",
        "@odata.etag":"W/\"host-interface-1\"",
        "Id":"1",
        "Name":"Host Interface One",
        "Description":"Local host communication interface",
        "HostInterfaceType":"NetworkHostInterface",
        "InterfaceEnabled":true,
        "ExternallyAccessible":false,
        "AuthenticationModes":["BasicAuth","RedfishSessionAuth"],
        "HostEthernetInterfaces":{"@odata.id":"/redfish/v1/Systems/1/EthernetInterfaces"},
        "ManagerEthernetInterface":{"@odata.id":"/redfish/v1/Managers/1/EthernetInterfaces/1"},
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A minimal `HostInterface` member: absent optional fields must be
    /// omitted from the projection, never emitted as null.
    const HOST_INTERFACE_TWO_BODY: &str = r##"{
        "@odata.type":"#HostInterface.v1_3_3.HostInterface",
        "@odata.id":"/redfish/v1/Managers/1/HostInterfaces/2",
        "@odata.etag":"W/\"host-interface-2\"",
        "Id":"2",
        "Name":"Host Interface Two"
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

    /// A Chassis member that advertises the 0.2 `Power`, `Thermal`,
    /// `Sensors`, and `Controls` telemetry surface.
    const CHASSIS_WITH_TELEMETRY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "@odata.etag":"W/\"chassis-1\"",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Power":{"@odata.id":"/redfish/v1/Chassis/1/Power"},
        "Thermal":{"@odata.id":"/redfish/v1/Chassis/1/Thermal"},
        "Sensors":{"@odata.id":"/redfish/v1/Chassis/1/Sensors"},
        "Controls":{"@odata.id":"/redfish/v1/Chassis/1/Controls"}
    }"#;

    /// A Chassis member that advertises only the `Power` and `Thermal`
    /// telemetry singletons, so a missing `Sensors` or `Controls` link stays
    /// absent without an error.
    const CHASSIS_WITH_POWER_AND_THERMAL_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "@odata.etag":"W/\"chassis-1\"",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Power":{"@odata.id":"/redfish/v1/Chassis/1/Power"},
        "Thermal":{"@odata.id":"/redfish/v1/Chassis/1/Thermal"}
    }"#;

    /// The full `Power` singleton projection: the `PowerControl` member is
    /// embedded with its capacity reading, while `Voltages`, `PowerSupplies`,
    /// and `Redundancy` stay linked only, so the projection must keep every
    /// non-contract field out of the snapshot.
    const POWER_FULL_BODY: &str = r##"{
        "@odata.type":"#Power.v1_7_0.Power",
        "@odata.id":"/redfish/v1/Chassis/1/Power",
        "@odata.etag":"W/\"power-1\"",
        "Id":"Power",
        "Name":"Chassis Power",
        "Description":"Chassis power readings and limits",
        "PowerControl":[
            {
                "@odata.id":"/redfish/v1/Chassis/1/Power/PowerControl/0",
                "MemberId":"0",
                "Name":"System Power Control",
                "PowerCapacityWatts":2500,
                "PowerConsumedWatts":850,
                "PowerRequestedWatts":900,
                "PowerAvailableWatts":1600,
                "PowerAllocatedWatts":900
            }
        ],
        "Voltages":[{"@odata.id":"/redfish/v1/Chassis/1/Power/Voltages/0"}],
        "PowerSupplies":[{"@odata.id":"/redfish/v1/Chassis/1/Power/PowerSupplies/0"}],
        "Redundancy":[{"@odata.id":"/redfish/v1/Chassis/1/Power/Redundancy/0"}]
    }"##;

    /// The full `Thermal` singleton projection: two `Temperatures` members
    /// are embedded with readings, while `Fans` stays linked only, so the
    /// projection must keep every non-contract field out of the snapshot.
    const THERMAL_FULL_BODY: &str = r##"{
        "@odata.type":"#Thermal.v1_7_0.Thermal",
        "@odata.id":"/redfish/v1/Chassis/1/Thermal",
        "@odata.etag":"W/\"thermal-1\"",
        "Id":"Thermal",
        "Name":"Chassis Thermal",
        "Description":"Chassis thermal readings",
        "Temperatures":[
            {
                "@odata.id":"/redfish/v1/Chassis/1/Thermal/Temperatures/0",
                "MemberId":"0",
                "Name":"CPU 1 Temp",
                "ReadingCelsius":42.5,
                "UpperThresholdCritical":70.0,
                "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
            },
            {
                "@odata.id":"/redfish/v1/Chassis/1/Thermal/Temperatures/1",
                "MemberId":"1",
                "Name":"Inlet Temp",
                "ReadingCelsius":25.0
            }
        ],
        "Fans":[{"@odata.id":"/redfish/v1/Chassis/1/Thermal/Fans/0"}],
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    const SENSORS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#SensorCollection.SensorCollection",
        "@odata.id":"/redfish/v1/Chassis/1/Sensors",
        "Name":"Sensor Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Chassis/1/Sensors/1"},
            {"@odata.id":"/redfish/v1/Chassis/1/Sensors/2"}
        ]
    }"##;

    /// The full `Sensor` member projection with every optional contract field
    /// populated; the threshold and range bags are decoded but stay outside
    /// the projection contract.
    const SENSOR_ONE_BODY: &str = r##"{
        "@odata.type":"#Sensor.v1_7_0.Sensor",
        "@odata.id":"/redfish/v1/Chassis/1/Sensors/1",
        "@odata.etag":"W/\"sensor-1\"",
        "Id":"1",
        "Name":"CPU 1 Temperature Sensor",
        "Description":"CPU package temperature",
        "ReadingType":"Temperature",
        "Reading":47.5,
        "ReadingUnits":"Cel",
        "ReadingRangeMin":0,
        "ReadingRangeMax":100,
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A minimal `Sensor` member carrying only the required identity fields
    /// plus a `Power` reading; every optional contract field is absent so the
    /// projection omits it instead of emitting null.
    const SENSOR_TWO_BODY: &str = r##"{
        "@odata.type":"#Sensor.v1_7_0.Sensor",
        "@odata.id":"/redfish/v1/Chassis/1/Sensors/2",
        "@odata.etag":"W/\"sensor-2\"",
        "Id":"2",
        "Name":"Power Sensor",
        "ReadingType":"Power",
        "Reading":300.0,
        "ReadingUnits":"W"
    }"##;

    const CONTROLS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#ControlCollection.ControlCollection",
        "@odata.id":"/redfish/v1/Chassis/1/Controls",
        "Name":"Control Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Chassis/1/Controls/1"},
            {"@odata.id":"/redfish/v1/Chassis/1/Controls/2"}
        ]
    }"##;

    /// The full `Control` member projection with every optional contract
    /// field populated; the setting ranges are decoded but stay outside the
    /// projection contract.
    const CONTROL_ONE_BODY: &str = r##"{
        "@odata.type":"#Control.v1_4_0.Control",
        "@odata.id":"/redfish/v1/Chassis/1/Controls/1",
        "@odata.etag":"W/\"control-1\"",
        "Id":"1",
        "Name":"System Power Limit",
        "Description":"Power capping control",
        "ControlType":"Power",
        "SetPoint":1800,
        "SetPointUnits":"W",
        "SettingMin":0,
        "SettingMax":2500,
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// A minimal `Control` member carrying only the required identity fields
    /// plus a `Temperature` set point; every optional contract field is
    /// absent so the projection omits it instead of emitting null.
    const CONTROL_TWO_BODY: &str = r##"{
        "@odata.type":"#Control.v1_4_0.Control",
        "@odata.id":"/redfish/v1/Chassis/1/Controls/2",
        "@odata.etag":"W/\"control-2\"",
        "Id":"2",
        "Name":"Chassis Fan Control",
        "ControlType":"Temperature",
        "SetPoint":35.0
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

    /// The request order for one Manager member that carries populated
    /// `LogServices`, `NetworkProtocol`, and `HostInterfaces` surfaces: the
    /// families are read right after their parent, before the Session
    /// cleanup. The `LogServices` members are fetched individually, then the
    /// `NetworkProtocol` singleton, then the `HostInterfaces` members.
    const MANAGER_FAMILY_RESOURCE_REQUEST_PATHS: [&str; 18] = [
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
        "/redfish/v1/Managers/1/LogServices",
        "/redfish/v1/Managers/1/LogServices/SEL",
        "/redfish/v1/Managers/1/LogServices/Audit",
        "/redfish/v1/Managers/1/NetworkProtocol",
        "/redfish/v1/Managers/1/HostInterfaces",
        "/redfish/v1/Managers/1/HostInterfaces/1",
        "/redfish/v1/Managers/1/HostInterfaces/2",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `LogServices` and `HostInterfaces`
    /// collections are advertised but empty: the collection documents are
    /// still read, no member is, and the `NetworkProtocol` singleton is read
    /// because its link is present.
    const EMPTY_MANAGER_FAMILY_REQUEST_PATHS: [&str; 14] = [
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
        "/redfish/v1/Managers/1/LogServices",
        "/redfish/v1/Managers/1/NetworkProtocol",
        "/redfish/v1/Managers/1/HostInterfaces",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when a Manager member advertises none of the three
    /// families: the collection and singleton URIs are never requested.
    const ABSENT_MANAGER_FAMILY_REQUEST_PATHS: [&str; 11] = [
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
    /// `Bios`, `BootOptions`, and `SecureBoot` surfaces: the configuration
    /// families are read right after their parent, before the sibling
    /// collections.
    const CONFIG_FAMILY_REQUEST_PATHS: [&str; 16] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Bios",
        "/redfish/v1/Systems/1/BootOptions",
        "/redfish/v1/Systems/1/BootOptions/1",
        "/redfish/v1/Systems/1/BootOptions/2",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for the root-level `Accounts` family read: the
    /// `AccountService` document and its `Accounts` collection are requested
    /// after the manager families, before the Session cleanup.
    const ACCOUNTS_RESOURCE_REQUEST_PATHS: [&str; 15] = [
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
        "/redfish/v1/AccountService/Accounts",
        "/redfish/v1/AccountService/Accounts/1",
        "/redfish/v1/AccountService/Accounts/2",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `AccountService` advertises no `Accounts`
    /// link: the `AccountService` document is still read, no account member
    /// is.
    const ABSENT_FAMILY_REQUEST_PATHS: [&str; 12] = [
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
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `BootOptions` and `Accounts` collections
    /// are advertised but empty: the collection documents are still read, no
    /// member is.
    const EMPTY_CONFIG_FAMILY_REQUEST_PATHS: [&str; 16] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Bios",
        "/redfish/v1/Systems/1/BootOptions",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/AccountService",
        "/redfish/v1/AccountService/Accounts",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `Bios` singleton and the second
    /// `BootOption` member are undecodable: their URIs are still requested
    /// (that is how the skip is observed), then the remaining configuration
    /// families complete.
    const SINGLETON_SKIP_REQUEST_PATHS: [&str; 16] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Bios",
        "/redfish/v1/Systems/1/BootOptions",
        "/redfish/v1/Systems/1/BootOptions/1",
        "/redfish/v1/Systems/1/BootOptions/2",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `AccountService` document is undecodable:
    /// the failing singleton URI is still requested, the whole `Accounts`
    /// family is skipped with the member-level semantics, and the read
    /// completes.
    const ACCOUNT_SERVICE_SKIP_REQUEST_PATHS: [&str; 12] = [
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
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for the complete 0.2 device-family read: every
    /// `PCIeDevices` link of the System member, the `Assembly` document and
    /// its `AssemblyData` members, and the `UpdateService` document plus the
    /// `SoftwareInventory` collection members are fetched individually.
    const DEVICE_FAMILY_RESOURCE_REQUEST_PATHS: [&str; 20] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/PCIeDevices/GPU1",
        "/redfish/v1/Systems/1/PCIeDevices/NIC1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Assembly",
        // The `AssemblyData` member URIs embed a JSON-pointer fragment; the
        // transport percent-encodes the `#` as `%23` on the wire.
        "/redfish/v1/Chassis/1/Assembly%23/Assemblies/0",
        "/redfish/v1/Chassis/1/Assembly%23/Assemblies/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/UpdateService",
        "/redfish/v1/UpdateService/SoftwareInventory",
        "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
        "/redfish/v1/UpdateService/SoftwareInventory/BMC",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when none of the three device families are
    /// advertised: the `UpdateService` document is still read, no
    /// `SoftwareInventory` member is, and the System/Chassis members
    /// advertise neither `PCIeDevices` nor `Assembly`.
    const ABSENT_DEVICE_FAMILY_REQUEST_PATHS: [&str; 12] = [
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
        "/redfish/v1/UpdateService",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the advertised device surfaces are empty: the
    /// empty `PCIeDevices` array and the `Assembly` document and the empty
    /// `SoftwareInventory` collection are still read, no member is.
    const EMPTY_DEVICE_FAMILY_REQUEST_PATHS: [&str; 14] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Assembly",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/UpdateService",
        "/redfish/v1/UpdateService/SoftwareInventory",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the second `PCIeDevice`, the second
    /// `AssemblyData`, and the second `SoftwareInventory` members are
    /// undecodable: their URIs are still requested (that is how the skip is
    /// observed), then the remaining device families complete.
    const DEVICE_MEMBER_SKIP_REQUEST_PATHS: [&str; 20] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/PCIeDevices/GPU1",
        "/redfish/v1/Systems/1/PCIeDevices/NIC1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Assembly",
        // The `AssemblyData` member URIs embed a JSON-pointer fragment; the
        // transport percent-encodes the `#` as `%23` on the wire.
        "/redfish/v1/Chassis/1/Assembly%23/Assemblies/0",
        "/redfish/v1/Chassis/1/Assembly%23/Assemblies/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/UpdateService",
        "/redfish/v1/UpdateService/SoftwareInventory",
        "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
        "/redfish/v1/UpdateService/SoftwareInventory/BMC",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for the single unnamed `AssemblyData` member: the
    /// `Assembly` document and its one member are fetched through the Chassis
    /// navigation, and no other family makes a request.
    const UNNAMED_ASSEMBLY_REQUEST_PATHS: [&str; 13] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Assembly",
        // The `AssemblyData` member URI embeds a JSON-pointer fragment; the
        // transport percent-encodes the `#` as `%23` on the wire.
        "/redfish/v1/Chassis/1/Assembly%23/Assemblies/0",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the first account member is undecodable: its
    /// URI is still requested (that is how the skip is observed), then the
    /// second account member completes the family.
    const ACCOUNT_MEMBER_SKIP_REQUEST_PATHS: [&str; 15] = [
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
        "/redfish/v1/AccountService/Accounts",
        "/redfish/v1/AccountService/Accounts/1",
        "/redfish/v1/AccountService/Accounts/2",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one Chassis member that carries populated
    /// `Power`, `Thermal`, `Sensors`, and `Controls` surfaces: the telemetry
    /// families are read right after their parent, in fixture order.
    const TELEMETRY_RESOURCE_REQUEST_PATHS: [&str; 19] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Power",
        "/redfish/v1/Chassis/1/Thermal",
        "/redfish/v1/Chassis/1/Sensors",
        "/redfish/v1/Chassis/1/Sensors/1",
        "/redfish/v1/Chassis/1/Sensors/2",
        "/redfish/v1/Chassis/1/Controls",
        "/redfish/v1/Chassis/1/Controls/1",
        "/redfish/v1/Chassis/1/Controls/2",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `Sensors` and `Controls` collections are
    /// advertised but empty: the collection documents are still read, no
    /// member is; the singletons are still projected.
    const EMPTY_TELEMETRY_REQUEST_PATHS: [&str; 15] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Power",
        "/redfish/v1/Chassis/1/Thermal",
        "/redfish/v1/Chassis/1/Sensors",
        "/redfish/v1/Chassis/1/Controls",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the Chassis member advertises the `Power` and
    /// `Thermal` singletons but no `Sensors` or `Controls` link: the missing
    /// collections are never requested ("资源存在才呈现").
    const PARTIAL_TELEMETRY_REQUEST_PATHS: [&str; 13] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Power",
        "/redfish/v1/Chassis/1/Thermal",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for the complete 0.2 service-family read: the
    /// `EventService` singleton and its `Subscriptions` members, the
    /// `TelemetryService` singleton and its `MetricDefinitions` and
    /// `MetricReports` members, and the `TaskService` singleton and its
    /// `Tasks` members are read after the manager families, before the
    /// Session cleanup.
    const SERVICES_RESOURCE_REQUEST_PATHS: [&str; 26] = [
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
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions",
        "/redfish/v1/EventService/Subscriptions/1",
        "/redfish/v1/EventService/Subscriptions/2",
        "/redfish/v1/TelemetryService",
        "/redfish/v1/TelemetryService/MetricDefinitions",
        "/redfish/v1/TelemetryService/MetricDefinitions/1",
        "/redfish/v1/TelemetryService/MetricDefinitions/2",
        "/redfish/v1/TelemetryService/MetricReports",
        "/redfish/v1/TelemetryService/MetricReports/1",
        "/redfish/v1/TelemetryService/MetricReports/2",
        "/redfish/v1/TaskService",
        "/redfish/v1/TaskService/Tasks",
        "/redfish/v1/TaskService/Tasks/1",
        "/redfish/v1/TaskService/Tasks/2",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when none of the three service links is advertised:
    /// the service URIs are never requested ("资源存在才呈现").
    const ABSENT_SERVICES_REQUEST_PATHS: [&str; 11] = [
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

    /// The request order when the three service singletons are advertised but
    /// every collection below them is empty: the collection documents are
    /// still read, no member is, and the three singletons are projected.
    const EMPTY_SERVICES_REQUEST_PATHS: [&str; 18] = [
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
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions",
        "/redfish/v1/TelemetryService",
        "/redfish/v1/TelemetryService/MetricDefinitions",
        "/redfish/v1/TelemetryService/MetricReports",
        "/redfish/v1/TaskService",
        "/redfish/v1/TaskService/Tasks",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when the `EventService` and `TaskService` singletons
    /// are undecodable and the second `MetricDefinition` member is
    /// undecodable: the failing URIs are still requested (that is how the
    /// skip is observed), the skipped families complete around them, and the
    /// `MetricReports` member failure is skipped the same way.
    const SERVICES_SKIP_REQUEST_PATHS: [&str; 19] = [
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
        "/redfish/v1/EventService",
        "/redfish/v1/TelemetryService",
        "/redfish/v1/TelemetryService/MetricDefinitions",
        "/redfish/v1/TelemetryService/MetricDefinitions/1",
        "/redfish/v1/TelemetryService/MetricDefinitions/2",
        "/redfish/v1/TelemetryService/MetricReports",
        "/redfish/v1/TelemetryService/MetricReports/1",
        "/redfish/v1/TaskService",
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
    async fn reads_manager_families_through_typed_manager_navigation() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_MANAGER_FAMILIES_BODY),
                ("200 OK", LOG_SERVICES_WITH_MEMBERS_BODY),
                ("200 OK", LOG_SERVICE_ONE_BODY),
                ("200 OK", LOG_SERVICE_TWO_BODY),
                ("200 OK", NETWORK_PROTOCOL_FULL_BODY),
                ("200 OK", HOST_INTERFACES_WITH_MEMBERS_BODY),
                ("200 OK", HOST_INTERFACE_ONE_BODY),
                ("200 OK", HOST_INTERFACE_TWO_BODY),
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

        assert_eq!(resources.len(), 9);
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
                ResourceFeature::LogServices,
                ResourceFeature::LogServices,
                ResourceFeature::ManagerNetworkProtocol,
                ResourceFeature::HostInterfaces,
                ResourceFeature::HostInterfaces,
            ]
        );
        assert_log_service_projection(&resources[4])?;
        assert_minimal_log_service_projection(&resources[5])?;
        assert_manager_network_protocol_projection(&resources[6])?;
        assert_host_interface_projection(&resources[7])?;
        assert_minimal_host_interface_projection(&resources[8])?;
        assert_session_requests(
            &server.finish_all().await?,
            &MANAGER_FAMILY_RESOURCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    /// Asserts the full `LogService` member projection with every optional
    /// contract field populated. Only the contract fields may leave the
    /// gateway: the decoded schema fields that are not part of the contract
    /// must stay out of the snapshot or the strict application decoder
    /// rejects it, and the linked `LogEntryCollection` is never fetched.
    fn assert_log_service_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Managers/1/LogServices/SEL"
        );
        assert_eq!(
            projection.etag().map(ResourceEtag::as_str),
            Some("W/\"log-service-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["ServiceEnabled"], true);
        assert_eq!(payload["MaxNumberOfRecords"], 10000);
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("OverWritePolicy"), None);
        assert_eq!(payload.get("LogEntryType"), None);
        assert_eq!(payload.get("DateTime"), None);
        assert_eq!(payload.get("Entries"), None);
        Ok(())
    }

    /// Asserts the minimal `LogService` member projection: every optional
    /// contract field is absent and must be omitted, not emitted as null.
    fn assert_minimal_log_service_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Managers/1/LogServices/Audit"
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Id"], "Audit");
        assert_eq!(payload.get("ServiceEnabled"), None);
        assert_eq!(payload.get("MaxNumberOfRecords"), None);
        assert_eq!(payload.get("Status"), None);
        Ok(())
    }

    /// Asserts the full `ManagerNetworkProtocol` singleton projection with
    /// every optional contract field populated; the per-protocol settings are
    /// nested `Protocol` objects that stay out of the strictly projectable
    /// field set.
    fn assert_manager_network_protocol_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Managers/1/NetworkProtocol",
            "W/\"network-protocol-1\"",
            "HostName",
            "bmc-rack-a",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["FQDN"], "bmc-rack-a.example.test");
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("HTTP"), None);
        assert_eq!(payload.get("HTTPS"), None);
        assert_eq!(payload.get("SSH"), None);
        assert_eq!(payload.get("SNMP"), None);
        Ok(())
    }

    /// Asserts the full `HostInterface` member projection with every optional
    /// contract field populated; the host-facing ethernet links and the
    /// authentication sections stay out.
    fn assert_host_interface_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Managers/1/HostInterfaces/1"
        );
        assert_eq!(
            projection.etag().map(ResourceEtag::as_str),
            Some("W/\"host-interface-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["InterfaceEnabled"], true);
        assert_eq!(payload["HostInterfaceType"], "NetworkHostInterface");
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("ExternallyAccessible"), None);
        assert_eq!(payload.get("AuthenticationModes"), None);
        assert_eq!(payload.get("HostEthernetInterfaces"), None);
        assert_eq!(payload.get("ManagerEthernetInterface"), None);
        Ok(())
    }

    /// Asserts the minimal `HostInterface` member projection: every optional
    /// contract field is absent and must be omitted, not emitted as null.
    fn assert_minimal_host_interface_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Managers/1/HostInterfaces/2"
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Id"], "2");
        assert_eq!(payload.get("InterfaceEnabled"), None);
        assert_eq!(payload.get("HostInterfaceType"), None);
        assert_eq!(payload.get("Status"), None);
        Ok(())
    }

    #[tokio::test]
    async fn absent_manager_family_links_produce_no_family_snapshots() -> Result<(), Box<dyn Error>>
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

        // The Manager member advertises no LogServices, NetworkProtocol, or
        // HostInterfaces links, so none of the three families produce
        // snapshots ("资源存在才呈现").
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
        assert_session_requests(
            &server.finish_all().await?,
            &ABSENT_MANAGER_FAMILY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn empty_manager_family_collections_produce_no_member_snapshots()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_MANAGER_FAMILIES_BODY),
                ("200 OK", LOG_SERVICES_BODY),
                ("200 OK", NETWORK_PROTOCOL_FULL_BODY),
                ("200 OK", HOST_INTERFACES_BODY),
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

        // The advertised-but-empty LogServices and HostInterfaces
        // collections produce no member snapshots, while the NetworkProtocol
        // singleton is still read because its link is present
        // ("资源存在才呈现").
        assert_eq!(resources.len(), 5);
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
                ResourceFeature::ManagerNetworkProtocol,
            ]
        );
        assert_eq!(
            resources[4].odata_id().as_str(),
            "/redfish/v1/Managers/1/NetworkProtocol"
        );
        assert_session_requests(
            &server.finish_all().await?,
            &EMPTY_MANAGER_FAMILY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_undecodable_manager_family_members_and_singleton_without_aborting()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_MANAGER_FAMILIES_BODY),
                ("200 OK", LOG_SERVICES_WITH_MEMBERS_BODY),
                ("200 OK", LOG_SERVICE_ONE_BODY),
                ("200 OK", "{}"),
                ("200 OK", "{}"),
                ("200 OK", HOST_INTERFACES_WITH_MEMBERS_BODY),
                ("200 OK", HOST_INTERFACE_ONE_BODY),
                ("200 OK", HOST_INTERFACE_TWO_BODY),
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

        // The undecodable second LogService member and the undecodable
        // NetworkProtocol singleton are skipped; the readable members of
        // every family still produce snapshots (§0.2.0 acceptance, singleton
        // failure treated as member-level skip).
        assert_eq!(resources.len(), 7);
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
                ResourceFeature::LogServices,
                ResourceFeature::HostInterfaces,
                ResourceFeature::HostInterfaces,
            ]
        );
        assert_eq!(
            resources[4].odata_id().as_str(),
            "/redfish/v1/Managers/1/LogServices/SEL"
        );
        assert_eq!(
            resources[5].odata_id().as_str(),
            "/redfish/v1/Managers/1/HostInterfaces/1"
        );
        assert_session_requests(
            &server.finish_all().await?,
            &MANAGER_FAMILY_RESOURCE_REQUEST_PATHS,
        )?;
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
    async fn reads_configuration_families_through_typed_system_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_CONFIG_FEATURES_BODY),
                ("200 OK", BIOS_FULL_BODY),
                ("200 OK", BOOT_OPTIONS_WITH_MEMBERS_BODY),
                ("200 OK", BOOT_OPTION_ONE_BODY),
                ("200 OK", BOOT_OPTION_TWO_BODY),
                ("200 OK", SECURE_BOOT_FULL_BODY),
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

        assert_eq!(resources.len(), 8);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Bios,
                ResourceFeature::BootOptions,
                ResourceFeature::BootOptions,
                ResourceFeature::SecureBoot,
                ResourceFeature::Chassis,
                ResourceFeature::Managers,
            ]
        );
        assert_projection(
            &resources[2],
            "/redfish/v1/Systems/1/Bios",
            "W/\"bios-1\"",
            "AttributeRegistry",
            "BiosAttributeRegistryP11.v1_2_0",
        )?;
        let bios_payload: serde_json::Value =
            serde_json::from_str(resources[2].payload().as_str())?;
        assert_eq!(bios_payload["ResetBiosToDefaultsPending"], false);
        // Only the contract fields may leave the gateway; the decoded
        // schema fields that are not part of the contract must stay out of
        // the snapshot or the strict application decoder rejects it.
        assert_eq!(bios_payload.get("Attributes"), None);
        assert_projection(
            &resources[3],
            "/redfish/v1/Systems/1/BootOptions/1",
            "W/\"boot-option-1\"",
            "BootOptionReference",
            "Boot0001",
        )?;
        let option_payload: serde_json::Value =
            serde_json::from_str(resources[3].payload().as_str())?;
        assert_eq!(option_payload["DisplayName"], "UEFI PXE IP4 Intel");
        assert_eq!(option_payload["BootOptionEnabled"], true);
        assert_eq!(
            option_payload["UefiDevicePath"],
            "PciRoot(0x0)/Pci(0x1C,0x4)"
        );
        assert_eq!(option_payload["Alias"], "Pxe");
        assert_eq!(option_payload.get("RelatedItem"), None);
        // The second boot option carries none of the optional contract
        // fields: they are omitted from the projection, never emitted as
        // null, so the strict application decoder accepts the snapshot.
        let minimal_payload: serde_json::Value =
            serde_json::from_str(resources[4].payload().as_str())?;
        assert_eq!(minimal_payload["BootOptionReference"], "Boot0002");
        assert_eq!(minimal_payload.get("DisplayName"), None);
        assert_eq!(minimal_payload.get("BootOptionEnabled"), None);
        assert_eq!(minimal_payload.get("UefiDevicePath"), None);
        assert_eq!(minimal_payload.get("Alias"), None);
        assert_projection(
            &resources[5],
            "/redfish/v1/Systems/1/SecureBoot",
            "W/\"secure-boot-1\"",
            "SecureBootMode",
            "UserMode",
        )?;
        let secure_payload: serde_json::Value =
            serde_json::from_str(resources[5].payload().as_str())?;
        assert_eq!(secure_payload["SecureBootEnable"], true);
        assert_eq!(secure_payload["SecureBootCurrentBoot"], "Enabled");
        assert_eq!(secure_payload.get("SecureBootDatabases"), None);
        assert_session_requests(&server.finish_all().await?, &CONFIG_FAMILY_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_accounts_through_typed_root_navigation() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_ACCOUNTS_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", ACCOUNT_SERVICE_WITH_ACCOUNTS_BODY),
                ("200 OK", ACCOUNTS_WITH_MEMBERS_BODY),
                ("200 OK", ACCOUNT_ONE_BODY),
                ("200 OK", ACCOUNT_TWO_BODY),
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

        assert_eq!(resources.len(), 6);
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
                ResourceFeature::Accounts,
                ResourceFeature::Accounts,
            ]
        );
        assert_projection(
            &resources[4],
            "/redfish/v1/AccountService/Accounts/1",
            "W/\"account-1\"",
            "UserName",
            "admin",
        )?;
        let account_payload: serde_json::Value =
            serde_json::from_str(resources[4].payload().as_str())?;
        assert_eq!(account_payload["RoleId"], "Administrator");
        assert_eq!(account_payload["Enabled"], true);
        assert_eq!(account_payload["Locked"], false);
        assert_eq!(
            account_payload["AccountTypes"],
            serde_json::json!(["Redfish", "IPMI"])
        );
        // Only the contract fields may leave the gateway; the decoded
        // schema fields that are not part of the contract must stay out of
        // the snapshot or the strict application decoder rejects it.
        assert_eq!(account_payload.get("PasswordChangeRequired"), None);
        assert_eq!(account_payload.get("AccountExpiration"), None);
        assert_eq!(account_payload.get("HostBootstrapAccount"), None);
        assert_eq!(account_payload.get("SNMP"), None);
        // The second account carries none of the optional contract fields:
        // they are omitted, never emitted as null.
        let minimal_payload: serde_json::Value =
            serde_json::from_str(resources[5].payload().as_str())?;
        assert_eq!(minimal_payload["UserName"], "viewer");
        assert_eq!(
            minimal_payload["AccountTypes"],
            serde_json::json!(["Redfish"])
        );
        assert_eq!(minimal_payload.get("RoleId"), None);
        assert_eq!(minimal_payload.get("Enabled"), None);
        assert_eq!(minimal_payload.get("Locked"), None);
        assert_session_requests(
            &server.finish_all().await?,
            &ACCOUNTS_RESOURCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_pcie_assembly_and_software_inventory_families_through_typed_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_PCIE_DEVICES_BODY),
                ("200 OK", PCIE_DEVICE_GPU_BODY),
                ("200 OK", PCIE_DEVICE_NIC_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_ASSEMBLY_BODY),
                ("200 OK", ASSEMBLY_WITH_MEMBERS_BODY),
                ("200 OK", ASSEMBLY_FAN_BODY),
                ("200 OK", ASSEMBLY_PSU_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
                ("200 OK", SOFTWARE_INVENTORY_WITH_MEMBERS_BODY),
                ("200 OK", SOFTWARE_INVENTORY_BIOS_BODY),
                ("200 OK", SOFTWARE_INVENTORY_BMC_BODY),
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

        assert_eq!(resources.len(), 10);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::PcieDevices,
                ResourceFeature::PcieDevices,
                ResourceFeature::Chassis,
                ResourceFeature::Assembly,
                ResourceFeature::Assembly,
                ResourceFeature::Managers,
                ResourceFeature::SoftwareInventory,
                ResourceFeature::SoftwareInventory,
            ]
        );
        assert_projection(
            &resources[2],
            "/redfish/v1/Systems/1/PCIeDevices/GPU1",
            "W/\"pcie-device-1\"",
            "DeviceType",
            "SingleFunction",
        )?;
        assert_projection(
            &resources[3],
            "/redfish/v1/Systems/1/PCIeDevices/NIC1",
            "W/\"pcie-device-2\"",
            "DeviceType",
            "MultiFunction",
        )?;
        assert_projection(
            &resources[5],
            "/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
            "W/\"assembly-data-0\"",
            "Producer",
            "Vendor D",
        )?;
        assert_projection(
            &resources[6],
            "/redfish/v1/Chassis/1/Assembly#/Assemblies/1",
            "W/\"assembly-data-1\"",
            "Producer",
            "Vendor E",
        )?;
        assert_projection(
            &resources[8],
            "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
            "W/\"sw-1\"",
            "SoftwareId",
            "BIOS-2026-1",
        )?;
        assert_projection(
            &resources[9],
            "/redfish/v1/UpdateService/SoftwareInventory/BMC",
            "W/\"sw-2\"",
            "SoftwareId",
            "BMC-2026-1",
        )?;
        assert_device_family_payloads(&resources)?;
        assert_session_requests(
            &server.finish_all().await?,
            &DEVICE_FAMILY_RESOURCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    /// Asserts the exact contract field set of every device-family snapshot:
    /// the populated fields of the full members, the omitted fields of the
    /// minimal members, and the absence of every decoded schema field that is
    /// not part of the contract (an extra key would make the stored snapshot
    /// unreadable to the strict application decoder).
    fn assert_device_family_payloads(
        resources: &[CoreResourceProjection],
    ) -> Result<(), Box<dyn Error>> {
        let pcie_payload: serde_json::Value =
            serde_json::from_str(resources[2].payload().as_str())?;
        assert_eq!(pcie_payload["Manufacturer"], "Vendor C");
        assert_eq!(pcie_payload["Model"], "PCIE-GEN4-X16");
        assert_eq!(pcie_payload["Status"]["Health"], "OK");
        assert_eq!(pcie_payload["Id"], "GPU1");
        assert_eq!(pcie_payload["Name"], "PCIe Device One");
        assert_eq!(pcie_payload.get("FirmwareVersion"), None);
        assert_eq!(pcie_payload.get("SerialNumber"), None);
        assert_eq!(pcie_payload.get("SKU"), None);
        let pcie_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[3].payload().as_str())?;
        assert_eq!(pcie_minimal_payload.get("Manufacturer"), None);
        assert_eq!(pcie_minimal_payload.get("Model"), None);
        assert_eq!(pcie_minimal_payload.get("Status"), None);
        let assembly_payload: serde_json::Value =
            serde_json::from_str(resources[5].payload().as_str())?;
        assert_eq!(assembly_payload["Producer"], "Vendor D");
        assert_eq!(assembly_payload["Status"]["Health"], "OK");
        assert_eq!(assembly_payload["Id"], "0");
        assert_eq!(assembly_payload["Name"], "Fan Assembly");
        assert_eq!(assembly_payload.get("Model"), None);
        assert_eq!(assembly_payload.get("SerialNumber"), None);
        assert_eq!(assembly_payload.get("Version"), None);
        let assembly_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[6].payload().as_str())?;
        assert_eq!(assembly_minimal_payload["Producer"], "Vendor E");
        assert_eq!(assembly_minimal_payload.get("Status"), None);
        let software_payload: serde_json::Value =
            serde_json::from_str(resources[8].payload().as_str())?;
        assert_eq!(software_payload["SoftwareId"], "BIOS-2026-1");
        assert_eq!(software_payload["Version"], "2.7.0");
        assert_eq!(software_payload["ReleaseDate"], "2026-05-01T00:00:00Z");
        assert_eq!(software_payload["Status"]["Health"], "OK");
        assert_eq!(software_payload["Id"], "BIOS");
        assert_eq!(software_payload["Name"], "System BIOS");
        assert_eq!(software_payload.get("Updateable"), None);
        assert_eq!(software_payload.get("Manufacturer"), None);
        assert_eq!(software_payload.get("LowestSupportedVersion"), None);
        let software_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[9].payload().as_str())?;
        assert_eq!(software_minimal_payload["SoftwareId"], "BMC-2026-1");
        assert_eq!(software_minimal_payload["Version"], "1.4.2");
        assert_eq!(software_minimal_payload.get("ReleaseDate"), None);
        assert_eq!(software_minimal_payload.get("Status"), None);
        Ok(())
    }

    #[tokio::test]
    async fn absent_device_links_produce_no_family_snapshots() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", UPDATE_SERVICE_BODY),
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

        // The System member advertises no PCIeDevices array, the Chassis
        // member no Assembly document, and the UpdateService no
        // SoftwareInventory collection, so none of the three families produce
        // snapshots ("资源存在才呈现").
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
        assert_session_requests(
            &server.finish_all().await?,
            &ABSENT_DEVICE_FAMILY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn empty_device_arrays_and_collections_produce_no_family_snapshots()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_EMPTY_PCIE_DEVICES_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_ASSEMBLY_BODY),
                ("200 OK", ASSEMBLY_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
                ("200 OK", SOFTWARE_INVENTORY_BODY),
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

        // The advertised-but-empty PCIeDevices array, Assembly document
        // without Assemblies members, and SoftwareInventory collection
        // produce no member snapshots ("资源存在才呈现").
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
        assert_session_requests(
            &server.finish_all().await?,
            &EMPTY_DEVICE_FAMILY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_undecodable_device_members_without_aborting_the_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_PCIE_DEVICES_BODY),
                ("200 OK", PCIE_DEVICE_GPU_BODY),
                ("200 OK", "{}"),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_ASSEMBLY_BODY),
                ("200 OK", ASSEMBLY_WITH_MEMBERS_BODY),
                ("200 OK", ASSEMBLY_FAN_BODY),
                ("200 OK", "{}"),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
                ("200 OK", SOFTWARE_INVENTORY_WITH_MEMBERS_BODY),
                ("200 OK", SOFTWARE_INVENTORY_BIOS_BODY),
                ("200 OK", "{}"),
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

        // The second PCIe device, the second AssemblyData member, and the
        // second SoftwareInventory member all return undecodable bodies and
        // are skipped; every other member still produces a snapshot (§0.2.0
        // acceptance, per-member skip without erasing peers).
        assert_eq!(resources.len(), 7);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::PcieDevices,
                ResourceFeature::Chassis,
                ResourceFeature::Assembly,
                ResourceFeature::Managers,
                ResourceFeature::SoftwareInventory,
            ]
        );
        assert_session_requests(
            &server.finish_all().await?,
            &DEVICE_MEMBER_SKIP_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    // The fixture sequence and the per-family snapshot assertions of all
    // seven families live in one test so the request order is asserted as a
    // whole; splitting them would duplicate the session and core-triad
    // fixtures. The domain crate allows the same on its long round-trip
    // tests.
    #[allow(clippy::too_many_lines)]
    async fn reads_event_telemetry_and_task_families_through_typed_root_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_SERVICES_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", EVENT_SERVICE_WITH_SUBSCRIPTIONS_BODY),
                ("200 OK", EVENT_SUBSCRIPTIONS_WITH_MEMBERS_BODY),
                ("200 OK", EVENT_SUBSCRIPTION_ONE_BODY),
                ("200 OK", EVENT_SUBSCRIPTION_TWO_BODY),
                ("200 OK", TELEMETRY_SERVICE_WITH_LINKS_BODY),
                ("200 OK", METRIC_DEFINITIONS_WITH_MEMBERS_BODY),
                ("200 OK", METRIC_DEFINITION_ONE_BODY),
                ("200 OK", METRIC_DEFINITION_TWO_BODY),
                ("200 OK", METRIC_REPORTS_WITH_MEMBERS_BODY),
                ("200 OK", METRIC_REPORT_ONE_BODY),
                ("200 OK", METRIC_REPORT_TWO_BODY),
                ("200 OK", TASK_SERVICE_WITH_TASKS_BODY),
                ("200 OK", TASKS_WITH_MEMBERS_BODY),
                ("200 OK", TASK_ONE_BODY),
                ("200 OK", TASK_TWO_BODY),
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

        assert_eq!(resources.len(), 15);
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
                ResourceFeature::EventService,
                ResourceFeature::EventSubscription,
                ResourceFeature::EventSubscription,
                ResourceFeature::TelemetryService,
                ResourceFeature::MetricDefinition,
                ResourceFeature::MetricDefinition,
                ResourceFeature::MetricReport,
                ResourceFeature::MetricReport,
                ResourceFeature::TaskService,
                ResourceFeature::Task,
                ResourceFeature::Task,
            ]
        );
        assert_projection(
            &resources[4],
            "/redfish/v1/EventService",
            "W/\"event-service-1\"",
            "Name",
            "Event Service",
        )?;
        assert_projection(
            &resources[5],
            "/redfish/v1/EventService/Subscriptions/1",
            "W/\"subscription-1\"",
            "Protocol",
            "Redfish",
        )?;
        assert_projection(
            &resources[6],
            "/redfish/v1/EventService/Subscriptions/2",
            "W/\"subscription-2\"",
            "Destination",
            "https://events.example.com/hook-2",
        )?;
        assert_projection(
            &resources[7],
            "/redfish/v1/TelemetryService",
            "W/\"telemetry-service-1\"",
            "Name",
            "Telemetry Service",
        )?;
        assert_projection(
            &resources[8],
            "/redfish/v1/TelemetryService/MetricDefinitions/1",
            "W/\"metric-definition-1\"",
            "Units",
            "W",
        )?;
        assert_projection(
            &resources[9],
            "/redfish/v1/TelemetryService/MetricDefinitions/2",
            "W/\"metric-definition-2\"",
            "MetricType",
            "Gauge",
        )?;
        assert_projection(
            &resources[10],
            "/redfish/v1/TelemetryService/MetricReports/1",
            "W/\"metric-report-1\"",
            "Id",
            "1",
        )?;
        assert_projection(
            &resources[11],
            "/redfish/v1/TelemetryService/MetricReports/2",
            "W/\"metric-report-2\"",
            "Id",
            "2",
        )?;
        assert_projection(
            &resources[12],
            "/redfish/v1/TaskService",
            "W/\"task-service-1\"",
            "Name",
            "Task Service",
        )?;
        assert_projection(
            &resources[13],
            "/redfish/v1/TaskService/Tasks/1",
            "W/\"task-1\"",
            "TaskState",
            "Running",
        )?;
        assert_projection(
            &resources[14],
            "/redfish/v1/TaskService/Tasks/2",
            "W/\"task-2\"",
            "TaskState",
            "Completed",
        )?;
        assert_service_family_payloads(&resources)?;
        assert_session_requests(
            &server.finish_all().await?,
            &SERVICES_RESOURCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    /// The request order of one Task read: the Session lifecycle around the
    /// direct `Bmc::get` of the Task URI.
    const TASK_READ_REQUEST_PATHS: [&str; 6] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/TaskService/Tasks/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    #[tokio::test]
    async fn reads_a_task_through_typed_navigation_with_session_token_auth()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[("200 OK", TASK_MONITOR_RUNNING_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let observation = gateway
            .read_task(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &ResourceODataId::parse("/redfish/v1/TaskService/Tasks/1")?,
            )
            .await?;

        assert_eq!(
            observation.task_uri().as_str(),
            "/redfish/v1/TaskService/Tasks/1"
        );
        assert_eq!(
            observation.task_monitor().map(ResourceODataId::as_str),
            Some("/redfish/v1/TaskService/Tasks/1/Monitor")
        );
        assert_eq!(
            observation.etag().map(ResourceEtag::as_str),
            Some("W/\"task-1\"")
        );
        assert_eq!(observation.task_state(), Some("running"));
        assert_eq!(observation.task_status(), Some("ok"));
        assert_eq!(observation.percent_complete(), Some(42));
        let message = observation
            .messages()
            .last()
            .ok_or_else(|| io::Error::other("the Task must report its progress message"))?;
        assert_eq!(message.message_id(), "Base.1.0.Progress");
        assert_eq!(message.message(), Some("Firmware update in progress"));
        assert_eq!(message.severity(), Some("OK"));
        assert_session_requests(&server.finish_all().await?, &TASK_READ_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn maps_unknown_task_states_into_the_stable_unsupported_code()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[("200 OK", TASK_WITH_UNKNOWN_STATE_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let observation = gateway
            .read_task(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &ResourceODataId::parse("/redfish/v1/TaskService/Tasks/2")?,
            )
            .await?;

        assert_eq!(observation.task_state(), Some("unsupported_value"));
        assert_eq!(observation.task_status(), Some("critical"));
        assert_eq!(observation.percent_complete(), None);
        assert!(
            observation.messages().is_empty(),
            "a Task without a Messages property reports no messages"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_a_disappeared_task_as_gone_for_recovery_reverification()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[(
                "404 Not Found",
                "{\"error\":{\"code\":\"Base.1.0.ResourceMissing\",\"message\":\"The task was deleted\"}}",
            )],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .read_task(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &ResourceODataId::parse("/redfish/v1/TaskService/Tasks/1")?,
            )
            .await;

        match result {
            Err(TaskReadError::TaskGone { task_uri, .. }) => {
                assert_eq!(task_uri.as_str(), "/redfish/v1/TaskService/Tasks/1");
            }
            other => {
                return Err(
                    format!("a 404 Task read must surface as TaskGone, got {other:?}").into(),
                );
            }
        }
        // The poll stops immediately — the Task URI was still requested
        // through the Session before the Session was deleted.
        assert_session_requests(&server.finish_all().await?, &TASK_READ_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn classifies_an_undecodable_task_document_as_schema_incompatible()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[(
                "200 OK",
                "{\"@odata.id\":\"/redfish/v1/TaskService/Tasks/1\"}",
            )],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .read_task(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &ResourceODataId::parse("/redfish/v1/TaskService/Tasks/1")?,
            )
            .await;

        let error = match result {
            Err(error) => error,
            Ok(observation) => {
                return Err(format!("an undecodable Task must fail, got {observation:?}").into());
            }
        };
        match error {
            TaskReadError::ReadFailed { task_uri, source } => {
                assert_eq!(task_uri.as_str(), "/redfish/v1/TaskService/Tasks/1");
                assert!(
                    matches!(*source, RedfishServiceRootError::SchemaIncompatible { .. }),
                    "an undecodable Task document is a schema failure: {source}"
                );
            }
            other => {
                return Err(format!("an undecodable Task must be ReadFailed, got {other}").into());
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn classifies_a_dropped_task_read_as_an_unknown_network_result()
    -> Result<(), Box<dyn Error>> {
        // The empty response at the Task position encodes a dropped
        // connection: the request is captured, no response ever arrives.
        let mut responses = session_response_sequence(CORE_SERVICE_ROOT_BODY, &[]);
        responses.insert(4, Vec::new());
        let server = TestRedfishServer::start_raw_sequence(responses).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .read_task(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &ResourceODataId::parse("/redfish/v1/TaskService/Tasks/1")?,
            )
            .await;

        let error = match result {
            Err(error) => error,
            Ok(observation) => {
                return Err(format!("a dropped Task read must fail, got {observation:?}").into());
            }
        };
        match error {
            TaskReadError::ReadFailed { task_uri, source } => {
                assert_eq!(task_uri.as_str(), "/redfish/v1/TaskService/Tasks/1");
                assert!(
                    matches!(*source, RedfishServiceRootError::Network { .. }),
                    "a dropped connection is an unprovable network result: {source}"
                );
            }
            other => {
                return Err(format!("a dropped Task read must be ReadFailed, got {other}").into());
            }
        }
        // The Task request itself was captured before the connection dropped,
        // proving the monitor did attempt the read.
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 6);
        assert!(
            std::str::from_utf8(&requests[4])?
                .starts_with("GET /redfish/v1/TaskService/Tasks/1 HTTP/1.1\r\n")
        );
        Ok(())
    }

    /// Pins the compiled `TaskState` wire values to the stable snake-case
    /// codes the observation carries (§7.2) — the exact code set the
    /// `remote_tasks` persistence contract enforces. A future `nv-redfish`
    /// CSDL update that renames a wire value or its canonical mapping fails
    /// here instead of silently producing a code the engine cannot classify.
    #[test]
    fn task_state_wire_values_map_to_the_stable_recovery_codes() -> Result<(), Box<dyn Error>> {
        use nv_redfish::core::ToSnakeCase;
        use nv_redfish::schema::task::TaskState;

        let pairs = [
            ("New", TaskState::New, "new"),
            ("Starting", TaskState::Starting, "starting"),
            ("Running", TaskState::Running, "running"),
            ("Suspended", TaskState::Suspended, "suspended"),
            ("Interrupted", TaskState::Interrupted, "interrupted"),
            ("Pending", TaskState::Pending, "pending"),
            ("Stopping", TaskState::Stopping, "stopping"),
            ("Completed", TaskState::Completed, "completed"),
            ("Killed", TaskState::Killed, "killed"),
            ("Exception", TaskState::Exception, "exception"),
            ("Service", TaskState::Service, "service"),
            ("Cancelling", TaskState::Cancelling, "cancelling"),
            ("Cancelled", TaskState::Cancelled, "cancelled"),
        ];
        for (wire, state, code) in pairs {
            let decoded: TaskState = serde_json::from_str(&format!("\"{wire}\""))?;
            assert_eq!(decoded, state);
            assert_eq!(decoded.to_snake_case(), code);
        }
        Ok(())
    }

    /// Asserts the exact contract field set of every service-family snapshot:
    /// the populated fields of the full members, the omitted fields of the
    /// minimal members, and the absence of every decoded schema field that is
    /// not part of the contract — an extra key would make the stored snapshot
    /// unreadable to the strict application decoder. The `MetricReport`
    /// snapshots in particular carry only the derived `MetricValuesCount`;
    /// the `MetricValues` value array and the `Status` key of the fixture
    /// must never leave the gateway.
    // All seven families are asserted in one place so the contract field set
    // stays auditable side by side; splitting per family would duplicate the
    // common absent-key checks. The domain crate's round-trip tests and the
    // mock-BMC route dispatch allow the same on their long assertions.
    #[allow(clippy::too_many_lines)]
    fn assert_service_family_payloads(
        resources: &[CoreResourceProjection],
    ) -> Result<(), Box<dyn Error>> {
        let event_service_payload: serde_json::Value =
            serde_json::from_str(resources[4].payload().as_str())?;
        assert_eq!(event_service_payload["ServiceEnabled"], true);
        assert_eq!(event_service_payload["Status"]["Health"], "OK");
        assert_eq!(event_service_payload["Id"], "EventService");
        assert_eq!(event_service_payload["Name"], "Event Service");
        assert_eq!(event_service_payload.get("DeliveryRetryAttempts"), None);
        assert_eq!(
            event_service_payload.get("DeliveryRetryIntervalSeconds"),
            None
        );
        assert_eq!(event_service_payload.get("ServerSentEventUri"), None);
        let subscription_payload: serde_json::Value =
            serde_json::from_str(resources[5].payload().as_str())?;
        assert_eq!(
            subscription_payload["Destination"],
            "https://events.example.com/hook-1"
        );
        assert_eq!(subscription_payload["Protocol"], "Redfish");
        assert_eq!(subscription_payload["Context"], "hook-one");
        assert_eq!(
            subscription_payload["EventTypes"],
            serde_json::json!(["StatusChange", "Alert"])
        );
        assert_eq!(subscription_payload["Status"]["Health"], "OK");
        assert_eq!(subscription_payload.get("HttpHeaders"), None);
        assert_eq!(subscription_payload.get("MessageIds"), None);
        let subscription_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[6].payload().as_str())?;
        assert_eq!(
            subscription_minimal_payload["Destination"],
            "https://events.example.com/hook-2"
        );
        assert_eq!(subscription_minimal_payload.get("Protocol"), None);
        assert_eq!(subscription_minimal_payload.get("Context"), None);
        assert_eq!(subscription_minimal_payload.get("EventTypes"), None);
        assert_eq!(subscription_minimal_payload.get("Status"), None);
        let telemetry_service_payload: serde_json::Value =
            serde_json::from_str(resources[7].payload().as_str())?;
        assert_eq!(telemetry_service_payload["Status"]["Health"], "OK");
        assert_eq!(telemetry_service_payload["Id"], "TelemetryService");
        assert_eq!(telemetry_service_payload["Name"], "Telemetry Service");
        // `ServiceEnabled` is decoded by the schema but the api contract
        // exposes only `Status`, so it must not be projected.
        assert_eq!(telemetry_service_payload.get("ServiceEnabled"), None);
        assert_eq!(telemetry_service_payload.get("MaxReports"), None);
        assert_eq!(telemetry_service_payload.get("MinCollectionInterval"), None);
        let definition_payload: serde_json::Value =
            serde_json::from_str(resources[8].payload().as_str())?;
        assert_eq!(definition_payload["Units"], "W");
        assert_eq!(definition_payload["MetricType"], "Numeric");
        assert_eq!(definition_payload["Id"], "1");
        assert_eq!(definition_payload["Name"], "Power Consumption");
        assert_eq!(definition_payload.get("MetricDataType"), None);
        assert_eq!(definition_payload.get("Precision"), None);
        assert_eq!(definition_payload.get("MetricProperties"), None);
        assert_eq!(definition_payload.get("Status"), None);
        let definition_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[9].payload().as_str())?;
        assert_eq!(definition_minimal_payload["MetricType"], "Gauge");
        assert_eq!(definition_minimal_payload["Units"], "Cel");
        let report_payload: serde_json::Value =
            serde_json::from_str(resources[10].payload().as_str())?;
        assert_eq!(report_payload["MetricValuesCount"], 2);
        assert_eq!(report_payload["Id"], "1");
        assert_eq!(report_payload["Name"], "Power Report");
        // The fixture carries a two-entry `MetricValues` array and a `Status`
        // object; neither may leave the gateway, only the derived count may.
        assert_eq!(report_payload.get("MetricValues"), None);
        assert_eq!(report_payload.get("Status"), None);
        assert_eq!(report_payload.get("Timestamp"), None);
        assert_eq!(report_payload.get("Context"), None);
        assert_eq!(report_payload.get("ReportSequence"), None);
        let report_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[11].payload().as_str())?;
        assert_eq!(report_minimal_payload["MetricValuesCount"], 0);
        let task_service_payload: serde_json::Value =
            serde_json::from_str(resources[12].payload().as_str())?;
        assert_eq!(task_service_payload["ServiceEnabled"], true);
        assert_eq!(
            task_service_payload["CompletedTaskOverWritePolicy"],
            "Oldest"
        );
        assert_eq!(task_service_payload["Status"]["Health"], "OK");
        assert_eq!(task_service_payload.get("DateTime"), None);
        assert_eq!(
            task_service_payload.get("TaskAutoDeleteTimeoutMinutes"),
            None
        );
        let task_payload: serde_json::Value =
            serde_json::from_str(resources[13].payload().as_str())?;
        assert_eq!(task_payload["TaskState"], "Running");
        assert_eq!(task_payload["TaskStatus"], "OK");
        assert_eq!(task_payload["PercentComplete"], 42);
        assert_eq!(task_payload["StartTime"], "2026-08-01T09:30:00Z");
        assert_eq!(task_payload.get("EndTime"), None);
        assert_eq!(task_payload.get("TaskMonitor"), None);
        assert_eq!(task_payload.get("HidePayload"), None);
        assert_eq!(task_payload.get("Messages"), None);
        let task_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[14].payload().as_str())?;
        assert_eq!(task_minimal_payload["TaskState"], "Completed");
        assert_eq!(task_minimal_payload["TaskStatus"], "OK");
        assert_eq!(task_minimal_payload["PercentComplete"], 100);
        assert_eq!(task_minimal_payload["StartTime"], "2026-08-01T09:00:00Z");
        assert_eq!(task_minimal_payload["EndTime"], "2026-08-01T09:05:00Z");
        Ok(())
    }

    #[tokio::test]
    async fn absent_service_links_produce_no_family_snapshots() -> Result<(), Box<dyn Error>> {
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

        // The Service Root advertises none of the three service links, so
        // none of the seven families produce snapshots ("资源存在才呈现").
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
        assert_session_requests(&server.finish_all().await?, &ABSENT_SERVICES_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn empty_service_collections_produce_no_member_snapshots() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_SERVICES_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", EVENT_SERVICE_WITH_SUBSCRIPTIONS_BODY),
                ("200 OK", EVENT_SUBSCRIPTIONS_BODY),
                ("200 OK", TELEMETRY_SERVICE_WITH_LINKS_BODY),
                ("200 OK", METRIC_DEFINITIONS_BODY),
                ("200 OK", METRIC_REPORTS_BODY),
                ("200 OK", TASK_SERVICE_WITH_TASKS_BODY),
                ("200 OK", TASKS_BODY),
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

        // The three service singletons are projected; every collection below
        // them is advertised but empty, so no member snapshot is produced.
        assert_eq!(resources.len(), 7);
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
                ResourceFeature::EventService,
                ResourceFeature::TelemetryService,
                ResourceFeature::TaskService,
            ]
        );
        assert_session_requests(&server.finish_all().await?, &EMPTY_SERVICES_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_undecodable_service_singletons_and_members_without_aborting()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_SERVICES_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", "{}"),
                ("200 OK", TELEMETRY_SERVICE_WITH_LINKS_BODY),
                ("200 OK", METRIC_DEFINITIONS_WITH_MEMBERS_BODY),
                ("200 OK", METRIC_DEFINITION_ONE_BODY),
                ("200 OK", "{}"),
                ("200 OK", METRIC_REPORTS_WITH_ONE_MEMBER_BODY),
                ("200 OK", "{}"),
                ("200 OK", "{}"),
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

        // The `EventService` singleton is undecodable and takes its whole
        // `Subscriptions` family with it; the `TaskService` singleton is
        // undecodable the same way. The second `MetricDefinition` and the
        // first `MetricReport` members are skipped with the member-level
        // semantics. Every other resource still produces a snapshot.
        assert_eq!(resources.len(), 6);
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
                ResourceFeature::TelemetryService,
                ResourceFeature::MetricDefinition,
            ]
        );
        assert_session_requests(&server.finish_all().await?, &SERVICES_SKIP_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn assembly_member_without_name_falls_back_to_empty_common_name()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_ASSEMBLY_BODY),
                ("200 OK", ASSEMBLY_WITH_UNNAMED_MEMBER_BODY),
                ("200 OK", ASSEMBLY_UNNAMED_BODY),
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

        assert_eq!(resources.len(), 5);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Chassis,
                ResourceFeature::Assembly,
                ResourceFeature::Managers,
            ]
        );
        // The `AssemblyData` schema makes `Name` optional while the common
        // projection requires a string, so the missing name falls back to
        // the empty string instead of producing an undecodable snapshot.
        let assembly_payload: serde_json::Value =
            serde_json::from_str(resources[3].payload().as_str())?;
        assert_eq!(assembly_payload["Id"], "0");
        assert_eq!(assembly_payload["Name"], "");
        assert_eq!(assembly_payload.get("Description"), None);
        assert_eq!(assembly_payload["Producer"], "Vendor D");
        assert_eq!(assembly_payload["Status"]["Health"], "OK");
        assert_session_requests(&server.finish_all().await?, &UNNAMED_ASSEMBLY_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn absent_configuration_links_produce_no_family_snapshots() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_ACCOUNTS_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", ACCOUNT_SERVICE_BODY),
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

        // The System member advertises no Bios, BootOptions, or SecureBoot
        // links and the AccountService advertises no Accounts collection, so
        // none of the four families produce snapshots ("资源存在才呈现").
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
        assert_session_requests(&server.finish_all().await?, &ABSENT_FAMILY_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn empty_configuration_collections_produce_no_member_snapshots()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_ACCOUNTS_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_CONFIG_FEATURES_BODY),
                ("200 OK", BIOS_FULL_BODY),
                ("200 OK", BOOT_OPTIONS_BODY),
                ("200 OK", SECURE_BOOT_FULL_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", ACCOUNT_SERVICE_WITH_ACCOUNTS_BODY),
                ("200 OK", ACCOUNTS_BODY),
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

        // The advertised-but-empty BootOptions and Accounts collections
        // produce no member snapshots; the Bios and SecureBoot singletons
        // still do ("资源存在才呈现").
        assert_eq!(resources.len(), 6);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Bios,
                ResourceFeature::SecureBoot,
                ResourceFeature::Chassis,
                ResourceFeature::Managers,
            ]
        );
        assert_session_requests(
            &server.finish_all().await?,
            &EMPTY_CONFIG_FAMILY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_undecodable_configuration_singletons_and_members_without_aborting()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_CONFIG_FEATURES_BODY),
                ("200 OK", "{}"),
                ("200 OK", BOOT_OPTIONS_WITH_MEMBERS_BODY),
                ("200 OK", BOOT_OPTION_ONE_BODY),
                ("200 OK", "{}"),
                ("200 OK", SECURE_BOOT_FULL_BODY),
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

        // The undecodable Bios singleton and the second BootOption member
        // are skipped; the remaining configuration families still produce
        // snapshots (§0.2.0 acceptance, singleton failure treated as
        // member-level skip).
        assert_eq!(resources.len(), 6);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::BootOptions,
                ResourceFeature::SecureBoot,
                ResourceFeature::Chassis,
                ResourceFeature::Managers,
            ]
        );
        assert_eq!(
            resources[2].odata_id().as_str(),
            "/redfish/v1/Systems/1/BootOptions/1"
        );
        assert_session_requests(&server.finish_all().await?, &SINGLETON_SKIP_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_chassis_telemetry_families_through_typed_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_TELEMETRY_BODY),
                ("200 OK", POWER_FULL_BODY),
                ("200 OK", THERMAL_FULL_BODY),
                ("200 OK", SENSORS_WITH_MEMBERS_BODY),
                ("200 OK", SENSOR_ONE_BODY),
                ("200 OK", SENSOR_TWO_BODY),
                ("200 OK", CONTROLS_WITH_MEMBERS_BODY),
                ("200 OK", CONTROL_ONE_BODY),
                ("200 OK", CONTROL_TWO_BODY),
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

        assert_eq!(resources.len(), 10);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Chassis,
                ResourceFeature::Power,
                ResourceFeature::Thermal,
                ResourceFeature::Sensors,
                ResourceFeature::Sensors,
                ResourceFeature::Controls,
                ResourceFeature::Controls,
                ResourceFeature::Managers,
            ]
        );
        assert_power_projection(&resources[3])?;
        assert_thermal_projection(&resources[4])?;
        assert_sensor_projection(&resources[5])?;
        assert_minimal_sensor_projection(&resources[6])?;
        assert_control_projection(&resources[7])?;
        assert_minimal_control_projection(&resources[8])?;
        assert_session_requests(
            &server.finish_all().await?,
            &TELEMETRY_RESOURCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    /// Asserts the `Power` singleton projection carries only the common
    /// fields: the contract carries no details, so every decoded schema
    /// field must stay out of the snapshot or the strict application decoder
    /// rejects it — not the embedded `PowerControl` capacity reading, and
    /// not the linked `Voltages`, `PowerSupplies`, or `Redundancy` arrays.
    fn assert_power_projection(projection: &CoreResourceProjection) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/Power",
            "W/\"power-1\"",
            "Id",
            "Power",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Name"], "Chassis Power");
        assert_eq!(payload.get("PowerCapacityWatts"), None);
        assert_eq!(payload.get("PowerControl"), None);
        assert_eq!(payload.get("Voltages"), None);
        assert_eq!(payload.get("PowerSupplies"), None);
        assert_eq!(payload.get("Redundancy"), None);
        Ok(())
    }

    /// Asserts the `Thermal` singleton projection carries the direct
    /// `Status` only: the `Temperatures` and `Fans` reading arrays stay out
    /// of the snapshot.
    fn assert_thermal_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/Thermal",
            "W/\"thermal-1\"",
            "Id",
            "Thermal",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("TemperatureCount"), None);
        assert_eq!(payload.get("Temperatures"), None);
        assert_eq!(payload.get("Fans"), None);
        Ok(())
    }

    /// Asserts the full `Sensor` member projection with every optional
    /// contract field populated; the range bags stay out.
    fn assert_sensor_projection(projection: &CoreResourceProjection) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/Sensors/1",
            "W/\"sensor-1\"",
            "ReadingType",
            "Temperature",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Reading"], 47.5);
        assert_eq!(payload["ReadingUnits"], "Cel");
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("ReadingRangeMin"), None);
        assert_eq!(payload.get("ReadingRangeMax"), None);
        Ok(())
    }

    /// Asserts the minimal `Sensor` member projection: every optional
    /// contract field except the reading is absent and must be omitted, not
    /// emitted as null.
    fn assert_minimal_sensor_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Chassis/1/Sensors/2"
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["ReadingType"], "Power");
        assert_eq!(payload["Reading"], 300.0);
        assert_eq!(payload["ReadingUnits"], "W");
        assert_eq!(payload.get("Status"), None);
        Ok(())
    }

    /// Asserts the full `Control` member projection with every optional
    /// contract field populated; the setting ranges stay out.
    fn assert_control_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/Controls/1",
            "W/\"control-1\"",
            "ControlType",
            "Power",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["SetPoint"], 1800.0);
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("SetPointUnits"), None);
        assert_eq!(payload.get("SettingMin"), None);
        assert_eq!(payload.get("SettingMax"), None);
        Ok(())
    }

    /// Asserts the minimal `Control` member projection: every optional
    /// contract field except the set point is absent and must be omitted,
    /// not emitted as null.
    fn assert_minimal_control_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Chassis/1/Controls/2"
        );
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["ControlType"], "Temperature");
        assert_eq!(payload["SetPoint"], 35.0);
        assert_eq!(payload.get("Status"), None);
        Ok(())
    }

    #[tokio::test]
    async fn empty_telemetry_collections_produce_no_member_snapshots() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_TELEMETRY_BODY),
                ("200 OK", POWER_FULL_BODY),
                ("200 OK", THERMAL_FULL_BODY),
                ("200 OK", SENSORS_BODY),
                ("200 OK", CONTROLS_BODY),
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

        // The advertised-but-empty Sensors and Controls collections produce
        // no member snapshots; the Power and Thermal singletons still do
        // ("资源存在才呈现").
        assert_eq!(resources.len(), 6);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Chassis,
                ResourceFeature::Power,
                ResourceFeature::Thermal,
                ResourceFeature::Managers,
            ]
        );
        assert_session_requests(&server.finish_all().await?, &EMPTY_TELEMETRY_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn absent_telemetry_links_produce_no_telemetry_collection_snapshots()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_POWER_AND_THERMAL_BODY),
                ("200 OK", POWER_FULL_BODY),
                ("200 OK", THERMAL_FULL_BODY),
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

        // The Chassis member advertises the two telemetry singletons but no
        // Sensors or Controls link, so only the singletons are projected and
        // the missing collections are never requested ("资源存在才呈现").
        assert_eq!(resources.len(), 6);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Chassis,
                ResourceFeature::Power,
                ResourceFeature::Thermal,
                ResourceFeature::Managers,
            ]
        );
        assert_session_requests(
            &server.finish_all().await?,
            &PARTIAL_TELEMETRY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_undecodable_telemetry_singletons_and_members_without_aborting()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_TELEMETRY_BODY),
                ("200 OK", "{}"),
                ("200 OK", THERMAL_FULL_BODY),
                ("200 OK", SENSORS_WITH_MEMBERS_BODY),
                ("200 OK", "{}"),
                ("200 OK", SENSOR_TWO_BODY),
                ("200 OK", CONTROLS_WITH_MEMBERS_BODY),
                ("200 OK", "{}"),
                ("200 OK", CONTROL_TWO_BODY),
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

        // The undecodable Power singleton is skipped with the member-level
        // semantics, and the first Sensor and Control members are skipped
        // too; the remaining telemetry families still produce snapshots
        // (§0.2.0 acceptance).
        assert_eq!(resources.len(), 7);
        assert_eq!(
            resources
                .iter()
                .map(CoreResourceProjection::feature)
                .collect::<Vec<_>>(),
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Chassis,
                ResourceFeature::Thermal,
                ResourceFeature::Sensors,
                ResourceFeature::Controls,
                ResourceFeature::Managers,
            ]
        );
        assert_eq!(
            resources[4].odata_id().as_str(),
            "/redfish/v1/Chassis/1/Sensors/2"
        );
        assert_eq!(
            resources[5].odata_id().as_str(),
            "/redfish/v1/Chassis/1/Controls/2"
        );
        assert_session_requests(
            &server.finish_all().await?,
            &TELEMETRY_RESOURCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn skips_failing_account_service_and_account_members_without_aborting()
    -> Result<(), Box<dyn Error>> {
        let absent_service = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_ACCOUNTS_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(absent_service.certificate.clone())?;
        let trust = system_ca_trust(&absent_service.certificate)?;
        let resources = gateway
            .read_core_resources(
                &absent_service.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;
        // The undecodable AccountService document is a singleton failure: it
        // skips the whole Accounts family with the member-level semantics
        // instead of aborting the read.
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
        assert_session_requests(
            &absent_service.finish_all().await?,
            &ACCOUNT_SERVICE_SKIP_REQUEST_PATHS,
        )?;

        let failing_member = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_ACCOUNTS_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", ACCOUNT_SERVICE_WITH_ACCOUNTS_BODY),
                ("200 OK", ACCOUNTS_WITH_MEMBERS_BODY),
                ("200 OK", "{}"),
                ("200 OK", ACCOUNT_TWO_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(failing_member.certificate.clone())?;
        let trust = system_ca_trust(&failing_member.certificate)?;
        let resources = gateway
            .read_core_resources(
                &failing_member.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;
        // The undecodable first account member is skipped; the second
        // account member still produces a snapshot (§0.2.0 acceptance).
        assert_eq!(resources.len(), 5);
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
                ResourceFeature::Accounts,
            ]
        );
        assert_eq!(
            resources[4].odata_id().as_str(),
            "/redfish/v1/AccountService/Accounts/2"
        );
        assert_session_requests(
            &failing_member.finish_all().await?,
            &ACCOUNT_MEMBER_SKIP_REQUEST_PATHS,
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

    /// The System document for write tests: advertises the `Boot` object,
    /// the `SecureBoot` link, and the `#ComputerSystem.Reset` action.
    const COMMAND_SYSTEM_WITH_RESET_ACTION_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Boot":{
            "BootSourceOverrideTarget":"None",
            "BootSourceOverrideEnabled":"Disabled",
            "BootSourceOverrideMode":"UEFI"
        },
        "SecureBoot":{"@odata.id":"/redfish/v1/Systems/1/SecureBoot"},
        "Actions":{
            "#ComputerSystem.Reset":{"target":"/redfish/v1/Systems/1/Actions/ComputerSystem.Reset"}
        }
    }"##;

    /// A System document that advertises no write capability at all: no
    /// `Actions`, no `Boot` object, and no `SecureBoot` link. Used to pin
    /// the §13.3 step 2 capability checks.
    const COMMAND_SYSTEM_WITHOUT_CAPABILITIES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical"
    }"#;

    /// The Chassis document for write tests: advertises the
    /// `#Chassis.Reset` action.
    const COMMAND_CHASSIS_WITH_RESET_ACTION_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Actions":{
            "#Chassis.Reset":{"target":"/redfish/v1/Chassis/1/Actions/Chassis.Reset"}
        }
    }"##;

    /// The Manager document for write tests: advertises the
    /// `#Manager.Reset` action.
    const COMMAND_MANAGER_WITH_RESET_ACTION_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Managers/1",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Actions":{
            "#Manager.Reset":{"target":"/redfish/v1/Managers/1/Actions/Manager.Reset"}
        }
    }"##;

    /// The `SecureBoot` document for write tests: advertises the
    /// `#SecureBoot.ResetKeys` action.
    const COMMAND_SECURE_BOOT_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1/SecureBoot",
        "Id":"SecureBoot",
        "Name":"UEFI Secure Boot",
        "SecureBootEnable":true,
        "SecureBootCurrentBoot":"Enabled",
        "Actions":{
            "#SecureBoot.ResetKeys":{
                "target":"/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys"
            }
        }
    }"##;

    /// The `EventService` document for write tests: advertises the
    /// `Subscriptions` collection.
    const COMMAND_EVENT_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/EventService",
        "Id":"EventService",
        "Name":"Event Service",
        "ServiceEnabled":true,
        "Subscriptions":{"@odata.id":"/redfish/v1/EventService/Subscriptions"}
    }"#;

    /// An `EventService` document that advertises no `Subscriptions` link.
    const COMMAND_EVENT_SERVICE_WITHOUT_SUBSCRIPTIONS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/EventService",
        "Id":"EventService",
        "Name":"Event Service",
        "ServiceEnabled":true
    }"#;

    /// The `201` create response of one event subscription.
    const COMMAND_EVENT_SUBSCRIPTION_CREATED_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/EventService/Subscriptions/Sub-1",
        "Id":"Sub-1",
        "Name":"Event Subscription",
        "Destination":"https://example.com/hook",
        "Protocol":"Redfish",
        "EventTypes":["Alert"]
    }"#;

    /// The request order of one System/Manager/Chassis reset: the Session
    /// lifecycle around the collection, member, and action requests.
    const RESET_COMMAND_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Actions/ComputerSystem.Reset",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one Boot override: the Session lifecycle around
    /// the collection, member, and typed `PATCH` requests.
    const BOOT_OVERRIDE_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one Secure Boot property command: the Session
    /// lifecycle around the collection, member, `SecureBoot` document, and the
    /// `PATCH` of the `SecureBoot` document itself.
    const SECURE_BOOT_COMMAND_REQUEST_PATHS: [&str; 9] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one Secure Boot action command: identical to
    /// [`SECURE_BOOT_COMMAND_REQUEST_PATHS`] except that the write is the
    /// decoded `#SecureBoot.ResetKeys` action target.
    const SECURE_BOOT_ACTION_REQUEST_PATHS: [&str; 9] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Systems/1/SecureBoot/Actions/SecureBoot.ResetKeys",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one event subscription creation: the Session
    /// lifecycle around the `EventService` document and the `POST` onto the
    /// `Subscriptions` collection.
    const EVENT_SUBSCRIPTION_CREATE_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one event subscription deletion: identical to
    /// [`EVENT_SUBSCRIPTION_CREATE_REQUEST_PATHS`] except that the write is
    /// the `DELETE` of the typed subscription id joined onto the decoded
    /// collection URI.
    const EVENT_SUBSCRIPTION_DELETE_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions/Sub-1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// Builds the Session lifecycle responses around one write response, so
    /// a test can vary the write status (or drop the connection with an
    /// empty response) without repeating the lifecycle.
    fn command_write_sequence(
        service_root_body: &str,
        before_write: &[(&str, &str)],
        write: Vec<u8>,
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
            before_write
                .iter()
                .map(|(status, body)| http_response(status, body)),
        );
        responses.push(write);
        responses.push(http_response("204 No Content", ""));
        responses
    }

    /// Extracts the body of one captured request.
    fn request_body(request: &[u8]) -> Option<&str> {
        let header_end = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")?;
        std::str::from_utf8(request.get(header_end + 4..)?).ok()
    }

    /// Asserts the request sequence of one command execution: the standard
    /// Session lifecycle (index 3 creates the Session, the last request
    /// deletes it over the Basic transport) around one
    /// token-authenticated write request at `last - 1`.
    ///
    /// `write_method` and `expected_write_body` pin the wire form of the
    /// write request itself.
    fn assert_command_requests(
        requests: &[Vec<u8>],
        expected_paths: &[&str],
        write_method: &str,
        expected_write_body: &str,
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(requests.len(), expected_paths.len());
        let last = requests.len().saturating_sub(1);
        let write_index = last.saturating_sub(1);
        for (index, (request, expected_path)) in requests.iter().zip(expected_paths).enumerate() {
            let request = std::str::from_utf8(request)?;
            let expected_method = match index {
                3 => "POST",
                value if value == write_index => write_method,
                value if value == last => "DELETE",
                _ => "GET",
            };
            assert!(
                request.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1\r\n")),
                "request {index} must be {expected_method} {expected_path}, was: {request}"
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
            if index == write_index {
                assert_eq!(
                    request_body(request.as_bytes()),
                    Some(expected_write_body),
                    "write request body at index {index}"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn executes_system_reset_through_the_typed_action_api() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &RESET_COMMAND_REQUEST_PATHS,
            "POST",
            r#"{"ResetType":"PowerCycle"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_manager_reset_through_the_typed_action_api() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", COMMAND_MANAGER_WITH_RESET_ACTION_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Manager(ManagerCommand::Reset(ResetType::GracefulRestart)),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/Managers",
                "/redfish/v1/Managers/1",
                "/redfish/v1/Managers/1/Actions/Manager.Reset",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            r#"{"ResetType":"GracefulRestart"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_chassis_reset_through_the_typed_action_api() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", COMMAND_CHASSIS_WITH_RESET_ACTION_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::ForceOff)),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/Chassis",
                "/redfish/v1/Chassis/1",
                "/redfish/v1/Chassis/1/Actions/Chassis.Reset",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            r#"{"ResetType":"ForceOff"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_boot_override_through_the_typed_patch_api() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                    SetBootSourceOverride::new(
                        BootSource::Pxe,
                        BootSourceOverrideEnabled::Once,
                        BootSourceOverrideMode::Uefi,
                    ),
                )),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        let requests = server.finish_all().await?;
        assert_command_requests(
            &requests,
            &BOOT_OVERRIDE_REQUEST_PATHS,
            "PATCH",
            r#"{"Boot":{"BootSourceOverrideTarget":"Pxe","BootSourceOverrideEnabled":"Once","BootSourceOverrideMode":"UEFI"}}"#,
        )?;
        let write = std::str::from_utf8(&requests[6])?;
        assert_eq!(request_header(write, "if-match"), Some("*"));
        assert_eq!(
            request_header(write, "content-type"),
            Some("application/json")
        );
        Ok(())
    }

    #[tokio::test]
    async fn executes_secure_boot_enable_through_the_typed_patch_api() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
                ("200 OK", COMMAND_SECURE_BOOT_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::SecureBoot(SecureBootCommand::Enable),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &SECURE_BOOT_COMMAND_REQUEST_PATHS,
            "PATCH",
            r#"{"SecureBootEnable":true}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_secure_boot_disable_through_the_typed_patch_api() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
                ("200 OK", COMMAND_SECURE_BOOT_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::SecureBoot(SecureBootCommand::Disable),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &SECURE_BOOT_COMMAND_REQUEST_PATHS,
            "PATCH",
            r#"{"SecureBootEnable":false}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_secure_boot_reset_keys_through_the_typed_action_api()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
                ("200 OK", COMMAND_SECURE_BOOT_BODY),
            ],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(
                    ResetKeysType::ResetAllKeysToDefault,
                )),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &SECURE_BOOT_ACTION_REQUEST_PATHS,
            "POST",
            r#"{"ResetKeysType":"ResetAllKeysToDefault"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_event_subscription_creation_through_the_typed_create_api()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[("200 OK", COMMAND_EVENT_SERVICE_BODY)],
            http_response("201 Created", COMMAND_EVENT_SUBSCRIPTION_CREATED_BODY),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://example.com/hook".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &EVENT_SUBSCRIPTION_CREATE_REQUEST_PATHS,
            "POST",
            r#"{"Destination":"https://example.com/hook","Protocol":"Redfish","EventTypes":["Alert"]}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_event_subscription_deletion_through_the_typed_delete_api()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[("200 OK", COMMAND_EVENT_SERVICE_BODY)],
            http_response("204 No Content", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::DeleteSubscription(DeleteSubscription::new(
                    "Sub-1".to_owned(),
                ))),
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        assert_command_requests(
            &server.finish_all().await?,
            &EVENT_SUBSCRIPTION_DELETE_REQUEST_PATHS,
            "DELETE",
            "",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_system_reset_when_the_reset_action_is_not_advertised()
    -> Result<(), Box<dyn Error>> {
        // The capability check rejects the command after the member fetch,
        // so no write response is ever served: the sequence is exactly the
        // Session lifecycle plus the collection and member reads.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITHOUT_CAPABILITIES_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::CapabilityUnavailable
            ))
        ));
        // The capability check stops the sequence before any write request:
        // the collection and member are read, then the Session is deleted.
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 7);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"POST /redfish/v1/Systems/1/Actions"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_boot_override_when_the_system_carries_no_boot_object()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITHOUT_CAPABILITIES_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                    SetBootSourceOverride::new(
                        BootSource::Pxe,
                        BootSourceOverrideEnabled::Once,
                        BootSourceOverrideMode::Uefi,
                    ),
                )),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::CapabilityUnavailable
            ))
        ));
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 7);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"PATCH /redfish/v1/Systems/1 "))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_secure_boot_commands_when_the_secure_boot_link_is_absent()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITHOUT_CAPABILITIES_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::SecureBoot(SecureBootCommand::Enable),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::CapabilityUnavailable
            ))
        ));
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 7);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"PATCH /redfish/v1/Systems/1/SecureBoot "))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_subscription_creation_when_the_subscriptions_link_is_absent()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[("200 OK", COMMAND_EVENT_SERVICE_WITHOUT_SUBSCRIPTIONS_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://example.com/hook".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::CapabilityUnavailable
            ))
        ));
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 6);
        assert!(requests
            .iter()
            .all(|request| !request.starts_with(b"POST /redfish/v1/EventService/Subscriptions")));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_subscription_deletion_with_an_unsafe_subscription_id()
    -> Result<(), Box<dyn Error>> {
        for unsafe_id in [
            "../Systems/1",
            "a/b",
            "a?b",
            "a#b",
            "a%2Fb",
            "a b",
            "..",
            ".",
            "",
        ] {
            // The payload validation stops the sequence before the
            // EventService fetch, so only the Session lifecycle is served.
            let server = TestRedfishServer::start_raw_sequence(session_lifecycle_sequence(
                FULL_SERVICE_ROOT_BODY,
            ))
            .await?;
            let gateway = gateway_with_root(server.certificate.clone())?;
            let trust = system_ca_trust(&server.certificate)?;
            let outcome = gateway
                .execute_command(
                    &server.address,
                    &trust,
                    &CredentialUsername::parse("admin")?,
                    &SecretString::from("password"),
                    &RedfishCommand::Event(EventCommand::DeleteSubscription(
                        DeleteSubscription::new(unsafe_id.to_owned()),
                    )),
                )
                .await;
            assert!(
                matches!(
                    outcome,
                    Err(CommandExecutionError::Rejected(
                        CommandRejection::InvalidCommandPayload
                    ))
                ),
                "subscription id {unsafe_id:?} must be rejected before any request"
            );
            // The payload validation stops the sequence before the
            // EventService fetch: only the Session lifecycle requests were
            // made, and no deletion was ever dispatched.
            let requests = server.finish_all().await?;
            assert_eq!(requests.len(), 5);
            assert!(
                requests
                    .iter()
                    .all(|request| !request.starts_with(b"DELETE /redfish/v1/EventService/"))
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_commands_when_the_service_root_authentication_fails()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_sequence(&[("401 Unauthorized", "")]).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::AuthenticationFailed
            ))
        ));
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with(b"GET /redfish/v1 HTTP/1.1\r\n"));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_the_write_when_the_bmc_refuses_authentication() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response("401 Unauthorized", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::AuthenticationFailed
            ))
        ));
        assert_command_requests(
            &server.finish_all().await?,
            &RESET_COMMAND_REQUEST_PATHS,
            "POST",
            r#"{"ResetType":"On"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_the_write_when_permission_is_denied() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response("403 Forbidden", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::PermissionDenied
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_the_write_when_the_bmc_returns_another_client_error()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response(
                "400 Bad Request",
                r#"{"error":{"code":"Base.1.0.GeneralError","message":"ResetType not allowed"}}"#,
            ),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::RefusedByBmc
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn classifies_a_server_failure_during_the_write_as_result_unknown()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response(
                "500 Internal Server Error",
                r#"{"error":{"code":"Base.1.0.InternalError","message":"boom"}}"#,
            ),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        let error = match outcome {
            Err(error) => error,
            Ok(accepted) => {
                return Err(format!("a 5xx during the write must fail, got {accepted:?}").into());
            }
        };
        assert!(
            error.outcome_is_unknown(),
            "a 5xx response may mean the write was applied: {error}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn classifies_a_dropped_connection_during_the_write_as_result_unknown()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            Vec::new(),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        let error = match outcome {
            Err(error) => error,
            Ok(accepted) => {
                return Err(
                    format!("a dropped write connection must fail, got {accepted:?}").into(),
                );
            }
        };
        assert!(
            error.outcome_is_unknown(),
            "the write may already have been applied: {error}"
        );
        // The write request itself was captured before the connection
        // dropped, proving the write was actually dispatched.
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 8);
        let write = std::str::from_utf8(&requests[6])?;
        assert!(write.starts_with("POST /redfish/v1/Systems/1/Actions/ComputerSystem.Reset"));
        assert_eq!(request_body(&requests[6]), Some(r#"{"ResetType":"On"}"#));
        Ok(())
    }

    #[tokio::test]
    async fn surfaces_an_accepted_task_as_an_outcome_unknown_error() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
            ],
            http_response_with_headers(
                "202 Accepted",
                "",
                &[("Location", "/redfish/v1/TaskService/Tasks/42")],
            ),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        let task_location = match outcome {
            Err(CommandExecutionError::AsyncTaskAccepted { task_location }) => task_location,
            other => {
                return Err(
                    format!("a 202 must surface as AsyncTaskAccepted, got {other:?}").into(),
                );
            }
        };
        assert_eq!(
            task_location.to_string(),
            "/redfish/v1/TaskService/Tasks/42"
        );
        assert!(
            CommandExecutionError::AsyncTaskAccepted { task_location }.outcome_is_unknown(),
            "a 202 means the BMC accepted the write, so the outcome is unprovable"
        );
        Ok(())
    }

    #[test]
    fn subscription_id_validation_accepts_only_single_safe_segments() {
        for safe in ["Sub-1", "sub_1", "42", "aBcD-9_x"] {
            assert_eq!(validate_subscription_id(safe), Some(safe));
        }
        for unsafe_id in [
            "", "/", "a/b", "..", ".", "a%2Fb", "a b", "a#b", "a?b", "a\\b", "a\tb",
        ] {
            assert_eq!(
                validate_subscription_id(unsafe_id),
                None,
                "id {unsafe_id:?} must not form a deletion URI"
            );
        }
    }

    #[test]
    fn command_error_verdicts_match_the_design_13_5_classification() -> Result<(), Box<dyn Error>> {
        let url = url::Url::parse("https://192.0.2.1/redfish/v1")?;
        let bmc_error = |status| BmcError::InvalidResponse {
            url: url.clone(),
            status,
            text: String::new(),
        };

        let network =
            CommandExecutionError::OutcomeUnknown(Box::new(RedfishServiceRootError::Network {
                source: bmc_error(StatusCode::INTERNAL_SERVER_ERROR),
            }));
        assert!(network.outcome_is_unknown());

        let rejected = CommandExecutionError::Rejected(CommandRejection::RefusedByBmc);
        assert!(!rejected.outcome_is_unknown());

        let not_dispatched =
            CommandExecutionError::NotDispatched(Box::new(RedfishServiceRootError::TlsRejected {
                source: bmc_error(StatusCode::UNAUTHORIZED),
            }));
        assert!(!not_dispatched.outcome_is_unknown());

        let combined = CommandExecutionError::OperationAndSessionCleanupFailed {
            operation: Box::new(CommandExecutionError::OutcomeUnknown(Box::new(
                RedfishServiceRootError::NetworkTimeout {
                    source: bmc_error(StatusCode::REQUEST_TIMEOUT),
                },
            ))),
            cleanup: Box::new(RedfishServiceRootError::SessionCleanupFailed),
        };
        assert!(combined.outcome_is_unknown());

        let combined_not_dispatched = CommandExecutionError::OperationAndSessionCleanupFailed {
            operation: Box::new(rejected),
            cleanup: Box::new(RedfishServiceRootError::SessionCleanupFailed),
        };
        assert!(!combined_not_dispatched.outcome_is_unknown());
        Ok(())
    }

    /// Builds the bare Session lifecycle responses (root read, `SessionService`
    /// read, Sessions read, Session create, Session delete) without any
    /// post-session response, for tests whose command is rejected before it
    /// can dispatch a write.
    /// A `Subscriptions` collection whose single member is a subscription
    /// with a different `Destination` than the verification payload, used to
    /// pin the `Mismatched` verdict.
    const COMMAND_SUBSCRIPTIONS_WITH_ONE_MEMBER_BODY: &str = r##"{
        "@odata.type":"#EventDestinationCollection.EventDestinationCollection",
        "@odata.id":"/redfish/v1/EventService/Subscriptions",
        "Name":"Event Subscription Collection",
        "Members":[{"@odata.id":"/redfish/v1/EventService/Subscriptions/1"}]
    }"##;

    /// A `Subscriptions` collection whose single member is the freshly
    /// created subscription (`Sub-1`), used by the deletion verification
    /// tests.
    const COMMAND_SUBSCRIPTIONS_WITH_CREATED_MEMBER_BODY: &str = r##"{
        "@odata.type":"#EventDestinationCollection.EventDestinationCollection",
        "@odata.id":"/redfish/v1/EventService/Subscriptions",
        "Name":"Event Subscription Collection",
        "Members":[{"@odata.id":"/redfish/v1/EventService/Subscriptions/Sub-1"}]
    }"##;

    /// The request order of one subscription-create verification: the
    /// Session lifecycle around the `EventService` document, the
    /// `Subscriptions` collection, and the single member fetch.
    const VERIFY_SUBSCRIPTION_CREATE_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions",
        "/redfish/v1/EventService/Subscriptions/Sub-1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one subscription verification against a
    /// collection with one member: the Session lifecycle around the
    /// `EventService` document, the `Subscriptions` collection, and the
    /// member fetch.
    const VERIFY_SUBSCRIPTION_ONE_MEMBER_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions",
        "/redfish/v1/EventService/Subscriptions/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one subscription verification against an empty
    /// collection (or one whose collection fetch fails): the Session
    /// lifecycle around the `EventService` document and the `Subscriptions`
    /// collection.
    const VERIFY_SUBSCRIPTION_COLLECTION_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one system-family verification ("accepted"
    /// semantics): the Session lifecycle around the collection and member
    /// reads.
    const VERIFY_SYSTEM_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one Secure Boot verification: the Session
    /// lifecycle around the system and `SecureBoot` document reads.
    const VERIFY_SECURE_BOOT_REQUEST_PATHS: [&str; 8] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// Asserts the request sequence of one verification re-read: the
    /// standard Session lifecycle (index 3 creates the Session, the last
    /// request deletes it over the Basic transport) around
    /// token-authenticated `GET` re-reads.
    fn assert_verification_requests(
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
                request.starts_with(&format!("{expected_method} {expected_path} HTTP/1.1\r\n")),
                "request {index} must be {expected_method} {expected_path}, was: {request}"
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

    #[tokio::test]
    async fn verifies_subscription_creation_by_re_reading_the_collection()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", COMMAND_EVENT_SERVICE_BODY),
                ("200 OK", COMMAND_SUBSCRIPTIONS_WITH_CREATED_MEMBER_BODY),
                ("200 OK", COMMAND_EVENT_SUBSCRIPTION_CREATED_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://example.com/hook".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
            )
            .await?;

        assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SUBSCRIPTION_CREATE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_subscription_deletion_by_re_reading_the_collection()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", COMMAND_EVENT_SERVICE_BODY),
                ("200 OK", EVENT_SUBSCRIPTIONS_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::DeleteSubscription(DeleteSubscription::new(
                    "Sub-1".to_owned(),
                ))),
            )
            .await?;

        assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SUBSCRIPTION_COLLECTION_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_subscription_creation_as_mismatched_when_the_destination_is_absent()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", COMMAND_EVENT_SERVICE_BODY),
                ("200 OK", COMMAND_SUBSCRIPTIONS_WITH_ONE_MEMBER_BODY),
                ("200 OK", EVENT_SUBSCRIPTION_ONE_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://example.com/hook".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
            )
            .await?;

        assert_eq!(verdict, CommandVerificationOutcome::Mismatched);
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SUBSCRIPTION_ONE_MEMBER_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_subscription_deletion_as_mismatched_when_the_id_is_still_present()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", COMMAND_EVENT_SERVICE_BODY),
                ("200 OK", COMMAND_SUBSCRIPTIONS_WITH_CREATED_MEMBER_BODY),
                ("200 OK", COMMAND_EVENT_SUBSCRIPTION_CREATED_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::DeleteSubscription(DeleteSubscription::new(
                    "Sub-1".to_owned(),
                ))),
            )
            .await?;

        assert_eq!(verdict, CommandVerificationOutcome::Mismatched);
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SUBSCRIPTION_CREATE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_system_and_boot_commands_by_re_reading_the_target()
    -> Result<(), Box<dyn Error>> {
        for command in [
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                SetBootSourceOverride::new(
                    BootSource::Pxe,
                    BootSourceOverrideEnabled::Once,
                    BootSourceOverrideMode::Uefi,
                ),
            )),
        ] {
            let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
                FULL_SERVICE_ROOT_BODY,
                &[
                    ("200 OK", FULL_SYSTEMS_BODY),
                    ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
                ],
            ))
            .await?;
            let gateway = gateway_with_root(server.certificate.clone())?;
            let trust = system_ca_trust(&server.certificate)?;

            let verdict = gateway
                .verify_command(
                    &server.address,
                    &trust,
                    &CredentialUsername::parse("admin")?,
                    &SecretString::from("password"),
                    &command,
                )
                .await?;

            assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
            assert_verification_requests(
                &server.finish_all().await?,
                &VERIFY_SYSTEM_REQUEST_PATHS,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn verifies_manager_and_chassis_resets_by_re_reading_the_targets()
    -> Result<(), Box<dyn Error>> {
        for (command, paths, member) in [
            (
                RedfishCommand::Manager(ManagerCommand::Reset(ResetType::GracefulRestart)),
                [
                    "/redfish/v1",
                    "/redfish/v1/SessionService",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/Managers",
                    "/redfish/v1/Managers/1",
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                ("200 OK", COMMAND_MANAGER_WITH_RESET_ACTION_BODY),
            ),
            (
                RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::ForceOff)),
                [
                    "/redfish/v1",
                    "/redfish/v1/SessionService",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/Chassis",
                    "/redfish/v1/Chassis/1",
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                ("200 OK", COMMAND_CHASSIS_WITH_RESET_ACTION_BODY),
            ),
        ] {
            let collection = if matches!(command, RedfishCommand::Manager(_)) {
                ("200 OK", MANAGERS_WITH_MEMBER_BODY)
            } else {
                ("200 OK", CHASSIS_WITH_MEMBER_BODY)
            };
            let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
                FULL_SERVICE_ROOT_BODY,
                &[collection, member],
            ))
            .await?;
            let gateway = gateway_with_root(server.certificate.clone())?;
            let trust = system_ca_trust(&server.certificate)?;

            let verdict = gateway
                .verify_command(
                    &server.address,
                    &trust,
                    &CredentialUsername::parse("admin")?,
                    &SecretString::from("password"),
                    &command,
                )
                .await?;

            assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
            assert_verification_requests(&server.finish_all().await?, &paths)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn verifies_secure_boot_commands_by_re_reading_the_document() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_RESET_ACTION_BODY),
                ("200 OK", COMMAND_SECURE_BOOT_BODY),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(
                    ResetKeysType::ResetAllKeysToDefault,
                )),
            )
            .await?;

        assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SECURE_BOOT_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_subscription_commands_as_an_error_when_the_collection_cannot_be_re_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", COMMAND_EVENT_SERVICE_BODY),
                ("500 Internal Server Error", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::DeleteSubscription(DeleteSubscription::new(
                    "Sub-1".to_owned(),
                ))),
            )
            .await;

        assert!(
            matches!(verdict, Err(CommandVerificationError::ReReadFailed(_))),
            "an unreadable collection proves nothing about the write: {verdict:?}"
        );
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SUBSCRIPTION_COLLECTION_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_subscription_creation_as_an_error_when_a_member_cannot_be_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", COMMAND_EVENT_SERVICE_BODY),
                ("200 OK", COMMAND_SUBSCRIPTIONS_WITH_ONE_MEMBER_BODY),
                ("500 Internal Server Error", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://example.com/hook".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
            )
            .await;

        assert!(
            matches!(verdict, Err(CommandVerificationError::ReReadFailed(_))),
            "an unreadable member must not be reported as Mismatched: {verdict:?}"
        );
        assert_verification_requests(
            &server.finish_all().await?,
            &VERIFY_SUBSCRIPTION_ONE_MEMBER_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_reset_commands_as_an_error_when_the_target_cannot_be_re_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("500 Internal Server Error", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::System(SystemCommand::Reset(ResetType::On)),
            )
            .await;

        assert!(
            matches!(verdict, Err(CommandVerificationError::ReReadFailed(_))),
            "an unreadable target proves nothing about the write: {verdict:?}"
        );
        assert_verification_requests(&server.finish_all().await?, &VERIFY_SYSTEM_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_subscription_commands_as_an_error_when_the_link_is_gone()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[("200 OK", COMMAND_EVENT_SERVICE_WITHOUT_SUBSCRIPTIONS_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Event(EventCommand::DeleteSubscription(DeleteSubscription::new(
                    "Sub-1".to_owned(),
                ))),
            )
            .await;

        assert!(
            matches!(
                verdict,
                Err(CommandVerificationError::CapabilityUnavailable)
            ),
            "a vanished subscription link cannot confirm anything: {verdict:?}"
        );
        Ok(())
    }

    fn session_lifecycle_sequence(service_root_body: &str) -> Vec<Vec<u8>> {
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
        responses.push(http_response("204 No Content", ""));
        responses
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
            let request = read_request(&mut stream).await?;
            if response.is_empty() {
                // An empty response encodes a dropped connection: the
                // request is captured (so the test can assert it was
                // attempted) and the connection closes without any response,
                // which the client observes as a broken connection.
                requests.push(request);
                continue;
            }
            stream.write_all(&response).await?;
            stream.shutdown().await?;
            requests.push(request);
        }
        Ok(requests)
    }

    async fn read_request(
        stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    ) -> Result<Vec<u8>, io::Error> {
        const MAX_REQUEST_BYTES: usize = 16 * 1024;
        let mut request = Vec::new();
        let mut chunk = [0_u8; 1024];
        let header_end = loop {
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
            if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                break end + 4;
            }
        };
        // Write tests assert the exact request body, so the body is captured
        // after the headers. The body length comes from `Content-Length`;
        // the gateway's JSON requests always carry it.
        let content_length = std::str::from_utf8(&request[..header_end])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "test request headers"))?
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        while request.len() < header_end + content_length {
            let bytes = timeout(Duration::from_secs(5), stream.read(&mut chunk))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "test HTTP request body"))??;
            if bytes == 0 {
                break;
            }
            request.extend_from_slice(&chunk[..bytes]);
            if request.len() > MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "test HTTP request body exceeded limit",
                ));
            }
        }
        Ok(request)
    }
}
