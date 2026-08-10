use std::{
    collections::{BTreeSet, VecDeque},
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

use futures_util::TryStreamExt as _;
use futures_util::io::Cursor;
use nv_redfish::{
    Bmc as _,
    Resource as NvResource,
    ServiceRoot,
    bmc_http::{
        BmcCredentials, CacheSettings, HttpBmc,
        reqwest::{BmcError, Client as NvHttpClient},
    },
    chassis::{Chassis, ChassisCollection, Manufacturer as ChassisManufacturer, NetworkAdapter},
    computer_system::{ComputerSystem, SystemCollection},
    core::odata::ODataType,
    core::{
        BoxTryStream, DataStream, EdmPrimitiveType, EntityTypeRef, HttpPushUriUpdateRequest,
        ModificationResponse, MultipartUpdateRequest, NavProperty, ODataId, ReferenceLeaf,
        ToSnakeCase, UploadStream,
    },
    event_service::EventStreamPayload,
    manager::{Manager, ManagerCollection},
    // The Dell Attributes read surface is the one Dell OEM schema the
    // `oem-dell-attributes` feature compiles; it lives in the Dell OEM
    // feature's own generated module (`oem::dell::schema`), not in the base
    // `schema` module where the standard types are re-exported.
    oem::dell::schema::dell_attributes::DellAttributes as DellAttributesSchema,
    // The Lenovo OEM feature compiles its own generated module tree
    // (`oem::lenovo::schema`) exactly like the Dell, NVIDIA, and Supermicro
    // features. The manager's `Oem.Lenovo` segment decodes through the
    // compiled untagged `LenovoManagerSchema` — the same dual-version serde
    // fallback the upstream `LenovoManager` wrapper performs (v0_1_0 with the
    // boolean `KCSEnabled` shape, v1_0_0 with the state-string shape, and the
    // `Security` navigation on the unversioned `base` shared by both) — and
    // the `Security` navigation is resolved into the `LenovoSecurityService`
    // document.
    oem::lenovo::manager::LenovoManagerSchema,
    oem::lenovo::schema::lenovo_security_service::{
        FwRollbackState as LenovoFwRollbackStateSchema,
        LenovoSecurityService as LenovoSecurityServiceSchema,
    },
    oem::lenovo::schema::resource::Resource as LenovoResourceSchema,
    // The NVIDIA OEM feature compiles its own generated module tree
    // (`oem::nvidia::schema`) exactly like the Dell and Supermicro features.
    // The system-config-profile family navigates from the ComputerSystem's
    // `Oem.Nvidia` segment (the unversioned `nvidia_computer_system` module
    // carries the `SystemConfigProfile` navigation) into the profile
    // service, its status singleton, the profile collection, and each
    // member's profile file. The decode targets are the compiled types
    // themselves: the segment and every chain document are fetched and
    // decoded through these schemas, never a raw JSON read (§11.5 two-way
    // rule).
    oem::nvidia::schema::nvidia_chassis::NvidiaSmaChassis as NvidiaSmaChassisSchema,
    oem::nvidia::schema::nvidia_computer_system::NvidiaComputerSystem as NvidiaComputerSystemSchema,
    oem::nvidia::schema::nvidia_debug_token::{
        GenerateTokenResponse as NvidiaDebugTokenGenerateTokenResponse,
        NvidiaDebugToken as NvidiaDebugTokenSchema,
        NvidiaDebugTokenDisableTokenAction as NvidiaDebugTokenDisableTokenActionSchema,
        NvidiaDebugTokenGenerateTokenAction as NvidiaDebugTokenGenerateTokenActionSchema,
        NvidiaDebugTokenInstallTokenAction as NvidiaDebugTokenInstallTokenActionSchema,
    },
    oem::nvidia::schema::nvidia_debug_token_management::{
        EraseType as NvidiaEraseTypeSchema,
        NvidiaDebugTokenManagement as NvidiaDebugTokenManagementSchema,
        NvidiaDebugTokenManagementEraseTokenAction as NvidiaDebugTokenManagementEraseTokenActionSchema,
        TokenType as NvidiaTokenTypeSchema,
    },
    // The §0.5.0 NVIDIA manager chains navigate from the `Manager`'s
    // `Oem.Nvidia` segment: the versioned `NvidiaManager.v1_9_0` module
    // carries the `PowerCompliance` navigation (the decode target must be
    // this navigation-carrying versioned struct — decoding into an
    // unversioned shape would silently drop the navigation), into the
    // `NvidiaPowerComplianceManager` document, and from there into the
    // power-compliance and managed-entity sub-chains.
    oem::nvidia::schema::nvidia_managed_entity::NvidiaManagedEntity as NvidiaManagedEntitySchema,
    oem::nvidia::schema::nvidia_managed_entity_collection::NvidiaManagedEntityCollection as NvidiaManagedEntityCollectionSchema,
    oem::nvidia::schema::nvidia_managed_entity_group::NvidiaManagedEntityGroup as NvidiaManagedEntityGroupSchema,
    oem::nvidia::schema::nvidia_managed_entity_group_collection::NvidiaManagedEntityGroupCollection as NvidiaManagedEntityGroupCollectionSchema,
    oem::nvidia::schema::nvidia_manager::v1_9_0::NvidiaManager as NvidiaManagerSegmentSchema,
    oem::nvidia::schema::nvidia_power_compliance_manager::{
        NvidiaManagerType as NvidiaPowerComplianceManagerType,
        NvidiaPowerComplianceManager as NvidiaPowerComplianceManagerSchema,
    },
    oem::nvidia::schema::nvidia_power_domain::{
        ComparisonType as NvidiaPowerDomainComparisonType,
        NvidiaPowerDomain as NvidiaPowerDomainSchema, UnitType as NvidiaPowerDomainUnitType,
    },
    oem::nvidia::schema::nvidia_power_domain_collection::NvidiaPowerDomainCollection as NvidiaPowerDomainCollectionSchema,
    oem::nvidia::schema::nvidia_power_policy::{
        ActionType as NvidiaPowerPolicyActionType,
        ComparisonType as NvidiaPowerPolicyComparisonType,
        NvidiaPowerPolicy as NvidiaPowerPolicySchema, UnitType as NvidiaPowerPolicyUnitType,
    },
    oem::nvidia::schema::nvidia_power_smoothing::{
        NvidiaPowerSmoothing as NvidiaPowerSmoothingSchema,
        NvidiaPowerSmoothingActivatePresetProfileAction as NvidiaPowerSmoothingActivatePresetProfileActionSchema,
        NvidiaPowerSmoothingApplyAdminOverridesAction as NvidiaPowerSmoothingApplyAdminOverridesActionSchema,
    },
    oem::nvidia::schema::nvidia_power_state_group::NvidiaPowerStateGroup as NvidiaPowerStateGroupSchema,
    oem::nvidia::schema::nvidia_psc_state::{
        NvidiaPscState as NvidiaPscStateSchema, StatusType as NvidiaPscStateStatusType,
    },
    oem::nvidia::schema::nvidia_psc_state_collection::NvidiaPscStateCollection as NvidiaPscStateCollectionSchema,
    oem::nvidia::schema::nvidia_psu_redundancy::{
        NvidiaPsuRedundancy as NvidiaPsuRedundancySchema, RedundancyType as NvidiaPsuRedundancyType,
    },
    oem::nvidia::schema::nvidia_psu_state::NvidiaPsuState as NvidiaPsuStateSchema,
    oem::nvidia::schema::nvidia_psu_state_collection::NvidiaPsuStateCollection as NvidiaPsuStateCollectionSchema,
    oem::nvidia::schema::nvidia_system_config_profile::NvidiaSystemConfigProfile as NvidiaSystemConfigProfileSchema,
    oem::nvidia::schema::nvidia_system_config_profile::{
        NvidiaSystemConfigProfileFactoryResetAction as NvidiaSystemConfigProfileFactoryResetActionSchema,
        NvidiaSystemConfigProfileUpdateAction as NvidiaSystemConfigProfileUpdateActionSchema,
    },
    oem::nvidia::schema::nvidia_system_config_profile_status::NvidiaSystemConfigProfileStatus as NvidiaSystemConfigProfileStatusSchema,
    oem::nvidia::schema::nvidia_system_profile::NvidiaSystemProfile as NvidiaSystemProfileSchema,
    oem::nvidia::schema::nvidia_system_profile::NvidiaSystemProfileActivateAction as NvidiaSystemProfileActivateActionSchema,
    oem::nvidia::schema::nvidia_system_profile_collection::NvidiaSystemProfileCollection as NvidiaSystemProfileCollectionSchema,
    oem::nvidia::schema::nvidia_system_profile_file::NvidiaSystemProfileFile as NvidiaSystemProfileFileSchema,
    // The generated NVIDIA module tree carries its own copies of the
    // `protocol` and `sensor` modules (exactly like the base schema's
    // re-export), so the enum types the NVIDIA documents reference come from
    // this tree, never from the base `schema` module.
    oem::nvidia::schema::protocol::Protocol as NvidiaProtocolSchema,
    oem::nvidia::schema::resource::Resource as NvidiaResourceSchema,
    oem::nvidia::schema::sensor::ImplementationType as NvidiaSensorImplementationType,
    oem::nvidia::schema::sensor::ReadingType as NvidiaSensorReadingType,
    // The Supermicro OEM feature compiles its own generated module tree
    // (`oem::supermicro::schema`) exactly like the Dell feature: the
    // `smc_manager_extensions` schema models the manager's embedded
    // `Oem.Supermicro` segment, whose two `NavProperty` fields navigate to
    // the `SysLockdown` and `KcsInterface` documents.
    oem::supermicro::schema::kcs_interface::{
        KcsInterface as KcsInterfaceSchema, Privilege as KcsPrivilegeSchema,
    },
    oem::supermicro::schema::smc_manager_extensions::Manager as SmcManagerExtensionsSchema,
    oem::supermicro::schema::sys_lockdown::SysLockdown as SysLockdownSchema,
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
        environment_metrics::EnvironmentMetrics as EnvironmentMetricsSchema,
        ethernet_interface::EthernetInterface as EthernetInterfaceSchema,
        ethernet_interface_collection::EthernetInterfaceCollection as EthernetInterfaceCollectionSchema,
        event::EventRecord as EventRecordSchema,
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
        network_device_function::NetworkDeviceFunction as NetworkDeviceFunctionSchema,
        network_device_function_collection::NetworkDeviceFunctionCollection as NetworkDeviceFunctionCollectionSchema,
        pcie_device::PcieDevice as PcieDeviceSchema,
        power::Power as PowerSchema,
        power_distribution::PowerDistribution as PowerDistributionSchema,
        power_distribution_collection::PowerDistributionCollection as PowerDistributionCollectionSchema,
        power_equipment::PowerEquipment as PowerEquipmentSchema,
        power_subsystem::PowerSubsystem as PowerSubsystemSchema,
        power_supply::PowerSupply as PowerSupplySchema,
        power_supply_collection::PowerSupplyCollection as PowerSupplyCollectionSchema,
        processor::Processor as ProcessorSchema,
        processor_collection::ProcessorCollection as ProcessorCollectionSchema,
        resource::Health as HealthSchema,
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
        update_service::UpdateParametersUpdate as MultipartUpdateParameters,
        update_service::UpdateService as UpdateServiceSchema,
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
    EndpointId, EraseType, Event, EventCommand, EventDestinationProtocol, EventId, EventSeverity,
    EventType, ManagerCommand, MessageId, NvidiaDebugTokenCommand, NvidiaPowerSmoothingCommand,
    NvidiaSystemConfigProfileCommand, OemCommand, RedfishCommand, ResetKeysType, ResetType,
    ResourceEtag, ResourceEtagError, ResourceFeature, ResourceODataId, ResourceODataIdError,
    ResourceSnapshotPayload, ResourceSnapshotPayloadError, SecureBootCommand,
    SetBootSourceOverride, SystemCommand, TlsIdentityChanged, TlsTrust, TokenType,
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::error::Category as JsonErrorCategory;
use thiserror::Error;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

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

    /// Reads the Service Root and probes the complete §2.1 capability surface
    /// (30 standard and 14 OEM capabilities) through public, typed
    /// `nv-redfish` navigation methods.
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
    /// OEM capabilities are probed as a pure presence read over the resources
    /// this flow already decoded (Service Root plus collection members): the
    /// vendor namespace keys in their `Oem` segments decide the §11.3
    /// advertised layer without a single extra request.
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
                oem: probe_oem_namespaces(&authenticated.root, &systems, &chassis, &managers),
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

    /// Uploads one firmware artifact to the endpoint's `UpdateService` (§14.3)
    /// exclusively through the public `nv-redfish` typed upload API — the
    /// `Bmc::multipart_update` and `Bmc::http_push_uri_update` methods —
    /// never a raw `reqwest` request (§7.4).
    ///
    /// The upload method follows the caller's decision, which the §14.3 flow
    /// derives from the endpoint's published update surface:
    ///
    /// - `push_uri: None` — the standard multipart upload: a
    ///   `multipart/form-data` `POST` to the `MultipartHttpPushUri` the
    ///   decoded `UpdateService` document advertises, carrying the typed
    ///   `UpdateParameters` JSON part and the artifact as the named
    ///   `UpdateFile` binary part. §13.3 step 2: a missing `UpdateService`
    ///   link or a missing `MultipartHttpPushUri` property rejects the
    ///   upload before any write is sent.
    /// - `push_uri: Some(uri)` — the upstream-retained legacy direct push
    ///   (§0.4.0 "上游保留的 Legacy Update 兼容"): a raw `application/octet-stream`
    ///   `POST` to the caller-selected `HttpPushUri`. The endpoint must still
    ///   advertise `HttpPushUri` on its `UpdateService` document (§13.3 step
    ///   2); the gateway never constructs the URI and the transport resolves
    ///   it same-origin, so a caller-supplied value cannot escape the
    ///   endpoint (§15.6).
    ///
    /// The artifact arrives as an in-memory byte range because the gateway
    /// performs no file-system I/O: the application resolves the artifact's
    /// stored file and hands the bytes across the boundary (§7.2, §7.8), and
    /// the in-memory range is the artifact-size boundary of this iteration —
    /// streaming from storage and resumable transfers are the later §0.4.0
    /// large-file iteration.
    ///
    /// The transient Session lifecycle is identical to the write surfaces: a
    /// Session is established when usable, the upload authenticates with its
    /// token, and the Session is deleted before returning. A `202` response
    /// is reported as [`CommandExecutionError::AsyncTaskAccepted`], never as
    /// acceptance: the gateway itself never polls Tasks, so the application
    /// adapter maps that error onto the `AsyncTaskAccepted` outcome the Task
    /// monitor polls (§13.6) — the §14.3 flow tracks the Task, waits out a
    /// possible BMC restart, reconnects, and re-reads `SoftwareInventory`.
    ///
    /// # Errors
    ///
    /// Returns [`CommandExecutionError`] with the same classification
    /// contract as [`Self::execute_command`]: a provable rejection
    /// (capability unavailable, authentication/permission denial, refused by
    /// the BMC, unsafe payload), a client-side failure that provably
    /// prevented dispatch, a dispatched upload whose outcome cannot be
    /// proven (§13.5), or a `202` Task acceptance.
    pub async fn execute_update(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
        artifact: UpdateArtifactUpload,
        push_uri: Option<&ResourceODataId>,
    ) -> Result<CommandExecutionOutcome, CommandExecutionError> {
        // The artifact name becomes the `filename` attribute of the multipart
        // `UpdateFile` part, so it is validated before any network work: a
        // control character could smuggle request structure into the body,
        // and the rejection proves the write was never dispatched (§13.5).
        if !validate_update_file_name(artifact.name()) {
            return Err(CommandExecutionError::Rejected(
                CommandRejection::InvalidCommandPayload,
            ));
        }
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
        let result = execute_authenticated_update(
            authenticated.bmc.as_ref(),
            &authenticated.root,
            &identity,
            trust,
            artifact,
            push_uri,
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

    /// Re-reads the endpoint's `SoftwareInventory` family after an accepted
    /// firmware update (§14.3: "重新读取 `SoftwareInventory` → 验证版本").
    ///
    /// The verification is "accepted" verification in the same honest sense
    /// as the reset families: the re-read of the complete inventory family —
    /// the `UpdateService` document, the `SoftwareInventory` collection, and
    /// every member document — must succeed without error, and the verifier
    /// returns `Confirmed` without asserting a specific firmware version. The
    /// version expectation is not part of the update contract of this
    /// iteration (the artifact carries no declared target version), so
    /// claiming a version match from a successful read would fabricate a
    /// result (design section 13.7). The re-read itself is exactly the
    /// recovery re-read §13.6 performs after a BMC restart, and the strict
    /// member fetch (no member is skippable) keeps the verdict honest: after
    /// an accepted update, an inventory document that cannot be read leaves
    /// the outcome unprovable.
    ///
    /// Only `Accepted` or Task-completed updates reach the verifier, so every
    /// failure here proves nothing about the write: the scheduler records
    /// `Unknown` (§13.5) instead of a failure.
    ///
    /// The re-reads go through the same typed navigation and Session
    /// lifecycle as the write itself, and the endpoint's own URI structure is
    /// never guessed (§11.1): the collection and members are discovered
    /// through the decoded root `UpdateService` link. A `404` from the
    /// `UpdateService` document or the `SoftwareInventory` collection, or a
    /// vanished navigation link, is [`CommandVerificationOutcome::Mismatched`]:
    /// the application contract records a provably absent inventory surface
    /// as the update's result being absent, not as an unprovable re-read.
    ///
    /// # Errors
    ///
    /// Returns [`CommandVerificationError`] when the inventory cannot be
    /// re-read at all.
    pub async fn verify_update(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
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
        let result = verify_authenticated_update(
            authenticated.bmc.as_ref(),
            &authenticated.root,
            &identity,
            trust,
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

    /// Opens the endpoint's `EventService` SSE stream (§14.4) and binds it
    /// to one transient Session for the stream's whole lifetime.
    ///
    /// The stream is opened through the endpoint's advertised
    /// `ServerSentEventUri` (`EventService::events`), so no SSE URI is ever
    /// guessed (§11.1). Unlike every other authenticated operation — where
    /// the Session is deleted before returning — the returned [`EventStream`]
    /// OWNS the Session and deletes it when the stream reaches its terminal
    /// state: the upstream closes, a fatal error is delivered, or `cancel`
    /// fires. The caller must therefore poll `next()` to completion or call
    /// `shutdown()`; abandoning the stream without a terminal state closes
    /// the SSE connection (the stream is dropped) but leaves the Session
    /// alive until the BMC expires it (§7.8 forbids untraceable detached
    /// cleanup tasks).
    ///
    /// Each yielded [`EndpointEvent`] is bound to `endpoint_id` and carries
    /// the complete domain [`Event`] — `MessageId`, severity, message, BMC
    /// timestamp, the product-side receive time, and the derived dedup key
    /// already stamped (§14.4 记录事件来源 and 去除明显重复), exactly as the
    /// application `EventStream` boundary consumes it.
    ///
    /// # Cancellation
    ///
    /// Firing `cancel` stops the stream at the next poll: mapped events that
    /// were not yet delivered are discarded, the SSE connection is closed,
    /// and the Session is deleted.
    ///
    /// # Errors
    ///
    /// Returns [`EventStreamOpenError`]: `EventServiceNotAdvertised` or
    /// `ServerSentEventsUnavailable` when the endpoint has no SSE surface,
    /// `TrustOrSession` when the trust-bound Session setup failed, and
    /// `Reconnectable`/`Terminal` when the SSE request itself failed. A
    /// session already created for the failed open is deleted before the
    /// error returns.
    pub async fn open_event_stream(
        &self,
        address: &EndpointAddress,
        trust: &TlsTrust,
        username: &CredentialUsername,
        password: &SecretString,
        endpoint_id: EndpointId,
        cancel: CancellationToken,
    ) -> Result<EventStream, EventStreamOpenError> {
        let (bmc, http, identity) = self
            .authenticated_bmc(address, trust, username, password)
            .map_err(EventStreamOpenError::TrustOrSession)?;
        let root = match ServiceRoot::new(Arc::clone(&bmc)).await {
            Ok(root) => root,
            Err(source) => {
                return Err(EventStreamOpenError::TrustOrSession(
                    classify_service_root_error(source, &identity, trust),
                ));
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
            Err(source) => return Err(EventStreamOpenError::TrustOrSession(source)),
        };
        let result = open_authenticated_event_stream(&authenticated.root, &identity, trust).await;
        match result {
            Ok(upstream) => Ok(EventStream::new(
                endpoint_id,
                upstream,
                cancel,
                authenticated.session,
                authenticated.bmc,
                identity,
                trust.clone(),
            )),
            Err(operation) => {
                // The stream never opened: delete the transient Session
                // before surfacing the failure, exactly like
                // `finish_redfish_operation`.
                let cleanup = cleanup_session(authenticated.session, &identity, trust).await;
                match cleanup {
                    Ok(()) => Err(operation),
                    Err(cleanup) => Err(EventStreamOpenError::OpenAndSessionCleanupFailed {
                        open: Box::new(operation),
                        cleanup: Box::new(cleanup),
                    }),
                }
            }
        }
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

/// Opens the typed SSE stream of the root's `EventService` (§14.4).
///
/// A missing `EventService` link and an `EventService` without a
/// `ServerSentEventUri` are endpoint-level capability facts: the endpoint
/// has no SSE surface and no retry can change that. Every other open
/// failure is classified into the reconnectable/terminal contract the
/// application reconnect loop consumes.
async fn open_authenticated_event_stream(
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<BoxTryStream<EventStreamPayload, UpstreamServiceRootError>, EventStreamOpenError> {
    let Some(service) = root
        .event_service()
        .await
        .map_err(|source| classify_event_stream_open_error(source, identity, trust))?
    else {
        return Err(EventStreamOpenError::EventServiceNotAdvertised);
    };
    service
        .events()
        .await
        .map_err(|source| classify_event_stream_open_error(source, identity, trust))
}

/// Classifies a failure to OPEN the endpoint's SSE stream.
///
/// The stream opens through a GET on `ServerSentEventUri`; a status on that
/// request is the endpoint's live decision, so 401 (Session token
/// invalidated) and 5xx are reconnectable while 403 (permission) and other
/// 4xx are not. TLS-safety failures are never reconnectable: the persisted
/// trust decision must be re-evaluated before any retry.
fn classify_event_stream_open_error(
    source: UpstreamServiceRootError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> EventStreamOpenError {
    match identity.take_change(trust) {
        Ok(Some(changed)) => {
            return EventStreamOpenError::TrustOrSession(
                RedfishServiceRootError::TlsIdentityChanged(changed),
            );
        }
        Err(state) => {
            return EventStreamOpenError::TrustOrSession(
                RedfishServiceRootError::TlsIdentityState(state),
            );
        }
        Ok(None) => {}
    }
    if identity.validation_rejected() {
        return match source {
            nv_redfish::Error::Bmc(source) => {
                EventStreamOpenError::Terminal(RedfishServiceRootError::TlsRejected { source })
            }
            source => EventStreamOpenError::Terminal(RedfishServiceRootError::Upstream(source)),
        };
    }
    match source {
        nv_redfish::Error::EventServiceServerSentEventUriNotAvailable => {
            EventStreamOpenError::ServerSentEventsUnavailable
        }
        nv_redfish::Error::Json(_) => {
            EventStreamOpenError::Terminal(RedfishServiceRootError::SchemaIncompatible { source })
        }
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { status, .. }) => {
            if status == StatusCode::UNAUTHORIZED {
                EventStreamOpenError::Reconnectable(RedfishServiceRootError::AuthenticationFailed {
                    source,
                })
            } else if status == StatusCode::FORBIDDEN {
                EventStreamOpenError::Terminal(RedfishServiceRootError::PermissionDenied { source })
            } else if status == StatusCode::NOT_FOUND {
                EventStreamOpenError::Terminal(RedfishServiceRootError::NotRedfishService {
                    source,
                })
            } else if status.is_server_error() {
                EventStreamOpenError::Reconnectable(RedfishServiceRootError::RemoteResponse {
                    source,
                })
            } else {
                EventStreamOpenError::Terminal(RedfishServiceRootError::RemoteResponse { source })
            }
        }
        nv_redfish::Error::Bmc(source @ BmcError::ReqwestError(_))
            if is_transport_timeout(&source) =>
        {
            EventStreamOpenError::Reconnectable(RedfishServiceRootError::NetworkTimeout { source })
        }
        nv_redfish::Error::Bmc(source @ BmcError::ReqwestError(_)) => {
            EventStreamOpenError::Reconnectable(RedfishServiceRootError::Network { source })
        }
        nv_redfish::Error::Bmc(source @ (BmcError::JsonError(_) | BmcError::DecodeError(_))) => {
            EventStreamOpenError::Terminal(RedfishServiceRootError::SchemaIncompatible {
                source: nv_redfish::Error::Bmc(source),
            })
        }
        nv_redfish::Error::Bmc(
            source @ (BmcError::SseStreamError(_) | BmcError::SseIdleTimeout { .. }),
        ) => EventStreamOpenError::Reconnectable(RedfishServiceRootError::Upstream(
            nv_redfish::Error::Bmc(source),
        )),
        nv_redfish::Error::Bmc(source) => EventStreamOpenError::Terminal(
            RedfishServiceRootError::Upstream(nv_redfish::Error::Bmc(source)),
        ),
        source => EventStreamOpenError::Terminal(RedfishServiceRootError::Upstream(source)),
    }
}

/// Classifies one mid-stream failure of the SSE stream.
///
/// The upstream terminates the stream for every error except a per-event
/// JSON decode failure (filtered by [`is_skippable_event_stream_item`]), so
/// every error seen here ends the stream. Transport failures (connect/read
/// EOF/timeout) and SSE framing decode failures are reconnectable: the next
/// connection may decode cleanly. An event that exceeds the fixed 1 MiB
/// buffering budget is terminal: the budget is a compiled upstream default,
/// so reconnecting cannot succeed for that endpoint.
fn classify_event_stream_error(source: UpstreamServiceRootError) -> EventStreamError {
    match source {
        nv_redfish::Error::Json(_) => {
            EventStreamError::Terminal(RedfishServiceRootError::SchemaIncompatible { source })
        }
        nv_redfish::Error::Bmc(source @ BmcError::ReqwestError(_))
            if is_transport_timeout(&source) =>
        {
            EventStreamError::Reconnectable(RedfishServiceRootError::NetworkTimeout { source })
        }
        nv_redfish::Error::Bmc(source @ BmcError::ReqwestError(_)) => {
            EventStreamError::Reconnectable(RedfishServiceRootError::Network { source })
        }
        nv_redfish::Error::Bmc(
            source @ (BmcError::SseStreamError(_) | BmcError::SseIdleTimeout { .. }),
        ) => EventStreamError::Reconnectable(RedfishServiceRootError::Upstream(
            nv_redfish::Error::Bmc(source),
        )),
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { status, .. })
            if status == StatusCode::UNAUTHORIZED =>
        {
            EventStreamError::Reconnectable(RedfishServiceRootError::AuthenticationFailed {
                source,
            })
        }
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { status, .. })
            if status == StatusCode::FORBIDDEN =>
        {
            EventStreamError::Terminal(RedfishServiceRootError::PermissionDenied { source })
        }
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { status, .. })
            if status.is_server_error() =>
        {
            EventStreamError::Reconnectable(RedfishServiceRootError::RemoteResponse { source })
        }
        nv_redfish::Error::Bmc(source @ BmcError::InvalidResponse { .. }) => {
            EventStreamError::Terminal(RedfishServiceRootError::RemoteResponse { source })
        }
        nv_redfish::Error::Bmc(source @ (BmcError::JsonError(_) | BmcError::DecodeError(_))) => {
            EventStreamError::Terminal(RedfishServiceRootError::SchemaIncompatible {
                source: nv_redfish::Error::Bmc(source),
            })
        }
        // Every remaining `BmcError` — including `SseEventTooLarge`, whose
        // 1 MiB budget is a compiled upstream default — is terminal: no
        // transport error class reaches this catch-all, and an oversized
        // event is deterministic for the endpoint.
        nv_redfish::Error::Bmc(source) => EventStreamError::Terminal(
            RedfishServiceRootError::Upstream(nv_redfish::Error::Bmc(source)),
        ),
        source => EventStreamError::Terminal(RedfishServiceRootError::Upstream(source)),
    }
}

/// Reports whether a transport failure was a timeout.
fn is_transport_timeout(source: &BmcError) -> bool {
    matches!(source, BmcError::ReqwestError(error) if error.is_timeout())
}

/// Reports whether a mid-stream failure is scoped to one event and must not
/// end the stream.
///
/// The upstream surfaces only JSON decode failures this way (the payload
/// failed to deserialize into `EventStreamPayload`); every other error ends
/// the stream, so skipping keeps the SSE connection alive past a malformed
/// event instead of churning the reconnect loop.
fn is_skippable_event_stream_item(source: &UpstreamServiceRootError) -> bool {
    matches!(source, nv_redfish::Error::Json(_))
}

/// Builds the complete domain [`Event`] from one Redfish `EventRecord`
/// (§14.4).
///
/// Returns `None` — and the stream continues — for records the domain model
/// refuses: an unparseable `MessageId`, a severity outside the DMTF
/// vocabulary, or an event timestamp after the product receive time. The
/// domain treats a stored row with an unknown severity code or an inverted
/// timeline as corrupt (§9.3), so the stream never invents a value and never
/// clamps a BMC clock: a refused record is dropped, keeping the stream alive
/// and the boundary honest. These rejection decisions all live here, exactly
/// where the application `EventStream` boundary contract places them.
///
/// `event_timestamp` falls back to `observed_at` when the record carries no
/// timestamp, so a record without one stays recordable; the product receive
/// time is stamped by the stream (the product clock) and the dedup key is
/// derived inside [`Event::new`] (去除明显重复).
fn map_event_record(
    record: &EventRecordSchema,
    endpoint_id: EndpointId,
    observed_at: OffsetDateTime,
) -> Option<Event> {
    let message_id = MessageId::parse(&record.message_id).ok()?;
    let severity = map_event_severity(record.severity.as_deref(), record.message_severity)?;
    let event_timestamp = record
        .event_timestamp
        .map_or(observed_at, OffsetDateTime::from);
    // The timeline rejection: a BMC clock ahead of the product clock cannot
    // be recorded (§9.3), so the record is refused like every other domain
    // rejection — dropped, never clamped or invented.
    Event::new(
        EventId::generate(),
        endpoint_id,
        message_id,
        severity,
        record.message.clone(),
        event_timestamp,
        observed_at,
    )
    .ok()
}

/// Maps the Redfish severity fields onto the domain [`EventSeverity`].
///
/// `Severity` (the service-provided string) takes precedence over
/// `MessageSeverity` (the registry-typed `Health`), because the schema lets
/// services replace the registry value with a value more applicable to the
/// implementation. DMTF defines exactly `OK`/`Warning`/`Critical`; a value
/// outside that vocabulary — including a vendor extension — returns `None`
/// so the record is refused instead of guessing a severity the domain
/// refuses to store.
fn map_event_severity(
    severity: Option<&str>,
    message_severity: Option<HealthSchema>,
) -> Option<EventSeverity> {
    match severity {
        Some("OK") => Some(EventSeverity::Ok),
        Some("Warning") => Some(EventSeverity::Warning),
        Some("Critical") => Some(EventSeverity::Critical),
        _ => match message_severity {
            Some(HealthSchema::Ok) => Some(EventSeverity::Ok),
            Some(HealthSchema::Warning) => Some(EventSeverity::Warning),
            Some(HealthSchema::Critical) => Some(EventSeverity::Critical),
            Some(HealthSchema::UnsupportedValue) | None => None,
        },
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
    resources.extend(read_power_equipment_resources(bmc, root, identity, trust).await?);
    Ok(resources)
}

/// Reads the root-level `PowerEquipment` service document and its
/// `PowerShelves` collection members, so the 0.2 `power-equipment` family
/// follows its root service through the same typed navigation.
///
/// A missing `PowerEquipment` link leaves the whole family absent without an
/// error ("资源存在才呈现"); a failed `PowerEquipment` document aborts the read
/// with the existing classified error semantics, while the `PowerShelves`
/// collection and its members keep the per-collection and per-member skip
/// semantics of every other family.
async fn read_power_equipment_resources(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(power_equipment) = root.root.power_equipment.as_ref() else {
        return Ok(Vec::new());
    };
    let Some(equipment) = fetch_member(power_equipment, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    if let Some(projection) = member_projection(power_equipment_projection(&equipment))? {
        resources.push(projection);
    }
    resources.extend(
        read_collection_resources(
            equipment.power_shelves.as_ref(),
            bmc,
            identity,
            trust,
            power_distribution_projection,
        )
        .await?,
    );
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
        resources.extend(read_system_nvidia_oem(&system, bmc, identity, trust).await?);
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
/// `NetworkAdapters` collection (with the `NetworkDeviceFunctions` behind
/// each adapter), the `Power` and `Thermal` telemetry singletons, the
/// `Sensors` and `Controls` telemetry collections, the `Assembly` document,
/// the `EnvironmentMetrics` singleton, and the `PowerSupplies` collection
/// behind the `PowerSubsystem`, so the 0.2 telemetry, assembly, and
/// equipment surfaces follow their parent through the same typed
/// navigation.
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
            read_network_adapter_resources(chassis.network_adapters.as_ref(), bmc, identity, trust)
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
        resources.extend(
            read_singleton_resources(
                chassis.environment_metrics.as_ref(),
                bmc,
                identity,
                trust,
                environment_metrics_projection,
            )
            .await?,
        );
        resources.extend(
            read_power_supply_resources(chassis.power_subsystem.as_ref(), bmc, identity, trust)
                .await?,
        );
    }
    Ok(resources)
}

/// Reads the `PowerSupply` members of the `PowerSupplies` collection behind
/// the Chassis member's `PowerSubsystem` navigation, so the 0.2
/// `power-supplies` family follows its parent through the same typed
/// navigation.
///
/// A missing `PowerSubsystem` or `PowerSupplies` link leaves the family
/// absent without an error; a failed `PowerSubsystem` document aborts the
/// read with the existing classified error semantics, while the collection
/// and its members keep the per-collection and per-member skip semantics of
/// every other family.
async fn read_power_supply_resources(
    power_subsystem: Option<&NavProperty<PowerSubsystemSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(power_subsystem) = power_subsystem else {
        return Ok(Vec::new());
    };
    let Some(subsystem) = fetch_member(power_subsystem, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_collection_resources(
        subsystem.power_supplies.as_ref(),
        bmc,
        identity,
        trust,
        power_supply_projection,
    )
    .await
}

/// Reads the Chassis member's `NetworkAdapters` collection and, for every
/// decoded adapter member, its `NetworkDeviceFunctions` collection, so the
/// 0.2 `network-adapters` and `network-device-functions` families follow
/// their parent through the same typed navigation.
///
/// The two families share one collection fetch: the adapters collection is
/// the adapter family's whole surface and the functions family's entry
/// point, so reading it twice would double the adapter traffic on every
/// refresh. A missing `NetworkAdapters` link leaves both families absent
/// without an error ("资源存在才呈现"); a failed adapters collection document
/// aborts the read with the existing classified error semantics, while each
/// adapter member and its functions collection keep the per-member and
/// per-collection skip semantics of every other family.
async fn read_network_adapter_resources(
    network_adapters: Option<&NavProperty<NetworkAdapterCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(network_adapters) = network_adapters else {
        return Ok(Vec::new());
    };
    let collection = network_adapters
        .get(bmc)
        .await
        .map_err(|source| collection_failure(source, identity, trust))?;
    let mut resources = Vec::new();
    for member in collection.members() {
        let Some(adapter) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(network_adapter_projection(&adapter))? {
            resources.push(projection);
        }
        resources.extend(
            read_collection_resources(
                adapter.network_device_functions.as_ref(),
                bmc,
                identity,
                trust,
                network_device_function_projection,
            )
            .await?,
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
        resources.extend(read_manager_dell_attributes(&manager, bmc, identity, trust).await?);
        resources.extend(read_manager_supermicro_oem(&manager, bmc, identity, trust).await?);
        resources.extend(read_manager_nvidia_oem(&manager, bmc, identity, trust).await?);
        resources.extend(read_manager_lenovo_oem(&manager, bmc, identity, trust).await?);
    }
    Ok(resources)
}

/// Reads one manager's Dell OEM `DellAttributes` document (§11.5).
///
/// The only Dell OEM surface nv-redfish 0.13 compiles is the manager
/// `DellAttributes` leaf behind `oem-dell-attributes`, so the Dell OEM family
/// is exactly this document. The read mirrors `nv-redfish`'s own
/// manager-attributes constructor: only a manager document that advertises
/// `Oem.Dell` is probed, the probe URL is crafted from the manager's own
/// `@odata.id` (the same `{manager}/Oem/Dell/DellAttributes/{id}` the
/// upstream wrapper builds), and the document is fetched through the same
/// typed navigation into the compiled `DellAttributes` schema — never a raw
/// JSON read, per §11.5's two-way rule.
///
/// A manager without `Oem.Dell` produces no snapshot and no fabricated
/// request; a failed or undecodable Dell Attributes document is one odd
/// manager surface and follows the member-level skip semantics like any
/// other member fetch.
async fn read_manager_dell_attributes(
    manager: &ManagerSchema,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let advertises_dell = manager
        .base
        .base
        .oem
        .as_ref()
        .is_some_and(|oem| oem.additional_properties.get("Dell").is_some());
    if !advertises_dell {
        return Ok(Vec::new());
    }
    let odata_id = ODataId::from(format!(
        "{}/Oem/Dell/DellAttributes/{}",
        manager.odata_id(),
        manager.base.id
    ));
    let attributes = match NavProperty::<DellAttributesSchema>::new_reference(odata_id)
        .get(bmc)
        .await
    {
        Ok(attributes) => attributes,
        Err(source) => {
            skip_member_failure(source, identity, trust)?;
            return Ok(Vec::new());
        }
    };
    let Some(projection) = member_projection(dell_attributes_projection(&attributes))? else {
        return Ok(Vec::new());
    };
    Ok(vec![projection])
}

/// Reads one manager's Supermicro `SysLockdown` and `KcsInterface` documents
/// (§11.5).
///
/// The Supermicro read mirrors `nv-redfish`'s own manager OEM constructor:
/// only a manager document that advertises `Oem.Supermicro` is probed, the
/// embedded segment is decoded into the compiled `smc_manager_extensions`
/// schema, and each present `NavProperty` field is resolved through the same
/// typed navigation the upstream `sys_lockdown` / `kcs_interface` wrappers
/// perform — an embedded reference is fetched by its `@odata.id`, an embedded
/// expanded object is used as-is, never a raw JSON read. Unlike the Dell
/// Attributes surface there is no crafted URL: the Supermicro documents are
/// referenced by the manager's own `Oem.Supermicro` segment, so the product
/// follows the vendor's embedded navigation instead of building one.
///
/// A manager without `Oem.Supermicro`, or with an `Oem.Supermicro` segment
/// the compiled schema cannot decode, produces no snapshot and no fabricated
/// request; a failed or undecodable document is one odd manager surface and
/// follows the member-level skip semantics like any other member fetch.
async fn read_manager_supermicro_oem(
    manager: &ManagerSchema,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(oem_value) = manager
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Supermicro"))
    else {
        return Ok(Vec::new());
    };
    // The embedded `Oem.Supermicro` value is vendor-shaped until the compiled
    // `smc_manager_extensions` schema decodes it; a segment the compiled
    // schema rejects is one odd manager surface and leaves the whole
    // Supermicro family absent, exactly like an undecodable member.
    let extensions: SmcManagerExtensionsSchema = match serde_json::from_value(oem_value.clone()) {
        Ok(extensions) => extensions,
        Err(_) => return Ok(Vec::new()),
    };
    let mut resources = Vec::new();
    // Each present navigation property follows the singleton decision: an
    // absent link leaves that document absent, a failed fetch skips it with
    // the member-level semantics, and a failed projection skips it as well.
    resources.extend(
        read_singleton_resources(
            extensions.sys_lockdown.as_ref(),
            bmc,
            identity,
            trust,
            smc_sys_lockdown_projection,
        )
        .await?,
    );
    resources.extend(
        read_singleton_resources(
            extensions.kcs_interface.as_ref(),
            bmc,
            identity,
            trust,
            smc_kcs_interface_projection,
        )
        .await?,
    );
    Ok(resources)
}

/// Reads one manager's NVIDIA power-compliance and managed-entity chains
/// (§11.5).
///
/// Both families enter through the manager's `Oem.Nvidia` segment and share
/// the physical path to the `NvidiaPowerComplianceManager` document: the
/// segment's `PowerCompliance` navigation is decoded once and the compliance
/// document is fetched once, then the two families diverge at the compliance
/// document's sub-navigations. The power-compliance family (one family = one
/// entry navigation chain, the `power_compliance` navigation) covers the
/// compliance document itself plus the `PowerDomains` collection members,
/// the `ACLossPolicy` / `PSUCompliancePolicy` singletons, the
/// `ManagedEntityGroups` collection members, the `PowerStateGroup` document
/// with its `PowerShelfControllers` and `PowerSupplies` collection members,
/// and the `PSURedundancy` singleton. The managed-entity family (its entry
/// navigation is the `managed_entity_groups` chain, whose presence decides
/// whether the family exists) reuses the fetched group documents and follows
/// each group member's `ManagedEntities` navigation into the
/// `NvidiaManagedEntity` members.
///
/// # The segment decode
///
/// The segment value is vendor-shaped until the discrimination decodes it.
/// A `Manager` segment decodes into the compiled
/// `nvidia_manager::v1_9_0::NvidiaManager` type — the versioned module that
/// carries the `PowerCompliance` navigation. The decode target must be this
/// navigation-carrying versioned struct: serde tolerates unknown keys, so
/// decoding into an unversioned shape would silently drop the navigation.
///
/// A `BlueField` may inline only a partially expanded stub of the segment —
/// the value then has the `{"@odata.id": ...}` reference shape — so the
/// segment is fetched through that reference before decoding, exactly like
/// the system-config-profile chain. The reference is not a compiled
/// navigation property, so the fetch goes through a local typed decode
/// target (the compiled `NvidiaManager` type implements no `EntityTypeRef`),
/// never a raw JSON read (§11.5 two-way rule).
///
/// # Absence and failure semantics
///
/// A manager without `Oem.Nvidia`, or with a segment that cannot be
/// discriminated or decoded, produces no snapshot and no fabricated request,
/// and leaves `read_manager_resources`'s other families untouched (zero
/// behavior change). Every chain fetch failure — the compliance document,
/// each sub-collection document, and each member — follows the member-level
/// skip semantics (`skip_member_failure`), because the chain root decides
/// whether the chain exists and one odd chain surface must not erase the
/// readable remainder; a failed projection skips the member through
/// `member_projection`.
async fn read_manager_nvidia_oem(
    manager: &ManagerSchema,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nvidia) = manager
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Nvidia"))
    else {
        return Ok(Vec::new());
    };
    let Some(power_compliance) =
        decode_nvidia_manager_navigation(nvidia, bmc, identity, trust).await?
    else {
        return Ok(Vec::new());
    };
    let power_compliance =
        NavProperty::<NvidiaPowerComplianceManagerSchema>::new_reference(power_compliance);
    let Some(compliance) = fetch_member(&power_compliance, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    // The power-compliance family: the chain-root document first, then its
    // sub-chains in the compiled navigation order.
    if let Some(projection) =
        member_projection(nvidia_power_compliance_manager_projection(&compliance))?
    {
        resources.push(projection);
    }
    resources.extend(
        read_nvidia_power_domain_collection(
            compliance.power_domains.as_ref(),
            bmc,
            identity,
            trust,
        )
        .await?,
    );
    resources.extend(
        read_singleton_resources(
            compliance.ac_loss_policy.as_ref(),
            bmc,
            identity,
            trust,
            nvidia_power_policy_projection,
        )
        .await?,
    );
    resources.extend(
        read_singleton_resources(
            compliance.psu_compliance_policy.as_ref(),
            bmc,
            identity,
            trust,
            nvidia_power_policy_projection,
        )
        .await?,
    );
    // The managed entity groups chain is shared between the two families:
    // the group documents land in the power-compliance family and their
    // `ManagedEntities` members in the managed-entity family.
    resources.extend(
        read_nvidia_managed_entity_groups(
            compliance.managed_entity_groups.as_ref(),
            bmc,
            identity,
            trust,
        )
        .await?,
    );
    resources.extend(
        read_nvidia_power_state_group(compliance.power_state_group.as_ref(), bmc, identity, trust)
            .await?,
    );
    resources.extend(
        read_singleton_resources(
            compliance.psu_redundancy.as_ref(),
            bmc,
            identity,
            trust,
            nvidia_psu_redundancy_projection,
        )
        .await?,
    );
    Ok(resources)
}

/// Reads one manager's Lenovo `SecurityService` document (§11.5).
///
/// The Lenovo read mirrors `nv-redfish`'s own manager OEM constructor: only a
/// manager document that advertises `Oem.Lenovo` is probed, the embedded
/// segment is decoded into the compiled untagged `LenovoManagerSchema` — the
/// same dual-version serde fallback the upstream `LenovoManager` wrapper
/// performs (`v0_1_0` with the boolean `KCSEnabled` shape, `v1_0_0` with the
/// state-string shape, and the `Security` navigation on the unversioned
/// `base` both variants flatten) — and the present `Security` `NavProperty`
/// field is resolved through the same typed navigation the upstream
/// `LenovoManager::security` / `LenovoSecurityService::new` wrappers perform:
/// an embedded reference is fetched by its `@odata.id`, an embedded expanded
/// object is used as-is, never a raw JSON read. Unlike the Dell Attributes
/// surface there is no crafted URL: the `SecurityService` document is
/// referenced by the manager's own `Oem.Lenovo` segment, so the product
/// follows the vendor's embedded navigation instead of building one.
///
/// A manager without `Oem.Lenovo`, or with an `Oem.Lenovo` segment the
/// compiled schema cannot decode, produces no snapshot and no fabricated
/// request; a failed or undecodable document is one odd manager surface and
/// follows the member-level skip semantics like any other member fetch.
async fn read_manager_lenovo_oem(
    manager: &ManagerSchema,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(oem_value) = manager
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Lenovo"))
    else {
        return Ok(Vec::new());
    };
    // The embedded `Oem.Lenovo` value is vendor-shaped until the compiled
    // untagged `LenovoManagerSchema` decodes it; a segment the compiled
    // schema rejects is one odd manager surface and leaves the whole Lenovo
    // family absent, exactly like an undecodable member.
    let lenovo_manager: LenovoManagerSchema = match serde_json::from_value(oem_value.clone()) {
        Ok(segment) => segment,
        Err(_) => return Ok(Vec::new()),
    };
    // The two untagged versions flatten the same unversioned `base` with the
    // `Security` navigation, so either arm resolves the same reference: the
    // version difference (the `KCSEnabled` boolean vs state-string shapes)
    // never affects the read surface, exactly like the upstream `base()`
    // accessor that serves both versions.
    let security = match &lenovo_manager {
        LenovoManagerSchema::V0_1(data) => data.base.security.as_ref(),
        LenovoManagerSchema::V1_0(data) => data.base.security.as_ref(),
    };
    read_singleton_resources(
        security,
        bmc,
        identity,
        trust,
        lenovo_security_service_projection,
    )
    .await
}

/// Decodes one `Oem.Nvidia` segment value into the chain-entry
/// `PowerCompliance` identifier, or returns `None` when the segment is not a
/// `Manager` segment, carries no chain navigation, or cannot be decoded.
///
/// The chain entry is carried as its `@odata.id`: `NavProperty` is not
/// `Clone`, and the caller rebuilds the reference-form navigation from the
/// identifier exactly like the upstream `downcast` conversion, so an
/// embedded expanded segment entry is fetched by its own `@odata.id` (the
/// authoritative resource representation).
///
/// The reference form (`{"@odata.id": ...}`, the `BlueField` partial-stub
/// quirk) is fetched through a typed decode target first, with the
/// member-level skip semantics on a failed fetch; the fetched document is
/// decoded through the local segment schema (the compiled
/// `NvidiaManager.v1_9_0` type cannot be a fetch target: it implements no
/// `EntityTypeRef`). An undecodable segment leaves both families absent
/// without a fabricated request, exactly like the undecodable Supermicro
/// segment.
async fn decode_nvidia_manager_navigation(
    nvidia: &serde_json::Value,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<ODataId>, CoreResourceReadError> {
    if is_nvidia_reference_form(nvidia) {
        let Some(id) = nvidia.get("@odata.id").and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        let navigation = NavProperty::<NvidiaManagerSegmentReferenceSchema>::new_reference(
            ODataId::from(id.to_owned()),
        );
        let Some(segment) = fetch_member(&navigation, bmc, identity, trust).await? else {
            return Ok(None);
        };
        return Ok(segment
            .power_compliance
            .as_ref()
            .map(NavProperty::id)
            .cloned());
    }
    match nvidia_segment_kind(nvidia) {
        Some(NvidiaSegmentKind::Manager) => {
            match serde_json::from_value::<NvidiaManagerSegmentSchema>(nvidia.clone()) {
                Ok(segment) => Ok(segment
                    .power_compliance
                    .as_ref()
                    .map(NavProperty::id)
                    .cloned()),
                Err(_) => Ok(None),
            }
        }
        Some(NvidiaSegmentKind::ComputerSystem | NvidiaSegmentKind::Chassis) | None => Ok(None),
    }
}

/// The typed fetch target of a reference-form `Oem.Nvidia` manager segment.
///
/// The compiled `NvidiaManager.v1_9_0` type models the segment but does not
/// implement `EntityTypeRef` (it is an OEM segment, not a standalone
/// resource), so a reference-form fetch cannot go through
/// `bmc.get::<NvidiaManagerSegmentSchema>`. The fetched document decodes
/// through this minimal local schema instead — the same local-schema
/// precedent as the `EventSubscription` family and the reference-form
/// `NvidiaComputerSystem` segment — mirroring exactly the navigation fields
/// the chains follow, with the `@odata.id` the fetch proves.
#[derive(Deserialize)]
struct NvidiaManagerSegmentReferenceSchema {
    #[serde(rename = "@odata.id")]
    odata_id: ODataId,
    #[serde(rename = "PowerCompliance", default)]
    power_compliance: Option<NavProperty<NvidiaPowerComplianceManagerSchema>>,
    // The write-side debug-token-management chain resolves the same
    // reference-form segment through this schema, so the navigation field
    // lives here next to its sibling (the read side ignores it).
    #[serde(rename = "DebugTokenManagement", default)]
    debug_token_management: Option<NavProperty<NvidiaDebugTokenManagementSchema>>,
}

impl EntityTypeRef for NvidiaManagerSegmentReferenceSchema {
    fn odata_id(&self) -> &ODataId {
        &self.odata_id
    }

    fn etag(&self) -> Option<&nv_redfish::core::ODataETag> {
        None
    }
}

/// Reads the `NvidiaPowerDomainCollection` behind the compliance manager and
/// projects every decoded member.
///
/// Unlike a standard collection, a failed collection document follows the
/// member-level skip semantics instead of aborting the read: the chain's
/// failure rule treats every sub-document as one odd chain surface, so a
/// failed power-domain collection leaves the already-read compliance manager
/// snapshot in place.
async fn read_nvidia_power_domain_collection(
    nav: Option<&NavProperty<NvidiaPowerDomainCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(collection) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_nvidia_member_documents(
        &collection.members,
        bmc,
        identity,
        trust,
        nvidia_power_domain_projection,
    )
    .await
}

/// Reads the `NvidiaManagedEntityGroupCollection` behind the compliance
/// manager and, for every decoded group member, its `ManagedEntities`
/// collection members, so the managed-entity sub-chain follows its parent
/// through the same typed navigation.
///
/// The group documents belong to the power-compliance family (the
/// compliance manager's `ManagedEntityGroups` sub-chain) and the entity
/// members to the managed-entity family (the `managed_entity_groups` entry
/// navigation), so one shared traversal feeds both families from one set of
/// requests. A failed collection document skips the whole shared sub-chain
/// with the member-level semantics, exactly like the profile-collection
/// precedent; individual members keep the usual member-level semantics.
async fn read_nvidia_managed_entity_groups(
    nav: Option<&NavProperty<NvidiaManagedEntityGroupCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(collection) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    for group_nav in &collection.members {
        let Some(group) = fetch_member(group_nav, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(nvidia_managed_entity_group_projection(&group))?
        {
            resources.push(projection);
        }
        resources.extend(
            read_nvidia_managed_entity_collection(
                Some(&group.managed_entities),
                bmc,
                identity,
                trust,
            )
            .await?,
        );
    }
    Ok(resources)
}

/// Reads the `NvidiaManagedEntityCollection` behind one group member and
/// projects every decoded entity member into the managed-entity family.
async fn read_nvidia_managed_entity_collection(
    nav: Option<&NavProperty<NvidiaManagedEntityCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(collection) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_nvidia_member_documents(
        &collection.members,
        bmc,
        identity,
        trust,
        nvidia_managed_entity_projection,
    )
    .await
}

/// Reads the `NvidiaPowerStateGroup` document and its
/// `PowerShelfControllers` / `PowerSupplies` collection members, so the
/// power-state sub-chain follows its parent through the same typed
/// navigation. A failed power-state document skips the whole sub-chain with
/// the member-level semantics.
async fn read_nvidia_power_state_group(
    nav: Option<&NavProperty<NvidiaPowerStateGroupSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(group) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    if let Some(projection) = member_projection(nvidia_power_state_group_projection(&group))? {
        resources.push(projection);
    }
    resources.extend(
        read_nvidia_psc_state_collection(
            Some(&group.power_shelf_controllers),
            bmc,
            identity,
            trust,
        )
        .await?,
    );
    resources.extend(
        read_nvidia_psu_state_collection(Some(&group.power_supplies), bmc, identity, trust).await?,
    );
    Ok(resources)
}

/// Reads the `NvidiaPscStateCollection` and projects every decoded member.
async fn read_nvidia_psc_state_collection(
    nav: Option<&NavProperty<NvidiaPscStateCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(collection) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_nvidia_member_documents(
        &collection.members,
        bmc,
        identity,
        trust,
        nvidia_psc_state_projection,
    )
    .await
}

/// Reads the `NvidiaPsuStateCollection` and projects every decoded member.
async fn read_nvidia_psu_state_collection(
    nav: Option<&NavProperty<NvidiaPsuStateCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(collection) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    read_nvidia_member_documents(
        &collection.members,
        bmc,
        identity,
        trust,
        nvidia_psu_state_projection,
    )
    .await
}

/// Projects every decoded member of one decoded NVIDIA collection document.
///
/// The member loop is the shared tail of the NVIDIA collection readers; the
/// collection document itself is fetched by the caller with the chain's
/// member-level skip semantics (unlike a standard collection, whose failed
/// document aborts the read).
async fn read_nvidia_member_documents<M>(
    members: &[NavProperty<M>],
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    project: impl Fn(&M) -> Result<CoreResourceProjection, CoreResourceReadError>,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError>
where
    M: EntityTypeRef + for<'de> Deserialize<'de> + 'static,
{
    let mut resources = Vec::new();
    for member in members {
        let Some(member) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(project(&member))? {
            resources.push(projection);
        }
    }
    Ok(resources)
}

/// Reads one system's NVIDIA `SystemConfigProfile` chain (§11.5).
///
/// This is the first family that navigates through a vendor `Oem` segment of
/// a standard resource: NVIDIA resources are not standard `NavProperty` fields
/// (the base `redfish.rs` schema carries no NVIDIA reference), so every
/// NVIDIA surface enters through the parent's `Oem.Nvidia` segment.
///
/// # The segment decode
///
/// The segment value is vendor-shaped until the discrimination decodes it.
/// The segment kind is decided by the segment's own `@odata.type` — the top
/// namespace and the type name — exactly like nv-redfish's own
/// `NvidiaCbcChassis::new` constructor discriminates its segment
/// (`cbc_chassis.rs`). A `ComputerSystem` segment decodes into the compiled
/// `nvidia_computer_system::NvidiaComputerSystem` type, the unversioned
/// module that carries the `SystemConfigProfile` navigation; the Chassis
/// segments (the four `NvidiaChassis`-namespace shapes) carry no
/// system-config-profile chain, so the family stays absent for them and a
/// later chassis family can decode them through the same discrimination.
/// The decode target must be the versioned struct that carries the
/// navigation: serde tolerates unknown keys, so decoding into a shape
/// without the navigation would silently drop it.
///
/// A `BlueField` DPU may inline only a partially expanded stub of the segment
/// — the value then has the `{"@odata.id": ...}` reference shape — so the
/// segment is fetched through that reference before decoding, exactly like
/// nv-redfish's own `NvidiaComputerSystem::new` quirk handling
/// (`computer_system.rs`). The reference is not a compiled navigation
/// property, so the fetch goes through the typed decode target
/// (`bmc.get::<NvidiaComputerSystemSchema>`), never a raw JSON read (§11.5
/// two-way rule).
///
/// # Absence and failure semantics
///
/// A system without `Oem.Nvidia`, or with a segment that cannot be
/// discriminated or decoded, produces no snapshot and no fabricated request
/// (the supermicro precedent: `read_manager_supermicro_oem`). Every chain
/// fetch failure — the profile service document, its status singleton, the
/// profile collection document, and each profile member — follows the
/// member-level skip semantics (`skip_member_failure`), because the chain
/// root decides whether the chain exists and one odd chain surface must not
/// erase the readable remainder; a failed projection skips the member
/// through `member_projection`.
async fn read_system_nvidia_oem(
    system: &ComputerSystemSchema,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nvidia) = system
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Nvidia"))
    else {
        return Ok(Vec::new());
    };
    let Some(system_config_profile) =
        decode_nvidia_system_config_profile_navigation(nvidia, bmc, identity, trust).await?
    else {
        return Ok(Vec::new());
    };
    let system_config_profile =
        NavProperty::<NvidiaSystemConfigProfileSchema>::new_reference(system_config_profile);
    let Some(config_profile) = fetch_member(&system_config_profile, bmc, identity, trust).await?
    else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    if let Some(projection) =
        member_projection(nvidia_system_config_profile_projection(&config_profile))?
    {
        resources.push(projection);
    }
    resources.extend(
        read_singleton_resources(
            config_profile.status.as_ref(),
            bmc,
            identity,
            trust,
            nvidia_system_config_profile_status_projection,
        )
        .await?,
    );
    resources.extend(
        read_nvidia_profile_collection(config_profile.profiles.as_ref(), bmc, identity, trust)
            .await?,
    );
    Ok(resources)
}

/// Decodes one `Oem.Nvidia` segment value into the chain-entry
/// `SystemConfigProfile` identifier, or returns `None` when the segment is
/// not a `ComputerSystem` segment, carries no chain navigation, or cannot be
/// decoded.
///
/// The chain entry is carried as its `@odata.id`: `NavProperty` is not
/// `Clone`, and the caller rebuilds the reference-form navigation from the
/// identifier exactly like the upstream `downcast` conversion, so an
/// embedded expanded segment entry is fetched by its own `@odata.id` (the
/// authoritative resource representation).
///
/// The reference form (`{"@odata.id": ...}`, the `BlueField` DPU partial-stub
/// quirk) is fetched through a typed decode target first, with the
/// member-level skip semantics on a failed fetch; the fetched document is
/// decoded through the local segment schema (the compiled
/// `NvidiaComputerSystem` type cannot be a fetch target: it implements no
/// `EntityTypeRef`, exactly like the `EventSubscription` family's local
/// schemas). An undecodable segment leaves the family absent without a
/// fabricated request, exactly like the undecodable Supermicro segment.
async fn decode_nvidia_system_config_profile_navigation(
    nvidia: &serde_json::Value,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<ODataId>, CoreResourceReadError> {
    if is_nvidia_reference_form(nvidia) {
        let Some(id) = nvidia.get("@odata.id").and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        let navigation = NavProperty::<NvidiaComputerSystemSegmentSchema>::new_reference(
            ODataId::from(id.to_owned()),
        );
        let Some(segment) = fetch_member(&navigation, bmc, identity, trust).await? else {
            return Ok(None);
        };
        return Ok(segment
            .system_config_profile
            .as_ref()
            .map(NavProperty::id)
            .cloned());
    }
    match nvidia_segment_kind(nvidia) {
        Some(NvidiaSegmentKind::ComputerSystem) => {
            match serde_json::from_value::<NvidiaComputerSystemSchema>(nvidia.clone()) {
                Ok(segment) => Ok(segment
                    .system_config_profile
                    .as_ref()
                    .map(NavProperty::id)
                    .cloned()),
                Err(_) => Ok(None),
            }
        }
        // A Manager segment carries no system-config-profile chain; the
        // power-compliance and managed-entity families decode it through
        // their own navigation reader instead.
        Some(NvidiaSegmentKind::Chassis | NvidiaSegmentKind::Manager) | None => Ok(None),
    }
}

/// The typed fetch target of a reference-form `Oem.Nvidia` segment.
///
/// The compiled `NvidiaComputerSystem` type models the segment but does not
/// implement `EntityTypeRef` (it is an OEM segment, not a standalone
/// resource), so a reference-form fetch cannot go through
/// `bmc.get::<NvidiaComputerSystemSchema>`. The fetched document decodes
/// through this minimal local schema instead — the same local-schema
/// precedent as the `EventSubscription` family — mirroring exactly the
/// navigation fields the chain follows, with the `@odata.id` the fetch
/// proves.
#[derive(Deserialize)]
struct NvidiaComputerSystemSegmentSchema {
    #[serde(rename = "@odata.id")]
    odata_id: ODataId,
    #[serde(rename = "SystemConfigProfile", default)]
    system_config_profile: Option<NavProperty<NvidiaSystemConfigProfileSchema>>,
    // The write-side debug-token chain resolves the same reference-form
    // segment through this schema, so the navigation field lives here next to
    // its sibling (the read side ignores it).
    #[serde(rename = "CPUDebugToken", default)]
    cpu_debug_token: Option<NavProperty<NvidiaDebugTokenSchema>>,
}

impl EntityTypeRef for NvidiaComputerSystemSegmentSchema {
    fn odata_id(&self) -> &ODataId {
        &self.odata_id
    }

    fn etag(&self) -> Option<&nv_redfish::core::ODataETag> {
        None
    }
}

/// The kinds of one `Oem.Nvidia` segment value, discriminated by the
/// segment's own `@odata.type` (the top namespace and the type name), the
/// same discrimination nv-redfish's `NvidiaCbcChassis::new` constructor
/// performs (`cbc_chassis.rs`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NvidiaSegmentKind {
    /// A `ComputerSystem` `Oem.Nvidia` segment: the `NvidiaComputerSystem`
    /// type, whose unversioned module carries the `SystemConfigProfile`
    /// navigation the system-config-profile family follows.
    ComputerSystem,
    /// A Chassis `Oem.Nvidia` segment: the `NvidiaChassis` namespace shapes
    /// (`NvidiaChassis`, `NvidiaRoTchassis`, `NvidiaSmaChassis`,
    /// `NvidiaCBCChassis`) and the standalone `NvidiaRoTChassis` namespace.
    /// None of the compiled chassis segments carries the
    /// system-config-profile chain; the arm keeps the discrimination
    /// mechanism explicit so a later chassis family lands on it.
    Chassis,
    /// A `Manager` `Oem.Nvidia` segment: the `NvidiaManager` namespace type
    /// (versioned, the latest compiled `NvidiaManager.v1_9_0` module carries
    /// the `PowerCompliance` navigation), whose versioned module carries the
    /// navigation the power-compliance and managed-entity families follow.
    Manager,
}

/// Discriminates one `Oem.Nvidia` segment value by its own `@odata.type`.
///
/// The top namespace and the type name decide the kind, never a product
/// guess over the segment shape. A segment without a parseable `@odata.type`
/// is not discriminable and yields `None` — the segment is treated as one
/// odd vendor surface and the family stays absent.
fn nvidia_segment_kind(segment: &serde_json::Value) -> Option<NvidiaSegmentKind> {
    let odata_type = ODataType::parse_from(segment)?;
    let namespace = odata_type.namespace.first().copied();
    match (namespace, odata_type.type_name) {
        (Some("NvidiaComputerSystem"), "NvidiaComputerSystem") => {
            Some(NvidiaSegmentKind::ComputerSystem)
        }
        (
            Some("NvidiaChassis"),
            "NvidiaChassis" | "NvidiaRoTchassis" | "NvidiaSmaChassis" | "NvidiaCBCChassis",
        )
        | (Some("NvidiaRoTChassis"), "NvidiaRoTChassis") => Some(NvidiaSegmentKind::Chassis),
        // The manager segment is versioned (`NvidiaManager.v1_9_0.NvidiaManager`),
        // so the top namespace and the type name match both the versioned and
        // the hypothetical unversioned spelling; the decode target is the
        // versioned `v1_9_0::NvidiaManager` struct either way.
        (Some("NvidiaManager"), "NvidiaManager") => Some(NvidiaSegmentKind::Manager),
        _ => None,
    }
}

/// Whether a segment value has the reference shape (an object whose only key
/// is `@odata.id`), mirroring the `NavProperty` deserializer's own reference
/// rule.
fn is_nvidia_reference_form(segment: &serde_json::Value) -> bool {
    segment
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.contains_key("@odata.id"))
}

/// Reads the `NvidiaSystemProfileCollection` and, for every decoded member,
/// its `ProfileFile` document, so the profile sub-chain follows its parent
/// through the same typed navigation.
///
/// Unlike a standard collection, a failed collection document follows the
/// member-level skip semantics instead of aborting the read: the chain's
/// failure rule treats every sub-document as one odd chain surface, so a
/// failed profile collection leaves the already-read profile service and
/// status snapshots in place. Individual members and their `ProfileFile`
/// singletons keep the usual member-level semantics.
async fn read_nvidia_profile_collection(
    nav: Option<&NavProperty<NvidiaSystemProfileCollectionSchema>>,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Vec<CoreResourceProjection>, CoreResourceReadError> {
    let Some(nav) = nav else {
        return Ok(Vec::new());
    };
    let Some(collection) = fetch_member(nav, bmc, identity, trust).await? else {
        return Ok(Vec::new());
    };
    let mut resources = Vec::new();
    for member in &collection.members {
        let Some(member) = fetch_member(member, bmc, identity, trust).await? else {
            continue;
        };
        if let Some(projection) = member_projection(nvidia_system_profile_projection(&member))? {
            resources.push(projection);
        }
        resources.extend(
            read_singleton_resources(
                member.profile_file.as_ref(),
                bmc,
                identity,
                trust,
                nvidia_system_profile_file_projection,
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

impl MemberCollection for NetworkDeviceFunctionCollectionSchema {
    type Member = NetworkDeviceFunctionSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for PowerDistributionCollectionSchema {
    type Member = PowerDistributionSchema;

    fn members(&self) -> &[NavProperty<Self::Member>] {
        &self.members
    }
}

impl MemberCollection for PowerSupplyCollectionSchema {
    type Member = PowerSupplySchema;

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
        // The Update family is deliberately dispatched through the dedicated
        // `UpdateExecutor` boundary, never this one: the typed command
        // carries only the database-serializable artifact id, while the
        // upload needs the resolved artifact bytes, which the application
        // resolves from the artifact store at execution time (§13.3 step 4,
        // §14.3). Reaching this arm means the caller misrouted the command
        // through the wrong boundary; the refusal is provable (no write is
        // ever sent) and the payload is rejected because it cannot be
        // executed through this boundary.
        RedfishCommand::Update(_) => Err(CommandExecutionError::Rejected(
            CommandRejection::InvalidCommandPayload,
        )),
        RedfishCommand::Oem(oem) => {
            execute_nvidia_oem_command(bmc, root, identity, trust, oem).await
        }
    }
}

/// Executes one NVIDIA OEM command through the decoded CSDL actions of its
/// chain resource (§13.3 step 7).
///
/// Every action is invoked through the compiled action reference the decoded
/// resource advertises (`bmc.action`, the same typed path as the reset
/// families), with the domain payload projected onto the compiled parameter
/// types; responses project through [`outcome_from_modification`], so a `202`
/// Task acceptance surfaces as [`CommandExecutionError::AsyncTaskAccepted`]
/// for the §13.6 Task monitor. The navigation to each chain resource mirrors
/// the §11.5 read side exactly: the endpoint's first member of the core
/// collection, its `Oem.Nvidia` segment (embedded or the `BlueField`
/// reference-form quirk), and the compiled navigation property — the write
/// target URI is never guessed (§11.1).
async fn execute_nvidia_oem_command(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    oem: &OemCommand,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    match oem {
        OemCommand::SystemConfigProfile(command) => {
            execute_nvidia_system_config_profile_command(bmc, root, identity, trust, command).await
        }
        OemCommand::DebugToken(command) => {
            execute_nvidia_debug_token_command(bmc, root, identity, trust, command).await
        }
        OemCommand::PowerSmoothing(command) => {
            execute_nvidia_power_smoothing_command(bmc, root, identity, trust, command).await
        }
    }
}

/// Executes one `NvidiaSystemConfigProfile` command through the decoded
/// actions of the profile service document (and, for `ActivateProfile`, the
/// decoded first member of its `Profiles` collection).
async fn execute_nvidia_system_config_profile_command(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    command: &NvidiaSystemConfigProfileCommand,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let prepare = |source: BmcError| command_preparation_error(source, identity, trust);
    match command {
        NvidiaSystemConfigProfileCommand::Update(profile) => {
            let Some(service) = nvidia_system_config_profile_document(root, bmc, prepare).await?
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = service
                .actions
                .as_ref()
                .and_then(|actions| actions.update.as_ref())
            else {
                // §13.3 step 2: the decoded profile service does not advertise
                // the Update action, so the command is provably unsupported
                // on this endpoint.
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaSystemConfigProfileUpdateActionSchema {
                profile_file: Some(profile.profile_file().to_owned()),
            };
            run_nvidia_action::<NvidiaSystemConfigProfileUpdateActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
        NvidiaSystemConfigProfileCommand::FactoryReset => {
            let Some(service) = nvidia_system_config_profile_document(root, bmc, prepare).await?
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = service
                .actions
                .as_ref()
                .and_then(|actions| actions.factory_reset.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaSystemConfigProfileFactoryResetActionSchema {};
            run_nvidia_action::<NvidiaSystemConfigProfileFactoryResetActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
        NvidiaSystemConfigProfileCommand::ActivateProfile => {
            // The `#NvidiaSystemProfile.Activate` action is bound to the
            // profile member documents, so the write targets the first member
            // of the service's decoded `Profiles` collection — the
            // endpoint-scoped write rule of the reset families.
            let Some(service) = nvidia_system_config_profile_document(root, bmc, prepare).await?
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(profiles_nav) = service.profiles.as_ref() else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let collection = match profiles_nav.get(bmc).await {
                Ok(collection) => collection,
                Err(source) => {
                    return Err(command_preparation_error(source, identity, trust));
                }
            };
            let Some(member_nav) = collection.members.first() else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let member = match member_nav.get(bmc).await {
                Ok(member) => member,
                Err(source) => {
                    return Err(command_preparation_error(source, identity, trust));
                }
            };
            let Some(action) = member
                .actions
                .as_ref()
                .and_then(|actions| actions.activate.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaSystemProfileActivateActionSchema {};
            run_nvidia_action::<NvidiaSystemProfileActivateActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
    }
}

/// Executes one `NvidiaDebugToken` command through the decoded actions of the
/// device `NvidiaDebugToken` document behind the system's `CPUDebugToken`
/// navigation, or of the manager's `DebugTokenManagement` document for
/// `EraseToken`.
async fn execute_nvidia_debug_token_command(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    command: &NvidiaDebugTokenCommand,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let prepare = |source: BmcError| command_preparation_error(source, identity, trust);
    match command {
        NvidiaDebugTokenCommand::GenerateToken(token_type) => {
            let Some(token) = nvidia_cpu_debug_token_document(root, bmc, prepare).await? else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = token
                .actions
                .as_ref()
                .and_then(|actions| actions.generate_token.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaDebugTokenGenerateTokenActionSchema {
                token_type: Some(map_token_type(*token_type)),
            };
            run_nvidia_action::<
                NvidiaDebugTokenGenerateTokenActionSchema,
                NvidiaDebugTokenGenerateTokenResponse,
            >(action, &params, bmc, identity, trust)
            .await
        }
        NvidiaDebugTokenCommand::InstallToken(token_data) => {
            let Some(token) = nvidia_cpu_debug_token_document(root, bmc, prepare).await? else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = token
                .actions
                .as_ref()
                .and_then(|actions| actions.install_token.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaDebugTokenInstallTokenActionSchema {
                token_data: Some(token_data.token_data().to_owned()),
            };
            run_nvidia_action::<NvidiaDebugTokenInstallTokenActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
        NvidiaDebugTokenCommand::DisableToken => {
            let Some(token) = nvidia_cpu_debug_token_document(root, bmc, prepare).await? else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = token
                .actions
                .as_ref()
                .and_then(|actions| actions.disable_token.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaDebugTokenDisableTokenActionSchema {};
            run_nvidia_action::<NvidiaDebugTokenDisableTokenActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
        NvidiaDebugTokenCommand::EraseToken(erase) => {
            let Some(management) =
                nvidia_debug_token_management_document(root, bmc, prepare).await?
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = management
                .actions
                .as_ref()
                .and_then(|actions| actions.erase_token.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaDebugTokenManagementEraseTokenActionSchema {
                erase_type: Some(map_erase_type(erase.erase_type())),
                token_type: Some(map_token_type(erase.token_type())),
            };
            run_nvidia_action::<NvidiaDebugTokenManagementEraseTokenActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
    }
}

/// Executes one `NvidiaPowerSmoothing` command through the decoded actions of
/// the chassis's power smoothing document.
async fn execute_nvidia_power_smoothing_command(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    command: &NvidiaPowerSmoothingCommand,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let prepare = |source: BmcError| command_preparation_error(source, identity, trust);
    match command {
        NvidiaPowerSmoothingCommand::ActivatePresetProfile(profile_id) => {
            let Some(power_smoothing) = nvidia_power_smoothing_document(root, bmc, prepare).await?
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = power_smoothing
                .actions
                .as_ref()
                .and_then(|actions| actions.activate_preset_profile.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaPowerSmoothingActivatePresetProfileActionSchema {
                profile_id: Some(profile_id.profile_id()),
            };
            run_nvidia_action::<NvidiaPowerSmoothingActivatePresetProfileActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
        NvidiaPowerSmoothingCommand::ApplyAdminOverrides => {
            let Some(power_smoothing) = nvidia_power_smoothing_document(root, bmc, prepare).await?
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let Some(action) = power_smoothing
                .actions
                .as_ref()
                .and_then(|actions| actions.apply_admin_overrides.as_ref())
            else {
                return Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable,
                ));
            };
            let params = NvidiaPowerSmoothingApplyAdminOverridesActionSchema {};
            run_nvidia_action::<NvidiaPowerSmoothingApplyAdminOverridesActionSchema, _>(
                action, &params, bmc, identity, trust,
            )
            .await
        }
    }
}

/// Runs one compiled NVIDIA action through the typed `Bmc::action` API and
/// projects the modification response, classifying transport failures
/// through [`classify_command_write_error`] exactly like the reset families.
async fn run_nvidia_action<T, R>(
    action: &nv_redfish::core::Action<T, R>,
    params: &T,
    bmc: &UpstreamBmc,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandExecutionOutcome, CommandExecutionError>
where
    T: Send + Sync + Serialize,
    R: Send + Sync + for<'de> Deserialize<'de>,
{
    let response = match bmc.action::<T, R>(action, params).await {
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

/// Fetches the first member of one core collection, returning the raw
/// transport failure for the caller's classification.
///
/// The write-side counterpart of [`first_collection_member`] without an
/// error contract: the execution path classifies through
/// [`command_preparation_error`] and the verification path through
/// [`command_verification_read_error`], so one navigation serves both.
async fn first_collection_member_raw<C>(
    nav: Option<&NavProperty<C>>,
    bmc: &UpstreamBmc,
) -> Result<Option<Arc<C::Member>>, BmcError>
where
    C: MemberCollection,
{
    let Some(collection_nav) = nav else {
        return Ok(None);
    };
    let collection = collection_nav.get(bmc).await?;
    let Some(member_nav) = collection.members().first() else {
        return Ok(None);
    };
    let member = member_nav.get(bmc).await?;
    Ok(Some(member))
}

/// The system-segment chain entries a write or verification resolves.
///
/// Both navigations hang off the same `NvidiaComputerSystem` segment, so one
/// decode resolves both identifiers and a command needs only the one it
/// targets.
struct NvidiaSystemChainEntries {
    system_config_profile: Option<ODataId>,
    cpu_debug_token: Option<ODataId>,
}

/// Resolves the endpoint's first system's `Oem.Nvidia` chain entries for one
/// write.
///
/// A missing system, missing `Oem.Nvidia` segment, or missing chain link is
/// `None` (the family is not advertised); a failed fetch is the raw
/// transport failure for the caller's classification. The navigation mirrors
/// the read-side [`decode_nvidia_system_config_profile_navigation`] exactly,
/// including the `BlueField` reference-form segment quirk.
async fn nvidia_system_segment_entries(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
) -> Result<Option<NvidiaSystemChainEntries>, BmcError> {
    let Some(system) = first_collection_member_raw(root.root.systems.as_ref(), bmc).await? else {
        return Ok(None);
    };
    let Some(nvidia) = system
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Nvidia"))
    else {
        return Ok(None);
    };
    resolve_nvidia_system_segment(nvidia, bmc).await
}

/// Decodes one `Oem.Nvidia` system-segment value into its chain-entry
/// identifiers, or returns `None` when the segment is not a `ComputerSystem`
/// segment or cannot be decoded.
async fn resolve_nvidia_system_segment(
    nvidia: &serde_json::Value,
    bmc: &UpstreamBmc,
) -> Result<Option<NvidiaSystemChainEntries>, BmcError> {
    if is_nvidia_reference_form(nvidia) {
        let Some(id) = nvidia.get("@odata.id").and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        let navigation = NavProperty::<NvidiaComputerSystemSegmentSchema>::new_reference(
            ODataId::from(id.to_owned()),
        );
        let segment = navigation.get(bmc).await?;
        return Ok(Some(nvidia_system_chain_entries(
            segment.system_config_profile.as_ref(),
            segment.cpu_debug_token.as_ref(),
        )));
    }
    match nvidia_segment_kind(nvidia) {
        Some(NvidiaSegmentKind::ComputerSystem) => {
            match serde_json::from_value::<NvidiaComputerSystemSchema>(nvidia.clone()) {
                Ok(segment) => Ok(Some(nvidia_system_chain_entries(
                    segment.system_config_profile.as_ref(),
                    segment.cpu_debug_token.as_ref(),
                ))),
                Err(_) => Ok(None),
            }
        }
        Some(NvidiaSegmentKind::Chassis | NvidiaSegmentKind::Manager) | None => Ok(None),
    }
}

/// Collects the two chain-entry identifiers from their decoded navigation
/// properties; `NavProperty` is not `Clone`, so the identifiers are the
/// rehydratable form, exactly like the read-side chain decoding.
fn nvidia_system_chain_entries(
    system_config_profile: Option<&NavProperty<NvidiaSystemConfigProfileSchema>>,
    cpu_debug_token: Option<&NavProperty<NvidiaDebugTokenSchema>>,
) -> NvidiaSystemChainEntries {
    NvidiaSystemChainEntries {
        system_config_profile: system_config_profile.map(NavProperty::id).cloned(),
        cpu_debug_token: cpu_debug_token.map(NavProperty::id).cloned(),
    }
}

/// Resolves the endpoint's first manager's `Oem.Nvidia` `DebugTokenManagement`
/// chain-entry identifier, or `None` when the endpoint does not advertise it.
async fn nvidia_manager_debug_token_management_id(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
) -> Result<Option<ODataId>, BmcError> {
    let Some(manager) = first_collection_member_raw(root.root.managers.as_ref(), bmc).await? else {
        return Ok(None);
    };
    let Some(nvidia) = manager
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Nvidia"))
    else {
        return Ok(None);
    };
    resolve_nvidia_manager_segment(nvidia, bmc).await
}

/// Decodes one `Oem.Nvidia` manager-segment value into its
/// `DebugTokenManagement` chain-entry identifier, or returns `None` when the
/// segment is not a `Manager` segment or cannot be decoded.
async fn resolve_nvidia_manager_segment(
    nvidia: &serde_json::Value,
    bmc: &UpstreamBmc,
) -> Result<Option<ODataId>, BmcError> {
    if is_nvidia_reference_form(nvidia) {
        let Some(id) = nvidia.get("@odata.id").and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        let navigation = NavProperty::<NvidiaManagerSegmentReferenceSchema>::new_reference(
            ODataId::from(id.to_owned()),
        );
        let segment = navigation.get(bmc).await?;
        return Ok(segment
            .debug_token_management
            .as_ref()
            .map(NavProperty::id)
            .cloned());
    }
    match nvidia_segment_kind(nvidia) {
        Some(NvidiaSegmentKind::Manager) => {
            match serde_json::from_value::<NvidiaManagerSegmentSchema>(nvidia.clone()) {
                Ok(segment) => Ok(segment
                    .debug_token_management
                    .as_ref()
                    .map(NavProperty::id)
                    .cloned()),
                Err(_) => Ok(None),
            }
        }
        Some(NvidiaSegmentKind::ComputerSystem | NvidiaSegmentKind::Chassis) | None => Ok(None),
    }
}

/// Resolves the endpoint's first chassis's `Oem.Nvidia` `PowerSmoothing`
/// chain-entry identifier, or `None` when the endpoint does not advertise it.
async fn nvidia_chassis_power_smoothing_id(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
) -> Result<Option<ODataId>, BmcError> {
    let Some(chassis) = first_collection_member_raw(root.root.chassis.as_ref(), bmc).await? else {
        return Ok(None);
    };
    let Some(nvidia) = chassis
        .base
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.get("Nvidia"))
    else {
        return Ok(None);
    };
    resolve_nvidia_chassis_segment(nvidia, bmc).await
}

/// Decodes one `Oem.Nvidia` chassis-segment value into its `PowerSmoothing`
/// chain-entry identifier, or returns `None` when the segment is not a
/// `Chassis` segment or cannot be decoded.
///
/// The decode target is the compiled `NvidiaSmaChassis` type — the chassis
/// shape that carries the `PowerSmoothing` navigation in `nv-redfish-schema`
/// 0.13.0; a segment of another chassis shape simply carries no navigation.
async fn resolve_nvidia_chassis_segment(
    nvidia: &serde_json::Value,
    bmc: &UpstreamBmc,
) -> Result<Option<ODataId>, BmcError> {
    if is_nvidia_reference_form(nvidia) {
        let Some(id) = nvidia.get("@odata.id").and_then(serde_json::Value::as_str) else {
            return Ok(None);
        };
        let navigation = NavProperty::<NvidiaChassisSegmentReferenceSchema>::new_reference(
            ODataId::from(id.to_owned()),
        );
        let segment = navigation.get(bmc).await?;
        return Ok(segment
            .power_smoothing
            .as_ref()
            .map(NavProperty::id)
            .cloned());
    }
    match nvidia_segment_kind(nvidia) {
        Some(NvidiaSegmentKind::Chassis) => {
            match serde_json::from_value::<NvidiaSmaChassisSchema>(nvidia.clone()) {
                Ok(segment) => Ok(segment
                    .power_smoothing
                    .as_ref()
                    .map(NavProperty::id)
                    .cloned()),
                Err(_) => Ok(None),
            }
        }
        Some(NvidiaSegmentKind::ComputerSystem | NvidiaSegmentKind::Manager) | None => Ok(None),
    }
}

/// Fetches one chain-root document through its decoded reference navigation,
/// classifying fetch failures with the caller's error mapper.
async fn nvidia_chain_document<T, E, F>(
    id: ODataId,
    bmc: &UpstreamBmc,
    map: F,
) -> Result<Option<Arc<T>>, E>
where
    T: EntityTypeRef + for<'de> Deserialize<'de> + 'static,
    F: Fn(BmcError) -> E,
{
    let navigation = NavProperty::<T>::new_reference(id);
    let document = navigation.get(bmc).await.map_err(&map)?;
    Ok(Some(document))
}

/// The `NvidiaSystemConfigProfile` chain root of the endpoint's first system,
/// or `None` when the endpoint does not advertise the chain.
///
/// The navigation mirrors the §11.5 read side exactly; fetch failures are
/// classified by the caller's mapper so the execution and verification paths
/// keep their own error contracts.
async fn nvidia_system_config_profile_document<E, F>(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
    map: F,
) -> Result<Option<Arc<NvidiaSystemConfigProfileSchema>>, E>
where
    F: Fn(BmcError) -> E,
{
    let Some(entries) = nvidia_system_segment_entries(root, bmc)
        .await
        .map_err(&map)?
    else {
        return Ok(None);
    };
    let Some(id) = entries.system_config_profile else {
        return Ok(None);
    };
    nvidia_chain_document(id, bmc, map).await
}

/// The device `NvidiaDebugToken` document behind the endpoint's first
/// system's `CPUDebugToken` navigation, or `None` when not advertised.
async fn nvidia_cpu_debug_token_document<E, F>(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
    map: F,
) -> Result<Option<Arc<NvidiaDebugTokenSchema>>, E>
where
    F: Fn(BmcError) -> E,
{
    let Some(entries) = nvidia_system_segment_entries(root, bmc)
        .await
        .map_err(&map)?
    else {
        return Ok(None);
    };
    let Some(id) = entries.cpu_debug_token else {
        return Ok(None);
    };
    nvidia_chain_document(id, bmc, map).await
}

/// The `NvidiaDebugTokenManagement` document behind the endpoint's first
/// manager's `Oem.Nvidia` segment, or `None` when not advertised.
async fn nvidia_debug_token_management_document<E, F>(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
    map: F,
) -> Result<Option<Arc<NvidiaDebugTokenManagementSchema>>, E>
where
    F: Fn(BmcError) -> E,
{
    let Some(id) = nvidia_manager_debug_token_management_id(root, bmc)
        .await
        .map_err(&map)?
    else {
        return Ok(None);
    };
    nvidia_chain_document(id, bmc, map).await
}

/// The `NvidiaPowerSmoothing` document behind the endpoint's first chassis's
/// `Oem.Nvidia` segment, or `None` when not advertised.
async fn nvidia_power_smoothing_document<E, F>(
    root: &ServiceRoot<UpstreamBmc>,
    bmc: &UpstreamBmc,
    map: F,
) -> Result<Option<Arc<NvidiaPowerSmoothingSchema>>, E>
where
    F: Fn(BmcError) -> E,
{
    let Some(id) = nvidia_chassis_power_smoothing_id(root, bmc)
        .await
        .map_err(&map)?
    else {
        return Ok(None);
    };
    nvidia_chain_document(id, bmc, map).await
}

/// The typed fetch target of a reference-form `Oem.Nvidia` chassis segment.
///
/// The compiled `NvidiaSmaChassis` type models the segment but implements no
/// `EntityTypeRef` (it is an OEM segment, not a standalone resource), so a
/// reference-form fetch goes through this minimal local schema, the same
/// local-schema precedent as the read side's segment schemas.
#[derive(Deserialize)]
struct NvidiaChassisSegmentReferenceSchema {
    #[serde(rename = "@odata.id")]
    odata_id: ODataId,
    #[serde(rename = "PowerSmoothing", default)]
    power_smoothing: Option<NavProperty<NvidiaPowerSmoothingSchema>>,
}

impl EntityTypeRef for NvidiaChassisSegmentReferenceSchema {
    fn odata_id(&self) -> &ODataId {
        &self.odata_id
    }

    fn etag(&self) -> Option<&nv_redfish::core::ODataETag> {
        None
    }
}

/// Dispatches one §14.3 firmware upload through the authenticated transport.
///
/// The upload is endpoint-scoped like every other write of this iteration:
/// the artifact is handed to the endpoint's `UpdateService`, which decides
/// the targets from the image. The method branches on the caller's upload
/// decision: `push_uri: None` selects the standard multipart upload, and a
/// caller-supplied `push_uri` selects the upstream-retained legacy direct
/// push. Both branches run the §13.3 step 2 capability check against the
/// decoded `UpdateService` document before any write is sent.
async fn execute_authenticated_update(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    artifact: UpdateArtifactUpload,
    push_uri: Option<&ResourceODataId>,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(update_service) = update_service_document(bmc, root, identity, trust).await? else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    match push_uri {
        None => execute_multipart_update(bmc, &update_service, identity, trust, artifact).await,
        Some(push_uri) => {
            execute_http_push_update(bmc, &update_service, identity, trust, artifact, push_uri)
                .await
        }
    }
}

/// Executes the standard §14.3 multipart upload through the typed
/// `Bmc::multipart_update` API.
///
/// The upload targets the `MultipartHttpPushUri` the decoded `UpdateService`
/// document advertises — never a guessed path (§11.1) — and the body is
/// produced by the upstream multipart machinery from the typed
/// [`MultipartUpdateParameters`] JSON part and the artifact as the named
/// `UpdateFile` binary part (§7.4). The parameters are empty: an image-based
/// upload leaves target selection to the endpoint, and the typed parameter
/// set (`Targets`, `ForceUpdate`, `Stage`, ...) stays empty until a product
/// flow needs it. The upload timeout is the shared request timeout; larger
/// firmware with streaming progress is the later §0.4.0 large-file
/// iteration.
async fn execute_multipart_update(
    bmc: &UpstreamBmc,
    update_service: &UpdateServiceSchema,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    artifact: UpdateArtifactUpload,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    let Some(multipart_uri) = update_service.multipart_http_push_uri.as_deref() else {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    };
    let parameters = MultipartUpdateParameters::default();
    let length = artifact.bytes.len();
    let request = MultipartUpdateRequest {
        update_parameters: &parameters,
        update_stream: DataStream::new(artifact.name, Cursor::new(artifact.bytes))
            .with_content_length(length as u64),
        oem_parts: Vec::new(),
        upload_timeout: HTTP_REQUEST_TIMEOUT,
    };
    let response = match bmc
        .multipart_update::<_, MultipartUpdateParameters, ()>(multipart_uri, request)
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

/// Executes the upstream-retained legacy direct push (§0.4.0) through the
/// typed `Bmc::http_push_uri_update` API.
///
/// The upload targets the caller-selected `HttpPushUri` as a raw
/// `application/octet-stream` body; the endpoint must still advertise
/// `HttpPushUri` on its `UpdateService` document (§13.3 step 2), and the
/// transport resolves the URI same-origin, so a caller-supplied value cannot
/// escape the endpoint (§15.6).
async fn execute_http_push_update(
    bmc: &UpstreamBmc,
    update_service: &UpdateServiceSchema,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    artifact: UpdateArtifactUpload,
    push_uri: &ResourceODataId,
) -> Result<CommandExecutionOutcome, CommandExecutionError> {
    if update_service.http_push_uri.is_none() {
        return Err(CommandExecutionError::Rejected(
            CommandRejection::CapabilityUnavailable,
        ));
    }
    let length = artifact.bytes.len();
    let request = HttpPushUriUpdateRequest {
        update_stream: UploadStream::new(Cursor::new(artifact.bytes))
            .with_content_length(length as u64),
        upload_timeout: HTTP_REQUEST_TIMEOUT,
    };
    let response = match bmc
        .http_push_uri_update::<_, ()>(push_uri.as_str(), request)
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

/// Fetches the typed `UpdateService` document through its root navigation
/// property, classifying fetch failures as command preparation failures; a
/// missing link is `None`.
async fn update_service_document(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<Option<Arc<UpdateServiceSchema>>, CommandExecutionError> {
    let Some(update_service) = root.root.update_service.as_ref() else {
        return Ok(None);
    };
    let service = update_service
        .get(bmc)
        .await
        .map_err(|source| command_preparation_error(source, identity, trust))?;
    Ok(Some(service))
}

/// Validates the artifact name as a safe multipart file name.
///
/// The name becomes the `filename` attribute of the multipart `UpdateFile`
/// part, so a control character could smuggle request structure into the
/// body; the domain's `ArtifactName` already rejects control characters, and
/// this check keeps the transport boundary safe even when a caller bypasses
/// the domain validation.
fn validate_update_file_name(name: &str) -> bool {
    // Control bytes (0x00-0x1F and 0x7F) are the header-injection surface:
    // CRLF terminates the part headers. Multi-byte UTF-8 sequences are all
    // >= 0x80, so the check keeps Unicode file names (the domain `ArtifactName`
    // allows them) while excluding every control byte.
    !name.is_empty() && name.bytes().all(|byte| byte >= 0x20 && byte != 0x7F)
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
        // §14.3 update verification: the complete `SoftwareInventory` family
        // must re-read without error. The application contract for this
        // family records a provably absent inventory surface as `Mismatched`
        // (the update did not leave the expected result) instead of the
        // reset families' `CapabilityUnavailable` error — see the
        // `CommandVerifier` contract doc.
        RedfishCommand::Update(_) => verify_authenticated_update(bmc, root, identity, trust).await,
        RedfishCommand::Oem(oem) => verify_nvidia_oem_target(bmc, root, identity, trust, oem).await,
    }
}

/// "Accepted" verification of an NVIDIA OEM command: the chain resource the
/// write targeted must re-read without error through the same §11.5
/// navigation the write used.
///
/// The physical effect is deliberately not asserted (see
/// [`RedfishGateway::verify_command`]): the profile-service and debug-token
/// actions take effect asynchronously on the BMC, so claiming an effect from
/// a successful read would fabricate a result. `EraseToken` targets the
/// manager's `DebugTokenManagement` document and the other debug-token
/// actions target the system's `CPUDebugToken` document, so the re-read
/// follows the document of the executed action.
async fn verify_nvidia_oem_target(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
    oem: &OemCommand,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    let map = |source: BmcError| command_verification_read_error(source, identity, trust);
    match oem {
        OemCommand::SystemConfigProfile(_) => {
            match nvidia_system_config_profile_document(root, bmc, map).await {
                Ok(Some(_)) => Ok(CommandVerificationOutcome::Confirmed),
                Ok(None) => Err(CommandVerificationError::CapabilityUnavailable),
                Err(source) => Err(source),
            }
        }
        OemCommand::DebugToken(NvidiaDebugTokenCommand::EraseToken(_)) => {
            match nvidia_debug_token_management_document(root, bmc, map).await {
                Ok(Some(_)) => Ok(CommandVerificationOutcome::Confirmed),
                Ok(None) => Err(CommandVerificationError::CapabilityUnavailable),
                Err(source) => Err(source),
            }
        }
        OemCommand::DebugToken(_) => match nvidia_cpu_debug_token_document(root, bmc, map).await {
            Ok(Some(_)) => Ok(CommandVerificationOutcome::Confirmed),
            Ok(None) => Err(CommandVerificationError::CapabilityUnavailable),
            Err(source) => Err(source),
        },
        OemCommand::PowerSmoothing(_) => {
            match nvidia_power_smoothing_document(root, bmc, map).await {
                Ok(Some(_)) => Ok(CommandVerificationOutcome::Confirmed),
                Ok(None) => Err(CommandVerificationError::CapabilityUnavailable),
                Err(source) => Err(source),
            }
        }
    }
}

/// Re-reads the complete `SoftwareInventory` family for §14.3 verification.
///
/// Every inventory document — the `UpdateService` singleton, the
/// `SoftwareInventory` collection, and each member — must re-read without
/// error, and a failed re-read converges on
/// [`CommandVerificationError::ReReadFailed`] exactly like the other
/// verification re-reads: after an accepted update, an unreadable inventory
/// leaves the outcome unprovable (§13.5). The application contract for this
/// family is stricter than the reset families about one case: a `404` from
/// the `UpdateService` document or the `SoftwareInventory` collection, or a
/// vanished navigation link, proves the inventory surface is absent after
/// the accepted update, and that provable absence is
/// [`CommandVerificationOutcome::Mismatched`] — the update did not leave the
/// expected readable inventory. Members are fetched strictly — none is
/// skippable — because the member documents are the inventory itself;
/// skipping a member could hide the proof of the write, and a member that
/// cannot be fetched fails outright (the surface exists, so the outcome is
/// unprovable, never `Mismatched`).
async fn verify_authenticated_update(
    bmc: &UpstreamBmc,
    root: &ServiceRoot<UpstreamBmc>,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    let Some(update_service) = root.root.update_service.as_ref() else {
        return Ok(CommandVerificationOutcome::Mismatched);
    };
    let service = match update_service.get(bmc).await {
        Ok(service) => service,
        Err(source) => return classify_update_surface_fetch(source, identity, trust),
    };
    let Some(software_inventory) = service.software_inventory.as_ref() else {
        return Ok(CommandVerificationOutcome::Mismatched);
    };
    let collection = match bmc
        .get::<SoftwareInventoryCollectionSchema>(software_inventory.odata_id())
        .await
    {
        Ok(collection) => collection,
        Err(source) => return classify_update_surface_fetch(source, identity, trust),
    };
    for member in collection.members() {
        member
            .get(bmc)
            .await
            .map_err(|source| command_verification_read_error(source, identity, trust))?;
    }
    Ok(CommandVerificationOutcome::Confirmed)
}

/// Classifies one §14.3 inventory-surface fetch failure.
///
/// A `404` proves the inventory surface no longer exists after the accepted
/// update and becomes [`CommandVerificationOutcome::Mismatched`]; every
/// other failure converges on [`CommandVerificationError::ReReadFailed`]
/// because the outcome is unprovable (§13.5). TLS-safety failures keep
/// precedence over the status: a changed or rejected identity is never read
/// as a vanished surface.
fn classify_update_surface_fetch(
    source: BmcError,
    identity: &IdentityMonitor,
    trust: &TlsTrust,
) -> Result<CommandVerificationOutcome, CommandVerificationError> {
    match identity.take_change(trust) {
        Err(state) => {
            return Err(CommandVerificationError::ReReadFailed(Box::new(
                RedfishServiceRootError::TlsIdentityState(state),
            )));
        }
        Ok(Some(changed)) => {
            return Err(CommandVerificationError::ReReadFailed(Box::new(
                RedfishServiceRootError::TlsIdentityChanged(changed),
            )));
        }
        Ok(None) => {}
    }
    if identity.validation_rejected() {
        return Err(CommandVerificationError::ReReadFailed(Box::new(
            RedfishServiceRootError::TlsRejected { source },
        )));
    }
    match source {
        BmcError::InvalidResponse {
            status: StatusCode::NOT_FOUND,
            ..
        } => Ok(CommandVerificationOutcome::Mismatched),
        source => Err(command_verification_read_error(source, identity, trust)),
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

/// One firmware artifact, fully resolved in memory, ready for the §14.3
/// upload.
///
/// The gateway deliberately performs no file-system I/O: the application
/// resolves the artifact's stored file (persistence derives the on-disk
/// location) and hands the complete byte range across the boundary, so
/// storage policy stays inside the application crate (§7.2, §7.8). The
/// in-memory byte range is the artifact-size boundary of this iteration —
/// streaming from storage and resumable transfers are the later §0.4.0
/// large-file iteration. `Clone` is deliberately not derived: firmware
/// images can be large, and duplicating the bytes should be an explicit
/// caller decision.
#[derive(Debug, Eq, PartialEq)]
pub struct UpdateArtifactUpload {
    name: String,
    bytes: Vec<u8>,
}

impl UpdateArtifactUpload {
    /// Bundles the artifact name and its complete byte range for one upload.
    #[must_use]
    pub const fn new(name: String, bytes: Vec<u8>) -> Self {
        Self { name, bytes }
    }

    /// Returns the file name, which becomes the `filename` attribute of the
    /// multipart `UpdateFile` part.
    #[must_use]
    pub fn name(&self) -> &str {
        self.name.as_str()
    }

    /// Returns the complete artifact byte range.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
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

/// One endpoint event consumed from an [`EventStream`], bound to the
/// endpoint that produced it (§14.4 记录事件来源).
///
/// The wrapped [`Event`] is the complete persisted domain model: it carries
/// the same `endpoint_id`, the product-side receive time, and the derived
/// dedup key (§14.4 去除明显重复). The field is repeated on the binding
/// because the ingestion layer consumes this binding and must never reach
/// into the domain aggregate to learn its source.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointEvent {
    endpoint_id: EndpointId,
    event: Event,
}

impl EndpointEvent {
    #[must_use]
    pub const fn new(endpoint_id: EndpointId, event: Event) -> Self {
        Self { endpoint_id, event }
    }

    /// Returns the identity of the endpoint that produced the event.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Borrows the persisted domain event.
    #[must_use]
    pub const fn event(&self) -> &Event {
        &self.event
    }

    /// Consumes the event into its source identity and domain record.
    #[must_use]
    pub fn into_parts(self) -> (EndpointId, Event) {
        (self.endpoint_id, self.event)
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

/// The §0.5.0 Dell OEM `DellAttributes` family projection.
///
/// The field set is exactly the `OemDellPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. Only the five
/// identity attributes Dell iDRAC documents on its `DellAttributes` resource
/// are projected, each read through the typed `Edm.PrimitiveType` map of the
/// compiled schema (the same typed lookup the upstream `DellAttributes`
/// wrapper performs); every other entry of the vendor-specific dynamic
/// attribute bag stays out exactly like `Bios`'s `Attributes` bag does,
/// because the bag is unbounded and untyped by key.
#[derive(Serialize)]
struct DellAttributesPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "ServerModel", skip_serializing_if = "Option::is_none")]
    server_model: Option<String>,
    #[serde(rename = "ServerServiceTag", skip_serializing_if = "Option::is_none")]
    server_service_tag: Option<String>,
    #[serde(rename = "ServerGeneration", skip_serializing_if = "Option::is_none")]
    server_generation: Option<String>,
    #[serde(
        rename = "ServerBmcMacAddress",
        skip_serializing_if = "Option::is_none"
    )]
    server_bmc_mac_address: Option<String>,
    #[serde(rename = "ServerName", skip_serializing_if = "Option::is_none")]
    server_name: Option<String>,
}

/// The §0.5.0 Supermicro `SysLockdown` family projection.
///
/// The field set is exactly the `OemSmcSysLockdownPayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The compiled
/// `SysLockdown` schema models only `SysLockdownEnabled` beside its base
/// `@odata.id` / `@odata.etag` (which stay on the snapshot, not the payload):
/// it flattens a `resource::Item` base that carries no `Id` / `Name` /
/// `Description` properties, so unlike every standard family there are no
/// common fields to project — the application boundary derives the product
/// identity from the snapshot's `@odata.id` instead.
#[derive(Serialize)]
struct SmcSysLockdownPayload {
    #[serde(rename = "SysLockdownEnabled", skip_serializing_if = "Option::is_none")]
    sys_lockdown_enabled: Option<bool>,
}

/// The §0.5.0 Supermicro `KcsInterface` family projection.
///
/// The field set is exactly the `OemSmcKcsInterfacePayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The compiled
/// `KcsInterface` schema models `Privilege` (an enum serialized by its
/// vendor-defined wire spelling, e.g. `Administrator`, `DisableKCS`) beside
/// its base `@odata.id` / `@odata.etag`, which stay on the snapshot; the
/// `@Redfish.Settings` annotations are meta-annotations, not document
/// content, and stay out exactly like every other family. The schema models
/// no `Id` / `Name` / `Description` properties either, so there are no common
/// fields to project — the application boundary derives the product identity
/// from the snapshot's `@odata.id` instead.
#[derive(Serialize)]
struct SmcKcsInterfacePayload {
    #[serde(rename = "Privilege", skip_serializing_if = "Option::is_none")]
    privilege: Option<KcsPrivilegeSchema>,
}

/// The §0.5.0 Lenovo `SecurityService` family projection.
///
/// The field set is exactly the `OemLenovoSecurityServicePayload` the
/// application boundary decodes with `deny_unknown_fields`, so an extra field
/// here would make every stored snapshot unreadable at projection time. The
/// compiled schema models the rollback state inside the `Configurator`
/// segment, and the upstream `LenovoSecurityService::fw_rollback` wrapper
/// collapses that nesting onto its single typed accessor; the projection
/// follows the wrapper surface, so the wire carries the flattened
/// `FWRollback` enum spelling verbatim (e.g. `Enabled`, `Disabled`, or
/// `UnsupportedValue` for a value this build cannot classify).
#[derive(Serialize)]
struct LenovoSecurityServicePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "FWRollback", skip_serializing_if = "Option::is_none")]
    fw_rollback: Option<LenovoFwRollbackStateSchema>,
}

/// The one document-kind discriminator of the §0.5.0 NVIDIA
/// system-config-profile family.
///
/// The whole chain shares the single family code
/// `nvidia-system-config-profile` (one family = one entry navigation chain),
/// so the snapshot payload must carry the chain document's kind for the
/// application boundary to route the snapshot to the right details shape.
/// The value is written by the infra projection — which knows the compiled
/// decode target it just projected — and consumed by the application
/// projection; it is a product discriminator, not a Redfish field, and never
/// reaches the wire response (the application consumes it).
#[derive(Clone, Copy, Debug, Serialize)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
enum NvidiaSystemConfigProfileDocument {
    SystemConfigProfile,
    SystemConfigProfileStatus,
    SystemProfile,
    SystemProfileFile,
}

/// The §0.5.0 NVIDIA `SystemConfigProfile` chain-root projection.
///
/// The field set is exactly the application payload decoded with
/// `deny_unknown_fields`, so an extra field here would make every stored
/// snapshot unreadable at projection time. The `Truststore` section carries
/// only link-presence metadata: the certificate documents behind the
/// `NvidiaCertificates` / `OemCertificates` links are never fetched, and
/// their certificate payloads (the base64 certificate bodies) never enter
/// the snapshot — the sensitive surface is deferred to a later slice.
#[derive(Serialize)]
struct NvidiaSystemConfigProfilePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaSystemConfigProfileDocument,
    #[serde(rename = "Truststore", skip_serializing_if = "Option::is_none")]
    truststore: Option<NvidiaSystemConfigProfileTruststorePayload>,
}

/// The compiled `Truststore` metadata of the profile service document: the
/// presence of each certificate-store link, never the certificates
/// themselves.
#[derive(Serialize)]
struct NvidiaSystemConfigProfileTruststorePayload {
    #[serde(rename = "NvidiaCertificates", skip_serializing_if = "Option::is_none")]
    nvidia_certificates: Option<bool>,
    #[serde(rename = "OemCertificates", skip_serializing_if = "Option::is_none")]
    oem_certificates: Option<bool>,
}

/// The §0.5.0 NVIDIA `SystemConfigProfileStatus` projection.
///
/// The field set is exactly the compiled `NvidiaSystemConfigProfileStatus`
/// schema: the `PendingList.Activation` text, the numeric
/// `ActiveProfileIndex` / `BmcProfileVersion` / `DefaultProfileIndex`
/// indices, and the `FactoryResetStatus` text. An absent property projects
/// as `None` and is skipped on the wire, exactly like every other family.
#[derive(Serialize)]
struct NvidiaSystemConfigProfileStatusPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaSystemConfigProfileDocument,
    #[serde(rename = "PendingList", skip_serializing_if = "Option::is_none")]
    pending_list: Option<NvidiaSystemConfigProfilePendingListPayload>,
    #[serde(rename = "ActiveProfileIndex", skip_serializing_if = "Option::is_none")]
    active_profile_index: Option<i64>,
    #[serde(rename = "BmcProfileVersion", skip_serializing_if = "Option::is_none")]
    bmc_profile_version: Option<i64>,
    #[serde(rename = "FactoryResetStatus", skip_serializing_if = "Option::is_none")]
    factory_reset_status: Option<String>,
    #[serde(
        rename = "DefaultProfileIndex",
        skip_serializing_if = "Option::is_none"
    )]
    default_profile_index: Option<i64>,
}

/// The `PendingList` member of the profile status document.
#[derive(Serialize)]
struct NvidiaSystemConfigProfilePendingListPayload {
    #[serde(rename = "Activation", skip_serializing_if = "Option::is_none")]
    activation: Option<String>,
}

/// The §0.5.0 NVIDIA `SystemProfile` member projection.
///
/// The field set is exactly the compiled `NvidiaSystemProfile` schema's
/// metadata fields: the `Default` boolean, the `Owner` / `UUID` /
/// `ProfileName` texts, and the numeric `Version` (an `Edm.Int64` in the
/// compiled schema, so it stays numeric). The `Status` action-state and the
/// `Actions` / `ProfileFile` navigation stay out of the strictly projectable
/// field set.
#[derive(Serialize)]
struct NvidiaSystemProfilePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaSystemConfigProfileDocument,
    #[serde(rename = "Default", skip_serializing_if = "Option::is_none")]
    default: Option<bool>,
    #[serde(rename = "Owner", skip_serializing_if = "Option::is_none")]
    owner: Option<String>,
    #[serde(rename = "UUID", skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<i64>,
    #[serde(rename = "ProfileName", skip_serializing_if = "Option::is_none")]
    profile_name: Option<String>,
}

/// The §0.5.0 NVIDIA `SystemProfileFile` projection.
///
/// The field set is exactly the compiled `NvidiaSystemProfileFile` schema:
/// the `ProfileFile` document with its `Metadata` (the activation/delete
/// flags, the origin-profile UUID, the `More_Profiles` continuation flag,
/// the project name, and the profile UUID) and the base64 `Profile` content.
/// The signed profile payload is the file's own content and is projected
/// verbatim (§12.3), bounded by the snapshot payload limit.
#[derive(Serialize)]
struct NvidiaSystemProfileFilePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaSystemConfigProfileDocument,
    #[serde(rename = "ProfileFile", skip_serializing_if = "Option::is_none")]
    profile_file: Option<NvidiaSystemProfileFileContentPayload>,
}

/// The `ProfileFile` member of the profile file document.
#[derive(Serialize)]
struct NvidiaSystemProfileFileContentPayload {
    #[serde(rename = "Metadata", skip_serializing_if = "Option::is_none")]
    metadata: Option<NvidiaSystemProfileFileMetadataPayload>,
    #[serde(rename = "Profile", skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}

/// The `Metadata` member of the profile file, exactly the compiled
/// `nvidia_system_profile_file::Metadata` fields (including the vendor's
/// `More_Profiles` underscore spelling, kept verbatim).
#[derive(Serialize)]
struct NvidiaSystemProfileFileMetadataPayload {
    #[serde(rename = "Activate", skip_serializing_if = "Option::is_none")]
    activate: Option<bool>,
    #[serde(rename = "Delete", skip_serializing_if = "Option::is_none")]
    delete: Option<bool>,
    #[serde(rename = "OriginProfileUUID", skip_serializing_if = "Option::is_none")]
    origin_profile_uuid: Option<String>,
    #[serde(rename = "More_Profiles", skip_serializing_if = "Option::is_none")]
    more_profiles: Option<bool>,
    #[serde(rename = "ProjectName", skip_serializing_if = "Option::is_none")]
    project_name: Option<String>,
    #[serde(rename = "UUID", skip_serializing_if = "Option::is_none")]
    uuid: Option<String>,
}

/// The one document-kind discriminator of the §0.5.0 NVIDIA power-compliance
/// family.
///
/// The whole chain shares the single family code `nvidia-power-compliance`
/// (one family = one entry navigation chain), so the snapshot payload must
/// carry the chain document's kind for the application boundary to route the
/// snapshot to the right details shape. The value is written by the infra
/// projection — which knows the compiled decode target it just projected —
/// and consumed by the application projection; it is a product discriminator,
/// not a Redfish field, and never reaches the wire response (the application
/// consumes it).
#[derive(Clone, Copy, Debug, Serialize)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
enum NvidiaPowerComplianceDocument {
    PowerComplianceManager,
    PowerDomain,
    PowerPolicy,
    ManagedEntityGroup,
    PowerStateGroup,
    PscState,
    PsuState,
    PsuRedundancy,
}

/// The one document-kind discriminator of the §0.5.0 NVIDIA managed-entity
/// family: exactly one compiled decode target carries the chain, so the
/// discriminator has a single arm (kept as an enum so the application
/// boundary routes through the same envelope shape as the other chains).
#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum NvidiaManagedEntityDocument {
    ManagedEntity,
}

/// The §0.5.0 NVIDIA `NvidiaPowerComplianceManager` chain-root projection.
///
/// The field set is exactly the application payload decoded with
/// `deny_unknown_fields`, so an extra field here would make every stored
/// snapshot unreadable at projection time. Only the compiled `ManagerType`
/// enumeration is projectable; the `Actions` section and every navigation
/// stay out of the strictly projectable field set.
#[derive(Serialize)]
struct NvidiaPowerComplianceManagerPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(rename = "ManagerType", skip_serializing_if = "Option::is_none")]
    manager_type: Option<NvidiaPowerComplianceManagerType>,
}

/// The §0.5.0 NVIDIA `NvidiaPowerDomain` member projection.
///
/// The field set is exactly the compiled `NvidiaPowerDomain` schema's
/// scalar fields: the numeric `Value`, the `Type` / `Unit` enumerations, and
/// the `SensorReadingType` / `SensorImpl` sensor enumerations. The
/// `PowerPolicies` navigation stays out of the strictly projectable field
/// set.
#[derive(Serialize)]
struct NvidiaPowerDomainPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(rename = "Value", skip_serializing_if = "Option::is_none")]
    value: Option<i64>,
    #[serde(rename = "Type", skip_serializing_if = "Option::is_none")]
    r#type: Option<NvidiaPowerDomainComparisonType>,
    #[serde(rename = "Unit", skip_serializing_if = "Option::is_none")]
    unit: Option<NvidiaPowerDomainUnitType>,
    #[serde(rename = "SensorReadingType", skip_serializing_if = "Option::is_none")]
    sensor_reading_type: Option<NvidiaSensorReadingType>,
    #[serde(rename = "SensorImpl", skip_serializing_if = "Option::is_none")]
    sensor_impl: Option<NvidiaSensorImplementationType>,
}

/// The §0.5.0 NVIDIA `NvidiaPowerPolicy` projection, shared by the
/// `ACLossPolicy` and `PSUCompliancePolicy` singletons.
///
/// The field set is exactly the compiled `NvidiaPowerPolicy` schema's scalar
/// fields: the `AutoDeassertPowerBrake` boolean, the numeric `Min` / `Max`
/// thresholds, the `Type` / `Unit` enumerations, and the `PolicyActions`
/// enumeration. The `DwellTime` duration stays out of the strictly
/// projectable field set: the threshold duration carries no cross-vendor
/// identity and the strict field set keeps the policy's actionable scalars.
#[derive(Serialize)]
struct NvidiaPowerPolicyPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(
        rename = "AutoDeassertPowerBrake",
        skip_serializing_if = "Option::is_none"
    )]
    auto_deassert_power_brake: Option<bool>,
    #[serde(rename = "Min", skip_serializing_if = "Option::is_none")]
    min: Option<i64>,
    #[serde(rename = "Max", skip_serializing_if = "Option::is_none")]
    max: Option<i64>,
    #[serde(rename = "Type", skip_serializing_if = "Option::is_none")]
    r#type: Option<NvidiaPowerPolicyComparisonType>,
    #[serde(rename = "Unit", skip_serializing_if = "Option::is_none")]
    unit: Option<NvidiaPowerPolicyUnitType>,
    #[serde(rename = "PolicyActions", skip_serializing_if = "Option::is_none")]
    policy_actions: Option<NvidiaPowerPolicyActionType>,
}

/// The §0.5.0 NVIDIA `NvidiaManagedEntityGroup` member projection of the
/// power-compliance family.
///
/// The field set is exactly the compiled `NvidiaManagedEntityGroup` schema's
/// scalar field: the `CurrentManagedEntityId` text. The `ManagedEntities`
/// navigation belongs to the managed-entity family and stays out of this
/// payload.
#[derive(Serialize)]
struct NvidiaManagedEntityGroupPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(
        rename = "CurrentManagedEntityId",
        skip_serializing_if = "Option::is_none"
    )]
    current_managed_entity_id: Option<String>,
}

/// The §0.5.0 NVIDIA `NvidiaPowerStateGroup` projection.
///
/// The field set is exactly the compiled `NvidiaPowerStateGroup` schema's
/// scalar fields: the `PscId` text, the numeric `GeneratedWatts` /
/// `NumberOfPscs` / `NumberOfLocalPsus`. The `PowerShelfControllers` /
/// `PowerSupplies` navigations are their own chain documents and stay out of
/// this payload.
#[derive(Serialize)]
struct NvidiaPowerStateGroupPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(rename = "PscId", skip_serializing_if = "Option::is_none")]
    psc_id: Option<String>,
    #[serde(rename = "GeneratedWatts", skip_serializing_if = "Option::is_none")]
    generated_watts: Option<i64>,
    #[serde(rename = "NumberOfPscs", skip_serializing_if = "Option::is_none")]
    number_of_pscs: Option<i64>,
    #[serde(rename = "NumberOfLocalPsus", skip_serializing_if = "Option::is_none")]
    number_of_local_psus: Option<i64>,
}

/// The §0.5.0 NVIDIA `NvidiaPscState` member projection.
///
/// The field set is exactly the compiled `NvidiaPscState` schema's scalar
/// fields: the `PscId` text, the numeric `NumOfOperationalPsus` /
/// `MillisecondsSinceLastHeartbeat`, the `PowerBrakeAssert` boolean, and the
/// `Status` enumeration.
#[derive(Serialize)]
struct NvidiaPscStatePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(rename = "PscId", skip_serializing_if = "Option::is_none")]
    psc_id: Option<String>,
    #[serde(
        rename = "NumOfOperationalPsus",
        skip_serializing_if = "Option::is_none"
    )]
    num_of_operational_psus: Option<i64>,
    #[serde(rename = "PowerBrakeAssert", skip_serializing_if = "Option::is_none")]
    power_brake_assert: Option<bool>,
    #[serde(
        rename = "MillisecondsSinceLastHeartbeat",
        skip_serializing_if = "Option::is_none"
    )]
    milliseconds_since_last_heartbeat: Option<i64>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<NvidiaPscStateStatusType>,
}

/// The §0.5.0 NVIDIA `NvidiaPsuState` member projection.
///
/// The field set is exactly the compiled `NvidiaPsuState` schema's scalar
/// fields: the `PsuId` text and the `Presence` / `Input1Active` /
/// `Input2Active` booleans.
#[derive(Serialize)]
struct NvidiaPsuStatePayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(rename = "PsuId", skip_serializing_if = "Option::is_none")]
    psu_id: Option<String>,
    #[serde(rename = "Presence", skip_serializing_if = "Option::is_none")]
    presence: Option<bool>,
    #[serde(rename = "Input1Active", skip_serializing_if = "Option::is_none")]
    input1active: Option<bool>,
    #[serde(rename = "Input2Active", skip_serializing_if = "Option::is_none")]
    input2active: Option<bool>,
}

/// The §0.5.0 NVIDIA `NvidiaPsuRedundancy` projection.
///
/// The field set is exactly the compiled `NvidiaPsuRedundancy` schema's
/// scalar fields: the `MaxNumSupported` / `MinNumNeeded` texts and the
/// `RedundancySetting` enumeration.
#[derive(Serialize)]
struct NvidiaPsuRedundancyPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaPowerComplianceDocument,
    #[serde(rename = "MaxNumSupported", skip_serializing_if = "Option::is_none")]
    max_num_supported: Option<String>,
    #[serde(rename = "MinNumNeeded", skip_serializing_if = "Option::is_none")]
    min_num_needed: Option<String>,
    #[serde(rename = "RedundancySetting", skip_serializing_if = "Option::is_none")]
    redundancy_setting: Option<NvidiaPsuRedundancyType>,
}

/// The §0.5.0 NVIDIA `NvidiaManagedEntity` member projection of the
/// managed-entity family.
///
/// The field set is exactly the compiled `NvidiaManagedEntity` schema's
/// scalar fields: the `TransportProtocol` enumeration, the `IPv4Address` /
/// `IPv6Address` address texts (the compiled `Ipv4address` / `Ipv6address`
/// structs are not serializable, so the strictly projectable field set keeps
/// the address text itself, verbatim), and the numeric `Port`.
#[derive(Serialize)]
struct NvidiaManagedEntityPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "DocumentType")]
    document_type: NvidiaManagedEntityDocument,
    #[serde(rename = "TransportProtocol", skip_serializing_if = "Option::is_none")]
    transport_protocol: Option<NvidiaProtocolSchema>,
    #[serde(rename = "IPv4Address", skip_serializing_if = "Option::is_none")]
    ipv4_address: Option<String>,
    #[serde(rename = "IPv6Address", skip_serializing_if = "Option::is_none")]
    ipv6_address: Option<String>,
    #[serde(rename = "Port", skip_serializing_if = "Option::is_none")]
    port: Option<i64>,
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

/// The §0.2.0 `metric-report` family projection, extended by the 0.4.0
/// telemetry value-array read.
///
/// The field set is exactly the `MetricReport` variant the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. `metric_values`
/// now carries each timestamped reading of the `MetricValues` array — the
/// current-value surface of the telemetry-history iteration — alongside the
/// derived `metric_values_count`. Snapshots persisted by the 0.2.0 iteration
/// lack the array, so the application decodes it as `Option` (missing reads
/// as `None`) instead of failing the strict decoder. The report-level
/// `Timestamp`, `Context`, and `ReportSequence` metadata and the
/// (schema-absent) `Status` stay out.
#[derive(Serialize)]
struct MetricReportPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "MetricValuesCount", skip_serializing_if = "Option::is_none")]
    metric_values_count: Option<usize>,
    #[serde(rename = "MetricValues", skip_serializing_if = "Option::is_none")]
    metric_values: Option<Vec<MetricValuePayload>>,
}

/// One timestamped reading of a `MetricReport` member, kept exactly as the
/// compiled schema decodes it: `Timestamp` serializes as the RFC 3339 string
/// of the `Edm.DateTimeOffset` type and `MetricValue` stays the original
/// text of the `Edm.String` type (the DMTF schema represents numeric values
/// as strings, so a `f64` projection would lose the non-numeric boolean and
/// array representations). The `MetricId`, `MetricProperty`, `Oem`, and
/// `MetricDefinition` link of the schema entry stay out of the strictly
/// projectable field set.
#[derive(Serialize)]
struct MetricValuePayload {
    #[serde(rename = "Timestamp", skip_serializing_if = "Option::is_none")]
    timestamp: Option<nv_redfish::schema::edm::DateTimeOffset>,
    #[serde(rename = "MetricValue", skip_serializing_if = "Option::is_none")]
    metric_value: Option<String>,
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

/// The §0.2.0 `power-equipment` root document projection.
///
/// The field set is exactly the `PowerEquipmentPayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. The
/// `PowerEquipment` service document declares `Status` beside its common
/// identity fields; the collection navigations stay out of the strictly
/// projectable field set because the members carry the equipment data.
#[derive(Serialize)]
struct PowerEquipmentPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `power-equipment` `PowerShelves` member projection.
///
/// The field set is exactly the `PowerDistributionPayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. Fields are the
/// direct `EquipmentType` (required by the schema), the hardware identity
/// properties, and the `Status` property of the `PowerDistribution` schema.
#[derive(Serialize)]
struct PowerDistributionPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "EquipmentType")]
    equipment_type: nv_redfish::schema::power_distribution::PowerEquipmentType,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "PartNumber", skip_serializing_if = "Option::is_none")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(rename = "Version", skip_serializing_if = "Option::is_none")]
    version: Option<String>,
    #[serde(rename = "FirmwareVersion", skip_serializing_if = "Option::is_none")]
    firmware_version: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `power-supplies` family member projection.
///
/// The field set is exactly the `PowerSupplyPayload` the application boundary
/// decodes with `deny_unknown_fields`, so an extra field here would make
/// every stored snapshot unreadable at projection time. Fields are the direct
/// `PowerSupplyType`, `PowerCapacityWatts`, hardware identity, and `Status`
/// properties of the `PowerSupply` schema; the input-range and output-rail
/// bags stay out of this strictly projectable field set.
#[derive(Serialize)]
struct PowerSupplyPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "PowerSupplyType", skip_serializing_if = "Option::is_none")]
    power_supply_type: Option<nv_redfish::schema::power_supply::PowerSupplyType>,
    #[serde(rename = "PowerCapacityWatts", skip_serializing_if = "Option::is_none")]
    power_capacity_watts: Option<f64>,
    #[serde(rename = "Manufacturer", skip_serializing_if = "Option::is_none")]
    manufacturer: Option<String>,
    #[serde(rename = "Model", skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(rename = "FirmwareVersion", skip_serializing_if = "Option::is_none")]
    firmware_version: Option<String>,
    #[serde(rename = "SerialNumber", skip_serializing_if = "Option::is_none")]
    serial_number: Option<String>,
    #[serde(rename = "PartNumber", skip_serializing_if = "Option::is_none")]
    part_number: Option<String>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// The §0.2.0 `network-device-functions` family member projection.
///
/// The field set is exactly the `NetworkDeviceFunctionPayload` the
/// application boundary decodes with `deny_unknown_fields`, so an extra field
/// here would make every stored snapshot unreadable at projection time.
/// Fields are the direct `NetDevFuncType`, `DeviceEnabled`, and `Status`
/// properties of the `NetworkDeviceFunction` schema; the protocol-specific
/// configuration bags (`Ethernet`, `iSCSIBoot`, `FibreChannel`, ...) stay out
/// of this strictly projectable field set.
#[derive(Serialize)]
struct NetworkDeviceFunctionPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "NetDevFuncType", skip_serializing_if = "Option::is_none")]
    net_dev_func_type: Option<nv_redfish::schema::network_device_function::NetworkDeviceTechnology>,
    #[serde(rename = "DeviceEnabled", skip_serializing_if = "Option::is_none")]
    device_enabled: Option<bool>,
    #[serde(rename = "Status", skip_serializing_if = "Option::is_none")]
    status: Option<ResourceStatusPayload>,
}

/// One embedded sensor excerpt of the §0.2.0 `environment-metrics` document.
///
/// The `EnvironmentMetrics` schema embeds each measurement as an excerpt
/// carrying the `DataSourceUri` link to its backing `Sensor` resource and the
/// current `Reading` value, so the projection keeps exactly those two fields:
/// the console renders the reading without re-parsing text and the snapshot
/// names the sensor that sourced it.
#[derive(Serialize)]
struct EnvironmentMetricsReadingPayload {
    #[serde(rename = "DataSourceUri", skip_serializing_if = "Option::is_none")]
    data_source_uri: Option<String>,
    #[serde(rename = "Reading", skip_serializing_if = "Option::is_none")]
    reading: Option<f64>,
}

/// The embedded power-limit control excerpt of the §0.2.0
/// `environment-metrics` document.
///
/// `PowerLimitWatts` embeds a `Control` excerpt instead of a sensor excerpt,
/// so the projection carries its `DataSourceUri` link and `SetPoint` reading
/// exactly like the sensor excerpts carry theirs.
#[derive(Serialize)]
struct EnvironmentMetricsControlPayload {
    #[serde(rename = "DataSourceUri", skip_serializing_if = "Option::is_none")]
    data_source_uri: Option<String>,
    #[serde(rename = "SetPoint", skip_serializing_if = "Option::is_none")]
    set_point: Option<f64>,
}

/// The §0.2.0 `environment-metrics` singleton projection.
///
/// The field set is exactly the `EnvironmentMetricsPayload` the application
/// boundary decodes with `deny_unknown_fields`, so an extra field here would
/// make every stored snapshot unreadable at projection time. Every embedded
/// measurement the schema declares is projected through its excerpt reading
/// shape; the schema declares no `Status` property, so this family carries no
/// status field.
#[derive(Serialize)]
struct EnvironmentMetricsPayload {
    #[serde(flatten)]
    resource: CommonResourcePayload,
    #[serde(rename = "TemperatureCelsius", skip_serializing_if = "Option::is_none")]
    temperature_celsius: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "HumidityPercent", skip_serializing_if = "Option::is_none")]
    humidity_percent: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "FanSpeedsPercent", skip_serializing_if = "Option::is_none")]
    fan_speeds_percent: Option<Vec<EnvironmentMetricsReadingPayload>>,
    #[serde(rename = "PowerWatts", skip_serializing_if = "Option::is_none")]
    power_watts: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "EnergykWh", skip_serializing_if = "Option::is_none")]
    energyk_wh: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "PowerLoadPercent", skip_serializing_if = "Option::is_none")]
    power_load_percent: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "PowerLimitWatts", skip_serializing_if = "Option::is_none")]
    power_limit_watts: Option<EnvironmentMetricsControlPayload>,
    #[serde(rename = "DewPointCelsius", skip_serializing_if = "Option::is_none")]
    dew_point_celsius: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "AbsoluteHumidity", skip_serializing_if = "Option::is_none")]
    absolute_humidity: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "EnergyJoules", skip_serializing_if = "Option::is_none")]
    energy_joules: Option<EnvironmentMetricsReadingPayload>,
    #[serde(
        rename = "AmbientTemperatureCelsius",
        skip_serializing_if = "Option::is_none"
    )]
    ambient_temperature_celsius: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "Voltage", skip_serializing_if = "Option::is_none")]
    voltage: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "CurrentAmps", skip_serializing_if = "Option::is_none")]
    current_amps: Option<EnvironmentMetricsReadingPayload>,
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

/// Projects one typed Dell `DellAttributes` document into the OEM family.
///
/// The `@odata.id`, `ETag`, `Id`, `Name`, and `Description` come from the
/// typed schema base exactly like every other family; the identity attributes
/// come from the typed primitive map. The document is one manager surface,
/// so an unrepresentable identifier or payload is skipped by the caller
/// through the member-level `member_projection` semantics.
fn dell_attributes_projection(
    attributes: &DellAttributesSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = DellAttributesPayload {
        // The Dell OEM feature generates its own `resource::Resource` base
        // type (a separate module tree from the base schema re-export), so
        // the common fields are copied here with the same shape
        // `from_schema_base` projects instead of converting between the two
        // nominally distinct resource types.
        resource: CommonResourcePayload {
            id: attributes.base.id.clone(),
            name: attributes.base.name.clone(),
            description: attributes
                .base
                .description
                .as_ref()
                .and_then(Option::as_ref)
                .cloned(),
        },
        server_model: dell_attribute_string(attributes, "ServerModel"),
        server_service_tag: dell_attribute_string(attributes, "ServerServiceTag"),
        server_generation: dell_attribute_string(attributes, "ServerGeneration"),
        server_bmc_mac_address: dell_attribute_string(attributes, "ServerBmcMacAddress"),
        server_name: dell_attribute_string(attributes, "ServerName"),
    };
    build_core_projection(
        ResourceFeature::OemDell,
        attributes.odata_id(),
        attributes.etag(),
        &payload,
    )
}

/// Projects one typed Supermicro `SysLockdown` document into the OEM family.
///
/// The `@odata.id` and `ETag` come from the typed schema base exactly like
/// every other family; the `SysLockdownEnabled` boolean is projected with the
/// compiled `Edm.Boolean` semantics (an absent property projects as `None`
/// and is skipped on the wire). The document is one manager surface, so an
/// unrepresentable identifier or payload is skipped by the caller through the
/// member-level `member_projection` semantics.
fn smc_sys_lockdown_projection(
    sys_lockdown: &SysLockdownSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = SmcSysLockdownPayload {
        sys_lockdown_enabled: sys_lockdown.sys_lockdown_enabled,
    };
    build_core_projection(
        ResourceFeature::OemSmcSysLockdown,
        sys_lockdown.odata_id(),
        sys_lockdown.etag(),
        &payload,
    )
}

/// Projects one typed Supermicro `KcsInterface` document into the OEM family.
///
/// The `@odata.id` and `ETag` come from the typed schema exactly like every
/// other family; the `Privilege` enum is serialized by its vendor-defined
/// wire spelling (never translated, per §12.3), and an absent property
/// projects as `None` and is skipped on the wire. The document is one manager
/// surface, so an unrepresentable identifier or payload is skipped by the
/// caller through the member-level `member_projection` semantics.
fn smc_kcs_interface_projection(
    kcs_interface: &KcsInterfaceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = SmcKcsInterfacePayload {
        privilege: kcs_interface.privilege,
    };
    build_core_projection(
        ResourceFeature::OemSmcKcsInterface,
        kcs_interface.odata_id(),
        kcs_interface.etag(),
        &payload,
    )
}

/// Projects one typed Lenovo `LenovoSecurityService` document into the OEM
/// family.
///
/// The `@odata.id`, `ETag`, `Id`, `Name`, and `Description` come from the
/// typed schema base exactly like every other family; the `FWRollback` state
/// comes from the compiled type and is serialized by its vendor-defined wire
/// spelling (e.g. `Enabled`, `Disabled`, or `UnsupportedValue` for a value
/// this build cannot classify), never translated, per §12.3. The compiled
/// schema models the rollback state inside the `Configurator` segment, and
/// the upstream `LenovoSecurityService::fw_rollback` wrapper collapses that
/// nesting onto its single typed accessor; the projection follows the
/// wrapper's typed surface, so an absent `Configurator` or absent
/// `FWRollback` property projects as `None` and is skipped on the wire. The
/// document is one manager surface, so an unrepresentable identifier or
/// payload is skipped by the caller through the member-level
/// `member_projection` semantics.
fn lenovo_security_service_projection(
    security_service: &LenovoSecurityServiceSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = LenovoSecurityServicePayload {
        resource: lenovo_common_resource(&security_service.base),
        fw_rollback: security_service
            .configurator
            .as_ref()
            .and_then(Option::as_ref)
            .and_then(|configurator| configurator.fw_rollback)
            .flatten(),
    };
    build_core_projection(
        ResourceFeature::OemLenovoSecurityService,
        security_service.odata_id(),
        security_service.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `SystemConfigProfile` document into the OEM
/// family.
///
/// The `@odata.id`, `ETag`, `Id`, `Name`, and `Description` come from the
/// typed schema base exactly like every other family; the `Truststore`
/// metadata and the chain navigations come from the compiled type. The
/// document is one chain surface, so an unrepresentable identifier or
/// payload is skipped by the caller through the member-level
/// `member_projection` semantics.
fn nvidia_system_config_profile_projection(
    config_profile: &NvidiaSystemConfigProfileSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaSystemConfigProfilePayload {
        resource: nvidia_common_resource(&config_profile.base),
        document_type: NvidiaSystemConfigProfileDocument::SystemConfigProfile,
        truststore: config_profile.truststore.as_ref().map(|truststore| {
            NvidiaSystemConfigProfileTruststorePayload {
                nvidia_certificates: truststore.nvidia_certificates.as_ref().map(|_| true),
                oem_certificates: truststore.oem_certificates.as_ref().map(|_| true),
            }
        }),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaSystemConfigProfile,
        config_profile.odata_id(),
        config_profile.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `SystemConfigProfileStatus` document into the
/// OEM family, carrying the compiled status fields verbatim.
fn nvidia_system_config_profile_status_projection(
    status: &NvidiaSystemConfigProfileStatusSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaSystemConfigProfileStatusPayload {
        resource: nvidia_common_resource(&status.base),
        document_type: NvidiaSystemConfigProfileDocument::SystemConfigProfileStatus,
        pending_list: status.pending_list.as_ref().map(|pending_list| {
            NvidiaSystemConfigProfilePendingListPayload {
                activation: pending_list
                    .activation
                    .as_ref()
                    .and_then(Option::as_ref)
                    .cloned(),
            }
        }),
        active_profile_index: status.active_profile_index,
        bmc_profile_version: status.bmc_profile_version,
        factory_reset_status: status.factory_reset_status.clone(),
        default_profile_index: status.default_profile_index,
    };
    build_core_projection(
        ResourceFeature::OemNvidiaSystemConfigProfile,
        status.odata_id(),
        status.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `SystemProfile` member into the OEM family,
/// carrying the compiled metadata fields verbatim.
fn nvidia_system_profile_projection(
    profile: &NvidiaSystemProfileSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaSystemProfilePayload {
        resource: nvidia_common_resource(&profile.base),
        document_type: NvidiaSystemConfigProfileDocument::SystemProfile,
        default: profile.default,
        owner: profile.owner.clone(),
        uuid: profile.uuid.clone(),
        version: profile.version,
        profile_name: profile.profile_name.clone(),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaSystemConfigProfile,
        profile.odata_id(),
        profile.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `SystemProfileFile` document into the OEM
/// family, carrying the compiled file fields (metadata and the base64
/// profile content) verbatim.
fn nvidia_system_profile_file_projection(
    profile_file: &NvidiaSystemProfileFileSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaSystemProfileFilePayload {
        resource: nvidia_common_resource(&profile_file.base),
        document_type: NvidiaSystemConfigProfileDocument::SystemProfileFile,
        profile_file: profile_file.profile_file.as_ref().map(|content| {
            NvidiaSystemProfileFileContentPayload {
                metadata: content.metadata.as_ref().map(|metadata| {
                    NvidiaSystemProfileFileMetadataPayload {
                        activate: metadata.activate,
                        delete: metadata.delete,
                        origin_profile_uuid: metadata.origin_profile_uuid.clone(),
                        more_profiles: metadata.more_profiles,
                        project_name: metadata.project_name.clone(),
                        uuid: metadata.uuid.clone(),
                    }
                }),
                profile: content.profile.clone(),
            }
        }),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaSystemConfigProfile,
        profile_file.odata_id(),
        profile_file.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPowerComplianceManager` chain-root
/// document into the power-compliance family.
fn nvidia_power_compliance_manager_projection(
    compliance: &NvidiaPowerComplianceManagerSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPowerComplianceManagerPayload {
        resource: nvidia_common_resource(&compliance.base),
        document_type: NvidiaPowerComplianceDocument::PowerComplianceManager,
        manager_type: compliance.manager_type.as_ref().copied(),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        compliance.odata_id(),
        compliance.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPowerDomain` member into the
/// power-compliance family.
fn nvidia_power_domain_projection(
    domain: &NvidiaPowerDomainSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPowerDomainPayload {
        resource: nvidia_common_resource(&domain.base),
        document_type: NvidiaPowerComplianceDocument::PowerDomain,
        value: Some(domain.value),
        r#type: Some(domain.r#type),
        unit: Some(domain.unit),
        sensor_reading_type: Some(domain.sensor_reading_type),
        sensor_impl: Some(domain.sensor_impl),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        domain.odata_id(),
        domain.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPowerPolicy` document (the `ACLossPolicy`
/// or `PSUCompliancePolicy` singleton) into the power-compliance family.
fn nvidia_power_policy_projection(
    policy: &NvidiaPowerPolicySchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPowerPolicyPayload {
        resource: nvidia_common_resource(&policy.base),
        document_type: NvidiaPowerComplianceDocument::PowerPolicy,
        auto_deassert_power_brake: Some(policy.auto_deassert_power_brake),
        min: Some(policy.min),
        max: Some(policy.max),
        r#type: policy.r#type,
        unit: Some(policy.unit),
        policy_actions: policy.policy_actions,
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        policy.odata_id(),
        policy.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaManagedEntityGroup` member into the
/// power-compliance family.
fn nvidia_managed_entity_group_projection(
    group: &NvidiaManagedEntityGroupSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaManagedEntityGroupPayload {
        resource: nvidia_common_resource(&group.base),
        document_type: NvidiaPowerComplianceDocument::ManagedEntityGroup,
        current_managed_entity_id: Some(group.current_managed_entity_id.clone()),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        group.odata_id(),
        group.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPowerStateGroup` document into the
/// power-compliance family.
fn nvidia_power_state_group_projection(
    group: &NvidiaPowerStateGroupSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPowerStateGroupPayload {
        resource: nvidia_common_resource(&group.base),
        document_type: NvidiaPowerComplianceDocument::PowerStateGroup,
        psc_id: Some(group.psc_id.clone()),
        generated_watts: Some(group.generated_watts),
        number_of_pscs: group.number_of_pscs,
        number_of_local_psus: Some(group.number_of_local_psus),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        group.odata_id(),
        group.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPscState` member into the
/// power-compliance family.
fn nvidia_psc_state_projection(
    state: &NvidiaPscStateSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPscStatePayload {
        resource: nvidia_common_resource(&state.base),
        document_type: NvidiaPowerComplianceDocument::PscState,
        psc_id: Some(state.psc_id.clone()),
        num_of_operational_psus: state.num_of_operational_psus,
        power_brake_assert: state.power_brake_assert,
        milliseconds_since_last_heartbeat: state.milliseconds_since_last_heartbeat,
        status: state.status,
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        state.odata_id(),
        state.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPsuState` member into the
/// power-compliance family.
fn nvidia_psu_state_projection(
    state: &NvidiaPsuStateSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPsuStatePayload {
        resource: nvidia_common_resource(&state.base),
        document_type: NvidiaPowerComplianceDocument::PsuState,
        psu_id: Some(state.psu_id.clone()),
        presence: Some(state.presence),
        input1active: Some(state.input1active),
        input2active: Some(state.input2active),
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        state.odata_id(),
        state.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaPsuRedundancy` document into the
/// power-compliance family.
fn nvidia_psu_redundancy_projection(
    redundancy: &NvidiaPsuRedundancySchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaPsuRedundancyPayload {
        resource: nvidia_common_resource(&redundancy.base),
        document_type: NvidiaPowerComplianceDocument::PsuRedundancy,
        max_num_supported: redundancy.max_num_supported.clone(),
        min_num_needed: redundancy.min_num_needed.clone(),
        redundancy_setting: redundancy.redundancy_setting,
    };
    build_core_projection(
        ResourceFeature::OemNvidiaPowerCompliance,
        redundancy.odata_id(),
        redundancy.etag(),
        &payload,
    )
}

/// Projects one typed NVIDIA `NvidiaManagedEntity` member into the
/// managed-entity family.
fn nvidia_managed_entity_projection(
    entity: &NvidiaManagedEntitySchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NvidiaManagedEntityPayload {
        resource: nvidia_common_resource(&entity.base),
        document_type: NvidiaManagedEntityDocument::ManagedEntity,
        transport_protocol: entity.transport_protocol.as_ref().copied(),
        ipv4_address: entity
            .ipv4address
            .as_ref()
            .and_then(|address| address.address.as_ref().and_then(Option::as_deref))
            .map(str::to_owned),
        ipv6_address: entity
            .ipv6address
            .as_ref()
            .and_then(|address| address.address.as_ref().and_then(Option::as_deref))
            .map(str::to_owned),
        port: entity.port,
    };
    build_core_projection(
        ResourceFeature::OemNvidiaManagedEntity,
        entity.odata_id(),
        entity.etag(),
        &payload,
    )
}

/// Copies the common identity fields from one compiled NVIDIA schema base.
///
/// The NVIDIA OEM feature generates its own `resource::Resource` base type (a
/// separate module tree from the base schema re-export, exactly like the Dell
/// feature), so the common fields are copied here with the same shape
/// `CommonResourcePayload::from_schema_base` projects instead of converting
/// between the two nominally distinct resource types.
fn nvidia_common_resource(base: &NvidiaResourceSchema) -> CommonResourcePayload {
    CommonResourcePayload {
        id: base.id.clone(),
        name: base.name.clone(),
        description: base.description.as_ref().and_then(Option::as_ref).cloned(),
    }
}

/// Copies the common identity fields from one compiled Lenovo schema base.
///
/// The Lenovo OEM feature generates its own `resource::Resource` base type (a
/// separate module tree from the base schema re-export, exactly like the Dell
/// and NVIDIA features), so the common fields are copied here with the same
/// shape `CommonResourcePayload::from_schema_base` projects instead of
/// converting between the two nominally distinct resource types.
fn lenovo_common_resource(base: &LenovoResourceSchema) -> CommonResourcePayload {
    CommonResourcePayload {
        id: base.id.clone(),
        name: base.name.clone(),
        description: base.description.as_ref().and_then(Option::as_ref).cloned(),
    }
}

/// Reads one Dell Attributes entry as its typed string value.
///
/// Mirrors the upstream `DellAttributeRef::str_value` semantics: an absent
/// entry, an explicitly null entry, or an entry of another `Edm.PrimitiveType`
/// (boolean, integer, decimal) projects as `None` instead of failing the
/// projection — the typed surface decides what a key is worth, the product
/// never re-interprets a vendor string.
fn dell_attribute_string(attributes: &DellAttributesSchema, name: &str) -> Option<String> {
    attributes
        .attributes
        .as_ref()
        .and_then(|bag| bag.dynamic_properties.get(name))
        .and_then(Option::as_ref)
        .and_then(|value| match value {
            EdmPrimitiveType::String(text) => Some(text.clone()),
            _ => None,
        })
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
        metric_values: report.metric_values.as_ref().map(|values| {
            values
                .iter()
                .map(|value| MetricValuePayload {
                    timestamp: value.timestamp.flatten(),
                    metric_value: optional_nullable_text(value.metric_value.as_ref()),
                })
                .collect()
        }),
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

fn power_equipment_projection(
    equipment: &PowerEquipmentSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = PowerEquipmentPayload {
        resource: CommonResourcePayload::from_schema_base(&equipment.base),
        status: equipment
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::PowerEquipment,
        equipment.odata_id(),
        equipment.etag(),
        &payload,
    )
}

fn power_distribution_projection(
    distribution: &PowerDistributionSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = PowerDistributionPayload {
        resource: CommonResourcePayload::from_schema_base(&distribution.base),
        equipment_type: distribution.equipment_type,
        manufacturer: optional_nullable_text(distribution.manufacturer.as_ref()),
        model: optional_nullable_text(distribution.model.as_ref()),
        part_number: optional_nullable_text(distribution.part_number.as_ref()),
        serial_number: optional_nullable_text(distribution.serial_number.as_ref()),
        version: optional_nullable_text(distribution.version.as_ref()),
        firmware_version: distribution.firmware_version.clone(),
        status: distribution
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::PowerEquipment,
        distribution.odata_id(),
        distribution.etag(),
        &payload,
    )
}

fn power_supply_projection(
    supply: &PowerSupplySchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = PowerSupplyPayload {
        resource: CommonResourcePayload::from_schema_base(&supply.base),
        power_supply_type: supply.power_supply_type.as_ref().copied().flatten(),
        power_capacity_watts: supply.power_capacity_watts.as_ref().copied().flatten(),
        manufacturer: optional_nullable_text(supply.manufacturer.as_ref()),
        model: optional_nullable_text(supply.model.as_ref()),
        firmware_version: optional_nullable_text(supply.firmware_version.as_ref()),
        serial_number: optional_nullable_text(supply.serial_number.as_ref()),
        part_number: optional_nullable_text(supply.part_number.as_ref()),
        status: supply
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::PowerSupplies,
        supply.odata_id(),
        supply.etag(),
        &payload,
    )
}

fn network_device_function_projection(
    function: &NetworkDeviceFunctionSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = NetworkDeviceFunctionPayload {
        resource: CommonResourcePayload::from_schema_base(&function.base),
        net_dev_func_type: function.net_dev_func_type.as_ref().copied().flatten(),
        device_enabled: function.device_enabled.as_ref().copied().flatten(),
        status: function
            .status
            .as_ref()
            .map(ResourceStatusPayload::from_status),
    };
    build_core_projection(
        ResourceFeature::NetworkDeviceFunctions,
        function.odata_id(),
        function.etag(),
        &payload,
    )
}

fn environment_metrics_projection(
    metrics: &EnvironmentMetricsSchema,
) -> Result<CoreResourceProjection, CoreResourceReadError> {
    let payload = EnvironmentMetricsPayload {
        resource: CommonResourcePayload::from_schema_base(&metrics.base),
        temperature_celsius: metrics.temperature_celsius.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        humidity_percent: metrics.humidity_percent.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        fan_speeds_percent: metrics.fan_speeds_percent.as_ref().map(|excerpts| {
            excerpts
                .iter()
                .map(|excerpt| {
                    environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
                })
                .collect::<Vec<_>>()
        }),
        power_watts: metrics.power_watts.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        energyk_wh: metrics.energyk_wh.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        power_load_percent: metrics.power_load_percent.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        power_limit_watts: metrics.power_limit_watts.as_ref().map(|excerpt| {
            EnvironmentMetricsControlPayload {
                data_source_uri: optional_nullable_text(excerpt.data_source_uri.as_ref()),
                set_point: excerpt.set_point.as_ref().copied().flatten(),
            }
        }),
        dew_point_celsius: metrics.dew_point_celsius.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        absolute_humidity: metrics.absolute_humidity.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        energy_joules: metrics.energy_joules.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        ambient_temperature_celsius: metrics.ambient_temperature_celsius.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        voltage: metrics.voltage.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
        current_amps: metrics.current_amps.as_ref().map(|excerpt| {
            environment_reading(excerpt.data_source_uri.as_ref(), excerpt.reading.as_ref())
        }),
    };
    build_core_projection(
        ResourceFeature::EnvironmentMetrics,
        metrics.odata_id(),
        metrics.etag(),
        &payload,
    )
}

/// Projects one embedded sensor excerpt of the `EnvironmentMetrics` document
/// onto its reading shape.
///
/// Every excerpt type of the compiled schema (`SensorExcerpt`,
/// `SensorExcerptFanArray`, `SensorExcerptPower`, `SensorExcerptEnergykWh`,
/// `SensorExcerptVoltage`, `SensorExcerptCurrent`) carries the same
/// `DataSourceUri` and `Reading` fields, so one field-level function covers
/// the whole family without coupling the call sites to a shared trait.
fn environment_reading(
    data_source_uri: Option<&Option<String>>,
    reading: Option<&Option<f64>>,
) -> EnvironmentMetricsReadingPayload {
    EnvironmentMetricsReadingPayload {
        data_source_uri: optional_nullable_text(data_source_uri),
        reading: reading.copied().flatten(),
    }
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

/// A live SSE stream of one endpoint's Redfish events (§14.4).
///
/// Consumed through [`Self::next`], which returns one [`EndpointEvent`] per
/// Redfish `EventRecord` until the stream reaches its terminal state: the
/// upstream closed, a fatal error was delivered, or the `cancel` token given
/// to [`RedfishGateway::open_event_stream`] fired. The terminal phase then
/// deletes the transient Session the stream owns — never before, so the
/// session lives exactly as long as the stream (§7.8: long-lived connections
/// have a shutdown signal).
///
/// Dropping the stream without reaching a terminal state closes the SSE
/// connection but abandons the Session until the BMC expires it;
/// [`Self::shutdown`] is the structured drain path (§7.8: no untraceable
/// detached cleanup tasks).
///
/// The stream is consumed through the inherent `next`/`shutdown` methods
/// rather than a `Stream` impl, because the terminal phase performs an
/// asynchronous Session deletion that cannot run inside `poll_next`.
pub struct EventStream {
    endpoint_id: EndpointId,
    upstream: Option<BoxTryStream<EventStreamPayload, UpstreamServiceRootError>>,
    cancel: CancellationToken,
    /// The Session deleted in the terminal phase; `None` once the stream
    /// closed or the Session was moved into cleanup.
    session: Option<Session<UpstreamBmc>>,
    identity: IdentityMonitor,
    trust: TlsTrust,
    bmc: Arc<UpstreamBmc>,
    pending: VecDeque<EndpointEvent>,
    /// The single terminal error item still to be delivered.
    terminal: Option<EventStreamError>,
    /// The terminal phase already ran; nothing more will be delivered.
    finished: bool,
}

/// The outcome of one poll of the upstream SSE stream.
///
/// The item is boxed so the enum stays small: `Cancelled` is a zero-size
/// variant and the payload error type is large.
enum EventStreamPoll {
    /// The cancellation token fired before the upstream produced an item.
    Cancelled,
    /// The upstream produced one item (`Ok(Some(..))`), ended (`Ok(None)`),
    /// or failed.
    Item(Box<Result<Option<EventStreamPayload>, UpstreamServiceRootError>>),
}

impl EventStream {
    fn new(
        endpoint_id: EndpointId,
        upstream: BoxTryStream<EventStreamPayload, UpstreamServiceRootError>,
        cancel: CancellationToken,
        session: Option<Session<UpstreamBmc>>,
        bmc: Arc<UpstreamBmc>,
        identity: IdentityMonitor,
        trust: TlsTrust,
    ) -> Self {
        Self {
            endpoint_id,
            upstream: Some(upstream),
            cancel,
            session,
            identity,
            trust,
            bmc,
            pending: VecDeque::new(),
            terminal: None,
            finished: false,
        }
    }

    /// Returns the endpoint identity every delivered event is bound to.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Consumes the next endpoint event from the SSE stream.
    ///
    /// Returns `Some(Ok(..))` for each delivered event, then — once — the
    /// terminal error if the stream ended in failure or its Session could
    /// not be deleted, and finally `None` when nothing more will be
    /// delivered. After `cancel` fires, the next call returns the terminal
    /// state promptly: mapped events not yet delivered are discarded, the
    /// SSE connection is closed, and the Session is deleted.
    pub async fn next(&mut self) -> Option<Result<EndpointEvent, EventStreamError>> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Some(Ok(event));
            }
            if let Some(terminal) = self.terminal.take() {
                return Some(Err(terminal));
            }
            if self.finished {
                return None;
            }
            let Some(upstream) = self.upstream.as_mut() else {
                // The terminal phase already consumed the upstream; nothing
                // more can be delivered.
                return None;
            };
            let item = tokio::select! {
                () = self.cancel.cancelled() => EventStreamPoll::Cancelled,
                item = upstream.try_next() => EventStreamPoll::Item(Box::new(item)),
            };
            match item {
                EventStreamPoll::Cancelled => {
                    self.finish(None).await;
                }
                EventStreamPoll::Item(item) => match *item {
                    Ok(Some(EventStreamPayload::Event(event))) => {
                        for record in &event.events {
                            // A bare `@odata.id` reference carries no
                            // payload; only inline records are mappable
                            // events.
                            if !matches!(record, NavProperty::Expanded(_)) {
                                continue;
                            }
                            // `get` on an already-expanded property is a
                            // zero-copy Arc return, never a fetch.
                            let Ok(record) = record.get(self.bmc.as_ref()).await else {
                                continue;
                            };
                            let observed_at = OffsetDateTime::now_utc();
                            if let Some(event) =
                                map_event_record(record.as_ref(), self.endpoint_id, observed_at)
                            {
                                self.pending
                                    .push_back(EndpointEvent::new(self.endpoint_id, event));
                            }
                        }
                    }
                    Ok(Some(EventStreamPayload::MetricReport(_))) => {
                        // A telemetry payload is not an event: the boundary
                        // record models BMC events only, and §14.4 keeps
                        // Telemetry a separate surface. Skipping keeps the
                        // stream alive.
                    }
                    Ok(None) => {
                        self.finish(None).await;
                    }
                    Err(source) if is_skippable_event_stream_item(&source) => {
                        // One malformed event must not kill the stream; the
                        // vendor's next record may decode cleanly.
                    }
                    Err(source) => {
                        self.finish(Some(classify_event_stream_error(source))).await;
                    }
                },
            }
        }
    }

    /// Cancels the stream and drains it to its terminal state, deleting the
    /// transient Session. Safe to call multiple times and after the stream
    /// already ended.
    pub async fn shutdown(&mut self) {
        self.cancel.cancel();
        while self.next().await.is_some() {}
    }

    /// Runs the terminal phase exactly once: closes the SSE connection,
    /// deletes the Session, and records the one terminal item to deliver.
    ///
    /// The cleanup classification mirrors `cleanup_session`: a failed
    /// deletion surfaces as its own error item instead of masking the
    /// stream's termination reason, or combined with it when both failed.
    async fn finish(&mut self, failure: Option<EventStreamError>) {
        if self.finished {
            return;
        }
        self.finished = true;
        // Drop the SSE connection before the Session DELETE so the BMC
        // stops streaming into a connection the stream is abandoning.
        self.upstream.take();
        let cleanup = cleanup_session(self.session.take(), &self.identity, &self.trust).await;
        self.terminal = match (failure, cleanup) {
            (None, Ok(())) => None,
            (None, Err(cleanup)) => Some(EventStreamError::SessionCleanup(cleanup)),
            (Some(failure), Ok(())) => Some(failure),
            (Some(failure), Err(cleanup)) => {
                Some(EventStreamError::StreamAndSessionCleanupFailed {
                    stream: Box::new(failure),
                    cleanup: Box::new(EventStreamError::SessionCleanup(cleanup)),
                })
            }
        };
    }
}

/// Why opening an endpoint's `EventService` SSE stream failed.
#[derive(Debug, Error)]
pub enum EventStreamOpenError {
    /// The endpoint does not advertise the Redfish `EventService` at all
    /// (§14.4 使用 `EventService` 公开能力): there is nothing to stream.
    #[error("the endpoint does not advertise the Redfish EventService")]
    EventServiceNotAdvertised,
    /// The endpoint's `EventService` exists but exposes no
    /// `ServerSentEventUri`: SSE is not available on this endpoint.
    #[error("the endpoint's EventService does not expose an SSE stream URI")]
    ServerSentEventsUnavailable,
    /// Session establishment, TLS identity, or trust-bound transport
    /// failed; the persisted trust decision must be re-evaluated before
    /// retrying.
    #[error("the event stream could not be set up with the current trust decision: {0}")]
    TrustOrSession(#[source] RedfishServiceRootError),
    /// The SSE request failed transiently (network, 5xx, or an invalidated
    /// Session token); reopening with the same inputs may succeed.
    #[error("the SSE stream could not be opened but may succeed when retried: {0}")]
    Reconnectable(#[source] RedfishServiceRootError),
    /// The SSE request failed and cannot succeed with the same inputs
    /// (permission, schema incompatibility, TLS rejection).
    #[error("the SSE stream cannot be opened: {0}")]
    Terminal(#[source] RedfishServiceRootError),
    #[error(
        "the SSE stream could not be opened and the transient Session cleanup also failed; open: {open}; cleanup: {cleanup}"
    )]
    OpenAndSessionCleanupFailed {
        open: Box<EventStreamOpenError>,
        #[source]
        cleanup: Box<RedfishServiceRootError>,
    },
}

/// A failure of a live [`EventStream`].
#[derive(Debug, Error)]
pub enum EventStreamError {
    /// The stream failed transiently; re-establishing the Session and
    /// reopening the stream may succeed (network drop, 5xx, invalidated
    /// Session token, SSE framing decode failure).
    #[error("the SSE stream failed transiently and can be reopened: {0}")]
    Reconnectable(#[source] RedfishServiceRootError),
    /// The stream terminated and cannot be resumed with the same trust
    /// decision or endpoint configuration (permission, schema
    /// incompatibility, oversized event budget).
    #[error("the SSE stream terminated and cannot be reopened: {0}")]
    Terminal(#[source] RedfishServiceRootError),
    /// The stream ended but its transient Session could not be deleted; the
    /// token lingers until the BMC expires it.
    #[error("the transient Session could not be deleted after the event stream closed: {0}")]
    SessionCleanup(#[source] RedfishServiceRootError),
    #[error(
        "the SSE stream failed and the transient Session cleanup also failed; stream: {stream}; cleanup: {cleanup}"
    )]
    StreamAndSessionCleanupFailed {
        stream: Box<EventStreamError>,
        #[source]
        cleanup: Box<EventStreamError>,
    },
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

/// The observed states of the §2.1 OEM capabilities, one field per variant
/// in [`rutilus_domain::OEM_CAPABILITY_LEDGER_ORDER`] order.
///
/// The states are decided at the vendor-namespace granularity (§11.3
/// advertised layer): a capability is `Supported` when the already-decoded
/// resources expose its vendor namespace, and `NotAdvertised` otherwise.
/// Sub-features that compile inside a parent namespace (`oem-dell-attributes`,
/// `oem-nvidia-*`) inherit the namespace state, because their sub-surfaces
/// (the `Attributes` resource, CPER records, fabric data, and so on) are only
/// distinguishable when the read slice actually reads the OEM resource.
struct OemNamespaceProbe {
    ami: CapabilityState,
    dell: CapabilityState,
    dell_attributes: CapabilityState,
    delta: CapabilityState,
    hpe: CapabilityState,
    lenovo: CapabilityState,
    liteon: CapabilityState,
    nvidia: CapabilityState,
    nvidia_cper: CapabilityState,
    nvidia_fabrics: CapabilityState,
    nvidia_power_management: CapabilityState,
    nvidia_profiles: CapabilityState,
    nvidia_security: CapabilityState,
    supermicro: CapabilityState,
}

/// The chassis `Manufacturer` hardware-id value that advertises `LiteOn` OEM
/// extensions.
///
/// `LiteOn` is the one compiled vendor whose surface `nv-redfish` 0.13 keys
/// by manufacturer instead of an `Oem` namespace
/// (`oem/liteon/power_supply.rs` gates on exactly this value), so the probe
/// mirrors that exact gate instead of inventing a namespace key the vendor
/// does not use.
const LITEON_CHASSIS_MANUFACTURER: &str = "LITE-ON TECHNOLOGY CORP.";

/// Every probed state grouped by origin, so the §2.1 observation vector can
/// be assembled exhaustively without a 44-field hand-written tuple.
struct CapabilityObservations {
    session: CapabilityState,
    systems: CapabilityState,
    chassis: CapabilityState,
    managers: CapabilityState,
    root: RootServiceProbe,
    systems_features: SystemFeatureProbe,
    chassis_features: ChassisFeatureProbe,
    manager_features: ManagerFeatureProbe,
    oem: OemNamespaceProbe,
}

/// Returns the vendor namespace keys present in one decoded resource's `Oem`
/// segment.
///
/// The `Oem` segment always preserves its keys as additional properties (the
/// vendor schemas are decoded separately), so this is a pure presence read
/// over data the capability probe already fetched: it never issues a request
/// and cannot fail, which is why the §11.3 advertised layer is decided
/// without error classification.
fn oem_namespace_keys(resource: &ResourceSchema) -> Vec<&str> {
    resource
        .base
        .oem
        .as_ref()
        .and_then(|oem| oem.additional_properties.as_object())
        .map(|namespaces| namespaces.keys().map(String::as_str).collect())
        .unwrap_or_default()
}

/// Collects the `Oem` namespace keys of every decoded member of one
/// collection into the probe set.
///
/// Members that could not be fetched are absent from the set; they neither
/// advertise nor deny a namespace, because their documents were never
/// decoded. The root resource always contributes its own `Oem` segment, so
/// the probe basis is never empty.
fn collect_member_oem_namespaces<'a, M>(
    namespaces: &mut BTreeSet<&'a str>,
    collection: &'a ProbedCollection<M>,
) where
    M: NvResource,
{
    if let Some(members) = &collection.members {
        for member in members {
            namespaces.extend(oem_namespace_keys(NvResource::resource_ref(member)));
        }
    }
}

/// Probes the §2.1 OEM capabilities through the vendor namespaces already
/// decoded by the capability probe.
///
/// Advertisement is an endpoint-level property, so one decoded resource that
/// carries the vendor namespace decides the capability. The vendor namespace
/// keys mirror the exact keys `nv-redfish` 0.13 reads (`Ami`, `Dell`,
/// `deltaenergysystems`, `Hpe`, `Lenovo`, `Nvidia`, `Supermicro`); `LiteOn`
/// is decided by the chassis `Manufacturer` value instead (see
/// [`LITEON_CHASSIS_MANUFACTURER`]). Sub-features inherit their parent
/// namespace state because their surfaces cannot be told apart at the
/// namespace granularity — the read slice verifies them by reading the OEM
/// resource itself.
fn probe_oem_namespaces(
    root: &ServiceRoot<UpstreamBmc>,
    systems: &ProbedCollection<ComputerSystem<UpstreamBmc>>,
    chassis: &ProbedCollection<Chassis<UpstreamBmc>>,
    managers: &ProbedCollection<Manager<UpstreamBmc>>,
) -> OemNamespaceProbe {
    let mut namespaces = BTreeSet::new();
    namespaces.extend(oem_namespace_keys(NvResource::resource_ref(root)));
    collect_member_oem_namespaces(&mut namespaces, systems);
    collect_member_oem_namespaces(&mut namespaces, chassis);
    collect_member_oem_namespaces(&mut namespaces, managers);
    let liteon_advertised = chassis.members.as_deref().is_some_and(|members| {
        members.iter().any(|member| {
            member.hardware_id().manufacturer
                == Some(ChassisManufacturer::new(LITEON_CHASSIS_MANUFACTURER))
        })
    });
    let namespace_state = |key: &str| {
        if namespaces.contains(key) {
            CapabilityState::Supported
        } else {
            CapabilityState::NotAdvertised
        }
    };
    OemNamespaceProbe {
        ami: namespace_state("Ami"),
        dell: namespace_state("Dell"),
        dell_attributes: namespace_state("Dell"),
        delta: namespace_state("deltaenergysystems"),
        hpe: namespace_state("Hpe"),
        lenovo: namespace_state("Lenovo"),
        liteon: {
            if liteon_advertised {
                CapabilityState::Supported
            } else {
                CapabilityState::NotAdvertised
            }
        },
        nvidia: namespace_state("Nvidia"),
        nvidia_cper: namespace_state("Nvidia"),
        nvidia_fabrics: namespace_state("Nvidia"),
        nvidia_power_management: namespace_state("Nvidia"),
        nvidia_profiles: namespace_state("Nvidia"),
        nvidia_security: namespace_state("Nvidia"),
        supermicro: namespace_state("Supermicro"),
    }
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

/// Assembles the §2.1 inventory in design-document order: the 30 standard
/// capabilities first, then the 14 OEM capabilities in
/// `COMPILED_OEM_FEATURES` order.
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
        oem,
    } = states;
    let mut observations = vec![
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
    ];
    observations.extend(oem_observations(&oem));
    observations
}

/// Assembles the 14 OEM observations in [`rutilus_domain::OEM_CAPABILITY_LEDGER_ORDER`]
/// order, mirroring the `COMPILED_OEM_FEATURES` feature order.
///
/// Kept separate from [`build_observations`] so the standard section stays
/// readable at its full 30-entry length; every field of
/// [`OemNamespaceProbe`] maps to exactly one entry, so a future OEM
/// capability cannot silently drop out of discovery.
fn oem_observations(oem: &OemNamespaceProbe) -> Vec<EndpointCapabilityObservation> {
    vec![
        EndpointCapabilityObservation::new(EndpointCapability::OemAmi, oem.ami),
        EndpointCapabilityObservation::new(EndpointCapability::OemDell, oem.dell),
        EndpointCapabilityObservation::new(
            EndpointCapability::OemDellAttributes,
            oem.dell_attributes,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::OemDelta, oem.delta),
        EndpointCapabilityObservation::new(EndpointCapability::OemHpe, oem.hpe),
        EndpointCapabilityObservation::new(EndpointCapability::OemLenovo, oem.lenovo),
        EndpointCapabilityObservation::new(EndpointCapability::OemLiteOn, oem.liteon),
        EndpointCapabilityObservation::new(EndpointCapability::OemNvidia, oem.nvidia),
        EndpointCapabilityObservation::new(EndpointCapability::OemNvidiaCper, oem.nvidia_cper),
        EndpointCapabilityObservation::new(
            EndpointCapability::OemNvidiaFabrics,
            oem.nvidia_fabrics,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::OemNvidiaPowerManagement,
            oem.nvidia_power_management,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::OemNvidiaProfiles,
            oem.nvidia_profiles,
        ),
        EndpointCapabilityObservation::new(
            EndpointCapability::OemNvidiaSecurity,
            oem.nvidia_security,
        ),
        EndpointCapabilityObservation::new(EndpointCapability::OemSupermicro, oem.supermicro),
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
        // A URI reference the transport refused before the request was sent
        // (cross-origin or malformed — the §15.6 same-origin policy): the
        // write was provably never dispatched, so this is a rejection —
        // `InvalidCommandPayload` because a payload value could not be
        // represented safely on the wire — never an outcome-unknown failure
        // (§13.5). The upload paths are the only writers that resolve
        // service-provided URI references, so only they can produce this
        // error.
        nv_redfish::Error::Bmc(BmcError::InvalidRequest(_)) => {
            CommandExecutionError::Rejected(CommandRejection::InvalidCommandPayload)
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

/// Maps the domain `TokenType` projection onto the compiled CSDL member set.
///
/// The domain member set is pinned to the CSDL by const tests, so this match
/// cannot drift silently.
fn map_token_type(value: TokenType) -> NvidiaTokenTypeSchema {
    use NvidiaTokenTypeSchema as NvTokenType;
    match value {
        TokenType::Frc => NvTokenType::Frc,
        TokenType::Crcs => NvTokenType::Crcs,
        TokenType::Crdt => NvTokenType::Crdt,
        TokenType::DebugFirmwareRunning => NvTokenType::DebugFirmwareRunning,
        TokenType::DebugFirmwareUnlock => NvTokenType::DebugFirmwareUnlock,
        TokenType::OtpDumpEnable => NvTokenType::OtpDumpEnable,
        TokenType::JtagUnlock => NvTokenType::JtagUnlock,
        TokenType::HardwareUnlock => NvTokenType::HardwareUnlock,
        TokenType::RuntimeDebugUnlock => NvTokenType::RuntimeDebugUnlock,
        TokenType::FeatureUnlock => NvTokenType::FeatureUnlock,
        TokenType::Mtdt => NvTokenType::Mtdt,
        TokenType::CcplexArmJtagDebugCont => NvTokenType::CcplexArmJtagDebugCont,
        TokenType::NvJtagControl => NvTokenType::NvJtagControl,
        TokenType::DiagnosticBoot => NvTokenType::DiagnosticBoot,
        TokenType::BpmpFirmwareDebugFs => NvTokenType::BpmpFirmwareDebugFs,
        TokenType::FirmwareDebugKnobs => NvTokenType::FirmwareDebugKnobs,
        TokenType::FirewallLifting => NvTokenType::FirewallLifting,
        TokenType::Verbosity => NvTokenType::Verbosity,
        TokenType::SmaDebugCapability => NvTokenType::SmaDebugCapability,
        TokenType::CpldDebugCapability => NvTokenType::CpldDebugCapability,
    }
}

/// Maps the domain `EraseType` projection onto the compiled CSDL member set.
fn map_erase_type(value: EraseType) -> NvidiaEraseTypeSchema {
    use NvidiaEraseTypeSchema as NvEraseType;
    match value {
        EraseType::EraseAll => NvEraseType::EraseAll,
        EraseType::EraseAllAndRatchetCounterIncreased => {
            NvEraseType::EraseAllAndRatchetCounterIncreased
        }
        EraseType::TokenType => NvEraseType::TokenType,
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
    use rutilus_domain::{
        EraseToken, ProfileFile, ProfileId, StartUpdate, TlsCertificate, TlsTrust, TokenData,
        UpdateCommand,
    };
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
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

    /// A Manager member whose `Oem.Dell` segment advertises the Dell
    /// Attributes surface, so the OEM read probes the crafted Dell Attributes
    /// URL (the field shape follows what nv-redfish's own manager-attributes
    /// constructor checks: the `Dell` key under `Oem`).
    const MANAGER_WITH_DELL_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Dell":{}}
    }"#;

    /// A Manager member whose `Oem` segment belongs to another vendor: the
    /// upstream constructor keys on the literal `Dell` name, so a Contoso
    /// segment must not trigger a Dell probe.
    const MANAGER_WITH_OTHER_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Contoso":{"Anything":true}}
    }"#;

    /// The typed Dell `DellAttributes` document served at the crafted
    /// `{manager}/Oem/Dell/DellAttributes/{id}` URL. The `Attributes` bag
    /// carries the identity keys the product pins plus one unprojected key,
    /// so the strict payload contract is exercised both ways.
    const DELL_ATTRIBUTES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1",
        "@odata.etag":"W/\"dell-attributes-1\"",
        "Id":"1",
        "Name":"Dell Attributes",
        "Description":"Dell iDRAC attributes",
        "Attributes":{
            "ServerModel":"PowerEdge R750",
            "ServerServiceTag":"ABC1234",
            "ServerGeneration":"16G",
            "ServerBmcMacAddress":"14:18:77:aa:bb:cc",
            "ServerName":"rack-1-server-2",
            "BiosVersion":"2.14.2"
        }
    }"#;

    /// A Manager member whose `Oem.Supermicro` segment embeds the two
    /// navigation references the Supermicro read follows: `SysLockdown` and
    /// `KCSInterface`, each carrying the `@odata.id` the compiled
    /// `smc_manager_extensions` schema resolves through `NavProperty` — the
    /// same embedded-reference shape nv-redfish's own Supermicro manager
    /// constructor decodes (reference form, so each leaf is fetched by its
    /// `@odata.id`).
    const MANAGER_WITH_SUPERMICRO_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Supermicro":{
            "SysLockdown":{"@odata.id":"/redfish/v1/Managers/1/SysLockdown"},
            "KCSInterface":{"@odata.id":"/redfish/v1/Managers/1/KCSInterface"}
        }}
    }"#;

    /// A Manager member whose `Oem.Supermicro` segment cannot be decoded by
    /// the compiled `smc_manager_extensions` schema: the `SysLockdown` key
    /// carries a non-object value, so the segment is one odd manager surface
    /// and leaves the whole Supermicro family absent without a request.
    const MANAGER_WITH_UNDECODABLE_SUPERMICRO_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Supermicro":{"SysLockdown":5}}
    }"#;

    /// The typed Supermicro `SysLockdown` document served at the embedded
    /// `@odata.id`. The compiled schema models only `SysLockdownEnabled`
    /// beside the `@odata.id` / `@odata.etag`; it flattens a `resource::Item`
    /// base that carries no `Id` / `Name` / `Description` properties, so the
    /// fixture deliberately carries none (an unmodeled wire `Id` would be
    /// dropped by the typed decode either way, per §11.5's two-way rule).
    const SUPERMICRO_SYS_LOCKDOWN_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/SysLockdown",
        "@odata.etag":"W/\"sys-lockdown-1\"",
        "SysLockdownEnabled":true
    }"#;

    /// The typed Supermicro `KcsInterface` document served at the embedded
    /// `@odata.id`, carrying the vendor's enum spelling verbatim.
    const SUPERMICRO_KCS_INTERFACE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/KCSInterface",
        "@odata.etag":"W/\"kcs-interface-1\"",
        "Privilege":"Administrator"
    }"#;

    /// A Manager member whose `Oem.Nvidia` segment embeds the inline
    /// versioned `NvidiaManager` object: the segment carries its own
    /// `@odata.type` (the discrimination the gateway performs, matching the
    /// `NvidiaManager.v1_9_0` namespace) and the `PowerCompliance`
    /// navigation both the power-compliance and the managed-entity families
    /// follow.
    const MANAGER_WITH_NVIDIA_POWER_COMPLIANCE_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Nvidia":{
            "@odata.type":"#NvidiaManager.v1_9_0.NvidiaManager",
            "PowerCompliance":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"}
        }}
    }"##;

    /// A Manager member whose `Oem.Nvidia` segment has the reference shape
    /// (`{"@odata.id": ...}`), the `BlueField` partial-stub quirk: the
    /// segment body at the reference is fetched and decoded before the chain
    /// navigation can be followed.
    const MANAGER_WITH_NVIDIA_REFERENCE_FORM_SEGMENT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Nvidia":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia"}}
    }"#;

    /// The `NvidiaManager` document served at the reference-form segment's
    /// `@odata.id`, carrying the `PowerCompliance` navigation.
    const NVIDIA_MANAGER_SEGMENT_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia",
        "@odata.type":"#NvidiaManager.v1_9_0.NvidiaManager",
        "PowerCompliance":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"}
    }"##;

    /// A Manager member whose `Oem.Nvidia` segment cannot be discriminated or
    /// decoded (a non-object value): one odd manager surface, both NVIDIA
    /// power families stay absent and no chain request is fabricated.
    const MANAGER_WITH_UNDECODABLE_NVIDIA_SEGMENT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Nvidia":5}
    }"#;

    /// A Manager member whose `Oem.Lenovo` segment embeds the `Security`
    /// navigation reference the Lenovo read follows: the segment carries the
    /// boolean `KCSEnabled` shape (`v0_1_0`, what a real Lenovo XCC
    /// publishes) plus the `Security` navigation carrying the `@odata.id` the
    /// compiled untagged `LenovoManagerSchema` resolves through `NavProperty`
    /// — the same embedded-reference shape nv-redfish's own Lenovo manager
    /// constructor decodes (reference form, so the document is fetched by its
    /// `@odata.id`).
    const MANAGER_WITH_LENOVO_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Lenovo":{
            "KCSEnabled":true,
            "Security":{"@odata.id":"/redfish/v1/Managers/1/Oem/Lenovo/SecurityService"}
        }}
    }"#;

    /// A Manager member whose `Oem.Lenovo` segment carries the state-string
    /// `KCSEnabled` shape (`v1_0_0`): the untagged dual-version decode must
    /// fall back to the `v1_0_0` variant (the boolean `v0_1_0` shape cannot
    /// parse a string) and still resolve the same `Security` navigation from
    /// the shared unversioned `base`.
    const MANAGER_WITH_LENOVO_STRING_KCS_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Lenovo":{
            "KCSEnabled":"Enabled",
            "Security":{"@odata.id":"/redfish/v1/Managers/1/Oem/Lenovo/SecurityService"}
        }}
    }"#;

    /// A Manager member whose `Oem.Lenovo` segment cannot be decoded by the
    /// compiled untagged `LenovoManagerSchema`: the segment value is not an
    /// object, so the segment is one odd manager surface and leaves the whole
    /// Lenovo family absent without a request.
    const MANAGER_WITH_UNDECODABLE_LENOVO_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1",
        "@odata.etag":"W/\"manager-1\"",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Lenovo":5}
    }"#;

    /// The typed Lenovo `LenovoSecurityService` document served at the
    /// embedded `@odata.id`. The compiled schema models the `Configurator`
    /// segment with the `FWRollback` state; the fixture carries the vendor's
    /// enum spelling verbatim and the common identity fields the base
    /// `resource::Resource` requires.
    const LENOVO_SECURITY_SERVICE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Lenovo/SecurityService",
        "@odata.etag":"W/\"lenovo-security-1\"",
        "Id":"SecurityService",
        "Name":"Lenovo Security Service",
        "Description":"Lenovo security service",
        "Configurator":{"FWRollback":"Enabled"}
    }"#;

    /// The typed NVIDIA `NvidiaPowerComplianceManager` chain-root document,
    /// served at the segment's `PowerCompliance` navigation. Every
    /// sub-navigation of the power-compliance family is present, so the full
    /// chain is exercised in one fixture sequence.
    const NVIDIA_POWER_COMPLIANCE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance",
        "@odata.etag":"W/\"nvidia-pc-1\"",
        "Id":"PowerCompliance",
        "Name":"NVIDIA Power Compliance",
        "Description":"Power compliance manager",
        "ManagerType":"PowerManager",
        "PowerDomains":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains"},
        "ACLossPolicy":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy"},
        "PSUCompliancePolicy":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy"},
        "ManagedEntityGroups":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups"},
        "PowerStateGroup":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup"},
        "PSURedundancy":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy"}
    }"#;

    /// The typed NVIDIA `NvidiaPowerDomainCollection` with the single
    /// power-domain member.
    const NVIDIA_POWER_DOMAINS_COLLECTION_BODY: &str = r##"{
        "@odata.type":"#NvidiaPowerDomainCollection.NvidiaPowerDomainCollection",
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains",
        "Id":"PowerDomains",
        "Name":"Power Domain Collection",
        "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1"}]
    }"##;

    /// The typed NVIDIA `NvidiaPowerDomain` member with every compiled scalar
    /// field populated (the `PowerPolicies` navigation is required by the
    /// schema and stays in the fixture even though the strictly projectable
    /// field set never follows it).
    const NVIDIA_POWER_DOMAIN_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1",
        "@odata.etag":"W/\"nvidia-domain-1\"",
        "Id":"1",
        "Name":"Power Domain One",
        "Description":"Power comparison domain",
        "Value":800,
        "Type":"Above",
        "Unit":"Watts",
        "SensorReadingType":"Power",
        "SensorImpl":"PhysicalSensor",
        "PowerPolicies":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1/PowerPolicies"}
    }"#;

    /// The typed NVIDIA `NvidiaPowerPolicy` document served at the
    /// `ACLossPolicy` navigation, with every compiled scalar field
    /// populated.
    const NVIDIA_POWER_AC_LOSS_POLICY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy",
        "@odata.etag":"W/\"nvidia-acloss-1\"",
        "Id":"ACLossPolicy",
        "Name":"AC Loss Policy",
        "Description":"AC loss power policy",
        "AutoDeassertPowerBrake":true,
        "Min":200,
        "Max":600,
        "Type":"Inclusive",
        "Unit":"Watts",
        "DwellTime":"PT1S",
        "PolicyActions":"AssertPowerBrake"
    }"#;

    /// The typed NVIDIA `NvidiaPowerPolicy` document served at the
    /// `PSUCompliancePolicy` navigation.
    const NVIDIA_POWER_PSU_COMPLIANCE_POLICY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy",
        "@odata.etag":"W/\"nvidia-psupolicy-1\"",
        "Id":"PSUCompliancePolicy",
        "Name":"PSU Compliance Policy",
        "Description":"PSU compliance power policy",
        "AutoDeassertPowerBrake":false,
        "Min":100,
        "Max":500,
        "Type":"Below",
        "Unit":"Watts",
        "DwellTime":"PT2S",
        "PolicyActions":"DoNothing"
    }"#;

    /// The typed NVIDIA `NvidiaManagedEntityGroupCollection` with the single
    /// group member.
    const NVIDIA_MANAGED_ENTITY_GROUPS_COLLECTION_BODY: &str = r##"{
        "@odata.type":"#NvidiaManagedEntityGroupCollection.NvidiaManagedEntityGroupCollection",
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups",
        "Id":"ManagedEntityGroups",
        "Name":"Managed Entity Group Collection",
        "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1"}]
    }"##;

    /// The typed NVIDIA `NvidiaManagedEntityGroup` member with its
    /// `ManagedEntities` navigation into the managed-entity family.
    const NVIDIA_MANAGED_ENTITY_GROUP_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
        "@odata.etag":"W/\"nvidia-group-1\"",
        "Id":"1",
        "Name":"Managed Entity Group One",
        "Description":"BlueField group",
        "CurrentManagedEntityId":"BF1",
        "ManagedEntities":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities"}
    }"#;

    /// The typed NVIDIA `NvidiaManagedEntityCollection` with the single
    /// entity member.
    const NVIDIA_MANAGED_ENTITIES_COLLECTION_BODY: &str = r##"{
        "@odata.type":"#NvidiaManagedEntityCollection.NvidiaManagedEntityCollection",
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities",
        "Id":"ManagedEntities",
        "Name":"Managed Entity Collection",
        "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1"}]
    }"##;

    /// The typed NVIDIA `NvidiaManagedEntity` member with every compiled
    /// scalar field populated.
    const NVIDIA_MANAGED_ENTITY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
        "@odata.etag":"W/\"nvidia-entity-1\"",
        "Id":"1",
        "Name":"Managed Entity One",
        "Description":"BlueField managed entity",
        "TransportProtocol":"HTTPS",
        "IPv4Address":{"Address":"192.0.2.10","SubnetMask":"255.255.255.0","Gateway":"192.0.2.1"},
        "IPv6Address":{"Address":"2001:db8::10","PrefixLength":64},
        "Port":443
    }"#;

    /// The typed NVIDIA `NvidiaPowerStateGroup` document with every compiled
    /// scalar field populated and the two required state-collection
    /// navigations.
    const NVIDIA_POWER_STATE_GROUP_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup",
        "@odata.etag":"W/\"nvidia-state-group-1\"",
        "Id":"PowerStateGroup",
        "Name":"Power State Group",
        "Description":"Power shelf state",
        "PscId":"PSC1",
        "GeneratedWatts":2400,
        "NumberOfPscs":1,
        "NumberOfLocalPsus":2,
        "PowerShelfControllers":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers"},
        "PowerSupplies":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies"}
    }"#;

    /// The typed NVIDIA `NvidiaPscStateCollection` with the single PSC
    /// member.
    const NVIDIA_PSC_STATES_COLLECTION_BODY: &str = r##"{
        "@odata.type":"#NvidiaPscStateCollection.NvidiaPscStateCollection",
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers",
        "Id":"PowerShelfControllers",
        "Name":"Power Shelf Controller Collection",
        "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1"}]
    }"##;

    /// The typed NVIDIA `NvidiaPscState` member with every compiled scalar
    /// field populated.
    const NVIDIA_PSC_STATE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
        "@odata.etag":"W/\"nvidia-psc-1\"",
        "Id":"1",
        "Name":"Power Shelf Controller One",
        "Description":"PSC state",
        "PscId":"PSC1",
        "NumOfOperationalPsus":4,
        "PowerBrakeAssert":false,
        "MillisecondsSinceLastHeartbeat":12,
        "Status":"Operational"
    }"#;

    /// The typed NVIDIA `NvidiaPsuStateCollection` with the single PSU
    /// member.
    const NVIDIA_PSU_STATES_COLLECTION_BODY: &str = r##"{
        "@odata.type":"#NvidiaPsuStateCollection.NvidiaPsuStateCollection",
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies",
        "Id":"PowerSupplies",
        "Name":"Power Supply Collection",
        "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1"}]
    }"##;

    /// The typed NVIDIA `NvidiaPsuState` member with every compiled scalar
    /// field populated.
    const NVIDIA_PSU_STATE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
        "@odata.etag":"W/\"nvidia-psu-1\"",
        "Id":"1",
        "Name":"Power Supply One",
        "Description":"PSU state",
        "PsuId":"PSU1",
        "Presence":true,
        "Input1Active":true,
        "Input2Active":false
    }"#;

    /// The typed NVIDIA `NvidiaPsuRedundancy` document with every compiled
    /// scalar field populated.
    const NVIDIA_PSU_REDUNDANCY_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
        "@odata.etag":"W/\"nvidia-redundancy-1\"",
        "Id":"PSURedundancy",
        "Name":"PSU Redundancy",
        "Description":"PSU redundancy settings",
        "MaxNumSupported":"4",
        "MinNumNeeded":"2",
        "RedundancySetting":"NPlusOne"
    }"#;

    /// A System member whose `Oem.Nvidia` segment embeds the inline
    /// `NvidiaComputerSystem` object: the segment carries its own
    /// `@odata.type` (the discrimination the gateway performs) and the
    /// `SystemConfigProfile` navigation the system-config-profile family
    /// follows.
    const SYSTEM_WITH_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Oem":{"Nvidia":{
            "@odata.type":"#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem",
            "SystemConfigProfile":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"}
        }}
    }"##;

    /// A System member whose `Oem.Nvidia` segment has the reference shape
    /// (`{"@odata.id": ...}`), the `BlueField` DPU partial-stub quirk: the
    /// segment body at the reference is fetched and decoded before the chain
    /// navigation can be followed.
    const SYSTEM_WITH_NVIDIA_REFERENCE_FORM_SEGMENT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Oem":{"Nvidia":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia"}}
    }"#;

    /// The `NvidiaComputerSystem` document served at the reference-form
    /// segment's `@odata.id`, carrying the `SystemConfigProfile` navigation.
    const NVIDIA_COMPUTER_SYSTEM_SEGMENT_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia",
        "@odata.type":"#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem",
        "SystemConfigProfile":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"}
    }"##;

    /// A System member whose `Oem.Nvidia` segment is a Chassis-kind segment
    /// (here the plain `NvidiaChassis` shape): the discrimination must leave
    /// the whole system-config-profile family absent instead of decoding the
    /// segment into the `ComputerSystem` type (which would silently drop the
    /// chassis navigation, and there is no chain to follow anyway).
    const SYSTEM_WITH_CHASSIS_KIND_NVIDIA_SEGMENT_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Oem":{"Nvidia":{
            "@odata.type":"#NvidiaChassis.v1_14_0.NvidiaChassis"
        }}
    }"##;

    /// A System member whose `Oem.Nvidia` segment cannot be discriminated or
    /// decoded (a non-object value): one odd system surface, the family stays
    /// absent and no chain request is fabricated.
    const SYSTEM_WITH_UNDECODABLE_NVIDIA_SEGMENT_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "@odata.etag":"W/\"system-1\"",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Oem":{"Nvidia":5}
    }"#;

    /// The typed NVIDIA `SystemConfigProfile` chain-root document, served at
    /// the segment's `SystemConfigProfile` navigation. The `Truststore`
    /// section carries the two certificate-store links (whose documents the
    /// product never fetches) and the `Status` / `Profiles` navigations lead
    /// into the rest of the chain.
    const NVIDIA_SYSTEM_CONFIG_PROFILE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
        "@odata.etag":"W/\"nvidia-scp-1\"",
        "Id":"SystemConfigProfile",
        "Name":"NVIDIA System Config Profile",
        "Description":"Profile service",
        "Truststore":{
            "NvidiaCertificates":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Truststore/NvidiaCertificates"},
            "OemCertificates":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Truststore/OemCertificates"}
        },
        "Status":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"},
        "Profiles":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles"}
    }"#;

    /// The typed NVIDIA `SystemConfigProfileStatus` document with every
    /// compiled status field populated.
    const NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
        "@odata.etag":"W/\"nvidia-scp-status-1\"",
        "Id":"Status",
        "Name":"System Config Profile Status",
        "Description":"Profile service status",
        "PendingList":{"Activation":"profile-1"},
        "ActiveProfileIndex":1,
        "BmcProfileVersion":2,
        "FactoryResetStatus":"Idle",
        "DefaultProfileIndex":1
    }"#;

    /// The typed NVIDIA profile collection with the single profile member.
    const NVIDIA_PROFILES_COLLECTION_BODY: &str = r##"{
        "@odata.type":"#NvidiaSystemProfileCollection.NvidiaSystemProfileCollection",
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
        "Id":"Profiles",
        "Name":"System Profile Collection",
        "Members":[{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"}]
    }"##;

    /// The typed NVIDIA `SystemProfile` member with every compiled metadata
    /// field populated and the `ProfileFile` navigation.
    const NVIDIA_SYSTEM_PROFILE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
        "@odata.etag":"W/\"nvidia-profile-1\"",
        "Id":"1",
        "Name":"Default Profile",
        "Description":"Factory default profile",
        "Default":true,
        "Owner":"Nvidia",
        "UUID":"11111111-2222-3333-4444-555555555555",
        "Version":1,
        "ProfileName":"default-profile",
        "ProfileFile":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"}
    }"#;

    /// The typed NVIDIA `SystemProfileFile` document with every compiled
    /// field populated: the `Metadata` section and the base64 `Profile`
    /// content.
    const NVIDIA_SYSTEM_PROFILE_FILE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
        "@odata.etag":"W/\"nvidia-profile-file-1\"",
        "Id":"ProfileFile",
        "Name":"Profile File",
        "Description":"Signed profile file",
        "ProfileFile":{
            "Metadata":{
                "Activate":true,
                "Delete":false,
                "OriginProfileUUID":"11111111-2222-3333-4444-555555555555",
                "More_Profiles":false,
                "ProjectName":"BlueField",
                "UUID":"11111111-2222-3333-4444-555555555555"
            },
            "Profile":"eyJwcm9maWxlIjogInRlc3QifQ=="
        }
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

    /// A Service Root that advertises the HPE OEM namespace in its own `Oem`
    /// segment, so the OEM probe can observe a namespace that lives on the
    /// root resource instead of a collection member.
    const OEM_SERVICE_ROOT_BODY: &str = r#"{
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
        "Oem":{"Hpe":{"@odata.id":"/redfish/v1/Managers/1/Oem/Hpe"}}
    }"#;

    /// A System member that advertises the NVIDIA OEM namespace in its `Oem`
    /// segment, so the OEM probe can observe a namespace carried by a
    /// collection member.
    const SYSTEM_WITH_NVIDIA_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Oem":{"Nvidia":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia"}}
    }"#;

    /// A Chassis member that advertises the Dell OEM namespace in its `Oem`
    /// segment and the `LiteOn` chassis manufacturer value, so one fixture
    /// exercises both OEM advertisement signals at once (the `Dell` key and
    /// the `LITE-ON TECHNOLOGY CORP.` hardware-id that `nv-redfish` 0.13
    /// itself gates `LiteOn` support on).
    const CHASSIS_WITH_DELL_OEM_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Manufacturer":"LITE-ON TECHNOLOGY CORP.",
        "Oem":{"Dell":{"Attributes":{"@odata.id":"/redfish/v1/Chassis/1/Oem/Dell/Attributes"}}}
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

    /// The `PowerEquipment` service document advertising its `PowerShelves`
    /// collection, so the `power-equipment` family read exercises the
    /// collection member fetch and projection.
    const POWER_EQUIPMENT_WITH_SHELVES_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/PowerEquipment",
        "@odata.etag":"W/\"power-equipment-1\"",
        "Id":"PowerEquipment",
        "Name":"Power Equipment",
        "Description":"Managed power equipment",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
        "PowerShelves":{"@odata.id":"/redfish/v1/PowerEquipment/PowerShelves"}
    }"#;

    /// The `PowerShelves` collection with one member, so the
    /// `power-equipment` family read exercises its member fetch and
    /// projection.
    const POWER_SHELVES_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#PowerDistributionCollection.PowerDistributionCollection",
        "@odata.id":"/redfish/v1/PowerEquipment/PowerShelves",
        "Name":"Power Shelf Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/PowerEquipment/PowerShelves/1"}
        ]
    }"##;

    /// The full `PowerDistribution` power-shelf member projection with every
    /// optional contract field populated; the circuit, outlet, and sensor
    /// navigations are decoded but stay outside the projection contract.
    const POWER_SHELF_ONE_BODY: &str = r##"{
        "@odata.type":"#PowerDistribution.v1_2_0.PowerDistribution",
        "@odata.id":"/redfish/v1/PowerEquipment/PowerShelves/1",
        "@odata.etag":"W/\"power-shelf-1\"",
        "Id":"1",
        "Name":"Power Shelf One",
        "Description":"Rack power shelf",
        "EquipmentType":"PowerShelf",
        "Manufacturer":"Rutilus Test",
        "Model":"PDU-30K",
        "PartNumber":"PDU-PART-1",
        "SerialNumber":"PDU-1",
        "Version":"2.0",
        "FirmwareVersion":"3.1.4",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

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

    /// A Service Root that also advertises the 0.2 `power-equipment` service
    /// through the root-level `PowerEquipment` link.
    const CORE_WITH_POWER_EQUIPMENT_ROOT_BODY: &str = r#"{
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
        "PowerEquipment":{"@odata.id":"/redfish/v1/PowerEquipment"}
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

    /// The full `MetricReport` member fixture: the `MetricValues` array is
    /// decoded by the schema and projected as the timestamped readings of the
    /// 0.4.0 value-array read, while the report-level `Timestamp`/`Context`/
    /// `ReportSequence` metadata stays out of the snapshot. `Status` is not a
    /// `MetricReport_v1` property and must stay out as well, and the
    /// per-entry `MetricId` is not part of the strictly projectable field
    /// set.
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

    /// A Chassis member that advertises the 0.2 `EnvironmentMetrics`
    /// singleton, the `PowerSubsystem` with its `PowerSupplies` collection,
    /// and the `NetworkAdapters` surface with its `NetworkDeviceFunctions`
    /// collection, so the four new families follow their parent through the
    /// same typed navigation.
    const CHASSIS_WITH_POWER_AND_NETWORK_SURFACE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "@odata.etag":"W/\"chassis-1\"",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "PowerSubsystem":{"@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem"},
        "NetworkAdapters":{"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters"},
        "EnvironmentMetrics":{"@odata.id":"/redfish/v1/Chassis/1/EnvironmentMetrics"}
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

    /// The `NetworkDeviceFunction` collection with one member, so the
    /// `network-device-functions` family read exercises its member fetch and
    /// projection.
    const NETWORK_DEVICE_FUNCTIONS_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#NetworkDeviceFunctionCollection.NetworkDeviceFunctionCollection",
        "@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions",
        "Name":"Network Device Function Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions/1"}
        ]
    }"##;

    /// The full `NetworkDeviceFunction` member projection with every optional
    /// contract field populated; the protocol-specific configuration bags are
    /// decoded but stay outside the projection contract.
    const NETWORK_DEVICE_FUNCTION_ONE_BODY: &str = r##"{
        "@odata.type":"#NetworkDeviceFunction.v1_5_0.NetworkDeviceFunction",
        "@odata.id":"/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions/1",
        "@odata.etag":"W/\"ndf-1\"",
        "Id":"1",
        "Name":"Adapter One Function One",
        "Description":"First network device function",
        "NetDevFuncType":"Ethernet",
        "DeviceEnabled":true,
        "NetDevFuncCapabilities":["Ethernet"],
        "Ethernet":{"MACAddress":"AA:BB:CC:DD:EE:01","MTUSize":1500},
        "BootMode":"PXE",
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// The `PowerSupply` collection with one member, so the `power-supplies`
    /// family read exercises its member fetch and projection.
    const POWER_SUPPLIES_WITH_MEMBERS_BODY: &str = r##"{
        "@odata.type":"#PowerSupplyCollection.PowerSupplyCollection",
        "@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies",
        "Name":"Power Supply Collection",
        "Members":[
            {"@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1"}
        ]
    }"##;

    /// The full `PowerSupply` member projection with every optional contract
    /// field populated; the input-range and output-rail bags are decoded but
    /// stay outside the projection contract.
    const POWER_SUPPLY_ONE_BODY: &str = r##"{
        "@odata.type":"#PowerSupply.v1_5_0.PowerSupply",
        "@odata.id":"/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1",
        "@odata.etag":"W/\"power-supply-1\"",
        "Id":"1",
        "Name":"Power Supply One",
        "Description":"Chassis power supply",
        "PowerSupplyType":"AC",
        "PowerCapacityWatts":1600,
        "Manufacturer":"Rutilus Test",
        "Model":"PSU-1600",
        "FirmwareVersion":"1.0.0",
        "SerialNumber":"PSU-1",
        "PartNumber":"PSU-PART-1",
        "HotPluggable":true,
        "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
    }"##;

    /// The `EnvironmentMetrics` singleton with the embedded readings the
    /// `environment-metrics` family projects: each measurement carries its
    /// `DataSourceUri` link and current `Reading`, and `PowerLimitWatts`
    /// embeds its control `SetPoint` instead of a sensor reading.
    const ENVIRONMENT_METRICS_BODY: &str = r##"{
        "@odata.type":"#EnvironmentMetrics.v1_1_0.EnvironmentMetrics",
        "@odata.id":"/redfish/v1/Chassis/1/EnvironmentMetrics",
        "@odata.etag":"W/\"env-metrics-1\"",
        "Id":"EnvironmentMetrics",
        "Name":"Environment Metrics",
        "Description":"Chassis environment readings",
        "TemperatureCelsius":{
            "DataSourceUri":"/redfish/v1/Chassis/1/Sensors/InletTemp",
            "Reading":27.5
        },
        "HumidityPercent":{
            "DataSourceUri":"/redfish/v1/Chassis/1/Sensors/InletHumidity",
            "Reading":45.0
        },
        "FanSpeedsPercent":[
            {"DataSourceUri":"/redfish/v1/Chassis/1/Sensors/Fan1","Reading":55.0},
            {"DataSourceUri":"/redfish/v1/Chassis/1/Sensors/Fan2","Reading":60.0}
        ],
        "PowerWatts":{
            "DataSourceUri":"/redfish/v1/Chassis/1/Sensors/TotalPower",
            "Reading":320.0
        },
        "EnergykWh":{
            "DataSourceUri":"/redfish/v1/Chassis/1/Sensors/TotalEnergy",
            "Reading":1234.5
        },
        "PowerLoadPercent":{
            "DataSourceUri":"/redfish/v1/Chassis/1/Sensors/PowerLoad",
            "Reading":40.0
        },
        "PowerLimitWatts":{
            "DataSourceUri":"/redfish/v1/Chassis/1/Controls/PowerLimit",
            "SetPoint":1800
        }
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

    /// The request order for one manager that advertises `Oem.Dell`: the
    /// Dell Attributes document is read right after the manager member,
    /// exactly like the other manager-bound families.
    const CORE_RESOURCE_WITH_DELL_ATTRIBUTES_REQUEST_PATHS: [&str; 12] = [
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
        "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one manager that advertises `Oem.Lenovo`: the
    /// `SecurityService` document is read right after the manager member,
    /// fetched through the `@odata.id` embedded in the `Oem.Lenovo` segment's
    /// `Security` navigation, exactly like the other manager-bound families.
    const CORE_RESOURCE_WITH_LENOVO_SECURITY_SERVICE_REQUEST_PATHS: [&str; 12] = [
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
        "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one manager that advertises `Oem.Supermicro`:
    /// the `SysLockdown` and `KcsInterface` documents are read right after
    /// the manager member, each fetched through the `@odata.id` embedded in
    /// the `Oem.Supermicro` segment, exactly like the other manager-bound
    /// families.
    const CORE_RESOURCE_WITH_SUPERMICRO_OEM_REQUEST_PATHS: [&str; 13] = [
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
        "/redfish/v1/Managers/1/SysLockdown",
        "/redfish/v1/Managers/1/KCSInterface",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one System member that advertises `Oem.Nvidia`
    /// with an inline `NvidiaComputerSystem` segment: the chain is read right
    /// after the system member — the profile service document, its status
    /// singleton, the profile collection, the profile member, and its
    /// profile file — exactly like the other system-bound families.
    const CORE_RESOURCE_WITH_NVIDIA_SYSTEM_CONFIG_PROFILE_REQUEST_PATHS: [&str; 16] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one Manager member that advertises `Oem.Nvidia`
    /// with an inline `NvidiaManager` segment: the power-compliance and
    /// managed-entity chains are read right after the manager member — the
    /// compliance document, its `PowerDomains` collection with its member,
    /// the `ACLossPolicy` and `PSUCompliancePolicy` singletons, the
    /// `ManagedEntityGroups` collection with its member and the member's
    /// `ManagedEntities` collection with its entity member, the
    /// `PowerStateGroup` document with its `PowerShelfControllers` and
    /// `PowerSupplies` collections with their members, and the
    /// `PSURedundancy` singleton — exactly like the other manager-bound
    /// families.
    const CORE_RESOURCE_WITH_NVIDIA_POWER_COMPLIANCE_REQUEST_PATHS: [&str; 26] = [
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
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one Manager member whose `Oem.Nvidia` segment
    /// has the reference form: the segment body is fetched first, then the
    /// chains follow exactly like the inline form.
    const CORE_RESOURCE_WITH_NVIDIA_MANAGER_REFERENCE_SEGMENT_REQUEST_PATHS: [&str; 27] = [
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
        "/redfish/v1/Managers/1/Oem/Nvidia",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when a manager chain document fails (here the
    /// `PowerDomains` collection): the failed URI is still requested (that is
    /// how the skip is observed), the chain root and the remaining sub-chains
    /// stay in place, and the read completes.
    const CORE_RESOURCE_WITH_FAILED_NVIDIA_MANAGER_CHAIN_REQUEST_PATHS: [&str; 25] = [
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
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order for one System member whose `Oem.Nvidia` segment
    /// has the reference form: the segment body is fetched first, then the
    /// chain follows exactly like the inline form.
    const CORE_RESOURCE_WITH_NVIDIA_REFERENCE_SEGMENT_REQUEST_PATHS: [&str; 17] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Oem/Nvidia",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order when a chain document fails (here the profile
    /// collection): the failed URI is still requested (that is how the skip
    /// is observed), the chain root and status snapshots stay in place, and
    /// the read completes.
    const CORE_RESOURCE_WITH_FAILED_NVIDIA_CHAIN_REQUEST_PATHS: [&str; 14] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
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

    /// The request order for the 0.2 `power-equipment`, `power-supplies`,
    /// `network-device-functions`, and `environment-metrics` families: the
    /// chassis member's `NetworkAdapters` collection is fetched once for the
    /// `network-adapters` family, its member's `NetworkDeviceFunctions`
    /// collection is read right behind the member, the `PowerSubsystem`
    /// document precedes its `PowerSupplies` members, the `EnvironmentMetrics`
    /// singleton follows the chassis member, and the root `PowerEquipment`
    /// service document precedes its `PowerShelves` members at the end of the
    /// read.
    const POWER_AND_ENVIRONMENT_FAMILY_REQUEST_PATHS: [&str; 22] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/Systems",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Chassis",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/NetworkAdapters",
        "/redfish/v1/Chassis/1/NetworkAdapters/1",
        "/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions",
        "/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions/1",
        "/redfish/v1/Chassis/1/EnvironmentMetrics",
        "/redfish/v1/Chassis/1/PowerSubsystem",
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies",
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1",
        "/redfish/v1/Managers",
        "/redfish/v1/Managers/1",
        "/redfish/v1/PowerEquipment",
        "/redfish/v1/PowerEquipment/PowerShelves",
        "/redfish/v1/PowerEquipment/PowerShelves/1",
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

    /// The complete §2.1 capability inventory in ledger order (30 standard
    /// features in design-document order followed by the 14 OEM features in
    /// the compiled feature order), mirrored from `rutilus_domain` so
    /// discovery can prove it covers every capability exactly once.
    const CAPABILITY_INVENTORY_ORDER: [EndpointCapability; 44] = [
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
        EndpointCapability::OemAmi,
        EndpointCapability::OemDell,
        EndpointCapability::OemDellAttributes,
        EndpointCapability::OemDelta,
        EndpointCapability::OemHpe,
        EndpointCapability::OemLenovo,
        EndpointCapability::OemLiteOn,
        EndpointCapability::OemNvidia,
        EndpointCapability::OemNvidiaCper,
        EndpointCapability::OemNvidiaFabrics,
        EndpointCapability::OemNvidiaPowerManagement,
        EndpointCapability::OemNvidiaProfiles,
        EndpointCapability::OemNvidiaSecurity,
        EndpointCapability::OemSupermicro,
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
            oem,
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
            (EndpointCapability::OemAmi, oem.ami),
            (EndpointCapability::OemDell, oem.dell),
            (EndpointCapability::OemDellAttributes, oem.dell_attributes),
            (EndpointCapability::OemDelta, oem.delta),
            (EndpointCapability::OemHpe, oem.hpe),
            (EndpointCapability::OemLenovo, oem.lenovo),
            (EndpointCapability::OemLiteOn, oem.liteon),
            (EndpointCapability::OemNvidia, oem.nvidia),
            (EndpointCapability::OemNvidiaCper, oem.nvidia_cper),
            (EndpointCapability::OemNvidiaFabrics, oem.nvidia_fabrics),
            (
                EndpointCapability::OemNvidiaPowerManagement,
                oem.nvidia_power_management,
            ),
            (EndpointCapability::OemNvidiaProfiles, oem.nvidia_profiles),
            (EndpointCapability::OemNvidiaSecurity, oem.nvidia_security),
            (EndpointCapability::OemSupermicro, oem.supermicro),
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
        oem: CapabilityState,
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
            oem: uniform_oem(oem),
        }
    }

    /// Assigns one uniform state to every OEM capability, for fixtures whose
    /// decoded resources either all carry a vendor namespace or carry none.
    fn uniform_oem(state: CapabilityState) -> OemNamespaceProbe {
        OemNamespaceProbe {
            ami: state,
            dell: state,
            dell_attributes: state,
            delta: state,
            hpe: state,
            lenovo: state,
            liteon: state,
            nvidia: state,
            nvidia_cper: state,
            nvidia_fabrics: state,
            nvidia_power_management: state,
            nvidia_profiles: state,
            nvidia_security: state,
            supermicro: state,
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
                // The full fixture carries no `Oem` segments, so no vendor
                // namespace is advertised and every OEM capability is
                // `NotAdvertised` without a single extra request.
                CapabilityState::NotAdvertised,
            ))
        );
        assert_session_requests(&server.finish_all().await?, &FULL_PROBE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn detects_oem_namespaces_from_decoded_resources_without_extra_requests()
    -> Result<(), Box<dyn Error>> {
        // The fixture spreads the vendor namespaces across the resources the
        // capability probe already reads: `Hpe` on the Service Root, `Nvidia`
        // on the System member, and `Dell` plus the LiteOn chassis
        // manufacturer on the Chassis member. The Manager member carries no
        // `Oem` segment at all. The request sequence therefore contains only
        // the standard probe traffic: the OEM probe must not add a single
        // request and must not fail on any resource class.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            OEM_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_NVIDIA_OEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_DELL_OEM_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
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

        let mut expected = uniform_group(
            CapabilityState::Supported,
            CapabilityState::Supported,
            CapabilityState::NotAdvertised,
            CapabilityState::NotAdvertised,
            CapabilityState::NotAdvertised,
        );
        expected.oem = OemNamespaceProbe {
            ami: CapabilityState::NotAdvertised,
            dell: CapabilityState::Supported,
            dell_attributes: CapabilityState::Supported,
            delta: CapabilityState::NotAdvertised,
            hpe: CapabilityState::Supported,
            lenovo: CapabilityState::NotAdvertised,
            liteon: CapabilityState::Supported,
            nvidia: CapabilityState::Supported,
            nvidia_cper: CapabilityState::Supported,
            nvidia_fabrics: CapabilityState::Supported,
            nvidia_power_management: CapabilityState::Supported,
            nvidia_profiles: CapabilityState::Supported,
            nvidia_security: CapabilityState::Supported,
            supermicro: CapabilityState::NotAdvertised,
        };
        assert_eq!(discovery.capabilities(), expected_capabilities(expected));
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
                "/redfish/v1/Chassis/1",
                "/redfish/v1/Managers",
                "/redfish/v1/Managers/1",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;
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
                // The root-only fixture carries no `Oem` segment.
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
                // The fixture bodies carry no `Oem` segments.
                oem: uniform_oem(CapabilityState::NotAdvertised),
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
                // The fixture bodies carry no `Oem` segments.
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
                // The fixture bodies carry no `Oem` segments.
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
                // The fixture bodies carry no `Oem` segments.
                oem: uniform_oem(CapabilityState::NotAdvertised),
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
    async fn reads_dell_oem_attributes_through_typed_navigation() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_DELL_OEM_BODY),
                ("200 OK", DELL_ATTRIBUTES_BODY),
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
        let dell = &resources[4];
        assert_eq!(dell.feature(), ResourceFeature::OemDell);
        assert_eq!(
            dell.odata_id().as_str(),
            "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1"
        );
        assert_eq!(
            dell.etag().map(ResourceEtag::as_str),
            Some("W/\"dell-attributes-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(dell.payload().as_str())?;
        assert_eq!(payload["Id"], "1");
        assert_eq!(payload["Name"], "Dell Attributes");
        assert_eq!(payload["Description"], "Dell iDRAC attributes");
        assert_eq!(payload["ServerModel"], "PowerEdge R750");
        assert_eq!(payload["ServerServiceTag"], "ABC1234");
        assert_eq!(payload["ServerGeneration"], "16G");
        assert_eq!(payload["ServerBmcMacAddress"], "14:18:77:aa:bb:cc");
        assert_eq!(payload["ServerName"], "rack-1-server-2");
        // The unpinned `BiosVersion` entry of the dynamic bag stays out of the
        // strictly projectable field set, exactly like `Bios`'s attribute bag.
        assert!(payload.get("BiosVersion").is_none());
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_DELL_ATTRIBUTES_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn manager_without_dell_oem_produces_no_oem_snapshot() -> Result<(), Box<dyn Error>> {
        // An `Oem` segment of another vendor must not be mistaken for Dell,
        // and a manager without any `Oem` segment stays untouched; neither
        // case issues a Dell probe.
        for manager_body in [MANAGER_BODY, MANAGER_WITH_OTHER_OEM_BODY] {
            let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
                CORE_SERVICE_ROOT_BODY,
                &[
                    ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                    ("200 OK", SYSTEM_BODY),
                    ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                    ("200 OK", CHASSIS_MEMBER_BODY),
                    ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                    ("200 OK", manager_body),
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
            assert!(
                resources
                    .iter()
                    .all(|resource| resource.feature() != ResourceFeature::OemDell)
            );
            // No Dell probe was issued: the request sequence is exactly the
            // plain manager read.
            assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_dell_attributes_are_skipped_like_one_odd_member()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_DELL_OEM_BODY),
                // A Dell Attributes document that cannot be decoded into the
                // compiled `DellAttributes` schema (missing the required `Id`
                // and `Name`) is one odd manager surface, not an endpoint-wide
                // condition: the read succeeds and leaves the family absent.
                (
                    "200 OK",
                    r#"{"@odata.id":"/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1"}"#,
                ),
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
        assert!(
            resources
                .iter()
                .all(|resource| resource.feature() != ResourceFeature::OemDell)
        );
        // The failed Dell probe is still observable as a request, like every
        // member-level skip.
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_DELL_ATTRIBUTES_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[test]
    fn dell_attribute_lookup_keeps_the_typed_primitive_contract() -> Result<(), Box<dyn Error>> {
        // The compiled `DellAttributes` schema is the type boundary: an entry
        // of a non-string `Edm.PrimitiveType`, an explicit null, and an
        // absent key all project as `None` instead of being coerced.
        let attributes: DellAttributesSchema = serde_json::from_str(
            r#"{
            "@odata.id":"/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1",
            "Id":"1",
            "Name":"Dell Attributes",
            "Attributes":{
                "ServerModel":"PowerEdge R750",
                "ServerName":null,
                "ServerGeneration":16
            }
        }"#,
        )?;

        assert_eq!(
            dell_attribute_string(&attributes, "ServerModel"),
            Some("PowerEdge R750".to_owned())
        );
        assert_eq!(dell_attribute_string(&attributes, "ServerName"), None);
        // `ServerGeneration` is an integer on this fixture: the typed lookup
        // refuses to reinterpret it as text.
        assert_eq!(dell_attribute_string(&attributes, "ServerGeneration"), None);
        assert_eq!(dell_attribute_string(&attributes, "ServerServiceTag"), None);
        Ok(())
    }

    #[tokio::test]
    async fn reads_supermicro_oem_documents_through_embedded_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_SUPERMICRO_OEM_BODY),
                ("200 OK", SUPERMICRO_SYS_LOCKDOWN_BODY),
                ("200 OK", SUPERMICRO_KCS_INTERFACE_BODY),
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
        let sys_lockdown = &resources[4];
        assert_eq!(sys_lockdown.feature(), ResourceFeature::OemSmcSysLockdown);
        assert_eq!(
            sys_lockdown.odata_id().as_str(),
            "/redfish/v1/Managers/1/SysLockdown"
        );
        assert_eq!(
            sys_lockdown.etag().map(ResourceEtag::as_str),
            Some("W/\"sys-lockdown-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(sys_lockdown.payload().as_str())?;
        assert_eq!(payload["SysLockdownEnabled"], true);
        let kcs_interface = &resources[5];
        assert_eq!(kcs_interface.feature(), ResourceFeature::OemSmcKcsInterface);
        assert_eq!(
            kcs_interface.odata_id().as_str(),
            "/redfish/v1/Managers/1/KCSInterface"
        );
        assert_eq!(
            kcs_interface.etag().map(ResourceEtag::as_str),
            Some("W/\"kcs-interface-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(kcs_interface.payload().as_str())?;
        assert_eq!(payload["Privilege"], "Administrator");
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_SUPERMICRO_OEM_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn manager_without_supermicro_oem_produces_no_oem_snapshot() -> Result<(), Box<dyn Error>>
    {
        // An `Oem` segment of another vendor must not be mistaken for
        // Supermicro, and a manager without any `Oem` segment stays
        // untouched; neither case issues a Supermicro probe.
        for manager_body in [MANAGER_BODY, MANAGER_WITH_OTHER_OEM_BODY] {
            let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
                CORE_SERVICE_ROOT_BODY,
                &[
                    ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                    ("200 OK", SYSTEM_BODY),
                    ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                    ("200 OK", CHASSIS_MEMBER_BODY),
                    ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                    ("200 OK", manager_body),
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
            assert!(resources.iter().all(|resource| {
                !matches!(
                    resource.feature(),
                    ResourceFeature::OemSmcSysLockdown | ResourceFeature::OemSmcKcsInterface
                )
            }));
            // No Supermicro probe was issued: the request sequence is exactly
            // the plain manager read.
            assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_supermicro_oem_segment_leaves_the_family_absent()
    -> Result<(), Box<dyn Error>> {
        // An `Oem.Supermicro` segment the compiled `smc_manager_extensions`
        // schema cannot decode (here: a non-object `SysLockdown` key) is one
        // odd manager surface: the read succeeds and leaves both Supermicro
        // families absent, and no leaf request is ever fabricated.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_UNDECODABLE_SUPERMICRO_OEM_BODY),
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
        assert!(resources.iter().all(|resource| {
            !matches!(
                resource.feature(),
                ResourceFeature::OemSmcSysLockdown | ResourceFeature::OemSmcKcsInterface
            )
        }));
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_supermicro_documents_are_skipped_like_one_odd_member()
    -> Result<(), Box<dyn Error>> {
        // Both leaf documents cannot be decoded into the compiled schemas
        // (missing the required `@odata.id`) and are one odd manager surface
        // each: the read succeeds and leaves both families absent, while the
        // embedded probes stay observable as requests, like every
        // member-level skip.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_SUPERMICRO_OEM_BODY),
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

        assert_eq!(resources.len(), 4);
        assert!(resources.iter().all(|resource| {
            !matches!(
                resource.feature(),
                ResourceFeature::OemSmcSysLockdown | ResourceFeature::OemSmcKcsInterface
            )
        }));
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_SUPERMICRO_OEM_REQUEST_PATHS,
        )?;
        Ok(())
    }

    // The complete chain surface is asserted in one test so the snapshot
    // order and the request sequence stay one contract; the fixture
    // sequence exceeds the pedantic line budget, so the lint is scoped here
    // exactly like the other fixture-sequence tests.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn reads_nvidia_system_config_profile_chain_through_oem_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
                // The chain is read right after the System member and before
                // the sibling collections, so the bodies follow that order.
                ("200 OK", NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
                ("200 OK", NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS_BODY),
                ("200 OK", NVIDIA_PROFILES_COLLECTION_BODY),
                ("200 OK", NVIDIA_SYSTEM_PROFILE_BODY),
                ("200 OK", NVIDIA_SYSTEM_PROFILE_FILE_BODY),
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
        let chain_root = &resources[2];
        assert_eq!(
            chain_root.feature(),
            ResourceFeature::OemNvidiaSystemConfigProfile
        );
        assert_eq!(
            chain_root.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
        );
        assert_eq!(
            chain_root.etag().map(ResourceEtag::as_str),
            Some("W/\"nvidia-scp-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(chain_root.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "system_config_profile");
        assert_eq!(payload["Truststore"]["NvidiaCertificates"], true);
        assert_eq!(payload["Truststore"]["OemCertificates"], true);
        assert!(payload.get("Profiles").is_none());
        assert!(payload.get("Status").is_none());
        let status = &resources[3];
        assert_eq!(
            status.feature(),
            ResourceFeature::OemNvidiaSystemConfigProfile
        );
        assert_eq!(
            status.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"
        );
        let payload: serde_json::Value = serde_json::from_str(status.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "system_config_profile_status");
        assert_eq!(payload["PendingList"]["Activation"], "profile-1");
        assert_eq!(payload["ActiveProfileIndex"], 1);
        assert_eq!(payload["BmcProfileVersion"], 2);
        assert_eq!(payload["FactoryResetStatus"], "Idle");
        assert_eq!(payload["DefaultProfileIndex"], 1);
        let profile = &resources[4];
        assert_eq!(
            profile.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"
        );
        let payload: serde_json::Value = serde_json::from_str(profile.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "system_profile");
        assert_eq!(payload["Default"], true);
        assert_eq!(payload["Owner"], "Nvidia");
        assert_eq!(payload["UUID"], "11111111-2222-3333-4444-555555555555");
        assert_eq!(payload["Version"], 1);
        assert_eq!(payload["ProfileName"], "default-profile");
        let profile_file = &resources[5];
        assert_eq!(
            profile_file.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
        );
        let payload: serde_json::Value = serde_json::from_str(profile_file.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "system_profile_file");
        assert_eq!(payload["ProfileFile"]["Metadata"]["Activate"], true);
        assert_eq!(payload["ProfileFile"]["Metadata"]["Delete"], false);
        assert_eq!(
            payload["ProfileFile"]["Metadata"]["OriginProfileUUID"],
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(payload["ProfileFile"]["Metadata"]["More_Profiles"], false);
        assert_eq!(
            payload["ProfileFile"]["Metadata"]["ProjectName"],
            "BlueField"
        );
        assert_eq!(
            payload["ProfileFile"]["Profile"],
            "eyJwcm9maWxlIjogInRlc3QifQ=="
        );
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_NVIDIA_SYSTEM_CONFIG_PROFILE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn system_without_nvidia_oem_produces_no_nvidia_snapshot() -> Result<(), Box<dyn Error>> {
        // A system without any `Oem` segment stays untouched, exactly like
        // the other vendor families: no NVIDIA snapshot and no fabricated
        // chain request.
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
        assert!(resources
            .iter()
            .all(|resource| resource.feature() != ResourceFeature::OemNvidiaSystemConfigProfile));
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_nvidia_segment_leaves_the_family_absent() -> Result<(), Box<dyn Error>> {
        // An `Oem.Nvidia` segment that cannot be discriminated or decoded
        // (here: a non-object value) is one odd system surface: the read
        // succeeds and leaves the whole system-config-profile family absent,
        // and no chain request is ever fabricated.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_UNDECODABLE_NVIDIA_SEGMENT_BODY),
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
        assert!(resources
            .iter()
            .all(|resource| resource.feature() != ResourceFeature::OemNvidiaSystemConfigProfile));
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn chassis_kind_nvidia_segment_leaves_the_family_absent() -> Result<(), Box<dyn Error>> {
        // A Chassis-kind `Oem.Nvidia` segment (here the `NvidiaChassis`
        // shape) carries no system-config-profile chain: the discrimination
        // keeps the family absent and no chain request is fabricated. The
        // arm exists so a later chassis family decodes these segments.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_CHASSIS_KIND_NVIDIA_SEGMENT_BODY),
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
        assert!(resources
            .iter()
            .all(|resource| resource.feature() != ResourceFeature::OemNvidiaSystemConfigProfile));
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn nvidia_reference_form_segment_is_fetched_before_decoding() -> Result<(), Box<dyn Error>>
    {
        // A BlueField-style reference-form segment (`{"@odata.id": ...}`) is
        // fetched through the compiled decode target first; the fetched
        // document then navigates the chain exactly like the inline form.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_NVIDIA_REFERENCE_FORM_SEGMENT_BODY),
                // The reference-form segment body is fetched first, then the
                // chain follows right after the System member.
                ("200 OK", NVIDIA_COMPUTER_SYSTEM_SEGMENT_BODY),
                ("200 OK", NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
                ("200 OK", NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS_BODY),
                ("200 OK", NVIDIA_PROFILES_COLLECTION_BODY),
                ("200 OK", NVIDIA_SYSTEM_PROFILE_BODY),
                ("200 OK", NVIDIA_SYSTEM_PROFILE_FILE_BODY),
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
        assert!(resources.iter().any(|resource| {
            resource.feature() == ResourceFeature::OemNvidiaSystemConfigProfile
                && resource.odata_id().as_str()
                    == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
        }));
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_NVIDIA_REFERENCE_SEGMENT_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn failed_nvidia_chain_documents_are_skipped_like_one_odd_surface()
    -> Result<(), Box<dyn Error>> {
        // A failed chain sub-document (here the profile collection) follows
        // the member-level skip semantics: the read succeeds, the chain root
        // and status snapshots stay in place, and the profile sub-chain is
        // absent — the readable remainder is never erased.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_WITH_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
                ("200 OK", NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
                ("200 OK", NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS_BODY),
                ("404 Not Found", "{}"),
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

        assert_eq!(resources.len(), 6);
        let nvidia = resources
            .iter()
            .filter(|resource| resource.feature() == ResourceFeature::OemNvidiaSystemConfigProfile)
            .collect::<Vec<_>>();
        assert_eq!(nvidia.len(), 2);
        assert!(nvidia.iter().any(|resource| {
            resource.odata_id().as_str() == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
        }));
        assert!(nvidia.iter().any(|resource| {
            resource.odata_id().as_str()
                == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"
        }));
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_FAILED_NVIDIA_CHAIN_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[test]
    fn nvidia_segment_kind_discriminates_the_segment_shapes() {
        // The discrimination mirrors nv-redfish's own `NvidiaCbcChassis::new`
        // constructor: the top namespace and the type name decide the kind.
        let computer_system = serde_json::json!({
            "@odata.type": "#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem"
        });
        assert!(matches!(
            nvidia_segment_kind(&computer_system),
            Some(NvidiaSegmentKind::ComputerSystem)
        ));
        // The four chassis shapes of the `NvidiaChassis` namespace plus the
        // standalone `NvidiaRoTChassis` namespace are all Chassis kinds.
        for odata_type in [
            "#NvidiaChassis.v1_14_0.NvidiaChassis",
            "#NvidiaChassis.v1_14_0.NvidiaRoTchassis",
            "#NvidiaChassis.v1_14_0.NvidiaSmaChassis",
            "#NvidiaChassis.v1_14_0.NvidiaCBCChassis",
            "#NvidiaRoTChassis.v1_0_0.NvidiaRoTChassis",
        ] {
            let segment = serde_json::json!({ "@odata.type": odata_type });
            assert!(
                matches!(
                    nvidia_segment_kind(&segment),
                    Some(NvidiaSegmentKind::Chassis)
                ),
                "{odata_type} must discriminate as a chassis segment"
            );
        }
        // The manager segment is versioned: the top namespace and the type
        // name decide the kind for both the versioned and the hypothetical
        // unversioned spellings, and the decode target is the versioned
        // `v1_9_0` struct either way.
        for odata_type in [
            "#NvidiaManager.v1_9_0.NvidiaManager",
            "#NvidiaManager.NvidiaManager",
        ] {
            let segment = serde_json::json!({ "@odata.type": odata_type });
            assert!(
                matches!(
                    nvidia_segment_kind(&segment),
                    Some(NvidiaSegmentKind::Manager)
                ),
                "{odata_type} must discriminate as a manager segment"
            );
        }
        // A segment without a parseable `@odata.type`, or with a type from
        // outside the compiled NVIDIA surface, is not discriminable.
        for segment in [
            serde_json::json!({}),
            serde_json::json!({ "@odata.type": "#Chassis.v1_22_0.Chassis" }),
            serde_json::json!({ "@odata.type": "no-type-marker" }),
            serde_json::json!(5),
        ] {
            assert_eq!(nvidia_segment_kind(&segment), None);
        }
        // The reference form is recognized before discrimination, so the
        // `BlueField` partial-stub quirk never falls through as undecodable.
        let reference = serde_json::json!({ "@odata.id": "/redfish/v1/Systems/1/Oem/Nvidia" });
        assert!(is_nvidia_reference_form(&reference));
        assert!(!is_nvidia_reference_form(&computer_system));
    }

    #[test]
    fn nvidia_document_projections_keep_the_typed_field_contract() -> Result<(), Box<dyn Error>> {
        // The compiled schemas are the type boundary: the typed metadata
        // fields are projected verbatim, the `DocumentType` discriminator is
        // written by the projection, and absent fields are skipped on the
        // wire instead of coerced.
        let chain_root: NvidiaSystemConfigProfileSchema =
            serde_json::from_str(NVIDIA_SYSTEM_CONFIG_PROFILE_BODY)?;
        let projection = nvidia_system_config_profile_projection(&chain_root)?;
        assert_eq!(
            projection.feature(),
            ResourceFeature::OemNvidiaSystemConfigProfile
        );
        // The payloads are canonicalized by the snapshot payload rule (the
        // `serde_json` map order), so the expected strings follow the
        // alphabetical key order, not the declaration order.
        assert_eq!(
            projection.payload().as_str(),
            r#"{"Description":"Profile service","DocumentType":"system_config_profile","Id":"SystemConfigProfile","Name":"NVIDIA System Config Profile","Truststore":{"NvidiaCertificates":true,"OemCertificates":true}}"#
        );
        // Without `Id` / `Name` the compiled decode fails, so the family
        // cannot produce a bare chain-root snapshot; the closest legal
        // document is one without the optional `Truststore`, which projects
        // without the key.
        let no_truststore: NvidiaSystemConfigProfileSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile","Id":"SystemConfigProfile","Name":"NVIDIA System Config Profile"}"#,
        )?;
        assert_eq!(
            nvidia_system_config_profile_projection(&no_truststore)?
                .payload()
                .as_str(),
            r#"{"DocumentType":"system_config_profile","Id":"SystemConfigProfile","Name":"NVIDIA System Config Profile"}"#
        );

        let status: NvidiaSystemConfigProfileStatusSchema =
            serde_json::from_str(NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS_BODY)?;
        assert_eq!(
            nvidia_system_config_profile_status_projection(&status)?
                .payload()
                .as_str(),
            r#"{"ActiveProfileIndex":1,"BmcProfileVersion":2,"DefaultProfileIndex":1,"Description":"Profile service status","DocumentType":"system_config_profile_status","FactoryResetStatus":"Idle","Id":"Status","Name":"System Config Profile Status","PendingList":{"Activation":"profile-1"}}"#
        );
        let sparse_status: NvidiaSystemConfigProfileStatusSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status","Id":"Status","Name":"Status"}"#,
        )?;
        assert_eq!(
            nvidia_system_config_profile_status_projection(&sparse_status)?
                .payload()
                .as_str(),
            r#"{"DocumentType":"system_config_profile_status","Id":"Status","Name":"Status"}"#
        );

        let profile: NvidiaSystemProfileSchema = serde_json::from_str(NVIDIA_SYSTEM_PROFILE_BODY)?;
        assert_eq!(
            nvidia_system_profile_projection(&profile)?
                .payload()
                .as_str(),
            r#"{"Default":true,"Description":"Factory default profile","DocumentType":"system_profile","Id":"1","Name":"Default Profile","Owner":"Nvidia","ProfileName":"default-profile","UUID":"11111111-2222-3333-4444-555555555555","Version":1}"#
        );
        let sparse_profile: NvidiaSystemProfileSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1","Id":"1","Name":"Default Profile"}"#,
        )?;
        assert_eq!(
            nvidia_system_profile_projection(&sparse_profile)?
                .payload()
                .as_str(),
            r#"{"DocumentType":"system_profile","Id":"1","Name":"Default Profile"}"#
        );

        let profile_file: NvidiaSystemProfileFileSchema =
            serde_json::from_str(NVIDIA_SYSTEM_PROFILE_FILE_BODY)?;
        assert_eq!(
            nvidia_system_profile_file_projection(&profile_file)?
                .payload()
                .as_str(),
            r#"{"Description":"Signed profile file","DocumentType":"system_profile_file","Id":"ProfileFile","Name":"Profile File","ProfileFile":{"Metadata":{"Activate":true,"Delete":false,"More_Profiles":false,"OriginProfileUUID":"11111111-2222-3333-4444-555555555555","ProjectName":"BlueField","UUID":"11111111-2222-3333-4444-555555555555"},"Profile":"eyJwcm9maWxlIjogInRlc3QifQ=="}}"#
        );
        let sparse_file: NvidiaSystemProfileFileSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile","Id":"ProfileFile","Name":"Profile File"}"#,
        )?;
        assert_eq!(
            nvidia_system_profile_file_projection(&sparse_file)?
                .payload()
                .as_str(),
            r#"{"DocumentType":"system_profile_file","Id":"ProfileFile","Name":"Profile File"}"#
        );
        Ok(())
    }

    // The complete power chain surface is asserted in one test so the
    // snapshot order and the request sequence stay one contract; the fixture
    // sequence exceeds the pedantic line budget, so the lint is scoped here
    // exactly like the other fixture-sequence tests.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn reads_nvidia_power_compliance_and_managed_entity_chains_through_oem_navigation()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_NVIDIA_POWER_COMPLIANCE_BODY),
                // The chains are read right after the Manager member and
                // before the Session delete, so the bodies follow that order.
                ("200 OK", NVIDIA_POWER_COMPLIANCE_BODY),
                ("200 OK", NVIDIA_POWER_DOMAINS_COLLECTION_BODY),
                ("200 OK", NVIDIA_POWER_DOMAIN_BODY),
                ("200 OK", NVIDIA_POWER_AC_LOSS_POLICY_BODY),
                ("200 OK", NVIDIA_POWER_PSU_COMPLIANCE_POLICY_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_GROUPS_COLLECTION_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_GROUP_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITIES_COLLECTION_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_BODY),
                ("200 OK", NVIDIA_POWER_STATE_GROUP_BODY),
                ("200 OK", NVIDIA_PSC_STATES_COLLECTION_BODY),
                ("200 OK", NVIDIA_PSC_STATE_BODY),
                ("200 OK", NVIDIA_PSU_STATES_COLLECTION_BODY),
                ("200 OK", NVIDIA_PSU_STATE_BODY),
                ("200 OK", NVIDIA_PSU_REDUNDANCY_BODY),
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

        assert_eq!(resources.len(), 14);
        // The power-compliance family: the chain-root document, its
        // `PowerDomains` member, the two policy singletons, the
        // `ManagedEntityGroups` member, the `PowerStateGroup` document with
        // its PSC and PSU state members, and the `PSURedundancy` singleton.
        let compliance = &resources[4];
        assert_eq!(
            compliance.feature(),
            ResourceFeature::OemNvidiaPowerCompliance
        );
        assert_eq!(
            compliance.odata_id().as_str(),
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"
        );
        assert_eq!(
            compliance.etag().map(ResourceEtag::as_str),
            Some("W/\"nvidia-pc-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(compliance.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "power_compliance_manager");
        assert_eq!(payload["ManagerType"], "PowerManager");
        assert!(payload.get("PowerDomains").is_none());
        let domain = &resources[5];
        let payload: serde_json::Value = serde_json::from_str(domain.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "power_domain");
        assert_eq!(payload["Value"], 800);
        assert_eq!(payload["Type"], "Above");
        assert_eq!(payload["Unit"], "Watts");
        assert_eq!(payload["SensorReadingType"], "Power");
        assert_eq!(payload["SensorImpl"], "PhysicalSensor");
        assert!(payload.get("PowerPolicies").is_none());
        let ac_loss = &resources[6];
        let payload: serde_json::Value = serde_json::from_str(ac_loss.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "power_policy");
        assert_eq!(payload["AutoDeassertPowerBrake"], true);
        assert_eq!(payload["Min"], 200);
        assert_eq!(payload["Max"], 600);
        assert_eq!(payload["Type"], "Inclusive");
        assert_eq!(payload["Unit"], "Watts");
        assert_eq!(payload["PolicyActions"], "AssertPowerBrake");
        assert!(payload.get("DwellTime").is_none());
        let psu_policy = &resources[7];
        let payload: serde_json::Value = serde_json::from_str(psu_policy.payload().as_str())?;
        assert_eq!(payload["PolicyActions"], "DoNothing");
        assert_eq!(payload["Type"], "Below");
        let group = &resources[8];
        assert_eq!(group.feature(), ResourceFeature::OemNvidiaPowerCompliance);
        let payload: serde_json::Value = serde_json::from_str(group.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "managed_entity_group");
        assert_eq!(payload["CurrentManagedEntityId"], "BF1");
        assert!(payload.get("ManagedEntities").is_none());
        // The managed-entity family: the entity member behind the group's
        // `ManagedEntities` navigation.
        let entity = &resources[9];
        assert_eq!(entity.feature(), ResourceFeature::OemNvidiaManagedEntity);
        assert_eq!(
            entity.odata_id().as_str(),
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1"
        );
        let payload: serde_json::Value = serde_json::from_str(entity.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "managed_entity");
        assert_eq!(payload["TransportProtocol"], "HTTPS");
        assert_eq!(payload["IPv4Address"], "192.0.2.10");
        assert_eq!(payload["IPv6Address"], "2001:db8::10");
        assert_eq!(payload["Port"], 443);
        let state_group = &resources[10];
        let payload: serde_json::Value = serde_json::from_str(state_group.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "power_state_group");
        assert_eq!(payload["PscId"], "PSC1");
        assert_eq!(payload["GeneratedWatts"], 2400);
        assert_eq!(payload["NumberOfPscs"], 1);
        assert_eq!(payload["NumberOfLocalPsus"], 2);
        let psc = &resources[11];
        let payload: serde_json::Value = serde_json::from_str(psc.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "psc_state");
        assert_eq!(payload["PscId"], "PSC1");
        assert_eq!(payload["NumOfOperationalPsus"], 4);
        assert_eq!(payload["PowerBrakeAssert"], false);
        assert_eq!(payload["MillisecondsSinceLastHeartbeat"], 12);
        assert_eq!(payload["Status"], "Operational");
        let psu = &resources[12];
        let payload: serde_json::Value = serde_json::from_str(psu.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "psu_state");
        assert_eq!(payload["PsuId"], "PSU1");
        assert_eq!(payload["Presence"], true);
        assert_eq!(payload["Input1Active"], true);
        assert_eq!(payload["Input2Active"], false);
        // The `PSURedundancy` singleton follows the PSU states.
        let redundancy = resources
            .iter()
            .find(|resource| {
                resource.odata_id().as_str()
                    == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy"
            })
            .ok_or("the redundancy snapshot must exist")?;
        let payload: serde_json::Value = serde_json::from_str(redundancy.payload().as_str())?;
        assert_eq!(payload["DocumentType"], "psu_redundancy");
        assert_eq!(payload["MaxNumSupported"], "4");
        assert_eq!(payload["MinNumNeeded"], "2");
        assert_eq!(payload["RedundancySetting"], "NPlusOne");
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_NVIDIA_POWER_COMPLIANCE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn manager_without_nvidia_oem_produces_no_nvidia_snapshot() -> Result<(), Box<dyn Error>>
    {
        // A manager without any `Oem` segment stays untouched, exactly like
        // the other vendor families: no NVIDIA snapshot and no fabricated
        // chain request, and the standard manager surface is byte-identical.
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
        assert!(resources.iter().all(|resource| {
            resource.feature() != ResourceFeature::OemNvidiaPowerCompliance
                && resource.feature() != ResourceFeature::OemNvidiaManagedEntity
        }));
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_nvidia_manager_segment_leaves_both_families_absent()
    -> Result<(), Box<dyn Error>> {
        // An `Oem.Nvidia` segment that cannot be discriminated or decoded
        // (here: a non-object value) is one odd manager surface: the read
        // succeeds, both power families stay absent, and no chain request is
        // ever fabricated.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_UNDECODABLE_NVIDIA_SEGMENT_BODY),
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
        assert!(resources.iter().all(|resource| {
            resource.feature() != ResourceFeature::OemNvidiaPowerCompliance
                && resource.feature() != ResourceFeature::OemNvidiaManagedEntity
        }));
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn nvidia_manager_reference_form_segment_is_fetched_before_decoding()
    -> Result<(), Box<dyn Error>> {
        // A BlueField-style reference-form segment (`{"@odata.id": ...}`) is
        // fetched through the local typed decode target first; the fetched
        // document then navigates the chains exactly like the inline form.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_NVIDIA_REFERENCE_FORM_SEGMENT_BODY),
                // The reference-form segment body is fetched first, then the
                // chains follow right after the Manager member.
                ("200 OK", NVIDIA_MANAGER_SEGMENT_BODY),
                ("200 OK", NVIDIA_POWER_COMPLIANCE_BODY),
                ("200 OK", NVIDIA_POWER_DOMAINS_COLLECTION_BODY),
                ("200 OK", NVIDIA_POWER_DOMAIN_BODY),
                ("200 OK", NVIDIA_POWER_AC_LOSS_POLICY_BODY),
                ("200 OK", NVIDIA_POWER_PSU_COMPLIANCE_POLICY_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_GROUPS_COLLECTION_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_GROUP_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITIES_COLLECTION_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_BODY),
                ("200 OK", NVIDIA_POWER_STATE_GROUP_BODY),
                ("200 OK", NVIDIA_PSC_STATES_COLLECTION_BODY),
                ("200 OK", NVIDIA_PSC_STATE_BODY),
                ("200 OK", NVIDIA_PSU_STATES_COLLECTION_BODY),
                ("200 OK", NVIDIA_PSU_STATE_BODY),
                ("200 OK", NVIDIA_PSU_REDUNDANCY_BODY),
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

        assert_eq!(resources.len(), 14);
        assert!(resources.iter().any(|resource| {
            resource.feature() == ResourceFeature::OemNvidiaPowerCompliance
                && resource.odata_id().as_str()
                    == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"
        }));
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_NVIDIA_MANAGER_REFERENCE_SEGMENT_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn failed_nvidia_manager_chain_documents_are_skipped_like_one_odd_surface()
    -> Result<(), Box<dyn Error>> {
        // A failed chain sub-document (here the `PowerDomains` collection)
        // follows the member-level skip semantics: the read succeeds, the
        // chain root and every other sub-chain stay in place, and the failed
        // sub-chain alone is absent — the readable remainder is never erased.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_NVIDIA_POWER_COMPLIANCE_BODY),
                ("200 OK", NVIDIA_POWER_COMPLIANCE_BODY),
                ("404 Not Found", "{}"),
                ("200 OK", NVIDIA_POWER_AC_LOSS_POLICY_BODY),
                ("200 OK", NVIDIA_POWER_PSU_COMPLIANCE_POLICY_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_GROUPS_COLLECTION_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_GROUP_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITIES_COLLECTION_BODY),
                ("200 OK", NVIDIA_MANAGED_ENTITY_BODY),
                ("200 OK", NVIDIA_POWER_STATE_GROUP_BODY),
                ("200 OK", NVIDIA_PSC_STATES_COLLECTION_BODY),
                ("200 OK", NVIDIA_PSC_STATE_BODY),
                ("200 OK", NVIDIA_PSU_STATES_COLLECTION_BODY),
                ("200 OK", NVIDIA_PSU_STATE_BODY),
                ("200 OK", NVIDIA_PSU_REDUNDANCY_BODY),
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

        assert_eq!(resources.len(), 13);
        let compliance = resources
            .iter()
            .filter(|resource| resource.feature() == ResourceFeature::OemNvidiaPowerCompliance)
            .collect::<Vec<_>>();
        // The chain root and every other sub-chain stay: the compliance
        // manager, both policies, the managed entity group, the power state
        // group, the PSC and PSU states, and the PSU redundancy.
        assert_eq!(compliance.len(), 8);
        assert!(
            resources
                .iter()
                .any(|resource| { resource.feature() == ResourceFeature::OemNvidiaManagedEntity })
        );
        assert!(!resources.iter().any(|resource| {
            resource.odata_id().as_str()
                == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1"
        }));
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_FAILED_NVIDIA_MANAGER_CHAIN_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn reads_lenovo_security_service_through_oem_navigation() -> Result<(), Box<dyn Error>> {
        // The Lenovo `SecurityService` document is read right after the
        // Manager member, through the `@odata.id` embedded in the
        // `Oem.Lenovo` segment's `Security` navigation.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_LENOVO_OEM_BODY),
                ("200 OK", LENOVO_SECURITY_SERVICE_BODY),
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
        let security = &resources[4];
        assert_eq!(
            security.feature(),
            ResourceFeature::OemLenovoSecurityService
        );
        assert_eq!(
            security.odata_id().as_str(),
            "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService"
        );
        assert_eq!(
            security.etag().map(ResourceEtag::as_str),
            Some("W/\"lenovo-security-1\"")
        );
        let payload: serde_json::Value = serde_json::from_str(security.payload().as_str())?;
        assert_eq!(payload["Id"], "SecurityService");
        assert_eq!(payload["Name"], "Lenovo Security Service");
        assert_eq!(payload["Description"], "Lenovo security service");
        // The `Configurator` nesting of the compiled schema collapses onto
        // the wrapper's single `fw_rollback()` surface, so the wire carries
        // the flattened `FWRollback` enum spelling verbatim (§12.3).
        assert_eq!(payload["FWRollback"], "Enabled");
        assert_eq!(payload["Configurator"], serde_json::Value::Null);
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_LENOVO_SECURITY_SERVICE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn manager_without_lenovo_oem_produces_no_lenovo_snapshot() -> Result<(), Box<dyn Error>>
    {
        // An `Oem` segment of another vendor must not be mistaken for Lenovo,
        // and a manager without any `Oem` segment stays untouched; neither
        // case issues a Lenovo probe.
        for manager_body in [MANAGER_BODY, MANAGER_WITH_OTHER_OEM_BODY] {
            let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
                CORE_SERVICE_ROOT_BODY,
                &[
                    ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                    ("200 OK", SYSTEM_BODY),
                    ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                    ("200 OK", CHASSIS_MEMBER_BODY),
                    ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                    ("200 OK", manager_body),
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
            assert!(resources
                .iter()
                .all(|resource| resource.feature() != ResourceFeature::OemLenovoSecurityService));
            // No Lenovo probe was issued: the request sequence is exactly the
            // plain manager read.
            assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn undecodable_lenovo_segment_leaves_the_family_absent() -> Result<(), Box<dyn Error>> {
        // A manager whose `Oem.Lenovo` segment cannot be decoded by the
        // compiled untagged `LenovoManagerSchema` is one odd manager surface:
        // the read succeeds, the family stays absent, and no document request
        // is fabricated.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_UNDECODABLE_LENOVO_OEM_BODY),
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
        assert!(
            resources
                .iter()
                .all(|resource| resource.feature() != ResourceFeature::OemLenovoSecurityService)
        );
        assert_session_requests(&server.finish_all().await?, &CORE_RESOURCE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn failed_lenovo_security_service_fetch_skips_like_one_odd_member()
    -> Result<(), Box<dyn Error>> {
        // A `SecurityService` document that cannot be fetched (here a 404) is
        // one odd manager surface, not an endpoint-wide condition: the read
        // succeeds, leaves the family absent, and the failed URI stays
        // observable as a request like every member-level skip.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_MEMBER_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_WITH_LENOVO_OEM_BODY),
                ("404 Not Found", "{}"),
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
        assert!(
            resources
                .iter()
                .all(|resource| resource.feature() != ResourceFeature::OemLenovoSecurityService)
        );
        assert_session_requests(
            &server.finish_all().await?,
            &CORE_RESOURCE_WITH_LENOVO_SECURITY_SERVICE_REQUEST_PATHS,
        )?;
        Ok(())
    }

    #[test]
    fn lenovo_untagged_segment_decodes_both_kcs_enabled_shapes() -> Result<(), Box<dyn Error>> {
        // The untagged dual-version decode mirrors the upstream
        // `LenovoManager` wrapper: the boolean `KCSEnabled` shape (`v0_1_0`)
        // decodes as the first variant, the state-string shape (`v1_0_0`)
        // falls back to the second, and either way the shared unversioned
        // `base` carries the same `Security` navigation the read follows.
        let manager: serde_json::Value = serde_json::from_str(MANAGER_WITH_LENOVO_OEM_BODY)?;
        let boolean_segment: LenovoManagerSchema =
            serde_json::from_value(manager["Oem"]["Lenovo"].clone())?;
        assert!(matches!(boolean_segment, LenovoManagerSchema::V0_1(_)));
        assert!(security_navigation(&boolean_segment).is_some());

        let manager: serde_json::Value =
            serde_json::from_str(MANAGER_WITH_LENOVO_STRING_KCS_OEM_BODY)?;
        let string_segment: LenovoManagerSchema =
            serde_json::from_value(manager["Oem"]["Lenovo"].clone())?;
        // The boolean `v0_1_0` shape cannot parse a string, so the untagged
        // decode must fall back to the `v1_0_0` variant.
        assert!(matches!(string_segment, LenovoManagerSchema::V1_0(_)));
        assert!(security_navigation(&string_segment).is_some());

        // A segment without the `Security` navigation decodes fine but
        // carries no navigation, so the family stays absent.
        let bare: LenovoManagerSchema = serde_json::from_value(serde_json::json!({
            "KCSEnabled": true
        }))?;
        assert!(security_navigation(&bare).is_none());
        Ok(())
    }

    /// The `Security` navigation of one decoded untagged Lenovo segment,
    /// resolved exactly like `read_manager_lenovo_oem` resolves it.
    fn security_navigation(segment: &LenovoManagerSchema) -> Option<String> {
        let nav = match segment {
            LenovoManagerSchema::V0_1(data) => data.base.security.as_ref(),
            LenovoManagerSchema::V1_0(data) => data.base.security.as_ref(),
        };
        nav.map(|nav| nav.id().to_string())
    }

    #[test]
    fn lenovo_security_service_projection_keeps_the_typed_field_contract()
    -> Result<(), Box<dyn Error>> {
        // The compiled schema is the type boundary: the typed identity fields
        // are projected verbatim and the `FWRollback` enum spelling stays the
        // vendor's wire value (§12.3).
        let security_service: LenovoSecurityServiceSchema =
            serde_json::from_str(LENOVO_SECURITY_SERVICE_BODY)?;
        let projection = lenovo_security_service_projection(&security_service)?;
        assert_eq!(
            projection.feature(),
            ResourceFeature::OemLenovoSecurityService
        );
        // The payloads are canonicalized by the snapshot payload rule (the
        // `serde_json` map order), so the expected strings follow the
        // alphabetical key order, not the declaration order.
        assert_eq!(
            projection.payload().as_str(),
            r#"{"Description":"Lenovo security service","FWRollback":"Enabled","Id":"SecurityService","Name":"Lenovo Security Service"}"#
        );
        // Without the optional `Configurator` segment the rollback state is
        // absent and the wire key is skipped instead of coerced.
        let bare: LenovoSecurityServiceSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Managers/1/Oem/Lenovo/SecurityService","Id":"SecurityService","Name":"Lenovo Security Service"}"#,
        )?;
        assert_eq!(
            lenovo_security_service_projection(&bare)?
                .payload()
                .as_str(),
            r#"{"Id":"SecurityService","Name":"Lenovo Security Service"}"#
        );
        Ok(())
    }

    #[test]
    fn nvidia_power_document_projections_keep_the_typed_field_contract()
    -> Result<(), Box<dyn Error>> {
        // The compiled schemas are the type boundary: the typed metadata
        // fields are projected verbatim, the `DocumentType` discriminator is
        // written by the projection, and absent fields are skipped on the
        // wire instead of coerced.
        let compliance: NvidiaPowerComplianceManagerSchema =
            serde_json::from_str(NVIDIA_POWER_COMPLIANCE_BODY)?;
        assert_eq!(
            nvidia_power_compliance_manager_projection(&compliance)?
                .payload()
                .as_str(),
            r#"{"Description":"Power compliance manager","DocumentType":"power_compliance_manager","Id":"PowerCompliance","ManagerType":"PowerManager","Name":"NVIDIA Power Compliance"}"#
        );
        let bare_compliance: NvidiaPowerComplianceManagerSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance","Id":"PowerCompliance","Name":"NVIDIA Power Compliance"}"#,
        )?;
        assert_eq!(
            nvidia_power_compliance_manager_projection(&bare_compliance)?
                .payload()
                .as_str(),
            r#"{"DocumentType":"power_compliance_manager","Id":"PowerCompliance","Name":"NVIDIA Power Compliance"}"#
        );

        let domain: NvidiaPowerDomainSchema = serde_json::from_str(NVIDIA_POWER_DOMAIN_BODY)?;
        assert_eq!(
            nvidia_power_domain_projection(&domain)?.payload().as_str(),
            r#"{"Description":"Power comparison domain","DocumentType":"power_domain","Id":"1","Name":"Power Domain One","SensorImpl":"PhysicalSensor","SensorReadingType":"Power","Type":"Above","Unit":"Watts","Value":800}"#
        );

        let policy: NvidiaPowerPolicySchema =
            serde_json::from_str(NVIDIA_POWER_AC_LOSS_POLICY_BODY)?;
        assert_eq!(
            nvidia_power_policy_projection(&policy)?.payload().as_str(),
            r#"{"AutoDeassertPowerBrake":true,"Description":"AC loss power policy","DocumentType":"power_policy","Id":"ACLossPolicy","Max":600,"Min":200,"Name":"AC Loss Policy","PolicyActions":"AssertPowerBrake","Type":"Inclusive","Unit":"Watts"}"#
        );

        let group: NvidiaManagedEntityGroupSchema =
            serde_json::from_str(NVIDIA_MANAGED_ENTITY_GROUP_BODY)?;
        assert_eq!(
            nvidia_managed_entity_group_projection(&group)?
                .payload()
                .as_str(),
            r#"{"CurrentManagedEntityId":"BF1","Description":"BlueField group","DocumentType":"managed_entity_group","Id":"1","Name":"Managed Entity Group One"}"#
        );

        let state_group: NvidiaPowerStateGroupSchema =
            serde_json::from_str(NVIDIA_POWER_STATE_GROUP_BODY)?;
        assert_eq!(
            nvidia_power_state_group_projection(&state_group)?
                .payload()
                .as_str(),
            r#"{"Description":"Power shelf state","DocumentType":"power_state_group","GeneratedWatts":2400,"Id":"PowerStateGroup","Name":"Power State Group","NumberOfLocalPsus":2,"NumberOfPscs":1,"PscId":"PSC1"}"#
        );

        let psc: NvidiaPscStateSchema = serde_json::from_str(NVIDIA_PSC_STATE_BODY)?;
        assert_eq!(
            nvidia_psc_state_projection(&psc)?.payload().as_str(),
            r#"{"Description":"PSC state","DocumentType":"psc_state","Id":"1","MillisecondsSinceLastHeartbeat":12,"Name":"Power Shelf Controller One","NumOfOperationalPsus":4,"PowerBrakeAssert":false,"PscId":"PSC1","Status":"Operational"}"#
        );

        let psu: NvidiaPsuStateSchema = serde_json::from_str(NVIDIA_PSU_STATE_BODY)?;
        assert_eq!(
            nvidia_psu_state_projection(&psu)?.payload().as_str(),
            r#"{"Description":"PSU state","DocumentType":"psu_state","Id":"1","Input1Active":true,"Input2Active":false,"Name":"Power Supply One","Presence":true,"PsuId":"PSU1"}"#
        );

        let redundancy: NvidiaPsuRedundancySchema =
            serde_json::from_str(NVIDIA_PSU_REDUNDANCY_BODY)?;
        assert_eq!(
            nvidia_psu_redundancy_projection(&redundancy)?
                .payload()
                .as_str(),
            r#"{"Description":"PSU redundancy settings","DocumentType":"psu_redundancy","Id":"PSURedundancy","MaxNumSupported":"4","MinNumNeeded":"2","Name":"PSU Redundancy","RedundancySetting":"NPlusOne"}"#
        );

        let entity: NvidiaManagedEntitySchema = serde_json::from_str(NVIDIA_MANAGED_ENTITY_BODY)?;
        assert_eq!(
            nvidia_managed_entity_projection(&entity)?
                .payload()
                .as_str(),
            r#"{"Description":"BlueField managed entity","DocumentType":"managed_entity","IPv4Address":"192.0.2.10","IPv6Address":"2001:db8::10","Id":"1","Name":"Managed Entity One","Port":443,"TransportProtocol":"HTTPS"}"#
        );
        let sparse_entity: NvidiaManagedEntitySchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1","Id":"1","Name":"Managed Entity One"}"#,
        )?;
        assert_eq!(
            nvidia_managed_entity_projection(&sparse_entity)?
                .payload()
                .as_str(),
            r#"{"DocumentType":"managed_entity","Id":"1","Name":"Managed Entity One"}"#
        );
        Ok(())
    }

    #[test]
    fn smc_document_projections_keep_the_typed_field_contract() -> Result<(), Box<dyn Error>> {
        // The compiled schemas are the type boundary: the typed boolean and
        // the vendor enum spelling are projected verbatim, and an absent
        // field is skipped on the wire instead of coerced.
        let sys_lockdown: SysLockdownSchema = serde_json::from_str(SUPERMICRO_SYS_LOCKDOWN_BODY)?;
        let projection = smc_sys_lockdown_projection(&sys_lockdown)?;
        assert_eq!(projection.feature(), ResourceFeature::OemSmcSysLockdown);
        assert_eq!(
            projection.odata_id().as_str(),
            "/redfish/v1/Managers/1/SysLockdown"
        );
        assert_eq!(
            projection.payload().as_str(),
            r#"{"SysLockdownEnabled":true}"#
        );
        let bare: SysLockdownSchema =
            serde_json::from_str(r#"{"@odata.id":"/redfish/v1/Managers/1/SysLockdown"}"#)?;
        assert_eq!(smc_sys_lockdown_projection(&bare)?.payload().as_str(), "{}");

        let kcs_interface: KcsInterfaceSchema =
            serde_json::from_str(SUPERMICRO_KCS_INTERFACE_BODY)?;
        let projection = smc_kcs_interface_projection(&kcs_interface)?;
        assert_eq!(projection.feature(), ResourceFeature::OemSmcKcsInterface);
        assert_eq!(
            projection.payload().as_str(),
            r#"{"Privilege":"Administrator"}"#
        );
        // The enum spelling stays exactly the vendor's wire value, including
        // the non-snake `DisableKCS` case (§12.3).
        let disable: KcsInterfaceSchema = serde_json::from_str(
            r#"{"@odata.id":"/redfish/v1/Managers/1/KCSInterface","Privilege":"DisableKCS"}"#,
        )?;
        assert_eq!(
            smc_kcs_interface_projection(&disable)?.payload().as_str(),
            r#"{"Privilege":"DisableKCS"}"#
        );
        let bare: KcsInterfaceSchema =
            serde_json::from_str(r#"{"@odata.id":"/redfish/v1/Managers/1/KCSInterface"}"#)?;
        assert_eq!(
            smc_kcs_interface_projection(&bare)?.payload().as_str(),
            "{}"
        );
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
    /// snapshots in particular carry the derived `MetricValuesCount` and the
    /// timestamped `MetricValues` readings; the `Status` key and the
    /// report-level `Timestamp`/`Context`/`ReportSequence` metadata of the
    /// fixture must never leave the gateway.
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
        // The fixture carries a two-entry `MetricValues` array: every reading
        // keeps its RFC 3339 `Timestamp` and the original `MetricValue` text,
        // while the per-entry `MetricId` stays out of the strictly
        // projectable field set. The report-level `Timestamp`/`Context`/
        // `ReportSequence` metadata and the (schema-absent) `Status` object
        // of the fixture never leave the gateway either.
        let report_values = report_payload["MetricValues"]
            .as_array()
            .ok_or("MetricValues must be an array")?;
        assert_eq!(report_values.len(), 2);
        assert_eq!(report_values[0]["Timestamp"], "2026-08-01T09:30:00Z");
        assert_eq!(report_values[0]["MetricValue"], "100");
        assert_eq!(report_values[0].get("MetricId"), None);
        assert_eq!(report_values[1]["Timestamp"], "2026-08-01T09:31:00Z");
        assert_eq!(report_values[1]["MetricValue"], "94");
        assert_eq!(report_payload.get("Status"), None);
        assert_eq!(report_payload.get("Timestamp"), None);
        assert_eq!(report_payload.get("Context"), None);
        assert_eq!(report_payload.get("ReportSequence"), None);
        let report_minimal_payload: serde_json::Value =
            serde_json::from_str(resources[11].payload().as_str())?;
        assert_eq!(report_minimal_payload["MetricValuesCount"], 0);
        // The empty `MetricValues` array of the minimal member is projected
        // as an empty array, not omitted, mirroring the derived zero count.
        assert_eq!(
            report_minimal_payload["MetricValues"],
            serde_json::json!([])
        );
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
    async fn reads_power_equipment_power_supplies_network_functions_and_environment_metrics()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_POWER_EQUIPMENT_ROOT_BODY,
            &[
                ("200 OK", SYSTEMS_WITH_MEMBER_BODY),
                ("200 OK", SYSTEM_BODY),
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", CHASSIS_WITH_POWER_AND_NETWORK_SURFACE_BODY),
                ("200 OK", NETWORK_ADAPTERS_BODY),
                ("200 OK", NETWORK_ADAPTER_BODY),
                ("200 OK", NETWORK_DEVICE_FUNCTIONS_WITH_MEMBERS_BODY),
                ("200 OK", NETWORK_DEVICE_FUNCTION_ONE_BODY),
                ("200 OK", ENVIRONMENT_METRICS_BODY),
                ("200 OK", POWER_SUBSYSTEM_BODY),
                ("200 OK", POWER_SUPPLIES_WITH_MEMBERS_BODY),
                ("200 OK", POWER_SUPPLY_ONE_BODY),
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", MANAGER_BODY),
                ("200 OK", POWER_EQUIPMENT_WITH_SHELVES_BODY),
                ("200 OK", POWER_SHELVES_WITH_MEMBERS_BODY),
                ("200 OK", POWER_SHELF_ONE_BODY),
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

        // The chassis member carries one adapter (projected by the
        // network-adapters family), the EnvironmentMetrics singleton, one
        // PowerSupply member, and one NetworkDeviceFunction member; the root
        // advertises the PowerEquipment service with one power-shelf member.
        // The adapter collection is fetched once and serves both the adapter
        // family and the functions behind its members.
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
                ResourceFeature::NetworkAdapters,
                ResourceFeature::NetworkDeviceFunctions,
                ResourceFeature::EnvironmentMetrics,
                ResourceFeature::PowerSupplies,
                ResourceFeature::Managers,
                ResourceFeature::PowerEquipment,
                ResourceFeature::PowerEquipment,
            ]
        );
        // The adapter member carries no fixture ETag, so its identity is
        // asserted directly instead of through the ETag-bearing helper.
        assert_eq!(
            resources[3].odata_id().as_str(),
            "/redfish/v1/Chassis/1/NetworkAdapters/1"
        );
        assert_network_device_function_projection(&resources[4])?;
        assert_environment_metrics_projection(&resources[5])?;
        assert_power_supply_projection(&resources[6])?;
        assert_power_equipment_projection(&resources[8])?;
        assert_power_shelf_projection(&resources[9])?;
        assert_session_requests(
            &server.finish_all().await?,
            &POWER_AND_ENVIRONMENT_FAMILY_REQUEST_PATHS,
        )?;
        Ok(())
    }

    /// Asserts the `PowerEquipment` service document projection carries only
    /// the common fields and its `Status`, with the collection navigation
    /// staying out of the snapshot.
    fn assert_power_equipment_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/PowerEquipment",
            "W/\"power-equipment-1\"",
            "Id",
            "PowerEquipment",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("PowerShelves"), None);
        Ok(())
    }

    /// Asserts the power-shelf member projection carries its `EquipmentType`
    /// and hardware identity exactly as published.
    fn assert_power_shelf_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/PowerEquipment/PowerShelves/1",
            "W/\"power-shelf-1\"",
            "EquipmentType",
            "PowerShelf",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["Manufacturer"], "Rutilus Test");
        assert_eq!(payload["FirmwareVersion"], "3.1.4");
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("PowerSupplies"), None);
        Ok(())
    }

    /// Asserts the `PowerSupply` member projection carries its type, capacity,
    /// hardware identity, and status exactly as published, with the
    /// input-range and output-rail bags staying out of the snapshot.
    fn assert_power_supply_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1",
            "W/\"power-supply-1\"",
            "PowerSupplyType",
            "AC",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["PowerCapacityWatts"], 1600.0);
        assert_eq!(payload["Manufacturer"], "Rutilus Test");
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("InputRanges"), None);
        assert_eq!(payload.get("OutputRails"), None);
        Ok(())
    }

    /// Asserts the `NetworkDeviceFunction` member projection carries its
    /// function type and enable flag exactly as published, with the
    /// protocol-specific configuration bags staying out of the snapshot.
    fn assert_network_device_function_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions/1",
            "W/\"ndf-1\"",
            "NetDevFuncType",
            "Ethernet",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["DeviceEnabled"], true);
        assert_eq!(payload["Status"]["Health"], "OK");
        assert_eq!(payload.get("Ethernet"), None);
        Ok(())
    }

    /// Asserts the `EnvironmentMetrics` singleton projection carries every
    /// embedded measurement through its excerpt reading shape: the readings
    /// and their `DataSourceUri` links, the fan-speed array, and the control
    /// `SetPoint` of `PowerLimitWatts`.
    fn assert_environment_metrics_projection(
        projection: &CoreResourceProjection,
    ) -> Result<(), Box<dyn Error>> {
        assert_projection(
            projection,
            "/redfish/v1/Chassis/1/EnvironmentMetrics",
            "W/\"env-metrics-1\"",
            "Id",
            "EnvironmentMetrics",
        )?;
        let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
        assert_eq!(payload["TemperatureCelsius"]["Reading"], 27.5);
        assert_eq!(
            payload["TemperatureCelsius"]["DataSourceUri"],
            "/redfish/v1/Chassis/1/Sensors/InletTemp"
        );
        assert_eq!(payload["HumidityPercent"]["Reading"], 45.0);
        assert_eq!(payload["FanSpeedsPercent"][0]["Reading"], 55.0);
        assert_eq!(payload["FanSpeedsPercent"][1]["Reading"], 60.0);
        assert_eq!(payload["PowerWatts"]["Reading"], 320.0);
        assert_eq!(payload["EnergykWh"]["Reading"], 1234.5);
        assert_eq!(payload["PowerLoadPercent"]["Reading"], 40.0);
        assert_eq!(payload["PowerLimitWatts"]["SetPoint"], 1800.0);
        assert_eq!(
            payload["PowerLimitWatts"]["DataSourceUri"],
            "/redfish/v1/Chassis/1/Controls/PowerLimit"
        );
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
    /// The System document for the NVIDIA OEM write tests: advertises the
    /// `Oem.Nvidia` segment with the `SystemConfigProfile` and `CPUDebugToken`
    /// navigations the write chains follow.
    const COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1",
        "Id":"1",
        "Name":"System One",
        "SystemType":"Physical",
        "Oem":{"Nvidia":{
            "@odata.type":"#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem",
            "SystemConfigProfile":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"},
            "CPUDebugToken":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken"}
        }}
    }"##;

    /// The `NvidiaSystemConfigProfile` document for write tests: advertises
    /// the `#NvidiaSystemConfigProfile.Update` and `#NvidiaSystemConfigProfile.FactoryReset`
    /// actions, plus the `Profiles` navigation the activate flow follows.
    const COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
        "Id":"SystemConfigProfile",
        "Name":"NVIDIA System Config Profile",
        "Profiles":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles"},
        "Actions":{
            "#NvidiaSystemConfigProfile.Update":{"target":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Actions/NvidiaSystemConfigProfile.Update"},
            "#NvidiaSystemConfigProfile.FactoryReset":{"target":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Actions/NvidiaSystemConfigProfile.FactoryReset"}
        }
    }"##;

    /// A `NvidiaSystemConfigProfile` document that advertises no actions at
    /// all, for the §13.3 step 2 capability-check pin.
    const COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_WITHOUT_ACTIONS_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
        "Id":"SystemConfigProfile",
        "Name":"NVIDIA System Config Profile"
    }"#;

    /// The `Profiles` collection of the NVIDIA profile write tests.
    const COMMAND_NVIDIA_PROFILES_COLLECTION_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
        "Id":"Profiles",
        "Name":"System Profile Collection",
        "Members":[{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"}]
    }"#;

    /// The profile member document for write tests: advertises the
    /// `#NvidiaSystemProfile.Activate` action.
    const COMMAND_NVIDIA_SYSTEM_PROFILE_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
        "Id":"1",
        "Name":"Default Profile",
        "Actions":{
            "#NvidiaSystemProfile.Activate":{"target":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/Actions/NvidiaSystemProfile.Activate"}
        }
    }"##;

    /// The `NvidiaDebugToken` document for write tests: advertises the
    /// `#NvidiaDebugToken.GenerateToken`, `.InstallToken`, and `.DisableToken`
    /// actions.
    const COMMAND_NVIDIA_DEBUG_TOKEN_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken",
        "Id":"CPUDebugToken",
        "Name":"Debug Token",
        "Actions":{
            "#NvidiaDebugToken.GenerateToken":{"target":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.GenerateToken"},
            "#NvidiaDebugToken.InstallToken":{"target":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.InstallToken"},
            "#NvidiaDebugToken.DisableToken":{"target":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.DisableToken"}
        }
    }"##;

    /// The Manager document for the NVIDIA OEM write tests: advertises the
    /// `Oem.Nvidia` segment with the `DebugTokenManagement` navigation.
    const COMMAND_MANAGER_WITH_NVIDIA_OEM_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Managers/1",
        "Id":"1",
        "Name":"Manager One",
        "ManagerType":"BMC",
        "Oem":{"Nvidia":{
            "@odata.type":"#NvidiaManager.v1_9_0.NvidiaManager",
            "DebugTokenManagement":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement"}
        }}
    }"##;

    /// The `NvidiaDebugTokenManagement` document for write tests: advertises
    /// the `#NvidiaDebugTokenManagement.EraseToken` action.
    const COMMAND_NVIDIA_DEBUG_TOKEN_MANAGEMENT_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement",
        "Id":"DebugTokenManagement",
        "Name":"Debug Token Management",
        "Actions":{
            "#NvidiaDebugTokenManagement.EraseToken":{"target":"/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement/Actions/NvidiaDebugTokenManagement.EraseToken"}
        }
    }"##;

    /// The Chassis document for the NVIDIA OEM write tests: advertises the
    /// `Oem.Nvidia` segment with the `PowerSmoothing` navigation.
    const COMMAND_CHASSIS_WITH_NVIDIA_OEM_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Chassis/1",
        "Id":"1",
        "Name":"Chassis One",
        "ChassisType":"RackMount",
        "Oem":{"Nvidia":{
            "@odata.type":"#NvidiaChassis.v1_4_0.NvidiaSmaChassis",
            "PowerSmoothing":{"@odata.id":"/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing"}
        }}
    }"##;

    /// The `NvidiaPowerSmoothing` document for write tests: advertises the
    /// `#NvidiaPowerSmoothing.ActivatePresetProfile` and `.ApplyAdminOverrides`
    /// actions.
    const COMMAND_NVIDIA_POWER_SMOOTHING_BODY: &str = r##"{
        "@odata.id":"/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing",
        "Id":"PowerSmoothing",
        "Name":"Power Smoothing",
        "Actions":{
            "#NvidiaPowerSmoothing.ActivatePresetProfile":{"target":"/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing/Actions/NvidiaPowerSmoothing.ActivatePresetProfile"},
            "#NvidiaPowerSmoothing.ApplyAdminOverrides":{"target":"/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing/Actions/NvidiaPowerSmoothing.ApplyAdminOverrides"}
        }
    }"##;

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
    async fn executes_nvidia_profile_update_through_the_typed_action_api()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                ("200 OK", COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
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
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::Update(ProfileFile::new(
                        r#"{"UUID":"11111111-2222-3333-4444-555555555555"}"#.to_owned(),
                    )),
                )),
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
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Actions/NvidiaSystemConfigProfile.Update",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            r#"{"ProfileFile":"{\"UUID\":\"11111111-2222-3333-4444-555555555555\"}"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_nvidia_profile_factory_reset_through_the_typed_action_api()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                ("200 OK", COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
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
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
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
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Actions/NvidiaSystemConfigProfile.FactoryReset",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            "{}",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_nvidia_profile_activate_through_the_member_action_api()
    -> Result<(), Box<dyn Error>> {
        // `#NvidiaSystemProfile.Activate` is bound to the profile member
        // documents, so the write navigates the decoded `Profiles` collection
        // to its first member before dispatching.
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                ("200 OK", COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
                ("200 OK", COMMAND_NVIDIA_PROFILES_COLLECTION_BODY),
                ("200 OK", COMMAND_NVIDIA_SYSTEM_PROFILE_BODY),
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
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::ActivateProfile,
                )),
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
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
                "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/Actions/NvidiaSystemProfile.Activate",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            "{}",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_nvidia_debug_token_generate_through_the_typed_action_api()
    -> Result<(), Box<dyn Error>> {
        // The GenerateToken action answers with the `BinaryTokenURI` entity,
        // so the write response is a handled `200` body, not a `204`.
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                ("200 OK", COMMAND_NVIDIA_DEBUG_TOKEN_BODY),
            ],
            http_response(
                "200 OK",
                r#"{"BinaryTokenURI":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Token"}"#,
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
                &RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::GenerateToken(TokenType::Frc),
                )),
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
                "/redfish/v1/Systems",
                "/redfish/v1/Systems/1",
                "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken",
                "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.GenerateToken",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            r#"{"TokenType":"FRC"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_nvidia_debug_token_install_and_disable_through_the_typed_action_api()
    -> Result<(), Box<dyn Error>> {
        for (command, action_path, body) in [
            (
                RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::InstallToken(TokenData::new(
                        "dG9rZW4tZGF0YQ==".to_owned(),
                    )),
                )),
                "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.InstallToken",
                r#"{"TokenData":"dG9rZW4tZGF0YQ=="}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::DisableToken,
                )),
                "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.DisableToken",
                "{}",
            ),
        ] {
            let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
                FULL_SERVICE_ROOT_BODY,
                &[
                    ("200 OK", FULL_SYSTEMS_BODY),
                    ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                    ("200 OK", COMMAND_NVIDIA_DEBUG_TOKEN_BODY),
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
                    &command,
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
                    "/redfish/v1/Systems",
                    "/redfish/v1/Systems/1",
                    "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken",
                    action_path,
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                "POST",
                body,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn executes_nvidia_erase_token_through_the_manager_chain() -> Result<(), Box<dyn Error>> {
        // `EraseToken` runs on the manager's `DebugTokenManagement` document,
        // so the navigation goes through the managers collection instead of
        // the systems collection.
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", COMMAND_MANAGER_WITH_NVIDIA_OEM_BODY),
                ("200 OK", COMMAND_NVIDIA_DEBUG_TOKEN_MANAGEMENT_BODY),
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
                &RedfishCommand::Oem(OemCommand::DebugToken(NvidiaDebugTokenCommand::EraseToken(
                    EraseToken::new(EraseType::EraseAll, TokenType::Frc),
                ))),
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
                "/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement",
                "/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement/Actions/NvidiaDebugTokenManagement.EraseToken",
                "/redfish/v1/SessionService/Sessions/1",
            ],
            "POST",
            r#"{"EraseType":"EraseAll","TokenType":"FRC"}"#,
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn executes_nvidia_power_smoothing_actions_through_the_typed_action_api()
    -> Result<(), Box<dyn Error>> {
        for (command, action_path, body) in [
            (
                RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ActivatePresetProfile(ProfileId::new(3)),
                )),
                "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing/Actions/NvidiaPowerSmoothing.ActivatePresetProfile",
                r#"{"ProfileId":3}"#,
            ),
            (
                RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
                )),
                "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing/Actions/NvidiaPowerSmoothing.ApplyAdminOverrides",
                "{}",
            ),
        ] {
            let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
                FULL_SERVICE_ROOT_BODY,
                &[
                    ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                    ("200 OK", COMMAND_CHASSIS_WITH_NVIDIA_OEM_BODY),
                    ("200 OK", COMMAND_NVIDIA_POWER_SMOOTHING_BODY),
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
                    &command,
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
                    "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing",
                    action_path,
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                "POST",
                body,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn nvidia_profile_update_accepts_a_task_and_surfaces_its_location()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                ("200 OK", COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
            ],
            http_response_with_headers(
                "202 Accepted",
                "",
                &[("Location", "/redfish/v1/TaskService/Tasks/1")],
            ),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let result = gateway
            .execute_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::Update(ProfileFile::new("{}".to_owned())),
                )),
            )
            .await;

        assert!(matches!(
            result,
            Err(CommandExecutionError::AsyncTaskAccepted { task_location })
                if task_location.to_string() == "/redfish/v1/TaskService/Tasks/1"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn rejects_nvidia_commands_when_the_oem_chain_is_not_advertised()
    -> Result<(), Box<dyn Error>> {
        // A system without `Oem.Nvidia` makes every system-segment face
        // provably unsupported, so the capability check rejects the command
        // after the member fetch and no write response is ever served.
        for command in [
            RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                NvidiaSystemConfigProfileCommand::Update(ProfileFile::new("{}".to_owned())),
            )),
            RedfishCommand::Oem(OemCommand::DebugToken(
                NvidiaDebugTokenCommand::GenerateToken(TokenType::Frc),
            )),
        ] {
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
                    &command,
                )
                .await;

            assert!(matches!(
                outcome,
                Err(CommandExecutionError::Rejected(
                    CommandRejection::CapabilityUnavailable
                ))
            ));
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_nvidia_profile_update_when_the_action_is_not_advertised()
    -> Result<(), Box<dyn Error>> {
        // The decoded profile service exists but advertises no actions, so
        // the §13.3 step 2 capability check rejects the command.
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY),
                (
                    "200 OK",
                    COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_WITHOUT_ACTIONS_BODY,
                ),
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
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::CapabilityUnavailable
            ))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn verifies_nvidia_oem_commands_by_re_reading_the_chain() -> Result<(), Box<dyn Error>> {
        // "Accepted" verification: the chain document the write targeted must
        // re-read without error, and no physical effect is asserted.
        for (command, paths, member, document) in [
            (
                RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
                [
                    "/redfish/v1",
                    "/redfish/v1/SessionService",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/Systems",
                    "/redfish/v1/Systems/1",
                    "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_NVIDIA_SYSTEM_CONFIG_PROFILE_BODY),
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::GenerateToken(TokenType::Frc),
                )),
                [
                    "/redfish/v1",
                    "/redfish/v1/SessionService",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/Systems",
                    "/redfish/v1/Systems/1",
                    "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken",
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                ("200 OK", FULL_SYSTEMS_BODY),
                ("200 OK", COMMAND_NVIDIA_DEBUG_TOKEN_BODY),
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(NvidiaDebugTokenCommand::EraseToken(
                    EraseToken::new(EraseType::EraseAll, TokenType::Frc),
                ))),
                [
                    "/redfish/v1",
                    "/redfish/v1/SessionService",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/Managers",
                    "/redfish/v1/Managers/1",
                    "/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement",
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                ("200 OK", MANAGERS_WITH_MEMBER_BODY),
                ("200 OK", COMMAND_NVIDIA_DEBUG_TOKEN_MANAGEMENT_BODY),
            ),
            (
                RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
                )),
                [
                    "/redfish/v1",
                    "/redfish/v1/SessionService",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/SessionService/Sessions",
                    "/redfish/v1/Chassis",
                    "/redfish/v1/Chassis/1",
                    "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing",
                    "/redfish/v1/SessionService/Sessions/1",
                ],
                ("200 OK", CHASSIS_WITH_MEMBER_BODY),
                ("200 OK", COMMAND_NVIDIA_POWER_SMOOTHING_BODY),
            ),
        ] {
            let member_body = (
                "200 OK",
                match paths[4] {
                    "/redfish/v1/Systems" => COMMAND_SYSTEM_WITH_NVIDIA_OEM_BODY,
                    "/redfish/v1/Managers" => COMMAND_MANAGER_WITH_NVIDIA_OEM_BODY,
                    "/redfish/v1/Chassis" => COMMAND_CHASSIS_WITH_NVIDIA_OEM_BODY,
                    _ => unreachable!("unexpected collection path"),
                },
            );
            let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
                FULL_SERVICE_ROOT_BODY,
                &[member, member_body, document],
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
    async fn verifies_nvidia_oem_commands_as_an_error_when_the_chain_is_absent()
    -> Result<(), Box<dyn Error>> {
        // A vanished `Oem.Nvidia` chain makes the re-read inconclusive: the
        // verifier reports the same `CapabilityUnavailable` error as the
        // reset families instead of fabricating a verdict.
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

        let verdict = gateway
            .verify_command(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
            )
            .await;

        assert!(matches!(
            verdict,
            Err(CommandVerificationError::CapabilityUnavailable)
        ));
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

    /// The `UpdateService` document for §14.3 update write tests: advertises
    /// the standard `MultipartHttpPushUri` upload endpoint, the
    /// upstream-retained legacy `HttpPushUri`, and the `SoftwareInventory`
    /// collection.
    const UPDATE_SERVICE_WITH_UPLOAD_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/UpdateService",
        "@odata.etag":"W/\"update-service-1\"",
        "Id":"UpdateService",
        "Name":"Update Service",
        "Description":"Firmware update service",
        "ServiceEnabled":true,
        "MaxImageSizeBytes":2147483648,
        "MultipartHttpPushUri":"/redfish/v1/UpdateService/MultipartUpdate",
        "HttpPushUri":"/redfish/v1/UpdateService/HTTPPushUri",
        "SoftwareInventory":{"@odata.id":"/redfish/v1/UpdateService/SoftwareInventory"}
    }"#;

    /// An `UpdateService` document that advertises the upload endpoints but
    /// no `SoftwareInventory` link, for the vanished-inventory verification
    /// case.
    const UPDATE_SERVICE_WITHOUT_INVENTORY_LINK_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/UpdateService",
        "Id":"UpdateService",
        "Name":"Update Service",
        "Description":"Firmware update service",
        "ServiceEnabled":true,
        "MultipartHttpPushUri":"/redfish/v1/UpdateService/MultipartUpdate",
        "HttpPushUri":"/redfish/v1/UpdateService/HTTPPushUri"
    }"#;

    /// The request order of one multipart firmware upload: the Session
    /// lifecycle around the `UpdateService` document fetch and the multipart
    /// `POST` onto the advertised `MultipartHttpPushUri`.
    const MULTIPART_UPDATE_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/UpdateService",
        "/redfish/v1/UpdateService/MultipartUpdate",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one legacy `HttpPushUri` direct push: identical
    /// to [`MULTIPART_UPDATE_REQUEST_PATHS`] except that the write targets
    /// the caller-selected push URI.
    const HTTP_PUSH_UPDATE_REQUEST_PATHS: [&str; 7] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/UpdateService",
        "/redfish/v1/UpdateService/HTTPPushUri",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// The request order of one §14.3 update verification: the Session
    /// lifecycle around the `UpdateService` document, the
    /// `SoftwareInventory` collection, and both member documents.
    const VERIFY_UPDATE_REQUEST_PATHS: [&str; 9] = [
        "/redfish/v1",
        "/redfish/v1/SessionService",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/SessionService/Sessions",
        "/redfish/v1/UpdateService",
        "/redfish/v1/UpdateService/SoftwareInventory",
        "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
        "/redfish/v1/UpdateService/SoftwareInventory/BMC",
        "/redfish/v1/SessionService/Sessions/1",
    ];

    /// One small in-memory firmware artifact fixture.
    ///
    /// The bytes are ASCII so the captured multipart body stays valid UTF-8
    /// for the structural assertions; the fixture body asserts the exact
    /// `UpdateFile` part content, which only works when the bytes survive a
    /// UTF-8 decode.
    fn firmware_artifact() -> UpdateArtifactUpload {
        UpdateArtifactUpload::new(
            "firmware-2026.bin".to_owned(),
            b"rutilus fixture firmware image".to_vec(),
        )
    }

    /// Asserts the request sequence of one update upload: the Session
    /// lifecycle around one token-authenticated upload `POST`.
    ///
    /// This mirrors [`assert_command_requests`] without the exact-body
    /// assertion, because the multipart upload body carries a random boundary
    /// and is asserted structurally by the dedicated helpers instead.
    fn assert_update_write_requests(
        requests: &[Vec<u8>],
        expected_paths: &[&str],
    ) -> Result<(), Box<dyn Error>> {
        assert_eq!(requests.len(), expected_paths.len());
        let last = requests.len().saturating_sub(1);
        let write_index = last.saturating_sub(1);
        for (index, (request, expected_path)) in requests.iter().zip(expected_paths).enumerate() {
            let request = std::str::from_utf8(request)?;
            let expected_method = match index {
                3 => "POST",
                value if value == write_index => "POST",
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

    /// Asserts the wire form of one multipart upload request: the
    /// `multipart/form-data` content type with a boundary, the Session token,
    /// and the structural body — the typed `UpdateParameters` JSON part
    /// before the named `UpdateFile` binary part carrying the artifact bytes.
    ///
    /// The boundary is random per request, so the body is asserted
    /// structurally instead of byte-exactly: part names, part content types,
    /// the parameter projection, and the exact artifact bytes.
    fn assert_multipart_write_request(
        request: &[u8],
        expected_path: &str,
        artifact_name: &str,
        artifact_bytes: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let request = std::str::from_utf8(request)?;
        assert!(request.starts_with(&format!("POST {expected_path} HTTP/1.1\r\n")));
        let content_type = request_header(request, "content-type").unwrap_or_default();
        assert!(
            content_type.starts_with("multipart/form-data; boundary="),
            "the upload must be a multipart request, content-type was {content_type:?}"
        );
        assert_eq!(
            request_header(request, "x-auth-token"),
            Some("test-session-token")
        );
        assert!(
            request_header(request, "authorization").is_none(),
            "the token-authenticated upload must not carry Basic credentials"
        );
        let body = request_body(request.as_bytes())
            .ok_or_else(|| io::Error::other("the multipart upload body was not captured"))?;
        let parameters_start = body
            .find("name=\"UpdateParameters\"")
            .ok_or_else(|| io::Error::other("the UpdateParameters part is missing"))?;
        let file_start = body
            .find("name=\"UpdateFile\"")
            .ok_or_else(|| io::Error::other("the UpdateFile part is missing"))?;
        assert!(
            parameters_start < file_start,
            "the UpdateParameters part must precede the UpdateFile part"
        );
        let parameters_part = &body[parameters_start..file_start];
        assert!(
            parameters_part.contains("application/json"),
            "the UpdateParameters part must be JSON: {parameters_part}"
        );
        assert!(
            parameters_part.contains("{}"),
            "the image-based update parameters must be empty: {parameters_part}"
        );
        let file_part = &body[file_start..];
        assert!(
            file_part.contains("application/octet-stream"),
            "the UpdateFile part must be a raw binary stream"
        );
        assert!(
            file_part.contains(&format!("filename=\"{artifact_name}\"")),
            "the UpdateFile part must carry the artifact file name"
        );
        let artifact_text = std::str::from_utf8(artifact_bytes)?;
        assert!(
            file_part.contains(artifact_text),
            "the UpdateFile part must carry the exact artifact bytes"
        );
        Ok(())
    }

    #[tokio::test]
    async fn uploads_artifact_through_the_typed_multipart_api() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[("200 OK", UPDATE_SERVICE_WITH_UPLOAD_BODY)],
            http_response("200 OK", ""),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                None,
            )
            .await?;

        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
        let requests = server.finish_all().await?;
        assert_update_write_requests(&requests, &MULTIPART_UPDATE_REQUEST_PATHS)?;
        assert_multipart_write_request(
            &requests[5],
            "/redfish/v1/UpdateService/MultipartUpdate",
            "firmware-2026.bin",
            b"rutilus fixture firmware image",
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn surfaces_a_multipart_upload_acceptance_as_an_async_task() -> Result<(), Box<dyn Error>>
    {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[("200 OK", UPDATE_SERVICE_WITH_UPLOAD_BODY)],
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
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                None,
            )
            .await;

        let task_location = match outcome {
            Err(CommandExecutionError::AsyncTaskAccepted { task_location }) => task_location,
            other => {
                return Err(format!(
                    "a 202 upload must surface as AsyncTaskAccepted, got {other:?}"
                )
                .into());
            }
        };
        assert_eq!(
            task_location.to_string(),
            "/redfish/v1/TaskService/Tasks/42"
        );
        Ok(())
    }

    #[tokio::test]
    async fn pushes_artifact_through_the_legacy_http_push_uri() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[("200 OK", UPDATE_SERVICE_WITH_UPLOAD_BODY)],
            http_response_with_headers(
                "202 Accepted",
                "",
                &[("Location", "/redfish/v1/TaskService/Tasks/7")],
            ),
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;
        let push_uri = ResourceODataId::parse("/redfish/v1/UpdateService/HTTPPushUri")?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                Some(&push_uri),
            )
            .await;

        let task_location = match outcome {
            Err(CommandExecutionError::AsyncTaskAccepted { task_location }) => task_location,
            other => {
                return Err(
                    format!("a 202 push must surface as AsyncTaskAccepted, got {other:?}").into(),
                );
            }
        };
        assert_eq!(task_location.to_string(), "/redfish/v1/TaskService/Tasks/7");
        let requests = server.finish_all().await?;
        assert_update_write_requests(&requests, &HTTP_PUSH_UPDATE_REQUEST_PATHS)?;
        let write = std::str::from_utf8(&requests[5])?;
        assert_eq!(
            request_header(write, "content-type"),
            Some("application/octet-stream"),
            "the legacy push sends the raw binary body without multipart"
        );
        assert_eq!(
            request_body(&requests[5]),
            Some("rutilus fixture firmware image"),
            "the legacy push body must be exactly the artifact bytes"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_update_when_the_update_service_link_is_absent() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_lifecycle_sequence(
            CORE_SERVICE_ROOT_BODY,
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                None,
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::CapabilityUnavailable
            ))
        ));
        // The capability check stops the sequence before any upload request.
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 5);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"POST /redfish/v1/UpdateService/"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_update_when_multipart_http_push_uri_is_not_advertised()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                None,
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
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"POST /redfish/v1/UpdateService/"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_update_when_http_push_uri_is_not_advertised() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;
        let push_uri = ResourceODataId::parse("/redfish/v1/UpdateService/HTTPPushUri")?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                Some(&push_uri),
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
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"POST /redfish/v1/UpdateService/"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_update_uploads_the_bmc_refuses() -> Result<(), Box<dyn Error>> {
        for (status, expected) in [
            ("401 Unauthorized", CommandRejection::AuthenticationFailed),
            ("403 Forbidden", CommandRejection::PermissionDenied),
            ("400 Bad Request", CommandRejection::RefusedByBmc),
        ] {
            let server = TestRedfishServer::start_raw_sequence(command_write_sequence(
                CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
                &[("200 OK", UPDATE_SERVICE_WITH_UPLOAD_BODY)],
                http_response(status, ""),
            ))
            .await?;
            let gateway = gateway_with_root(server.certificate.clone())?;
            let trust = system_ca_trust(&server.certificate)?;

            let outcome = gateway
                .execute_update(
                    &server.address,
                    &trust,
                    &CredentialUsername::parse("admin")?,
                    &SecretString::from("password"),
                    firmware_artifact(),
                    None,
                )
                .await;

            assert!(
                matches!(outcome, Err(CommandExecutionError::Rejected(reason)) if reason == expected),
                "a {status} upload response must be rejected as {expected}, got {outcome:?}"
            );
            assert_update_write_requests(
                &server.finish_all().await?,
                &MULTIPART_UPDATE_REQUEST_PATHS,
            )?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn rejects_an_upload_when_the_push_uri_is_cross_origin() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[("200 OK", UPDATE_SERVICE_WITH_UPLOAD_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;
        let push_uri = ResourceODataId::parse("https://192.0.2.10/upload")?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                firmware_artifact(),
                Some(&push_uri),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::InvalidCommandPayload
            ))
        ));
        // The §15.6 same-origin policy rejects the URI before transport: the
        // UpdateService document is read, then no upload request is ever sent.
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 6);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"POST /upload"))
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_update_with_a_control_character_artifact_name() -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(Vec::new()).await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let outcome = gateway
            .execute_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                UpdateArtifactUpload::new("firmware\n2026.bin".to_owned(), Vec::new()),
                None,
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::InvalidCommandPayload
            ))
        ));
        assert!(
            server.finish_all().await?.is_empty(),
            "a control character in the file name must be rejected before any network request"
        );
        Ok(())
    }

    #[test]
    fn update_file_name_validation_accepts_only_control_free_names() {
        for safe in ["firmware.bin", "firmware 2026.bin", "固件-2026.bin", "a"] {
            assert!(
                validate_update_file_name(safe),
                "name {safe:?} must be accepted"
            );
        }
        for unsafe_name in ["", "a\nb", "a\rb", "a\tb", "a\x7Fb", "\u{0}"] {
            assert!(
                !validate_update_file_name(unsafe_name),
                "name {unsafe_name:?} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn verifies_update_by_re_reading_the_software_inventory_family()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(vec![
            http_response("200 OK", CORE_WITH_UPDATE_SERVICE_ROOT_BODY),
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
            http_response("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
            http_response("200 OK", SOFTWARE_INVENTORY_WITH_MEMBERS_BODY),
            http_response("200 OK", SOFTWARE_INVENTORY_BIOS_BODY),
            http_response("200 OK", SOFTWARE_INVENTORY_BMC_BODY),
            http_response("204 No Content", ""),
        ])
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await?;

        assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
        assert_verification_requests(&server.finish_all().await?, &VERIFY_UPDATE_REQUEST_PATHS)?;
        Ok(())
    }

    #[tokio::test]
    async fn verifies_update_as_an_error_when_the_inventory_cannot_be_re_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
                ("500 Internal Server Error", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        assert!(
            matches!(verdict, Err(CommandVerificationError::ReReadFailed(_))),
            "an unreadable inventory proves nothing about the update: {verdict:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verifies_update_as_mismatched_when_the_update_service_link_is_gone()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_lifecycle_sequence(
            CORE_SERVICE_ROOT_BODY,
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        assert!(
            matches!(verdict, Ok(CommandVerificationOutcome::Mismatched)),
            "a vanished UpdateService link proves the inventory surface is absent: {verdict:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verifies_update_as_mismatched_when_the_inventory_surface_vanished()
    -> Result<(), Box<dyn Error>> {
        for (doc_status, doc_body) in [
            // The `UpdateService` document itself is gone.
            ("404 Not Found", "{}"),
            // The `UpdateService` document no longer advertises the
            // `SoftwareInventory` collection link.
            ("200 OK", UPDATE_SERVICE_WITHOUT_INVENTORY_LINK_BODY),
        ] {
            let responses = vec![
                http_response("200 OK", CORE_WITH_UPDATE_SERVICE_ROOT_BODY),
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
                http_response(doc_status, doc_body),
                http_response("204 No Content", ""),
            ];
            let server = TestRedfishServer::start_raw_sequence(responses).await?;
            let gateway = gateway_with_root(server.certificate.clone())?;
            let trust = system_ca_trust(&server.certificate)?;

            let verdict = gateway
                .verify_update(
                    &server.address,
                    &trust,
                    &CredentialUsername::parse("admin")?,
                    &SecretString::from("password"),
                )
                .await;

            assert!(
                matches!(verdict, Ok(CommandVerificationOutcome::Mismatched)),
                "an absent inventory surface is the provably absent expected result: {verdict:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn verifies_update_as_mismatched_when_the_inventory_collection_is_gone()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
                ("404 Not Found", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        assert!(
            matches!(verdict, Ok(CommandVerificationOutcome::Mismatched)),
            "a 404 from the collection proves the inventory surface is absent: {verdict:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verifies_update_as_an_error_when_an_inventory_member_cannot_be_read()
    -> Result<(), Box<dyn Error>> {
        let server = TestRedfishServer::start_raw_sequence(session_response_sequence(
            CORE_WITH_UPDATE_SERVICE_ROOT_BODY,
            &[
                ("200 OK", UPDATE_SERVICE_WITH_INVENTORY_BODY),
                ("200 OK", SOFTWARE_INVENTORY_WITH_MEMBERS_BODY),
                ("200 OK", SOFTWARE_INVENTORY_BIOS_BODY),
                ("500 Internal Server Error", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let verdict = gateway
            .verify_update(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
            )
            .await;

        assert!(
            matches!(verdict, Err(CommandVerificationError::ReReadFailed(_))),
            "an unreadable member leaves the outcome unprovable, never Mismatched: {verdict:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_update_commands_dispatched_through_the_typed_command_boundary()
    -> Result<(), Box<dyn Error>> {
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
                &RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                    rutilus_domain::ArtifactId::generate(),
                    None,
                ))),
            )
            .await;

        assert!(matches!(
            outcome,
            Err(CommandExecutionError::Rejected(
                CommandRejection::InvalidCommandPayload
            ))
        ));
        // The misrouted family is refused before any update request: only the
        // Session lifecycle requests were made.
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 5);
        assert!(
            requests
                .iter()
                .all(|request| !request.starts_with(b"POST /redfish/v1/UpdateService/"))
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // §14.4 Event SSE stream consumption
    // ------------------------------------------------------------------

    const EVENT_SERVICE_WITH_SSE_BODY: &str = r#"{
        "@odata.id":"/redfish/v1/EventService",
        "Id":"EventService",
        "Name":"Event Service",
        "ServerSentEventUri":"/redfish/v1/EventService/SSE"
    }"#;

    /// The one-shot responses of the Session lifecycle around one SSE
    /// connection: Service Root, `SessionService`, Sessions, Session create,
    /// `EventService` document, and the Session delete the stream's terminal
    /// phase sends. The SSE connection itself (index 5) is served by the
    /// streaming mock.
    fn sse_lifecycle_responses() -> Vec<Vec<u8>> {
        session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[("200 OK", EVENT_SERVICE_WITH_SSE_BODY)],
        )
    }

    fn sse_frame(payload: &str) -> Vec<u8> {
        format!("data: {payload}\r\n\r\n").into_bytes()
    }

    /// One Redfish SSE frame carrying an `Event` resource with the given
    /// `Events` array.
    fn event_frame(records: &serde_json::Value) -> Vec<u8> {
        sse_frame(
            &serde_json::json!({
                "@odata.type": "#Event.v1_6_0.Event",
                "@odata.id": "/redfish/v1/EventService/SSE#/Event1",
                "Id": "1",
                "Name": "Event Array",
                "Context": "rutilus",
                "Events": records,
            })
            .to_string(),
        )
    }

    // The stream-under-test drives every mapping decision in one place, so
    // the scenario stays readable as one sequence instead of scattered
    // fragments.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn streams_events_with_severity_mapping_timestamp_fallback_and_refusals()
    -> Result<(), Box<dyn Error>> {
        let records_with_bmc_time = serde_json::json!([
            {
                "@odata.id": "/redfish/v1/EventService/SSE#/Events/1",
                "MemberId": "1",
                "EventId": "e1",
                "EventType": "Alert",
                "EventTimestamp": "2026-02-19T03:55:29+00:00",
                "Message": "The resource has been removed successfully.",
                "MessageId": "ResourceEvent.1.2.ResourceRemoved",
                // The service-provided `Severity` string replaces the
                // registry's `MessageSeverity`.
                "MessageSeverity": "OK",
                "Severity": "Warning"
            },
            {
                "@odata.id": "/redfish/v1/EventService/SSE#/Events/2",
                "MemberId": "2",
                "EventId": "e2",
                "EventType": "Alert",
                // No EventTimestamp: the domain event must fall back to the
                // product receive time.
                "Message": "A power supply lost input",
                "MessageId": "Alert.1.0.PowerSupplyFailure",
                "MessageSeverity": "Critical"
            },
            // A bare reference carries no event payload and is skipped.
            {
                "@odata.id": "/redfish/v1/EventService/SSE#/Events/99"
            }
        ]);
        let unclassifiable_severity = serde_json::json!([
            {
                "@odata.id": "/redfish/v1/EventService/SSE#/Events/4",
                "MemberId": "4",
                "EventId": "e4",
                "EventType": "Other",
                "MessageId": "Vendor.1.0.CustomSeverity",
                "Severity": "vendor-specific"
            }
        ]);
        let future_timestamp = serde_json::json!([
            {
                "@odata.id": "/redfish/v1/EventService/SSE#/Events/5",
                "MemberId": "5",
                "EventId": "e5",
                "EventType": "Alert",
                // The BMC clock runs ahead of the product clock: the
                // timeline rejection drops the record instead of clamping
                // it (§9.3 refuses an inverted timeline).
                "EventTimestamp": "2030-01-01T00:00:00+00:00",
                "Message": "The resource has been updated successfully.",
                "MessageId": "ResourceEvent.1.2.ResourceUpdated",
                "Severity": "OK"
            }
        ]);
        let metric_report = sse_frame(
            &serde_json::json!({
                "@odata.type": "#MetricReport.v1_3_0.MetricReport",
                "@odata.id": "/redfish/v1/TelemetryService/MetricReports/AvgPlatformPowerUsage",
                "Id": "AvgPlatformPowerUsage",
                "Name": "Average Platform Power Usage metric report",
                "MetricReportDefinition": {
                    "@odata.id": "/redfish/v1/TelemetryService/MetricReportDefinitions/AvgPlatformPowerUsage"
                },
                "MetricValues": [
                    {
                        "MetricId": "AverageConsumedWatts",
                        "MetricValue": "100",
                        "Timestamp": "2016-11-08T12:25:00-05:00",
                        "MetricProperty": "/redfish/v1/Chassis/Tray_1/Power#/0/PowerConsumedWatts"
                    }
                ]
            })
            .to_string(),
        );

        let server = TestSseServer::start_sse(
            sse_lifecycle_responses(),
            5,
            vec![
                event_frame(&records_with_bmc_time),
                metric_report,
                event_frame(&unclassifiable_severity),
                event_frame(&future_timestamp),
            ],
            SseEnd::Clean,
        )
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;
        let endpoint_id = EndpointId::generate();

        let mut stream = gateway
            .open_event_stream(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                endpoint_id,
                CancellationToken::new(),
            )
            .await?;

        let first = stream
            .next()
            .await
            .ok_or_else(|| io::Error::other("expected the first event"))??;
        assert_eq!(first.endpoint_id(), endpoint_id);
        assert_eq!(first.event().endpoint_id(), endpoint_id);
        assert_eq!(
            first.event().message_id().as_str(),
            "ResourceEvent.1.2.ResourceRemoved"
        );
        assert_eq!(
            first.event().severity(),
            EventSeverity::Warning,
            "the service-provided `Severity` must win over `MessageSeverity`"
        );
        assert_eq!(
            first.event().message(),
            Some("The resource has been removed successfully.")
        );
        assert_eq!(
            first.event().event_timestamp(),
            OffsetDateTime::parse("2026-02-19T03:55:29+00:00", &Rfc3339)?
        );

        let second = stream
            .next()
            .await
            .ok_or_else(|| io::Error::other("expected the second event"))??;
        assert_eq!(second.endpoint_id(), endpoint_id);
        assert_eq!(
            second.event().message_id().as_str(),
            "Alert.1.0.PowerSupplyFailure"
        );
        assert_eq!(
            second.event().severity(),
            EventSeverity::Critical,
            "`MessageSeverity` must fill in when `Severity` is absent"
        );
        assert_eq!(
            second.event().event_timestamp(),
            second.event().observed_at(),
            "a record without `EventTimestamp` must fall back to the receive time"
        );

        assert!(
            stream.next().await.is_none(),
            "the cleanly closed stream must end without an error; the vendor-severity \
             record, the future-timestamp record, the bare reference, and the metric \
             report must all be refused or skipped while the stream stays alive"
        );

        let requests = server.finish_all().await?;
        assert_session_requests(
            &requests,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/EventService",
                "/redfish/v1/EventService/SSE",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;
        // The SSE request itself carried the Session token and the
        // event-stream accept header on the typed `ServerSentEventUri`.
        let sse_request = std::str::from_utf8(&requests[5])?;
        assert!(sse_request.starts_with("GET /redfish/v1/EventService/SSE HTTP/1.1\r\n"));
        assert_eq!(
            request_header(sse_request, "accept"),
            Some("text/event-stream")
        );
        assert_eq!(
            request_header(sse_request, "x-auth-token"),
            Some("test-session-token")
        );
        Ok(())
    }

    #[tokio::test]
    async fn skips_malformed_events_and_keeps_the_stream_alive() -> Result<(), Box<dyn Error>> {
        let malformed = sse_frame(
            &serde_json::json!({
                "@odata.type": "#Event.v1_6_0.Event",
                "Events": [{"MessageId": 42}]
            })
            .to_string(),
        );
        let valid_records = serde_json::json!([
            {
                "@odata.id": "/redfish/v1/EventService/SSE#/Events/1",
                "MemberId": "1",
                "EventType": "Alert",
                "MessageId": "ResourceEvent.1.2.ResourceRemoved",
                "MessageSeverity": "OK"
            }
        ]);
        let valid = event_frame(&valid_records);

        let server = TestSseServer::start_sse(
            sse_lifecycle_responses(),
            5,
            vec![malformed, valid],
            SseEnd::Clean,
        )
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let mut stream = gateway
            .open_event_stream(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                EndpointId::generate(),
                CancellationToken::new(),
            )
            .await?;

        let event = stream
            .next()
            .await
            .ok_or_else(|| io::Error::other("expected the event after the malformed one"))??;
        assert_eq!(
            event.event().message_id().as_str(),
            "ResourceEvent.1.2.ResourceRemoved",
            "a malformed event must be dropped without ending the stream"
        );
        assert!(stream.next().await.is_none());
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 7);
        Ok(())
    }

    #[tokio::test]
    async fn classifies_an_abruptly_interrupted_stream_as_reconnectable()
    -> Result<(), Box<dyn Error>> {
        let server = TestSseServer::start_sse(
            sse_lifecycle_responses(),
            5,
            vec![{
                let records = serde_json::json!([
                {
                    "@odata.id": "/redfish/v1/EventService/SSE#/Events/1",
                    "MemberId": "1",
                    "EventType": "Alert",
                    "MessageId": "ResourceEvent.1.2.ResourceRemoved",
                    "MessageSeverity": "OK"
                }
                ]);
                event_frame(&records)
            }],
            SseEnd::Abrupt,
        )
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let mut stream = gateway
            .open_event_stream(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                EndpointId::generate(),
                CancellationToken::new(),
            )
            .await?;

        let event = stream
            .next()
            .await
            .ok_or_else(|| io::Error::other("expected the event before the interruption"))??;
        assert_eq!(
            event.event().message_id().as_str(),
            "ResourceEvent.1.2.ResourceRemoved"
        );
        assert!(
            matches!(
                stream.next().await,
                Some(Err(EventStreamError::Reconnectable(_)))
            ),
            "an EOF before the terminating chunk is a transport failure, not a clean end"
        );
        assert!(stream.next().await.is_none());
        // The terminal phase deleted the Session even though the stream
        // failed, so the reconnect loop starts from a clean slate.
        let requests = server.finish_all().await?;
        assert_session_requests(
            &requests,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/EventService",
                "/redfish/v1/EventService/SSE",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn classifies_sse_framing_decode_failures_as_reconnectable() -> Result<(), Box<dyn Error>>
    {
        // A line without a `:` is invalid SSE framing; the upstream decoder
        // terminates the stream with `SseStreamError`.
        let malformed_framing =
            b"data: {\"@odata.type\":\"#Event.v1_6_0.Event\",\"Events\":[]}\r\nno-colon-line\r\n\r\n"
                .to_vec();
        let server = TestSseServer::start_sse(
            sse_lifecycle_responses(),
            5,
            vec![malformed_framing],
            SseEnd::Clean,
        )
        .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;

        let mut stream = gateway
            .open_event_stream(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                EndpointId::generate(),
                CancellationToken::new(),
            )
            .await?;

        assert!(
            matches!(
                stream.next().await,
                Some(Err(EventStreamError::Reconnectable(_)))
            ),
            "an undecodable SSE stream is a reconnectable failure, not a terminal one"
        );
        assert!(stream.next().await.is_none());
        let requests = server.finish_all().await?;
        assert_eq!(requests.len(), 7);
        Ok(())
    }

    #[test]
    fn classifies_an_oversized_sse_event_as_terminal() {
        // The 1 MiB per-event budget is a compiled upstream default that no
        // gateway configuration can change, so an event that exceeds it is
        // deterministic for the endpoint: every reconnect reproduces the
        // same refusal, and a reconnect loop would churn instead of
        // recovering. The classification must therefore be terminal, not
        // reconnectable.
        let oversized = nv_redfish::Error::Bmc(BmcError::SseEventTooLarge { limit: 1024 * 1024 });

        assert!(
            matches!(
                classify_event_stream_error(oversized),
                EventStreamError::Terminal(RedfishServiceRootError::Upstream(
                    nv_redfish::Error::Bmc(BmcError::SseEventTooLarge { .. })
                ))
            ),
            "an event over the fixed budget must terminate the stream, never prompt a reconnect"
        );
    }

    #[tokio::test]
    async fn deletes_the_session_when_the_stream_is_cancelled() -> Result<(), Box<dyn Error>> {
        let server =
            TestSseServer::start_sse(sse_lifecycle_responses(), 5, Vec::new(), SseEnd::HoldOpen)
                .await?;
        let gateway = gateway_with_root(server.certificate.clone())?;
        let trust = system_ca_trust(&server.certificate)?;
        let cancel = CancellationToken::new();

        let mut stream = gateway
            .open_event_stream(
                &server.address,
                &trust,
                &CredentialUsername::parse("admin")?,
                &SecretString::from("password"),
                EndpointId::generate(),
                cancel.clone(),
            )
            .await?;

        cancel.cancel();
        assert!(
            timeout(Duration::from_secs(5), stream.next())
                .await?
                .is_none(),
            "a cancelled stream must reach its terminal state promptly"
        );
        drop(stream);
        // The terminal phase deleted the Session despite the stream having
        // produced nothing: the mock's SSE connection saw the client close,
        // and the Session DELETE arrived on a fresh connection.
        let requests = server.finish_all().await?;
        assert_session_requests(
            &requests,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/EventService",
                "/redfish/v1/EventService/SSE",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn classifies_event_stream_open_failures() -> Result<(), Box<dyn Error>> {
        let expected_paths = [
            "/redfish/v1",
            "/redfish/v1/SessionService",
            "/redfish/v1/SessionService/Sessions",
            "/redfish/v1/SessionService/Sessions",
            "/redfish/v1/EventService",
            "/redfish/v1/EventService/SSE",
            "/redfish/v1/SessionService/Sessions/1",
        ];
        let credentials = (
            CredentialUsername::parse("admin")?,
            SecretString::from("password"),
        );

        // A 5xx on the SSE request is transient: reopening may succeed.
        let transient = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", EVENT_SERVICE_WITH_SSE_BODY),
                ("500 Internal Server Error", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(transient.certificate.clone())?;
        let trust = system_ca_trust(&transient.certificate)?;
        assert!(
            matches!(
                gateway
                    .open_event_stream(
                        &transient.address,
                        &trust,
                        &credentials.0,
                        &credentials.1,
                        EndpointId::generate(),
                        CancellationToken::new(),
                    )
                    .await,
                Err(EventStreamOpenError::Reconnectable(_))
            ),
            "a 5xx SSE response is a reconnectable open failure"
        );
        assert_session_requests(&transient.finish_all().await?, &expected_paths)?;

        // A 403 on the SSE request is an authorization decision: retrying
        // with the same account cannot succeed.
        let forbidden = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[
                ("200 OK", EVENT_SERVICE_WITH_SSE_BODY),
                ("403 Forbidden", "{}"),
            ],
        ))
        .await?;
        let gateway = gateway_with_root(forbidden.certificate.clone())?;
        let trust = system_ca_trust(&forbidden.certificate)?;
        assert!(
            matches!(
                gateway
                    .open_event_stream(
                        &forbidden.address,
                        &trust,
                        &credentials.0,
                        &credentials.1,
                        EndpointId::generate(),
                        CancellationToken::new(),
                    )
                    .await,
                Err(EventStreamOpenError::Terminal(_))
            ),
            "a 403 SSE response is a terminal open failure"
        );
        // Both failures deleted the Session created for the failed open.
        assert_session_requests(&forbidden.finish_all().await?, &expected_paths)?;
        Ok(())
    }

    #[tokio::test]
    async fn refuses_to_open_a_stream_without_an_sse_surface() -> Result<(), Box<dyn Error>> {
        // No EventService link on the Service Root: nothing to stream.
        let without_event_service = TestRedfishServer::start_raw_sequence(
            session_lifecycle_sequence(CORE_SERVICE_ROOT_BODY),
        )
        .await?;
        let gateway = gateway_with_root(without_event_service.certificate.clone())?;
        let trust = system_ca_trust(&without_event_service.certificate)?;
        assert!(
            matches!(
                gateway
                    .open_event_stream(
                        &without_event_service.address,
                        &trust,
                        &CredentialUsername::parse("admin")?,
                        &SecretString::from("password"),
                        EndpointId::generate(),
                        CancellationToken::new(),
                    )
                    .await,
                Err(EventStreamOpenError::EventServiceNotAdvertised)
            ),
            "a root without EventService must refuse the stream, not guess a path"
        );
        // The Session created before the capability check was deleted.
        assert_session_requests(
            &without_event_service.finish_all().await?,
            &[
                "/redfish/v1",
                "/redfish/v1/SessionService",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions",
                "/redfish/v1/SessionService/Sessions/1",
            ],
        )?;

        // EventService exists but exposes no ServerSentEventUri.
        let without_sse_uri = TestRedfishServer::start_raw_sequence(session_response_sequence(
            FULL_SERVICE_ROOT_BODY,
            &[("200 OK", EVENT_SERVICE_BODY)],
        ))
        .await?;
        let gateway = gateway_with_root(without_sse_uri.certificate.clone())?;
        let trust = system_ca_trust(&without_sse_uri.certificate)?;
        assert!(
            matches!(
                gateway
                    .open_event_stream(
                        &without_sse_uri.address,
                        &trust,
                        &CredentialUsername::parse("admin")?,
                        &SecretString::from("password"),
                        EndpointId::generate(),
                        CancellationToken::new(),
                    )
                    .await,
                Err(EventStreamOpenError::ServerSentEventsUnavailable)
            ),
            "an EventService without an SSE URI must refuse the stream"
        );
        let requests = without_sse_uri.finish_all().await?;
        assert_eq!(requests.len(), 6);
        assert!(requests[5].starts_with(b"DELETE /redfish/v1/SessionService/Sessions/1"));
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

    /// How a mock SSE connection ends.
    #[derive(Clone, Copy)]
    enum SseEnd {
        /// Send the terminating `0` chunk: the client observes a clean end.
        Clean,
        /// Close without the terminating chunk: the client's chunked
        /// decoder fails, which is how a mid-stream network drop is
        /// observed.
        Abrupt,
        /// Keep the connection open until the client closes it (used by
        /// cancellation tests).
        HoldOpen,
    }

    /// A TLS test server that streams SSE frames on one connection.
    ///
    /// The `sse_index`-th connection (0-based, in client request order)
    /// answers with a chunked `text/event-stream` response carrying `frames`
    /// and ending per `end`; every other connection serves one `responses`
    /// entry with `Connection: close`, exactly like `TestRedfishServer`.
    struct TestSseServer {
        address: EndpointAddress,
        certificate: CertificateDer<'static>,
        task: JoinHandle<Result<Vec<Vec<u8>>, io::Error>>,
    }

    impl TestSseServer {
        async fn start_sse(
            responses: Vec<Vec<u8>>,
            sse_index: usize,
            frames: Vec<Vec<u8>>,
            end: SseEnd,
        ) -> Result<Self, Box<dyn Error>> {
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
            let task = tokio::spawn(run_sse_server(
                listener, acceptor, responses, sse_index, frames, end,
            ));
            Ok(Self {
                address: endpoint_address(socket, "localhost")?,
                certificate,
                task,
            })
        }

        async fn finish_all(self) -> Result<Vec<Vec<u8>>, Box<dyn Error>> {
            Ok(self.task.await??)
        }
    }

    async fn run_sse_server(
        listener: TcpListener,
        acceptor: TlsAcceptor,
        responses: Vec<Vec<u8>>,
        sse_index: usize,
        frames: Vec<Vec<u8>>,
        end: SseEnd,
    ) -> Result<Vec<Vec<u8>>, io::Error> {
        let total_connections = responses.len() + 1;
        let mut responses = responses.into_iter();
        let mut requests = Vec::with_capacity(total_connections);
        for connection in 0..total_connections {
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
            requests.push(request);
            if connection == sse_index {
                write_sse_response(&mut stream, &frames, end).await?;
            } else {
                let Some(response) = responses.next() else {
                    // The response plan is exhausted; close the connection so
                    // the client observes a clean EOF instead of a hang.
                    stream.shutdown().await?;
                    continue;
                };
                if response.is_empty() {
                    // An empty response encodes a dropped connection, like
                    // `run_server_sequence`.
                    continue;
                }
                stream.write_all(&response).await?;
                stream.shutdown().await?;
            }
        }
        Ok(requests)
    }

    /// Writes one chunked `text/event-stream` response and ends it per
    /// `end`.
    ///
    /// Mid-stream read and write failures are tolerated: they are expected
    /// whenever the client aborts the stream (cancellation and abrupt-drop
    /// tests), so the server task reports the captured requests instead of
    /// the client's close.
    async fn write_sse_response(
        stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        frames: &[Vec<u8>],
        end: SseEnd,
    ) -> Result<(), io::Error> {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await?;
        for frame in frames {
            let header = format!("{:x}\r\n", frame.len());
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(frame).await?;
            stream.write_all(b"\r\n").await?;
        }
        match end {
            SseEnd::Clean => {
                stream.write_all(b"0\r\n\r\n").await?;
                stream.shutdown().await?;
            }
            SseEnd::Abrupt => {
                let _ = stream.shutdown().await;
            }
            SseEnd::HoldOpen => {
                let mut chunk = [0_u8; 1024];
                loop {
                    let bytes = timeout(Duration::from_secs(5), stream.read(&mut chunk))
                        .await
                        .map_err(|_| {
                            io::Error::new(io::ErrorKind::TimedOut, "test SSE hold-open")
                        })??;
                    if bytes == 0 {
                        break;
                    }
                }
                let _ = stream.shutdown().await;
            }
        }
        Ok(())
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
