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
        assembly::Assembly as AssemblySchema, assembly::AssemblyData as AssemblyDataSchema,
        bios::Bios as BiosSchema, boot_option::BootOption as BootOptionSchema,
        boot_option_collection::BootOptionCollection as BootOptionCollectionSchema,
        chassis::Chassis as ChassisSchema,
        chassis_collection::ChassisCollection as ChassisCollectionSchema,
        computer_system::ComputerSystem as ComputerSystemSchema,
        computer_system_collection::ComputerSystemCollection as ComputerSystemCollectionSchema,
        control::Control as ControlSchema,
        control_collection::ControlCollection as ControlCollectionSchema,
        ethernet_interface::EthernetInterface as EthernetInterfaceSchema,
        ethernet_interface_collection::EthernetInterfaceCollection as EthernetInterfaceCollectionSchema,
        host_interface::HostInterface as HostInterfaceSchema,
        host_interface_collection::HostInterfaceCollection as HostInterfaceCollectionSchema,
        log_service::LogService as LogServiceSchema,
        log_service_collection::LogServiceCollection as LogServiceCollectionSchema,
        manager::Manager as ManagerSchema, manager_account::ManagerAccount as ManagerAccountSchema,
        manager_account_collection::ManagerAccountCollection as ManagerAccountCollectionSchema,
        manager_collection::ManagerCollection as ManagerCollectionSchema,
        manager_network_protocol::ManagerNetworkProtocol as ManagerNetworkProtocolSchema,
        memory::Memory as MemorySchema,
        memory_collection::MemoryCollection as MemoryCollectionSchema,
        network_adapter::NetworkAdapter as NetworkAdapterSchema,
        network_adapter_collection::NetworkAdapterCollection as NetworkAdapterCollectionSchema,
        pcie_device::PcieDevice as PcieDeviceSchema, power::Power as PowerSchema,
        processor::Processor as ProcessorSchema,
        processor_collection::ProcessorCollection as ProcessorCollectionSchema,
        resource::Resource as ResourceSchema, secure_boot::SecureBoot as SecureBootSchema,
        sensor::Sensor as SensorSchema,
        sensor_collection::SensorCollection as SensorCollectionSchema,
        software_inventory::SoftwareInventory as SoftwareInventorySchema,
        software_inventory_collection::SoftwareInventoryCollection as SoftwareInventoryCollectionSchema,
        storage::Storage as StorageSchema,
        storage_collection::StorageCollection as StorageCollectionSchema,
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
    /// Memory, Storage, `NetworkAdapters`, `EthernetInterfaces`, `Accounts`,
    /// `Bios`, `BootOptions`, `SecureBoot`, `Power`, `Thermal`, `Sensors`,
    /// `Controls`, `LogServices`, `ManagerNetworkProtocol`, and
    /// `HostInterfaces` families) through public, typed `nv-redfish`
    /// navigation and returns bounded domain projections.
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
    resources.extend(read_account_resources(bmc, root, identity, trust).await?);
    resources.extend(read_software_inventory_resources(bmc, root, identity, trust).await?);
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
