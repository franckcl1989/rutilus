use std::error::Error;

use rutilus_domain::{
    Endpoint, EndpointId, RefreshGeneration, ResourceEtag, ResourceFeature, ResourceId,
    ResourceODataId, ResourceODataType, ResourceSnapshot,
};
use serde::Deserialize;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{EndpointInventoryQuery, EndpointInventoryQueryError, EndpointInventoryRepository};

/// Product-level fields shared by every typed core Redfish resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoreResourceCommon {
    id: String,
    name: String,
    description: Option<String>,
}

impl CoreResourceCommon {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// Original typed Redfish status values retained without normalization loss.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceStatusSummary {
    state: Option<String>,
    health: Option<String>,
    health_rollup: Option<String>,
}

impl ResourceStatusSummary {
    #[must_use]
    pub fn state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    #[must_use]
    pub fn health(&self) -> Option<&str> {
        self.health.as_deref()
    }

    #[must_use]
    pub fn health_rollup(&self) -> Option<&str> {
        self.health_rollup.as_deref()
    }
}

/// One timestamped reading of a `MetricReport` member, retained without
/// normalization loss: `timestamp` keeps the RFC 3339 instant of the compiled
/// `Edm.DateTimeOffset` type and `value` the original text of the compiled
/// `Edm.String` type (the DMTF schema represents numeric readings as
/// strings, so a numeric projection would lose the non-numeric boolean and
/// array representations).
#[derive(Clone, Debug, PartialEq)]
pub struct MetricValueSummary {
    timestamp: Option<OffsetDateTime>,
    value: Option<String>,
}

impl MetricValueSummary {
    #[must_use]
    pub const fn new(timestamp: Option<OffsetDateTime>, value: Option<String>) -> Self {
        Self { timestamp, value }
    }

    #[must_use]
    pub const fn timestamp(&self) -> Option<OffsetDateTime> {
        self.timestamp
    }

    #[must_use]
    pub fn value(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

/// Feature-specific fields from one public `nv-redfish` typed projection.
///
/// `PartialEq` (not `Eq`) is deliberate: the Sensor and Control variants
/// carry numeric readings (`f64`, matching the compiled `Edm.Decimal` type
/// of nv-redfish 0.13), and `f64` cannot implement `Eq`.
#[derive(Clone, Debug, PartialEq)]
pub enum CoreResourceDetails {
    ServiceRoot {
        vendor: Option<String>,
        product: Option<String>,
        redfish_version: Option<String>,
    },
    System {
        system_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        sku: Option<String>,
        host_name: Option<String>,
        bios_version: Option<String>,
        power_state: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    Chassis {
        chassis_type: String,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        sku: Option<String>,
        asset_tag: Option<String>,
        power_state: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    Manager {
        manager_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        firmware_version: Option<String>,
        version: Option<String>,
        power_state: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §0.5.0 OEM family member: the manager's Dell `DellAttributes`
    /// document, read through the nv-redfish `oem-dell-attributes` typed
    /// surface (§11.5 — an OEM surface is projected only when upstream
    /// compiles it). The identity fields are the five Dell iDRAC attributes
    /// the product pins; every other entry of the vendor-specific dynamic
    /// attribute bag stays out exactly like the `Bios` family keeps its
    /// `Attributes` bag out, and each value is the typed string of the
    /// compiled `Edm.String` type — never raw JSON.
    OemDell {
        server_model: Option<String>,
        server_service_tag: Option<String>,
        server_generation: Option<String>,
        server_bmc_mac_address: Option<String>,
        server_name: Option<String>,
    },
    /// One §0.5.0 Supermicro OEM family member: the manager's `SysLockdown`
    /// document, read through the compiled `oem-supermicro` surface (§11.5 —
    /// an OEM surface is projected only when upstream compiles it). The
    /// `SysLockdownEnabled` boolean is the document's only substantive typed
    /// field; the compiled schema models no `Id` / `Name` / `Description`, so
    /// the product identity is derived from the snapshot's `@odata.id` (the
    /// Redfish `Id` equals the final path segment per DSP0266) and stays out
    /// of the wire payload, whose field set is exactly what the infra
    /// projection wrote.
    OemSmcSysLockdown { sys_lockdown_enabled: Option<bool> },
    /// One §0.5.0 Supermicro OEM family member: the manager's `KCSInterface`
    /// document, read through the compiled `oem-supermicro` surface (§11.5).
    /// The `Privilege` value is the vendor's enum spelling verbatim (e.g.
    /// `Administrator`, `DisableKCS`); the compiled schema models no `Id` /
    /// `Name` / `Description`, so the product identity is derived from the
    /// snapshot's `@odata.id` (the Redfish `Id` equals the final path segment
    /// per DSP0266) and stays out of the wire payload, whose field set is
    /// exactly what the infra projection wrote.
    OemSmcKcsInterface { privilege: Option<String> },
    Processor {
        processor_type: Option<String>,
        socket: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        total_cores: Option<u64>,
        status: Option<ResourceStatusSummary>,
    },
    Memory {
        memory_device_type: Option<String>,
        capacity_mib: Option<u64>,
        manufacturer: Option<String>,
        model: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `storages` family member; the counts come from the
    /// `StorageControllers` and `Drives` collections of the typed schema and
    /// stay numeric so no layer re-parses text.
    Storage {
        controller_count: Option<u64>,
        drive_count: Option<u64>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `network-adapters` family member.
    NetworkAdapter {
        manufacturer: Option<String>,
        model: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `ethernet-interfaces` family member; `speed_mbps` stays
    /// numeric so the console renders the link speed without re-parsing text.
    EthernetInterface {
        mac_address: Option<String>,
        speed_mbps: Option<u64>,
        interface_enabled: Option<bool>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `accounts` family member (a `ManagerAccount` inside the
    /// `AccountService`'s `Accounts` collection). The manager-account schema
    /// declares no `Status` property, so the details carry no status field;
    /// the persisted payload's `UserName` and `AccountTypes` stay internal.
    Account {
        enabled: Option<bool>,
        role_id: Option<String>,
        locked: Option<bool>,
    },
    /// One §2.1 `bios` family member. Only the `AttributeRegistry` metadata
    /// is retained: the `Attributes` bag is a vendor-specific dynamic map of
    /// unbounded size, and `Bios_v1` declares no `Status` property; the
    /// persisted payload's `ResetBiosToDefaultsPending` flag stays internal.
    Bios { attribute_registry: Option<String> },
    /// One §2.1 `boot-options` family member; `boot_option_enabled` stays a
    /// Boolean so the console renders it without re-parsing text, and
    /// `BootOption_v1` declares no `Status` property; the persisted payload's
    /// `BootOptionReference` and `Alias` stay internal.
    BootOption {
        display_name: Option<String>,
        boot_option_enabled: Option<bool>,
        uefi_device_path: Option<String>,
    },
    /// One §2.1 `secure-boot` family member; `secure_boot_mode` stays the
    /// original schema enumeration string so the console renders it without
    /// re-parsing text, and `SecureBoot_v1` declares no `Status` property;
    /// the persisted payload's `SecureBootCurrentBoot` stays internal.
    SecureBoot {
        secure_boot_enable: Option<bool>,
        secure_boot_mode: Option<String>,
    },
    /// One §2.1 `power` family member (a `Power_v1` chassis singleton).
    /// `Power_v1` declares no `Status` property and no reading or metadata
    /// properties of its own (consumption and capacity exist only on the
    /// nested `PowerControl`/`PowerSupply` reading arrays, which stay out of
    /// the strictly projectable field set), so the details carry no fields.
    Power {},
    /// One §2.1 `thermal` family member (a `Thermal_v1` chassis singleton).
    /// Only the resource-level `Status` is projectable: temperature readings
    /// exist only on nested `Temperatures` members, so they stay out of the
    /// strictly projectable field set.
    Thermal {
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `sensors` family member (a `Sensor_v1` collection member);
    /// the reading and its UCUM units stay numeric/text as published so the
    /// console renders the sensor without re-parsing text.
    Sensor {
        reading: Option<f64>,
        reading_units: Option<String>,
        reading_type: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `controls` family member (a `Control_v1` collection member);
    /// the set point stays numeric as published so the console renders the
    /// control without re-parsing text.
    Control {
        control_type: Option<String>,
        set_point: Option<f64>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `log-services` family member (a `LogService_v1` collection
    /// member under the manager). `service_enabled` is the direct
    /// `ServiceEnabled` Boolean and `max_log_entries` the direct
    /// `MaxNumberOfRecords` capacity, kept numeric so the console renders the
    /// log service without re-parsing text; the `Entries` log-entry
    /// collection is deliberately not counted, because that would require a
    /// nested fetch the strictly projectable field set does not perform.
    LogService {
        service_enabled: Option<bool>,
        max_log_entries: Option<u64>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `manager-network-protocol` family member (the
    /// `ManagerNetworkProtocol_v1` manager singleton). Only the direct
    /// `HostName` and `FQDN` metadata properties are projectable: the
    /// per-protocol sections (`HTTP`, `HTTPS`, `SSH`, ...) are nested
    /// `Protocol` objects, which stay out of the strictly projectable field
    /// set exactly like `NetworkAdapter`'s `Controllers[]` array.
    ManagerNetworkProtocol {
        host_name: Option<String>,
        fqdn: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `host-interfaces` family member (a `HostInterface_v1`
    /// collection member under the manager). `interface_enabled` is the
    /// direct `InterfaceEnabled` Boolean. The `HostInterface_v1` schema
    /// declares no `HostName` property (host identity lives in the linked
    /// host/manager ethernet interfaces), and the `HostInterfaceType`
    /// enumeration is retained only in the persisted payload, so the details
    /// carry the interface state exactly like the `Account` family carries
    /// only its direct properties.
    HostInterface {
        interface_enabled: Option<bool>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `pcie-devices` family member (a `PCIeDevice_v1` member linked
    /// from the computer system). `device_type` stays the original schema
    /// enumeration string so the console renders the device class without
    /// re-parsing text; `SlotType` entered `PCIeDevice_v1` only in `v1_9_0`
    /// and the schema compiles no such property, so it stays out of this
    /// strictly projectable field set.
    PcieDevice {
        device_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `assembly` family member (an `AssemblyData` member inside a
    /// chassis `Assembly` document; the `Assembly_v1` resource itself declares
    /// no `Id` property, so the member's `MemberId` array index is its stable
    /// identifier). Only the direct `Producer` and `Status` properties of the
    /// member schema are projectable: the type of an assembly is expressed
    /// through the `PhysicalContext` property, which stays out of this first
    /// strictly projectable field set.
    Assembly {
        producer: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One `software-inventory` family member under the §2.1 `update-service`
    /// feature (a `SoftwareInventory_v1` collection member under the root
    /// `UpdateService`). `release_date` stays the RFC 3339 timestamp of the
    /// compiled `Edm.DateTimeOffset` type so the console renders the release
    /// date without re-parsing text.
    SoftwareInventory {
        software_id: Option<String>,
        version: Option<String>,
        release_date: Option<OffsetDateTime>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `event-service` family member (an `EventService_v1` root
    /// singleton). Only the service posture is projectable: `ServiceEnabled`
    /// and `Status` are direct properties, while the retry-policy fields
    /// (`DeliveryRetryAttempts`, `DeliveryRetryIntervalSeconds`) govern event
    /// delivery rather than a console-rendered surface and the `Subscriptions`
    /// collection members are separate `EventSubscription` resources.
    EventService {
        service_enabled: Option<bool>,
        status: Option<ResourceStatusSummary>,
    },
    /// One subscription under the §2.1 `event-service` feature (an
    /// `EventDestination_v1` member of the `Subscriptions` collection).
    /// Redfish models subscriptions as `EventDestination`; nv-redfish 0.13
    /// does not compile that type, so infra decodes the `Subscriptions` leaf
    /// with a local minimal schema. `protocol` stays the
    /// `EventDestinationProtocol` enumeration string and `event_types` the
    /// `EventTypes` array of `EventType` values, so the console renders both
    /// without re-parsing text.
    EventSubscription {
        destination: Option<String>,
        protocol: Option<String>,
        context: Option<String>,
        event_types: Option<Vec<String>>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `telemetry-service` family member (a `TelemetryService_v1`
    /// root singleton). Only `Status` is projected this round: the compiled
    /// `TelemetryService` type exposes `ServiceEnabled` and the
    /// service-capacity fields (`MaxReports`, `MinCollectionInterval`,
    /// `SupportedCollectionFunctions`), but the product defers them to the
    /// 0.4.0 telemetry iteration, and projecting them now would widen this
    /// strictly projectable field set ahead of the infra payload that must
    /// feed it.
    TelemetryService {
        status: Option<ResourceStatusSummary>,
    },
    /// One metric definition under the §2.1 `telemetry-service` feature (a
    /// `MetricDefinition_v1` collection member). `metric_type` stays the
    /// `MetricType` enumeration string so the console renders it without
    /// re-parsing text; the schema declares no `Status` property, and
    /// `MetricDataType`, `Precision`, and the calculation properties describe
    /// measurement semantics left for the telemetry-history iteration.
    MetricDefinition {
        units: Option<String>,
        metric_type: Option<String>,
    },
    /// One metric report under the §2.1 `telemetry-service` feature (a
    /// `MetricReport_v1` collection member). `metric_values_count` is derived
    /// from the length of the `MetricValues` array and `metric_values` carries
    /// the timestamped readings themselves — the current-value surface of the
    /// telemetry-history iteration, rendered by the 0.4.0 Telemetry view.
    /// Both stay optional: the array is absent when the report carries no
    /// values, and snapshots persisted by the 0.2.0 iteration carry only the
    /// derived count, so a missing array must decode as `None` instead of
    /// failing the strict decoder. The schema declares no `Status` property
    /// (the report instead carries `Timestamp` and `Context` metadata).
    MetricReport {
        metric_values_count: Option<u64>,
        metric_values: Option<Vec<MetricValueSummary>>,
    },
    /// One §2.1 `task-service` family member (a `TaskService_v1` root
    /// singleton). `completed_task_overwrite_policy` stays the
    /// `OverWritePolicy` enumeration string so the console renders it without
    /// re-parsing text; `DateTime` and `LifeCycleEventOnTaskStateChange`
    /// describe service plumbing rather than a console-rendered surface.
    TaskService {
        service_enabled: Option<bool>,
        completed_task_overwrite_policy: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One task under the §2.1 `task-service` feature (a `Task_v1` collection
    /// member). `task_state` and `task_status` stay their enumeration strings,
    /// `percent_complete` stays numeric, and `start_time`/`end_time` keep the
    /// RFC 3339 instants of the compiled `Edm.DateTimeOffset` type so the
    /// console renders the task timeline without re-parsing text.
    Task {
        task_state: Option<String>,
        task_status: Option<String>,
        percent_complete: Option<u64>,
        start_time: Option<OffsetDateTime>,
        end_time: Option<OffsetDateTime>,
    },
}

/// One immutable core-resource snapshot ready for an API or UI boundary.
///
/// `PartialEq` (not `Eq`) because the details enum carries `f64` readings.
#[derive(Clone, Debug, PartialEq)]
pub struct CoreResourceSummary {
    resource_id: ResourceId,
    feature: ResourceFeature,
    odata_id: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    etag: Option<ResourceEtag>,
    common: CoreResourceCommon,
    details: CoreResourceDetails,
}

impl CoreResourceSummary {
    #[must_use]
    pub const fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
    }

    #[must_use]
    pub const fn odata_id(&self) -> &ResourceODataId {
        &self.odata_id
    }

    #[must_use]
    pub const fn odata_type(&self) -> Option<&ResourceODataType> {
        self.odata_type.as_ref()
    }

    #[must_use]
    pub const fn etag(&self) -> Option<&ResourceEtag> {
        self.etag.as_ref()
    }

    #[must_use]
    pub const fn common(&self) -> &CoreResourceCommon {
        &self.common
    }

    #[must_use]
    pub const fn details(&self) -> &CoreResourceDetails {
        &self.details
    }
}

/// One endpoint and either no successful refresh or its latest complete,
/// strongly typed core-resource Generation.
///
/// `PartialEq` (not `Eq`) because the resource summaries carry `f64`
/// readings.
#[derive(Clone, Debug, PartialEq)]
pub struct EndpointResourceInventory {
    endpoint: Endpoint,
    generation: Option<RefreshGeneration>,
    observed_at: Option<OffsetDateTime>,
    resources: Vec<CoreResourceSummary>,
}

impl EndpointResourceInventory {
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    #[must_use]
    pub const fn generation(&self) -> Option<RefreshGeneration> {
        self.generation
    }

    #[must_use]
    pub const fn observed_at(&self) -> Option<OffsetDateTime> {
        self.observed_at
    }

    #[must_use]
    pub fn resources(&self) -> &[CoreResourceSummary] {
        &self.resources
    }
}

/// Loads one endpoint's latest complete core-resource Generation.
pub struct EndpointResourceInventoryQuery<Repository> {
    repository: Repository,
    endpoint_id: EndpointId,
}

impl<Repository> EndpointResourceInventoryQuery<Repository>
where
    Repository: EndpointInventoryRepository,
{
    #[must_use]
    pub const fn new(repository: Repository, endpoint_id: EndpointId) -> Self {
        Self {
            repository,
            endpoint_id,
        }
    }

    /// Returns `None` for an unknown endpoint and otherwise validates every
    /// persisted typed payload before exposing it to delivery layers.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointResourceInventoryQueryError`] when inventory loading
    /// fails or a stored payload no longer matches its declared core feature.
    pub async fn execute(
        &self,
    ) -> Result<
        Option<EndpointResourceInventory>,
        EndpointResourceInventoryQueryError<Repository::Error>,
    > {
        let items = EndpointInventoryQuery::new(&self.repository)
            .execute()
            .await
            .map_err(EndpointResourceInventoryQueryError::Inventory)?;
        let Some(item) = items
            .into_iter()
            .find(|item| item.endpoint().id() == self.endpoint_id)
        else {
            return Ok(None);
        };
        let generation = item.generation();
        let observed_at = item.last_successful_refresh_at();
        let (endpoint, snapshots) = item.into_parts();
        let resources = snapshots
            .iter()
            .map(project_snapshot)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Some(EndpointResourceInventory {
            endpoint,
            generation,
            observed_at,
            resources,
        }))
    }
}

/// A controlled failure while loading one endpoint's core-resource view.
#[derive(Debug, Error)]
pub enum EndpointResourceInventoryQueryError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    #[error("failed to load endpoint inventory: {0}")]
    Inventory(#[source] EndpointInventoryQueryError<RepositoryError>),
    #[error("resource {resource_id} has an invalid typed {feature} payload: {source}")]
    Projection {
        resource_id: ResourceId,
        feature: ResourceFeature,
        #[source]
        source: serde_json::Error,
    },
}

fn project_snapshot<RepositoryError>(
    snapshot: &ResourceSnapshot,
) -> Result<CoreResourceSummary, EndpointResourceInventoryQueryError<RepositoryError>>
where
    RepositoryError: Error + 'static,
{
    let payload = snapshot.payload().as_str();
    let (common, details) = match snapshot.feature() {
        ResourceFeature::ServiceRoot => project_service_root(snapshot, payload)?,
        ResourceFeature::Systems => project_system(snapshot, payload)?,
        ResourceFeature::Chassis => project_chassis(snapshot, payload)?,
        ResourceFeature::Managers => project_manager(snapshot, payload)?,
        ResourceFeature::OemDell => project_oem_dell(snapshot, payload)?,
        ResourceFeature::OemSmcSysLockdown => project_oem_smc_sys_lockdown(snapshot, payload)?,
        ResourceFeature::OemSmcKcsInterface => project_oem_smc_kcs_interface(snapshot, payload)?,
        ResourceFeature::Processors => project_processor(snapshot, payload)?,
        ResourceFeature::Memory => project_memory(snapshot, payload)?,
        ResourceFeature::Storages => project_storage(snapshot, payload)?,
        ResourceFeature::NetworkAdapters => project_network_adapter(snapshot, payload)?,
        ResourceFeature::EthernetInterfaces => project_ethernet_interface(snapshot, payload)?,
        ResourceFeature::Accounts => project_account(snapshot, payload)?,
        ResourceFeature::Bios => project_bios(snapshot, payload)?,
        ResourceFeature::BootOptions => project_boot_option(snapshot, payload)?,
        ResourceFeature::SecureBoot => project_secure_boot(snapshot, payload)?,
        ResourceFeature::Power => project_power(snapshot, payload)?,
        ResourceFeature::Thermal => project_thermal(snapshot, payload)?,
        ResourceFeature::Sensors => project_sensor(snapshot, payload)?,
        ResourceFeature::Controls => project_control(snapshot, payload)?,
        ResourceFeature::LogServices => project_log_service(snapshot, payload)?,
        ResourceFeature::ManagerNetworkProtocol => {
            project_manager_network_protocol(snapshot, payload)?
        }
        ResourceFeature::HostInterfaces => project_host_interface(snapshot, payload)?,
        ResourceFeature::PcieDevices => project_pcie_device(snapshot, payload)?,
        ResourceFeature::Assembly => project_assembly(snapshot, payload)?,
        ResourceFeature::SoftwareInventory => project_software_inventory(snapshot, payload)?,
        ResourceFeature::EventService => project_event_service(snapshot, payload)?,
        ResourceFeature::EventSubscription => project_event_subscription(snapshot, payload)?,
        ResourceFeature::TelemetryService => project_telemetry_service(snapshot, payload)?,
        ResourceFeature::MetricDefinition => project_metric_definition(snapshot, payload)?,
        ResourceFeature::MetricReport => project_metric_report(snapshot, payload)?,
        ResourceFeature::TaskService => project_task_service(snapshot, payload)?,
        ResourceFeature::Task => project_task(snapshot, payload)?,
    };
    Ok(CoreResourceSummary {
        resource_id: snapshot.resource_id(),
        feature: snapshot.feature(),
        odata_id: snapshot.odata_id().clone(),
        odata_type: snapshot.odata_type().cloned(),
        etag: snapshot.etag().cloned(),
        common,
        details,
    })
}

fn project_service_root<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ServiceRootPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::ServiceRoot {
            vendor: parsed.vendor,
            product: parsed.product,
            redfish_version: parsed.redfish_version,
        }
    })
}

fn project_system<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<SystemPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::System {
            system_type: parsed.system_type,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            part_number: parsed.part_number,
            serial_number: parsed.serial_number,
            sku: parsed.sku,
            host_name: parsed.host_name,
            bios_version: parsed.bios_version,
            power_state: parsed.power_state,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_chassis<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ChassisPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Chassis {
            chassis_type: parsed.chassis_type,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            part_number: parsed.part_number,
            serial_number: parsed.serial_number,
            sku: parsed.sku,
            asset_tag: parsed.asset_tag,
            power_state: parsed.power_state,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_manager<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ManagerPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Manager {
            manager_type: parsed.manager_type,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            part_number: parsed.part_number,
            serial_number: parsed.serial_number,
            firmware_version: parsed.firmware_version,
            version: parsed.version,
            power_state: parsed.power_state,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_oem_dell<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<OemDellPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::OemDell {
            server_model: parsed.server_model,
            server_service_tag: parsed.server_service_tag,
            server_generation: parsed.server_generation,
            server_bmc_mac_address: parsed.server_bmc_mac_address,
            server_name: parsed.server_name,
        }
    })
}

fn project_oem_smc_sys_lockdown<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    // Unlike every standard family the payload carries no `Id` / `Name` /
    // `Description` (the compiled schema models none, so the infra projection
    // could never have seen them), and the common identity is derived from
    // the snapshot's `@odata.id` instead of the payload.
    let parsed =
        deserialize_payload::<OemSmcSysLockdownPayload, RepositoryError>(snapshot, payload)?;
    Ok((
        common_from_odata_id(snapshot.odata_id()),
        CoreResourceDetails::OemSmcSysLockdown {
            sys_lockdown_enabled: parsed.sys_lockdown_enabled,
        },
    ))
}

fn project_oem_smc_kcs_interface<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    let parsed =
        deserialize_payload::<OemSmcKcsInterfacePayload, RepositoryError>(snapshot, payload)?;
    Ok((
        common_from_odata_id(snapshot.odata_id()),
        CoreResourceDetails::OemSmcKcsInterface {
            privilege: parsed.privilege,
        },
    ))
}

/// Builds the product-level identity for an OEM document whose compiled
/// schema carries no `Id` / `Name` / `Description` properties.
///
/// The compiled Supermicro `SysLockdown` and `KcsInterface` types flatten a
/// `resource::Item` base that models only `@odata.id`, `@odata.etag`, and
/// the `@Redfish.Settings` annotations, so the wire `Id` / `Name` keys are
/// not part of the typed surface and cannot be projected (§11.5 two-way
/// rule). The Redfish spec (DSP0266 §7.4) requires `Id` to equal the final
/// segment of `@odata.id`, so that segment is the resource's own identity —
/// the exact `Id` a standard family derives from its typed `Id` property —
/// and never a product-invented label. `Name` falls back to the `Id`-derived
/// identity because the compiled schema carries no `Name` property (a
/// standard family takes its `Name` from the typed `Name` property instead).
/// A trailing slash would make the naive last segment empty, so empty
/// segments are filtered out before the final segment is taken; an `@odata.id`
/// with nothing but separators (or the empty string) falls back to the whole
/// value unchanged rather than deriving an empty identity. `Description`
/// stays `None`.
fn common_from_odata_id(odata_id: &ResourceODataId) -> CoreResourceCommon {
    let identity = odata_id
        .as_str()
        .rsplit('/')
        .find(|segment| !segment.is_empty())
        .unwrap_or(odata_id.as_str());
    CoreResourceCommon {
        id: identity.to_owned(),
        name: identity.to_owned(),
        description: None,
    }
}

fn project_processor<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ProcessorPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Processor {
            processor_type: parsed.processor_type,
            socket: parsed.socket,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            total_cores: parsed.total_cores,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_memory<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<MemoryPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Memory {
            memory_device_type: parsed.memory_device_type,
            capacity_mib: parsed.capacity_mib,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_storage<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<StoragePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Storage {
            controller_count: parsed.controller_count,
            drive_count: parsed.drive_count,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_network_adapter<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<NetworkAdapterPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::NetworkAdapter {
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_ethernet_interface<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<EthernetInterfacePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::EthernetInterface {
            mac_address: parsed.mac_address,
            speed_mbps: parsed.speed_mbps,
            interface_enabled: parsed.interface_enabled,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_account<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<AccountPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Account {
            enabled: parsed.enabled,
            role_id: parsed.role_id,
            locked: parsed.locked,
        }
    })
}

fn project_bios<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<BiosPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Bios {
            attribute_registry: parsed.attribute_registry,
        }
    })
}

fn project_boot_option<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<BootOptionPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::BootOption {
            display_name: parsed.display_name,
            boot_option_enabled: parsed.boot_option_enabled,
            uefi_device_path: parsed.uefi_device_path,
        }
    })
}

fn project_secure_boot<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<SecureBootPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::SecureBoot {
            secure_boot_enable: parsed.secure_boot_enable,
            secure_boot_mode: parsed.secure_boot_mode,
        }
    })
}

fn project_power<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<PowerPayload, _, RepositoryError>(snapshot, payload, |_parsed| {
        CoreResourceDetails::Power {}
    })
}

fn project_thermal<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ThermalPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Thermal {
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_sensor<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<SensorPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Sensor {
            reading: parsed.reading,
            reading_units: parsed.reading_units,
            reading_type: parsed.reading_type,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_control<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ControlPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Control {
            control_type: parsed.control_type,
            set_point: parsed.set_point,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_log_service<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<LogServicePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::LogService {
            service_enabled: parsed.service_enabled,
            max_log_entries: parsed.max_number_of_records,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_manager_network_protocol<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<ManagerNetworkProtocolPayload, _, RepositoryError>(
        snapshot,
        payload,
        |parsed| CoreResourceDetails::ManagerNetworkProtocol {
            host_name: parsed.host_name,
            fqdn: parsed.fqdn,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        },
    )
}

fn project_host_interface<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<HostInterfacePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::HostInterface {
            interface_enabled: parsed.interface_enabled,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_pcie_device<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<PcieDevicePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::PcieDevice {
            device_type: parsed.device_type,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_assembly<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<AssemblyPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Assembly {
            producer: parsed.producer,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_software_inventory<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<SoftwareInventoryPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::SoftwareInventory {
            software_id: parsed.software_id,
            version: parsed.version,
            release_date: parsed.release_date,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_event_service<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<EventServicePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::EventService {
            service_enabled: parsed.service_enabled,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_event_subscription<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<EventSubscriptionPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::EventSubscription {
            destination: parsed.destination,
            protocol: parsed.protocol,
            context: parsed.context,
            event_types: parsed.event_types,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_telemetry_service<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<TelemetryServicePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::TelemetryService {
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_metric_definition<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<MetricDefinitionPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::MetricDefinition {
            units: parsed.units,
            metric_type: parsed.metric_type,
        }
    })
}

fn project_metric_report<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<MetricReportPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::MetricReport {
            metric_values_count: parsed.metric_values_count,
            metric_values: parsed.metric_values.map(|values| {
                values
                    .into_iter()
                    .map(|value| MetricValueSummary::new(value.timestamp, value.metric_value))
                    .collect()
            }),
        }
    })
}

fn project_task_service<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<TaskServicePayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::TaskService {
            service_enabled: parsed.service_enabled,
            completed_task_overwrite_policy: parsed.completed_task_overwrite_policy,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_task<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<TaskPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::Task {
            task_state: parsed.task_state,
            task_status: parsed.task_status,
            percent_complete: parsed.percent_complete,
            start_time: parsed.start_time,
            end_time: parsed.end_time,
        }
    })
}

/// Decodes one feature payload and closes it over the feature-specific
/// details projection, keeping the per-family arms free of repeated
/// error-mapping and common-field plumbing.
fn project_typed<Payload, Details, RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
    project: impl FnOnce(Payload) -> Details,
) -> Result<(CoreResourceCommon, Details), EndpointResourceInventoryQueryError<RepositoryError>>
where
    Payload: for<'de> Deserialize<'de> + CommonPayload,
    Details: Sized,
    RepositoryError: Error + 'static,
{
    let parsed = deserialize_payload::<Payload, RepositoryError>(snapshot, payload)?;
    Ok((parsed.common(), project(parsed)))
}

fn deserialize_payload<Payload, RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<Payload, EndpointResourceInventoryQueryError<RepositoryError>>
where
    Payload: for<'de> Deserialize<'de>,
    RepositoryError: Error + 'static,
{
    serde_json::from_str(payload).map_err(|source| {
        EndpointResourceInventoryQueryError::Projection {
            resource_id: snapshot.resource_id(),
            feature: snapshot.feature(),
            source,
        }
    })
}

/// Every typed feature payload carries the three product-level fields shared
/// by all core resources, projected through one trait so the generic
/// projection path never re-maps common fields per family.
trait CommonPayload {
    fn common(&self) -> CoreResourceCommon;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRootPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Vendor")]
    vendor: Option<String>,
    #[serde(rename = "Product")]
    product: Option<String>,
    #[serde(rename = "RedfishVersion")]
    redfish_version: Option<String>,
}

impl CommonPayload for ServiceRootPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResourceStatusPayload {
    #[serde(rename = "State")]
    state: Option<String>,
    #[serde(rename = "Health")]
    health: Option<String>,
    #[serde(rename = "HealthRollup")]
    health_rollup: Option<String>,
}

impl ResourceStatusPayload {
    fn into_summary(self) -> ResourceStatusSummary {
        ResourceStatusSummary {
            state: self.state,
            health: self.health,
            health_rollup: self.health_rollup,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "SystemType")]
    system_type: Option<String>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "PartNumber")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "SKU")]
    sku: Option<String>,
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "BiosVersion")]
    bios_version: Option<String>,
    #[serde(rename = "PowerState")]
    power_state: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for SystemPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChassisPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ChassisType")]
    chassis_type: String,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "PartNumber")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "SKU")]
    sku: Option<String>,
    #[serde(rename = "AssetTag")]
    asset_tag: Option<String>,
    #[serde(rename = "PowerState")]
    power_state: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for ChassisPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ManagerType")]
    manager_type: Option<String>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "PartNumber")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "FirmwareVersion")]
    firmware_version: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "PowerState")]
    power_state: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for ManagerPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// The §0.5.0 Dell OEM `DellAttributes` snapshot payload, decoded exactly as
/// the infra projection wrote it: the five pinned Dell iDRAC identity
/// attributes, each `None` when the endpoint did not publish the key.
/// `deny_unknown_fields` keeps the snapshot contract strict, so a future
/// extra wire field would make stored snapshots unreadable exactly like an
/// extra top-level key would.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemDellPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ServerModel")]
    server_model: Option<String>,
    #[serde(rename = "ServerServiceTag")]
    server_service_tag: Option<String>,
    #[serde(rename = "ServerGeneration")]
    server_generation: Option<String>,
    #[serde(rename = "ServerBmcMacAddress")]
    server_bmc_mac_address: Option<String>,
    #[serde(rename = "ServerName")]
    server_name: Option<String>,
}

impl CommonPayload for OemDellPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// The §0.5.0 Supermicro `SysLockdown` snapshot payload, decoded exactly as
/// the infra projection wrote it: only the `SysLockdownEnabled` boolean the
/// compiled schema models. `deny_unknown_fields` keeps the snapshot contract
/// strict, so a future extra wire field would make stored snapshots
/// unreadable exactly like an extra top-level key would. The payload carries
/// no `Id` / `Name` / `Description` because the compiled schema has none; the
/// projection derives the product identity from the snapshot's `@odata.id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemSmcSysLockdownPayload {
    #[serde(rename = "SysLockdownEnabled")]
    sys_lockdown_enabled: Option<bool>,
}

/// The §0.5.0 Supermicro `KcsInterface` snapshot payload, decoded exactly as
/// the infra projection wrote it: only the `Privilege` enum spelling the
/// compiled schema models, kept verbatim. `deny_unknown_fields` keeps the
/// snapshot contract strict, and the payload carries no `Id` / `Name` /
/// `Description` because the compiled schema has none; the projection derives
/// the product identity from the snapshot's `@odata.id`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemSmcKcsInterfacePayload {
    #[serde(rename = "Privilege")]
    privilege: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessorPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ProcessorType")]
    processor_type: Option<String>,
    #[serde(rename = "Socket")]
    socket: Option<String>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "TotalCores")]
    total_cores: Option<u64>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for ProcessorPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "MemoryDeviceType")]
    memory_device_type: Option<String>,
    #[serde(rename = "CapacityMiB")]
    capacity_mib: Option<u64>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for MemoryPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoragePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ControllerCount")]
    controller_count: Option<u64>,
    #[serde(rename = "DriveCount")]
    drive_count: Option<u64>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for StoragePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkAdapterPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for NetworkAdapterPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EthernetInterfacePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "MACAddress")]
    mac_address: Option<String>,
    #[serde(rename = "SpeedMbps")]
    speed_mbps: Option<u64>,
    #[serde(rename = "InterfaceEnabled")]
    interface_enabled: Option<bool>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for EthernetInterfacePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "UserName")]
    _user_name: Option<String>,
    #[serde(rename = "RoleId")]
    role_id: Option<String>,
    #[serde(rename = "Enabled")]
    enabled: Option<bool>,
    #[serde(rename = "Locked")]
    locked: Option<bool>,
    #[serde(rename = "AccountTypes")]
    _account_types: Option<Vec<String>>,
}

impl CommonPayload for AccountPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BiosPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "AttributeRegistry")]
    attribute_registry: Option<String>,
    #[serde(rename = "ResetBiosToDefaultsPending")]
    _reset_bios_to_defaults_pending: Option<bool>,
}

impl CommonPayload for BiosPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BootOptionPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "BootOptionReference")]
    _boot_option_reference: Option<String>,
    #[serde(rename = "DisplayName")]
    display_name: Option<String>,
    #[serde(rename = "BootOptionEnabled")]
    boot_option_enabled: Option<bool>,
    #[serde(rename = "UefiDevicePath")]
    uefi_device_path: Option<String>,
    #[serde(rename = "Alias")]
    _alias: Option<String>,
}

impl CommonPayload for BootOptionPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecureBootPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "SecureBootEnable")]
    secure_boot_enable: Option<bool>,
    #[serde(rename = "SecureBootCurrentBoot")]
    _secure_boot_current_boot: Option<String>,
    #[serde(rename = "SecureBootMode")]
    secure_boot_mode: Option<String>,
}

impl CommonPayload for SecureBootPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
}

impl CommonPayload for PowerPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ThermalPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for ThermalPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Reading")]
    reading: Option<f64>,
    #[serde(rename = "ReadingUnits")]
    reading_units: Option<String>,
    #[serde(rename = "ReadingType")]
    reading_type: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for SensorPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ControlType")]
    control_type: Option<String>,
    #[serde(rename = "SetPoint")]
    set_point: Option<f64>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for ControlPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LogServicePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ServiceEnabled")]
    service_enabled: Option<bool>,
    #[serde(rename = "MaxNumberOfRecords")]
    max_number_of_records: Option<u64>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for LogServicePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagerNetworkProtocolPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "HostName")]
    host_name: Option<String>,
    #[serde(rename = "FQDN")]
    fqdn: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for ManagerNetworkProtocolPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostInterfacePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "InterfaceEnabled")]
    interface_enabled: Option<bool>,
    #[serde(rename = "HostInterfaceType")]
    _host_interface_type: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for HostInterfacePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PcieDevicePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "DeviceType")]
    device_type: Option<String>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for PcieDevicePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssemblyPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Producer")]
    producer: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for AssemblyPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SoftwareInventoryPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "SoftwareId")]
    software_id: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
    /// `ReleaseDate` keeps the RFC 3339 timestamp of the compiled
    /// `Edm.DateTimeOffset` type, so the projection carries the typed instant
    /// instead of a string the console would have to re-parse.
    #[serde(rename = "ReleaseDate", with = "time::serde::rfc3339::option")]
    release_date: Option<OffsetDateTime>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for SoftwareInventoryPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventServicePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ServiceEnabled")]
    service_enabled: Option<bool>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for EventServicePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EventSubscriptionPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Destination")]
    destination: Option<String>,
    #[serde(rename = "Protocol")]
    protocol: Option<String>,
    #[serde(rename = "Context")]
    context: Option<String>,
    #[serde(rename = "EventTypes")]
    event_types: Option<Vec<String>>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for EventSubscriptionPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryServicePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for TelemetryServicePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricDefinitionPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "MetricType")]
    metric_type: Option<String>,
    #[serde(rename = "Units")]
    units: Option<String>,
}

impl CommonPayload for MetricDefinitionPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricReportPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "MetricValuesCount")]
    metric_values_count: Option<u64>,
    /// The timestamped readings of the `MetricValues` array, projected since
    /// 0.4.0. Snapshots persisted by the 0.2.0 iteration carry only
    /// `MetricValuesCount`, so the field must be `Option`: a missing array
    /// decodes as `None` instead of failing the strict decoder.
    #[serde(rename = "MetricValues")]
    metric_values: Option<Vec<MetricValuePayload>>,
}

impl CommonPayload for MetricReportPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// One timestamped reading of a `MetricReport` snapshot, kept exactly as the
/// infra projection wrote it: `Timestamp` stays the RFC 3339 instant of the
/// compiled `Edm.DateTimeOffset` type and `MetricValue` the original text of
/// the compiled `Edm.String` type. `deny_unknown_fields` keeps the snapshot
/// contract strict, so a future extra entry key would make stored snapshots
/// unreadable exactly like an extra top-level key would.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricValuePayload {
    #[serde(rename = "Timestamp", with = "time::serde::rfc3339::option")]
    timestamp: Option<OffsetDateTime>,
    #[serde(rename = "MetricValue")]
    metric_value: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskServicePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "ServiceEnabled")]
    service_enabled: Option<bool>,
    #[serde(rename = "CompletedTaskOverWritePolicy")]
    completed_task_overwrite_policy: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for TaskServicePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "TaskState")]
    task_state: Option<String>,
    #[serde(rename = "TaskStatus")]
    task_status: Option<String>,
    #[serde(rename = "PercentComplete")]
    percent_complete: Option<u64>,
    /// `StartTime` keeps the RFC 3339 timestamp of the compiled
    /// `Edm.DateTimeOffset` type, so the projection carries the typed instants
    /// instead of strings the console would have to re-parse.
    #[serde(rename = "StartTime", with = "time::serde::rfc3339::option")]
    start_time: Option<OffsetDateTime>,
    #[serde(rename = "EndTime", with = "time::serde::rfc3339::option")]
    end_time: Option<OffsetDateTime>,
}

impl CommonPayload for TaskPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use rutilus_domain::{
        CredentialId, EndpointAddress, EndpointDisplayName, ResourceSnapshotPayload,
        TlsCertificate, TlsTrust,
    };

    use super::*;
    use crate::{BoundaryFuture, EndpointInventoryItem};

    #[tokio::test]
    async fn projects_every_core_feature_without_losing_source_values() -> Result<(), Box<dyn Error>>
    {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(9)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Systems,
                    "/redfish/v1/Systems/1",
                    r#"{"Id":"1","Name":"System One","Description":"Compute","SystemType":"Physical","Manufacturer":"Vendor A","Model":"Model S","PartNumber":"P1","SerialNumber":"S1","SKU":"SKU1","HostName":"compute-1","BiosVersion":"2.3.4","PowerState":"On","Status":{"State":"Enabled","Health":"OK","HealthRollup":"Warning"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Chassis,
                    "/redfish/v1/Chassis/1",
                    r#"{"Id":"1","Name":"Chassis One","ChassisType":"RackMount","Manufacturer":"Vendor A","Model":"Model C","PartNumber":"P2","SerialNumber":"C1","SKU":"SKU2","AssetTag":"RACK-01","PowerState":"On","Status":{"State":"Enabled","Health":"Warning","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Managers,
                    "/redfish/v1/Managers/1",
                    r#"{"Id":"1","Name":"Manager One","ManagerType":"BMC","Manufacturer":"Vendor A","Model":"Model M","PartNumber":"P3","SerialNumber":"M1","FirmwareVersion":"1.2.3","Version":"4.5.6","PowerState":"On","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.generation(), Some(generation));
        assert_eq!(result.observed_at(), Some(observed_at));
        assert_eq!(result.resources().len(), 4);
        assert_eq!(result.resources()[0].common().name(), "Root");
        assert_eq!(
            result.resources()[0].details(),
            &CoreResourceDetails::ServiceRoot {
                vendor: Some("Vendor A".to_owned()),
                product: Some("BMC".to_owned()),
                redfish_version: Some("1.20.0".to_owned()),
            }
        );
        let system = &result.resources()[3];
        assert_eq!(system.feature(), ResourceFeature::Systems);
        assert_eq!(system.odata_id().as_str(), "/redfish/v1/Systems/1");
        assert_eq!(system.common().id(), "1");
        assert_eq!(system.common().description(), Some("Compute"));
        assert!(matches!(
            system.details(),
            CoreResourceDetails::System {
                manufacturer: Some(manufacturer),
                bios_version: Some(bios_version),
                status: Some(status),
                ..
            } if manufacturer == "Vendor A"
                && bios_version == "2.3.4"
                && status.health() == Some("OK")
                && status.health_rollup() == Some("Warning")
                && status.state() == Some("Enabled")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_processor_and_memory_families_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(10)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Processors,
                    "/redfish/v1/Systems/1/Processors/CPU1",
                    r#"{"Id":"CPU1","Name":"Processor One","Description":"Primary CPU","ProcessorType":"CPU","Socket":"LGA4189","Manufacturer":"Vendor A","Model":"Model P","TotalCores":64,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Memory,
                    "/redfish/v1/Systems/1/Memory/DIMM1",
                    r#"{"Id":"DIMM1","Name":"Memory Module One","MemoryDeviceType":"DDR4","CapacityMiB":32768,"Manufacturer":"Vendor B","Model":"Model MEM","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.generation(), Some(generation));
        assert_eq!(result.observed_at(), Some(observed_at));
        assert_eq!(result.resources().len(), 3);
        let memory = &result.resources()[1];
        assert_eq!(memory.feature(), ResourceFeature::Memory);
        assert_eq!(
            memory.odata_id().as_str(),
            "/redfish/v1/Systems/1/Memory/DIMM1"
        );
        assert_eq!(memory.common().name(), "Memory Module One");
        assert!(matches!(
            memory.details(),
            CoreResourceDetails::Memory {
                memory_device_type: Some(memory_device_type),
                capacity_mib: Some(32768),
                manufacturer: Some(manufacturer),
                status: Some(status),
                ..
            } if memory_device_type == "DDR4"
                && manufacturer == "Vendor B"
                && status.health() == Some("OK")
        ));
        let processor = &result.resources()[2];
        assert_eq!(processor.feature(), ResourceFeature::Processors);
        assert_eq!(
            processor.odata_id().as_str(),
            "/redfish/v1/Systems/1/Processors/CPU1"
        );
        assert_eq!(processor.common().name(), "Processor One");
        assert!(matches!(
            processor.details(),
            CoreResourceDetails::Processor {
                processor_type: Some(processor_type),
                socket: Some(socket),
                model: Some(model),
                total_cores: Some(64),
                status: Some(status),
                ..
            } if processor_type == "CPU"
                && socket == "LGA4189"
                && model == "Model P"
                && status.state() == Some("Enabled")
                && status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_storage_network_and_ethernet_families_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(11)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Storages,
                    "/redfish/v1/Systems/1/Storage/SATA-1",
                    r#"{"Id":"SATA-1","Name":"Storage Subsystem One","Description":"SATA storage subsystem","ControllerCount":2,"DriveCount":6,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::NetworkAdapters,
                    "/redfish/v1/Chassis/1/NetworkAdapters/1",
                    r#"{"Id":"1","Name":"Network Adapter One","Manufacturer":"Vendor A","Model":"NA-25G-2P","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::EthernetInterfaces,
                    "/redfish/v1/Managers/1/EthernetInterfaces/1",
                    r#"{"Id":"1","Name":"Ethernet Interface One","MACAddress":"52:54:00:12:34:56","SpeedMbps":10000,"InterfaceEnabled":true,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.generation(), Some(generation));
        assert_eq!(result.observed_at(), Some(observed_at));
        assert_eq!(result.resources().len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the chassis
        // network adapter sorts before the manager ethernet interface, which
        // sorts before the system storage subsystem.
        let network = &result.resources()[1];
        assert_eq!(network.feature(), ResourceFeature::NetworkAdapters);
        assert_eq!(
            network.odata_id().as_str(),
            "/redfish/v1/Chassis/1/NetworkAdapters/1"
        );
        assert_eq!(network.common().name(), "Network Adapter One");
        assert!(matches!(
            network.details(),
            CoreResourceDetails::NetworkAdapter {
                manufacturer: Some(manufacturer),
                model: Some(model),
                status: Some(status),
                ..
            } if manufacturer == "Vendor A"
                && model == "NA-25G-2P"
                && status.state() == Some("Enabled")
        ));
        let ethernet = &result.resources()[2];
        assert_eq!(ethernet.feature(), ResourceFeature::EthernetInterfaces);
        assert_eq!(
            ethernet.odata_id().as_str(),
            "/redfish/v1/Managers/1/EthernetInterfaces/1"
        );
        assert!(matches!(
            ethernet.details(),
            CoreResourceDetails::EthernetInterface {
                mac_address: Some(mac_address),
                speed_mbps: Some(10000),
                interface_enabled: Some(true),
                status: Some(status),
                ..
            } if mac_address == "52:54:00:12:34:56"
                && status.health() == Some("OK")
        ));
        let storage = &result.resources()[3];
        assert_eq!(storage.feature(), ResourceFeature::Storages);
        assert_eq!(
            storage.odata_id().as_str(),
            "/redfish/v1/Systems/1/Storage/SATA-1"
        );
        assert_eq!(storage.common().name(), "Storage Subsystem One");
        assert!(matches!(
            storage.details(),
            CoreResourceDetails::Storage {
                controller_count: Some(2),
                drive_count: Some(6),
                status: Some(status),
                ..
            } if status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_accounts_family_without_losing_source_values() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(12)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Accounts,
                    "/redfish/v1/AccountService/Accounts/admin",
                    r#"{"Id":"admin","Name":"Administrator Account","Description":"Built-in administrator account","UserName":"admin","RoleId":"Administrator","Enabled":true,"Locked":false,"AccountTypes":["Redfish","IPMI"]}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let account = &result.resources()[1];
        assert_eq!(account.feature(), ResourceFeature::Accounts);
        assert_eq!(
            account.odata_id().as_str(),
            "/redfish/v1/AccountService/Accounts/admin"
        );
        assert_eq!(account.common().name(), "Administrator Account");
        assert_eq!(
            account.common().description(),
            Some("Built-in administrator account")
        );
        assert!(matches!(
            account.details(),
            CoreResourceDetails::Account {
                enabled: Some(true),
                role_id: Some(role_id),
                locked: Some(false),
            } if role_id == "Administrator"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_oem_dell_family_without_losing_source_values() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(13)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemDell,
                    "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1",
                    r#"{"Id":"1","Name":"Dell Attributes","Description":"Dell iDRAC attributes","ServerModel":"PowerEdge R750","ServerServiceTag":"ABC1234","ServerGeneration":"16G","ServerBmcMacAddress":"14:18:77:aa:bb:cc","ServerName":"rack-1-server-2"}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let oem_dell = &result.resources()[1];
        assert_eq!(oem_dell.feature(), ResourceFeature::OemDell);
        assert_eq!(
            oem_dell.odata_id().as_str(),
            "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1"
        );
        assert_eq!(oem_dell.common().id(), "1");
        assert_eq!(oem_dell.common().name(), "Dell Attributes");
        assert_eq!(
            oem_dell.common().description(),
            Some("Dell iDRAC attributes")
        );
        assert_eq!(
            oem_dell.details(),
            &CoreResourceDetails::OemDell {
                server_model: Some("PowerEdge R750".to_owned()),
                server_service_tag: Some("ABC1234".to_owned()),
                server_generation: Some("16G".to_owned()),
                server_bmc_mac_address: Some("14:18:77:aa:bb:cc".to_owned()),
                server_name: Some("rack-1-server-2".to_owned()),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn projects_oem_smc_families_without_losing_source_values() -> Result<(), Box<dyn Error>>
    {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(13)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemSmcSysLockdown,
                    "/redfish/v1/Managers/1/SysLockdown",
                    r#"{"SysLockdownEnabled":true}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemSmcKcsInterface,
                    "/redfish/v1/Managers/1/KCSInterface",
                    r#"{"Privilege":"Operator"}"#,
                    observed_at,
                    generation,
                )?,
                // A document whose only field was absent is still a snapshot
                // with `None` details, not an unreadable one.
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemSmcSysLockdown,
                    "/redfish/v1/Managers/2/SysLockdown",
                    r"{}",
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 4);
        // The inventory orders snapshots by `@odata.id`, so `KCSInterface`
        // sorts before the two `SysLockdown` documents.
        let kcs_interface = &result.resources()[1];
        assert_eq!(kcs_interface.feature(), ResourceFeature::OemSmcKcsInterface);
        assert_eq!(
            kcs_interface.odata_id().as_str(),
            "/redfish/v1/Managers/1/KCSInterface"
        );
        // The compiled schema models no `Id` / `Name`, so the product
        // identity is the resource's own `@odata.id` final segment.
        assert_eq!(kcs_interface.common().id(), "KCSInterface");
        assert_eq!(kcs_interface.common().name(), "KCSInterface");
        assert_eq!(kcs_interface.common().description(), None);
        assert_eq!(
            kcs_interface.details(),
            &CoreResourceDetails::OemSmcKcsInterface {
                privilege: Some("Operator".to_owned()),
            }
        );
        let sys_lockdown = &result.resources()[2];
        assert_eq!(sys_lockdown.feature(), ResourceFeature::OemSmcSysLockdown);
        assert_eq!(
            sys_lockdown.odata_id().as_str(),
            "/redfish/v1/Managers/1/SysLockdown"
        );
        assert_eq!(sys_lockdown.common().id(), "SysLockdown");
        assert_eq!(sys_lockdown.common().name(), "SysLockdown");
        assert_eq!(
            sys_lockdown.details(),
            &CoreResourceDetails::OemSmcSysLockdown {
                sys_lockdown_enabled: Some(true),
            }
        );
        assert_eq!(
            result.resources()[3].details(),
            &CoreResourceDetails::OemSmcSysLockdown {
                sys_lockdown_enabled: None,
            }
        );
        Ok(())
    }

    #[test]
    fn oem_identity_derives_the_final_odata_id_segment_without_empty_fallbacks()
    -> Result<(), Box<dyn Error>> {
        // A trailing slash must not derive an empty identity: empty segments
        // are filtered before the final one is taken.
        let trailing = common_from_odata_id(&ResourceODataId::parse(
            "/redfish/v1/Managers/1/SysLockdown/",
        )?);
        assert_eq!(trailing.id(), "SysLockdown");
        assert_eq!(trailing.name(), "SysLockdown");
        assert_eq!(trailing.description(), None);
        // A plain path derives its final segment.
        let plain = common_from_odata_id(&ResourceODataId::parse(
            "/redfish/v1/Managers/1/KCSInterface",
        )?);
        assert_eq!(plain.id(), "KCSInterface");
        assert_eq!(plain.name(), "KCSInterface");
        // A separator-only identifier has no segment to derive and falls
        // back to the whole value unchanged instead of an empty identity.
        let separators = common_from_odata_id(&ResourceODataId::parse("/")?);
        assert_eq!(separators.id(), "/");
        assert_eq!(separators.name(), "/");
        Ok(())
    }

    #[tokio::test]
    async fn projects_bios_family_without_losing_source_values() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(13)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Bios,
                    "/redfish/v1/Systems/1/Bios",
                    r#"{"Id":"BIOS","Name":"BIOS Configuration","AttributeRegistry":"BiosAttributeRegistry.v1_0_0","ResetBiosToDefaultsPending":false}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let bios = &result.resources()[1];
        assert_eq!(bios.feature(), ResourceFeature::Bios);
        assert_eq!(bios.odata_id().as_str(), "/redfish/v1/Systems/1/Bios");
        assert_eq!(bios.common().name(), "BIOS Configuration");
        assert!(matches!(
            bios.details(),
            CoreResourceDetails::Bios {
                attribute_registry: Some(registry),
            } if registry == "BiosAttributeRegistry.v1_0_0"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_boot_options_family_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(14)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::BootOptions,
                    "/redfish/v1/Systems/1/BootOptions/PXE-1",
                    r#"{"Id":"PXE-1","Name":"Network Boot Option","Description":"PXE boot option","BootOptionReference":"Boot0001","DisplayName":"PXE Network Boot","BootOptionEnabled":true,"UefiDevicePath":"PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)","Alias":"Pxe"}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let boot_option = &result.resources()[1];
        assert_eq!(boot_option.feature(), ResourceFeature::BootOptions);
        assert_eq!(
            boot_option.odata_id().as_str(),
            "/redfish/v1/Systems/1/BootOptions/PXE-1"
        );
        assert_eq!(boot_option.common().id(), "PXE-1");
        assert!(matches!(
            boot_option.details(),
            CoreResourceDetails::BootOption {
                display_name: Some(display_name),
                boot_option_enabled: Some(true),
                uefi_device_path: Some(device_path),
            } if display_name == "PXE Network Boot"
                && device_path == "PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_secure_boot_family_without_losing_source_values() -> Result<(), Box<dyn Error>>
    {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(15)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::SecureBoot,
                    "/redfish/v1/Systems/1/SecureBoot",
                    r#"{"Id":"SecureBoot","Name":"Secure Boot","SecureBootEnable":true,"SecureBootCurrentBoot":"Enabled","SecureBootMode":"DeployedMode"}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let secure_boot = &result.resources()[1];
        assert_eq!(secure_boot.feature(), ResourceFeature::SecureBoot);
        assert_eq!(
            secure_boot.odata_id().as_str(),
            "/redfish/v1/Systems/1/SecureBoot"
        );
        assert_eq!(secure_boot.common().name(), "Secure Boot");
        assert!(matches!(
            secure_boot.details(),
            CoreResourceDetails::SecureBoot {
                secure_boot_enable: Some(true),
                secure_boot_mode: Some(mode),
            } if mode == "DeployedMode"
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_power_and_thermal_families_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(16)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Power,
                    "/redfish/v1/Chassis/1/Power",
                    r#"{"Id":"Power","Name":"Power","Description":"Chassis power control"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Thermal,
                    "/redfish/v1/Chassis/1/Thermal",
                    r#"{"Id":"Thermal","Name":"Thermal","Description":"Chassis temperature and fan monitoring","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 3);
        let power = &result.resources()[1];
        assert_eq!(power.feature(), ResourceFeature::Power);
        assert_eq!(power.odata_id().as_str(), "/redfish/v1/Chassis/1/Power");
        assert_eq!(power.common().name(), "Power");
        assert!(matches!(power.details(), CoreResourceDetails::Power {}));
        let thermal = &result.resources()[2];
        assert_eq!(thermal.feature(), ResourceFeature::Thermal);
        assert_eq!(thermal.odata_id().as_str(), "/redfish/v1/Chassis/1/Thermal");
        assert_eq!(thermal.common().name(), "Thermal");
        assert!(matches!(
            thermal.details(),
            CoreResourceDetails::Thermal {
                status: Some(status),
            } if status.state() == Some("Enabled")
                && status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_sensors_and_controls_families_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(17)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Sensors,
                    "/redfish/v1/Chassis/1/Sensors/InletTemp",
                    r#"{"Id":"InletTemp","Name":"Chassis Inlet Temperature","ReadingType":"Temperature","Reading":27.5,"ReadingUnits":"Cel","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Controls,
                    "/redfish/v1/Chassis/1/Controls/FanDuty",
                    r#"{"Id":"FanDuty","Name":"Chassis Fan Duty","ControlType":"DutyCycle","SetPoint":30.0,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 3);
        // The inventory orders snapshots by `@odata.id`, so the controls
        // collection member sorts before the sensors collection member.
        let control = &result.resources()[1];
        assert_eq!(control.feature(), ResourceFeature::Controls);
        assert_eq!(
            control.odata_id().as_str(),
            "/redfish/v1/Chassis/1/Controls/FanDuty"
        );
        assert_eq!(control.common().name(), "Chassis Fan Duty");
        assert!(matches!(
            control.details(),
            CoreResourceDetails::Control {
                control_type: Some(control_type),
                set_point: Some(set_point),
                status: Some(status),
            } if control_type == "DutyCycle"
                && (*set_point - 30.0).abs() < f64::EPSILON
                && status.state() == Some("Enabled")
        ));
        let sensor = &result.resources()[2];
        assert_eq!(sensor.feature(), ResourceFeature::Sensors);
        assert_eq!(
            sensor.odata_id().as_str(),
            "/redfish/v1/Chassis/1/Sensors/InletTemp"
        );
        assert_eq!(sensor.common().name(), "Chassis Inlet Temperature");
        assert!(matches!(
            sensor.details(),
            CoreResourceDetails::Sensor {
                reading_type: Some(reading_type),
                reading: Some(reading),
                reading_units: Some(units),
                status: Some(status),
            } if reading_type == "Temperature"
                && (*reading - 27.5).abs() < f64::EPSILON
                && units == "Cel"
                && status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_log_services_manager_network_protocol_and_host_interfaces_families_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(18)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::LogServices,
                    "/redfish/v1/Managers/1/LogServices/1",
                    r#"{"Id":"1","Name":"BMC Event Log","Description":"Manager event log","ServiceEnabled":true,"MaxNumberOfRecords":1000,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::ManagerNetworkProtocol,
                    "/redfish/v1/Managers/1/NetworkProtocol",
                    r#"{"Id":"NetworkProtocol","Name":"Manager Network Protocol","HostName":"bmc-1","FQDN":"bmc-1.example.com","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::HostInterfaces,
                    "/redfish/v1/Managers/1/HostInterfaces/1",
                    r#"{"Id":"1","Name":"Host Interface One","InterfaceEnabled":true,"HostInterfaceType":"NetworkHostInterface","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.generation(), Some(generation));
        assert_eq!(result.observed_at(), Some(observed_at));
        assert_eq!(result.resources().len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the host
        // interface sorts before the log service, which sorts before the
        // manager network protocol singleton.
        let host_interface = &result.resources()[1];
        assert_eq!(host_interface.feature(), ResourceFeature::HostInterfaces);
        assert_eq!(
            host_interface.odata_id().as_str(),
            "/redfish/v1/Managers/1/HostInterfaces/1"
        );
        assert_eq!(host_interface.common().name(), "Host Interface One");
        assert!(matches!(
            host_interface.details(),
            CoreResourceDetails::HostInterface {
                interface_enabled: Some(true),
                status: Some(status),
            } if status.health() == Some("OK")
        ));
        let log_service = &result.resources()[2];
        assert_eq!(log_service.feature(), ResourceFeature::LogServices);
        assert_eq!(
            log_service.odata_id().as_str(),
            "/redfish/v1/Managers/1/LogServices/1"
        );
        assert_eq!(log_service.common().name(), "BMC Event Log");
        assert!(matches!(
            log_service.details(),
            CoreResourceDetails::LogService {
                service_enabled: Some(true),
                max_log_entries: Some(1000),
                status: Some(status),
            } if status.state() == Some("Enabled")
        ));
        let network_protocol = &result.resources()[3];
        assert_eq!(
            network_protocol.feature(),
            ResourceFeature::ManagerNetworkProtocol
        );
        assert_eq!(
            network_protocol.odata_id().as_str(),
            "/redfish/v1/Managers/1/NetworkProtocol"
        );
        assert_eq!(network_protocol.common().name(), "Manager Network Protocol");
        assert!(matches!(
            network_protocol.details(),
            CoreResourceDetails::ManagerNetworkProtocol {
                host_name: Some(host_name),
                fqdn: Some(fqdn),
                status: Some(status),
            } if host_name == "bmc-1"
                && fqdn == "bmc-1.example.com"
                && status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_pcie_devices_family_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(19)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::PcieDevices,
                    "/redfish/v1/Systems/1/PCIeDevices/GPU1",
                    r#"{"Id":"GPU1","Name":"PCIe Device One","Description":"GPU accelerator","DeviceType":"SingleFunction","Manufacturer":"Vendor C","Model":"PCIE-GEN4-X16","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let pcie_device = &result.resources()[1];
        assert_eq!(pcie_device.feature(), ResourceFeature::PcieDevices);
        assert_eq!(
            pcie_device.odata_id().as_str(),
            "/redfish/v1/Systems/1/PCIeDevices/GPU1"
        );
        assert_eq!(pcie_device.common().id(), "GPU1");
        assert_eq!(pcie_device.common().description(), Some("GPU accelerator"));
        assert!(matches!(
            pcie_device.details(),
            CoreResourceDetails::PcieDevice {
                device_type: Some(device_type),
                manufacturer: Some(manufacturer),
                model: Some(model),
                status: Some(status),
            } if device_type == "SingleFunction"
                && manufacturer == "Vendor C"
                && model == "PCIE-GEN4-X16"
                && status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_assembly_family_without_losing_source_values() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(20)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Assembly,
                    "/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
                    r#"{"Id":"0","Name":"Fan Assembly","Description":"Cooling fan","Producer":"Vendor D","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let assembly = &result.resources()[1];
        assert_eq!(assembly.feature(), ResourceFeature::Assembly);
        assert_eq!(
            assembly.odata_id().as_str(),
            "/redfish/v1/Chassis/1/Assembly#/Assemblies/0"
        );
        // The `AssemblyData` member schema declares no `Id` property, so the
        // member's `MemberId` array index is its stable identifier.
        assert_eq!(assembly.common().id(), "0");
        assert_eq!(assembly.common().name(), "Fan Assembly");
        assert!(matches!(
            assembly.details(),
            CoreResourceDetails::Assembly {
                producer: Some(producer),
                status: Some(status),
            } if producer == "Vendor D"
                && status.state() == Some("Enabled")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_software_inventory_family_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(21)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::SoftwareInventory,
                    "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
                    r#"{"Id":"BIOS","Name":"System BIOS","Description":"Host firmware","SoftwareId":"BIOS-2026-1","Version":"2.7.0","ReleaseDate":"2026-05-01T00:00:00Z","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let software_inventory = &result.resources()[1];
        assert_eq!(
            software_inventory.feature(),
            ResourceFeature::SoftwareInventory
        );
        assert_eq!(
            software_inventory.odata_id().as_str(),
            "/redfish/v1/UpdateService/SoftwareInventory/BIOS"
        );
        assert_eq!(software_inventory.common().name(), "System BIOS");
        assert!(matches!(
            software_inventory.details(),
            CoreResourceDetails::SoftwareInventory {
                software_id: Some(software_id),
                version: Some(version),
                release_date: Some(release_date),
                status: Some(status),
            } if software_id == "BIOS-2026-1"
                && version == "2.7.0"
                // The typed `ReleaseDate` instant of the fixture timestamp
                // `2026-05-01T00:00:00Z` (epoch seconds 1777593600) survives
                // the projection unchanged.
                && *release_date
                    == OffsetDateTime::from_unix_timestamp(1_777_593_600)
                        .map_err(|_| "fixture release date must convert")?
                && status.health() == Some("OK")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_event_service_family_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(22)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::EventService,
                    "/redfish/v1/EventService",
                    r#"{"Id":"EventService","Name":"Event Service","Description":"Event subscription service","ServiceEnabled":true,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::EventSubscription,
                    "/redfish/v1/EventService/Subscriptions/1",
                    r#"{"Id":"1","Name":"Subscription One","Description":"Alert subscription","Destination":"https://subscriber.example.test/events","Protocol":"Redfish","Context":"Rack A","EventTypes":["Alert","StatusChange"],"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.generation(), Some(generation));
        assert_eq!(result.resources().len(), 3);
        // The inventory orders snapshots by `@odata.id`, so the event service
        // root singleton sorts before its subscriptions collection member.
        let event_service = &result.resources()[1];
        assert_eq!(event_service.feature(), ResourceFeature::EventService);
        assert_eq!(
            event_service.odata_id().as_str(),
            "/redfish/v1/EventService"
        );
        assert_eq!(event_service.common().name(), "Event Service");
        assert!(matches!(
            event_service.details(),
            CoreResourceDetails::EventService {
                service_enabled: Some(true),
                status: Some(status),
            } if status.health() == Some("OK")
        ));
        let subscription = &result.resources()[2];
        assert_eq!(subscription.feature(), ResourceFeature::EventSubscription);
        assert_eq!(
            subscription.odata_id().as_str(),
            "/redfish/v1/EventService/Subscriptions/1"
        );
        assert_eq!(subscription.common().id(), "1");
        assert!(matches!(
            subscription.details(),
            CoreResourceDetails::EventSubscription {
                destination: Some(destination),
                protocol: Some(protocol),
                context: Some(context),
                event_types: Some(event_types),
                status: Some(status),
            } if destination == "https://subscriber.example.test/events"
                && protocol == "Redfish"
                && context == "Rack A"
                && *event_types == ["Alert", "StatusChange"]
                && status.state() == Some("Enabled")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_telemetry_service_family_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(23)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::TelemetryService,
                    "/redfish/v1/TelemetryService",
                    r#"{"Id":"TelemetryService","Name":"Telemetry Service","Description":"Telemetry collection service","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::MetricDefinition,
                    "/redfish/v1/TelemetryService/MetricDefinitions/1",
                    r#"{"Id":"1","Name":"Inlet Temperature Definition","Description":"Inlet temperature metric","MetricType":"Numeric","Units":"Cel"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::MetricReport,
                    "/redfish/v1/TelemetryService/MetricReports/1",
                    r#"{"Id":"1","Name":"Inlet Temperature Report","Description":"Latest inlet temperature report","MetricValuesCount":12}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the telemetry
        // service root singleton sorts before its definitions collection
        // member, which sorts before the reports collection member.
        let telemetry = &result.resources()[1];
        assert_eq!(telemetry.feature(), ResourceFeature::TelemetryService);
        assert_eq!(
            telemetry.odata_id().as_str(),
            "/redfish/v1/TelemetryService"
        );
        assert_eq!(telemetry.common().name(), "Telemetry Service");
        assert!(matches!(
            telemetry.details(),
            CoreResourceDetails::TelemetryService {
                status: Some(status),
            } if status.state() == Some("Enabled")
        ));
        let definition = &result.resources()[2];
        assert_eq!(definition.feature(), ResourceFeature::MetricDefinition);
        assert_eq!(
            definition.odata_id().as_str(),
            "/redfish/v1/TelemetryService/MetricDefinitions/1"
        );
        assert_eq!(definition.common().name(), "Inlet Temperature Definition");
        assert!(matches!(
            definition.details(),
            CoreResourceDetails::MetricDefinition {
                units: Some(units),
                metric_type: Some(metric_type),
            } if units == "Cel" && metric_type == "Numeric"
        ));
        let report = &result.resources()[3];
        assert_eq!(report.feature(), ResourceFeature::MetricReport);
        assert_eq!(
            report.odata_id().as_str(),
            "/redfish/v1/TelemetryService/MetricReports/1"
        );
        assert_eq!(report.common().name(), "Inlet Temperature Report");
        // The snapshot payload is the 0.2.0 shape (only the derived count):
        // the missing `MetricValues` array must decode as `None` instead of
        // failing the strict decoder, so pre-0.4.0 snapshots stay readable.
        assert!(matches!(
            report.details(),
            CoreResourceDetails::MetricReport {
                metric_values_count: Some(12),
                metric_values: None,
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_metric_report_value_arrays() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(23)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::MetricReport,
                    "/redfish/v1/TelemetryService/MetricReports/1",
                    // The 0.4.0 snapshot shape: the `MetricValues` array of
                    // timestamped readings beside the derived count, with an
                    // explicit null value exercising the nullable decode.
                    r#"{"Id":"1","Name":"Inlet Temperature Report","Description":"Latest inlet temperature report","MetricValuesCount":2,"MetricValues":[{"Timestamp":"2026-08-05T10:20:00Z","MetricValue":"31.5"},{"Timestamp":"2026-08-05T10:21:00Z","MetricValue":null}]}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 2);
        let report = &result.resources()[1];
        assert_eq!(report.feature(), ResourceFeature::MetricReport);
        assert_eq!(report.common().name(), "Inlet Temperature Report");
        assert!(matches!(
            report.details(),
            CoreResourceDetails::MetricReport {
                metric_values_count: Some(2),
                metric_values: Some(values),
            } if values.len() == 2
                // The typed `Timestamp` instants of the fixture timestamps
                // (epoch seconds 1785925200 and 1785925260) survive the
                // projection unchanged, and the explicit null value decodes
                // as `None` while the text `MetricValue` stays untouched.
                && values[0].timestamp()
                    == Some(OffsetDateTime::from_unix_timestamp(1_785_925_200)
                        .map_err(|_| "fixture timestamp must convert")?)
                && values[0].value() == Some("31.5")
                && values[1].timestamp()
                    == Some(OffsetDateTime::from_unix_timestamp(1_785_925_260)
                        .map_err(|_| "fixture timestamp must convert")?)
                && values[1].value().is_none()
        ));
        Ok(())
    }

    #[tokio::test]
    async fn projects_task_service_family_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(24)?;
        let observed_at = endpoint.updated_at();
        let item = EndpointInventoryItem::try_new(
            endpoint,
            vec![
                snapshot(
                    endpoint_id,
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::TaskService,
                    "/redfish/v1/TaskService",
                    r#"{"Id":"TaskService","Name":"Task Service","Description":"Asynchronous task service","ServiceEnabled":true,"CompletedTaskOverWritePolicy":"Oldest","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::Task,
                    "/redfish/v1/TaskService/Tasks/1",
                    r#"{"Id":"1","Name":"Firmware Update Task","Description":"BIOS firmware update","TaskState":"Running","TaskStatus":"OK","PercentComplete":42,"StartTime":"2026-08-05T10:20:00Z","EndTime":null}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.generation(), Some(generation));
        assert_eq!(result.resources().len(), 3);
        // The inventory orders snapshots by `@odata.id`, so the task service
        // root singleton sorts before its tasks collection member.
        let task_service = &result.resources()[1];
        assert_eq!(task_service.feature(), ResourceFeature::TaskService);
        assert_eq!(task_service.odata_id().as_str(), "/redfish/v1/TaskService");
        assert_eq!(task_service.common().name(), "Task Service");
        assert!(matches!(
            task_service.details(),
            CoreResourceDetails::TaskService {
                service_enabled: Some(true),
                completed_task_overwrite_policy: Some(policy),
                status: Some(status),
            } if policy == "Oldest" && status.health() == Some("OK")
        ));
        let task = &result.resources()[2];
        assert_eq!(task.feature(), ResourceFeature::Task);
        assert_eq!(task.odata_id().as_str(), "/redfish/v1/TaskService/Tasks/1");
        assert_eq!(task.common().name(), "Firmware Update Task");
        assert!(matches!(
            task.details(),
            CoreResourceDetails::Task {
                task_state: Some(task_state),
                task_status: Some(task_status),
                percent_complete: Some(42),
                start_time: Some(start_time),
                end_time: None,
            } if task_state == "Running"
                && task_status == "OK"
                // The typed `StartTime` instant of the fixture timestamp
                // `2026-08-05T10:20:00Z` (epoch seconds 1785925200) survives
                // the projection unchanged.
                && *start_time
                    == OffsetDateTime::from_unix_timestamp(1_785_925_200)
                        .map_err(|_| "fixture start time must convert")?
        ));
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_missing_waiting_repository_and_corrupt_payload_states()
    -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let waiting = EndpointInventoryItem::try_new(endpoint.clone(), Vec::new())?;
        let result =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![waiting]), endpoint_id)
                .execute()
                .await?
                .ok_or("waiting endpoint must exist")?;
        assert_eq!(result.generation(), None);
        assert_eq!(result.observed_at(), None);
        assert!(result.resources().is_empty());

        assert!(
            EndpointResourceInventoryQuery::new(MockRepository::ok(Vec::new()), endpoint_id,)
                .execute()
                .await?
                .is_none()
        );
        assert!(matches!(
            EndpointResourceInventoryQuery::new(MockRepository::failed(), endpoint_id)
                .execute()
                .await,
            Err(EndpointResourceInventoryQueryError::Inventory(_))
        ));

        let generation = RefreshGeneration::new(1)?;
        let corrupt = EndpointInventoryItem::try_new(
            endpoint,
            vec![snapshot(
                endpoint_id,
                ResourceFeature::ServiceRoot,
                "/redfish/v1",
                r#"{"Name":"missing required Id"}"#,
                OffsetDateTime::UNIX_EPOCH,
                generation,
            )?],
        )?;
        assert!(matches!(
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![corrupt]), endpoint_id)
                .execute()
                .await,
            Err(EndpointResourceInventoryQueryError::Projection {
                feature: ResourceFeature::ServiceRoot,
                ..
            })
        ));
        Ok(())
    }

    fn endpoint() -> Result<Endpoint, Box<dyn Error>> {
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Resource inventory BMC")?,
            EndpointAddress::parse("https://192.0.2.90")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"resource inventory certificate".to_vec())?,
                trusted_at: OffsetDateTime::UNIX_EPOCH,
            },
            CredentialId::generate(),
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH,
        )?)
    }

    fn snapshot(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        payload: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(payload)?,
            observed_at,
            generation,
        ))
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockError;

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock resource inventory failure")
        }
    }

    impl Error for MockError {}

    struct MockRepository {
        result: Result<Vec<EndpointInventoryItem>, MockError>,
    }

    impl MockRepository {
        fn ok(items: Vec<EndpointInventoryItem>) -> Self {
            Self { result: Ok(items) }
        }

        fn failed() -> Self {
            Self {
                result: Err(MockError),
            }
        }
    }

    impl EndpointInventoryRepository for MockRepository {
        type Error = MockError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async { self.result.clone() })
        }
    }
}
