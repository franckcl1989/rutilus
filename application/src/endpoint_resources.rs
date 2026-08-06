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

/// Feature-specific fields from one public `nv-redfish` typed projection.
#[derive(Clone, Debug, Eq, PartialEq)]
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
}

/// One immutable core-resource snapshot ready for an API or UI boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
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
#[derive(Clone, Debug, Eq, PartialEq)]
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
        ResourceFeature::Processors => project_processor(snapshot, payload)?,
        ResourceFeature::Memory => project_memory(snapshot, payload)?,
        ResourceFeature::Storages => project_storage(snapshot, payload)?,
        ResourceFeature::NetworkAdapters => project_network_adapter(snapshot, payload)?,
        ResourceFeature::EthernetInterfaces => project_ethernet_interface(snapshot, payload)?,
        ResourceFeature::Accounts => project_account(snapshot, payload)?,
        ResourceFeature::Bios => project_bios(snapshot, payload)?,
        ResourceFeature::BootOptions => project_boot_option(snapshot, payload)?,
        ResourceFeature::SecureBoot => project_secure_boot(snapshot, payload)?,
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
