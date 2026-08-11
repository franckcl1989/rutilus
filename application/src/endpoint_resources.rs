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

/// The §0.5.0 NVIDIA `Truststore` metadata of the `SystemConfigProfile`
/// chain-root document.
///
/// Each field records the presence of one certificate-store link
/// (`NvidiaCertificates` / `OemCertificates`) of the compiled schema; the
/// certificate documents behind the links are never fetched and their
/// certificate payloads never enter the product — the sensitive surface is
/// deferred to a later slice.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OemNvidiaSystemConfigProfileTruststore {
    nvidia_certificates: Option<bool>,
    oem_certificates: Option<bool>,
}

impl OemNvidiaSystemConfigProfileTruststore {
    #[must_use]
    pub fn new(nvidia_certificates: Option<bool>, oem_certificates: Option<bool>) -> Self {
        Self {
            nvidia_certificates,
            oem_certificates,
        }
    }

    /// Whether the `NvidiaCertificates` link was present.
    #[must_use]
    pub const fn nvidia_certificates(&self) -> Option<bool> {
        self.nvidia_certificates
    }

    /// Whether the `OemCertificates` link was present.
    #[must_use]
    pub const fn oem_certificates(&self) -> Option<bool> {
        self.oem_certificates
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

/// One embedded sensor excerpt of a §2.1 `environment-metrics` document.
///
/// The `EnvironmentMetrics` schema embeds each measurement as an excerpt
/// carrying the `DataSourceUri` link to its backing `Sensor` resource and the
/// current `Reading` value, so the projection keeps exactly those two fields:
/// the console renders the reading without re-parsing text and the summary
/// names the sensor that sourced it.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvironmentMetricsReadingSummary {
    data_source_uri: Option<String>,
    reading: Option<f64>,
}

impl EnvironmentMetricsReadingSummary {
    #[must_use]
    pub const fn new(data_source_uri: Option<String>, reading: Option<f64>) -> Self {
        Self {
            data_source_uri,
            reading,
        }
    }

    #[must_use]
    pub fn data_source_uri(&self) -> Option<&str> {
        self.data_source_uri.as_deref()
    }

    #[must_use]
    pub const fn reading(&self) -> Option<f64> {
        self.reading
    }
}

/// The embedded power-limit control excerpt of a §2.1 `environment-metrics`
/// document.
///
/// `PowerLimitWatts` embeds a `Control` excerpt instead of a sensor excerpt,
/// so the summary carries its `DataSourceUri` link and `SetPoint` reading
/// exactly like the sensor excerpts carry theirs.
#[derive(Clone, Debug, PartialEq)]
pub struct EnvironmentMetricsControlSummary {
    data_source_uri: Option<String>,
    set_point: Option<f64>,
}

impl EnvironmentMetricsControlSummary {
    #[must_use]
    pub const fn new(data_source_uri: Option<String>, set_point: Option<f64>) -> Self {
        Self {
            data_source_uri,
            set_point,
        }
    }

    #[must_use]
    pub fn data_source_uri(&self) -> Option<&str> {
        self.data_source_uri.as_deref()
    }

    #[must_use]
    pub const fn set_point(&self) -> Option<f64> {
        self.set_point
    }
}

/// Feature-specific fields from one public `nv-redfish` typed projection.
///
/// `PartialEq` (not `Eq`) is deliberate: the Sensor and Control variants
/// carry numeric readings (`f64`, matching the compiled `Edm.Decimal` type
/// of nv-redfish 0.13), and `f64` cannot implement `Eq`.
///
/// The `EnvironmentMetrics` variant is the largest because the schema embeds
/// thirteen measurements; its field set stays unboxed so the variant mirrors
/// the wire contract variant field for field (the shared contract keeps the
/// tagged `details` object flat for the strict `deny_unknown_fields`
/// boundary), so the size difference stays a deliberate contract property
/// exactly like the `CoreResourceDetailsResponse` enumeration.
#[allow(clippy::large_enum_variant)]
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
    /// One §0.5.0 NVIDIA system-config-profile chain member: the chain-root
    /// `SystemConfigProfile` document of the `ComputerSystem`'s `Oem.Nvidia`
    /// segment, read through the compiled `oem-nvidia-profiles` surface
    /// (§11.5). The whole chain — this document, its status singleton, the
    /// profile collection, and each member's profile file — shares the single
    /// family code `nvidia-system-config-profile`, because the chain root
    /// decides whether the chain exists at all. The details are the
    /// `Truststore` metadata: the presence of each certificate-store link,
    /// never the certificate payloads behind them (the sensitive surface is
    /// deferred).
    OemNvidiaSystemConfigProfile {
        truststore: Option<OemNvidiaSystemConfigProfileTruststore>,
    },
    /// One §0.5.0 NVIDIA system-config-profile chain member: the
    /// `SystemConfigProfileStatus` document. The details are the compiled
    /// status fields: the `PendingList.Activation` text, the numeric
    /// `ActiveProfileIndex` / `BmcProfileVersion` / `DefaultProfileIndex`
    /// indices, and the `FactoryResetStatus` text; each is `None` when the
    /// endpoint did not publish the property.
    OemNvidiaSystemConfigProfileStatus {
        pending_list_activation: Option<String>,
        active_profile_index: Option<i64>,
        bmc_profile_version: Option<i64>,
        factory_reset_status: Option<String>,
        default_profile_index: Option<i64>,
    },
    /// One §0.5.0 NVIDIA system-config-profile chain member: one
    /// `SystemProfile` member of the profile collection. The details are the
    /// compiled metadata fields (`Default`, `Owner`, `UUID`, the numeric
    /// `Version`, and `ProfileName`); the profile file behind the member's
    /// `ProfileFile` navigation is its own chain document and its own
    /// variant.
    OemNvidiaSystemProfile {
        default: Option<bool>,
        owner: Option<String>,
        uuid: Option<String>,
        version: Option<i64>,
        profile_name: Option<String>,
    },
    /// One §0.5.0 NVIDIA system-config-profile chain member: the
    /// `SystemProfileFile` document behind one profile member's
    /// `ProfileFile` navigation. The details are the compiled `Metadata`
    /// fields (`Activate`, `Delete`, `OriginProfileUUID`, `More_Profiles`,
    /// `ProjectName`, `UUID`) and the base64 `Profile` content, kept verbatim
    /// (§12.3).
    OemNvidiaSystemProfileFile {
        metadata_activate: Option<bool>,
        metadata_delete: Option<bool>,
        metadata_origin_profile_uuid: Option<String>,
        metadata_more_profiles: Option<bool>,
        metadata_project_name: Option<String>,
        metadata_uuid: Option<String>,
        profile: Option<String>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: the chain-root
    /// `NvidiaPowerComplianceManager` document of the `Manager`'s
    /// `Oem.Nvidia` segment, read through the compiled
    /// `oem-nvidia-power-management` surface (§11.5). The whole chain — this
    /// document, its `PowerDomains` collection members, the `ACLossPolicy` /
    /// `PSUCompliancePolicy` singletons, the `ManagedEntityGroups` collection
    /// members, the `PowerStateGroup` document with its
    /// `PowerShelfControllers` / `PowerSupplies` collection members, and the
    /// `PSURedundancy` singleton — shares the single family code
    /// `nvidia-power-compliance`, because the chain root decides whether the
    /// chain exists at all. The details are the compiled `ManagerType` enum
    /// spelling (e.g. `PowerManager`), verbatim per §12.3.
    OemNvidiaPowerCompliance { manager_type: Option<String> },
    /// One §0.5.0 NVIDIA power-compliance chain member: one `NvidiaPowerDomain`
    /// member of the compliance manager's `PowerDomains` collection. The
    /// details are the compiled scalar fields: the numeric `Value`, the
    /// `Type` / `Unit` enumerations, and the `SensorReadingType` /
    /// `SensorImpl` sensor enumerations, each verbatim per §12.3.
    OemNvidiaPowerDomain {
        value: Option<i64>,
        r#type: Option<String>,
        unit: Option<String>,
        sensor_reading_type: Option<String>,
        sensor_impl: Option<String>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: the `ACLossPolicy`
    /// or `PSUCompliancePolicy` singleton (one variant for both, they share
    /// the compiled `NvidiaPowerPolicy` schema). The details are the compiled
    /// scalar fields: the `AutoDeassertPowerBrake` boolean, the numeric
    /// `Min` / `Max` thresholds, the `Type` / `Unit` enumerations, and the
    /// `PolicyActions` enumeration, each verbatim per §12.3. The `DwellTime`
    /// duration stays out of the strictly projectable field set.
    OemNvidiaPowerPolicy {
        auto_deassert_power_brake: Option<bool>,
        min: Option<i64>,
        max: Option<i64>,
        r#type: Option<String>,
        unit: Option<String>,
        policy_actions: Option<String>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: one
    /// `NvidiaManagedEntityGroup` member of the compliance manager's
    /// `ManagedEntityGroups` collection. The details are the compiled
    /// `CurrentManagedEntityId` text; the group's `ManagedEntities`
    /// navigation belongs to the managed-entity family.
    OemNvidiaManagedEntityGroup {
        current_managed_entity_id: Option<String>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: the
    /// `NvidiaPowerStateGroup` document. The details are the compiled scalar
    /// fields: the `PscId` text and the numeric `GeneratedWatts` /
    /// `NumberOfPscs` / `NumberOfLocalPsus`; the `PowerShelfControllers` /
    /// `PowerSupplies` collection members are their own chain documents and
    /// their own variants.
    OemNvidiaPowerStateGroup {
        psc_id: Option<String>,
        generated_watts: Option<i64>,
        number_of_pscs: Option<i64>,
        number_of_local_psus: Option<i64>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: one `NvidiaPscState`
    /// member of the power state group's `PowerShelfControllers` collection.
    /// The details are the compiled scalar fields: the `PscId` text, the
    /// numeric `NumOfOperationalPsus` / `MillisecondsSinceLastHeartbeat`,
    /// the `PowerBrakeAssert` boolean, and the `Status` enumeration, each
    /// verbatim per §12.3.
    OemNvidiaPscState {
        psc_id: Option<String>,
        num_of_operational_psus: Option<i64>,
        power_brake_assert: Option<bool>,
        milliseconds_since_last_heartbeat: Option<i64>,
        status: Option<String>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: one `NvidiaPsuState`
    /// member of the power state group's `PowerSupplies` collection. The
    /// details are the compiled scalar fields: the `PsuId` text and the
    /// `Presence` / `Input1Active` / `Input2Active` booleans, each verbatim
    /// per §12.3.
    OemNvidiaPsuState {
        psu_id: Option<String>,
        presence: Option<bool>,
        input1active: Option<bool>,
        input2active: Option<bool>,
    },
    /// One §0.5.0 NVIDIA power-compliance chain member: the
    /// `NvidiaPsuRedundancy` document. The details are the compiled scalar
    /// fields: the `MaxNumSupported` / `MinNumNeeded` texts and the
    /// `RedundancySetting` enumeration, each verbatim per §12.3.
    OemNvidiaPsuRedundancy {
        max_num_supported: Option<String>,
        min_num_needed: Option<String>,
        redundancy_setting: Option<String>,
    },
    /// One §0.5.0 NVIDIA managed-entity chain member: one
    /// `NvidiaManagedEntity` member of a group member's `ManagedEntities`
    /// collection, read through the compiled `oem-nvidia-power-management`
    /// surface (§11.5). The chain — the `ManagedEntityGroups` collection
    /// behind the compliance manager's `ManagedEntityGroups` navigation (the
    /// chain's entry, whose presence decides whether the chain exists at
    /// all) and each entity member — shares the single family code
    /// `nvidia-managed-entity`. The details are the compiled scalar fields:
    /// the `TransportProtocol` enumeration, the `IPv4Address` /
    /// `IPv6Address` address texts, and the numeric `Port`, each verbatim
    /// per §12.3.
    OemNvidiaManagedEntity {
        transport_protocol: Option<String>,
        ipv4_address: Option<String>,
        ipv6_address: Option<String>,
        port: Option<i64>,
    },
    /// One §0.5.0 OEM family member: the manager's Lenovo `SecurityService`
    /// document, read through the compiled `oem-lenovo` surface (§11.5 — an
    /// OEM surface is projected only when upstream compiles it). The
    /// `FWRollback` value is the vendor's enum spelling verbatim (e.g.
    /// `Enabled`, `Disabled`, or `UnsupportedValue` for a value this build
    /// cannot classify), never translated, per §12.3. The compiled schema
    /// models the rollback state inside the `Configurator` segment, and the
    /// upstream `LenovoSecurityService::fw_rollback` wrapper collapses that
    /// nesting onto its single typed accessor; the projection follows the
    /// wrapper surface, so the wire carries the flattened `FWRollback` field.
    /// The compiled base `resource::Resource` requires `Id` / `Name`, so the
    /// product identity comes from the payload exactly like every standard
    /// family.
    OemLenovoSecurityService { fw_rollback: Option<String> },
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
    /// One §2.1 `network-device-functions` family member (a
    /// `NetworkDeviceFunction_v1` member linked from an adapter).
    /// `net_dev_func_type` stays the `NetworkDeviceTechnology` enumeration
    /// string so the console renders the function type without re-parsing
    /// text, and `device_enabled` is the direct `DeviceEnabled` Boolean; the
    /// protocol-specific configuration bags (`Ethernet`, `iSCSIBoot`,
    /// `FibreChannel`, ...) stay out of this strictly projectable field set.
    NetworkDeviceFunction {
        net_dev_func_type: Option<String>,
        device_enabled: Option<bool>,
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
    /// One §2.1 `power-equipment` family member (a `PowerEquipment_v1`
    /// service document or a `PowerDistribution_v1` member of its
    /// `PowerShelves` collection; the family shares the single feature code
    /// because the root document decides whether the family exists at all).
    /// The root document projects `Status` only; the shelf members add
    /// `equipment_type` (the `PowerEquipmentType` enumeration string) and the
    /// hardware identity properties. Every field stays optional so one
    /// projection covers both payload shapes.
    PowerEquipment {
        equipment_type: Option<String>,
        manufacturer: Option<String>,
        model: Option<String>,
        part_number: Option<String>,
        serial_number: Option<String>,
        version: Option<String>,
        firmware_version: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
    /// One §2.1 `power-supplies` family member (a `PowerSupply_v1` member of
    /// the `PowerSupplies` collection). `power_supply_type` stays the
    /// `PowerSupplyType` enumeration string (`AC`, `DC`, `ACorDC`,
    /// `DCRegulator`) and `power_capacity_watts` stays numeric, so the
    /// console renders the supply without re-parsing text; the input-range
    /// and output-rail bags stay out of this strictly projectable field set.
    PowerSupply {
        power_supply_type: Option<String>,
        power_capacity_watts: Option<f64>,
        manufacturer: Option<String>,
        model: Option<String>,
        firmware_version: Option<String>,
        serial_number: Option<String>,
        part_number: Option<String>,
        status: Option<ResourceStatusSummary>,
    },
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
    /// One §2.1 `environment-metrics` family member (an
    /// `EnvironmentMetrics_v1` chassis singleton). Every embedded measurement
    /// the schema declares is projected through its excerpt reading; the
    /// schema declares no `Status` property, so this family carries no status
    /// field.
    EnvironmentMetrics {
        temperature_celsius: Option<EnvironmentMetricsReadingSummary>,
        humidity_percent: Option<EnvironmentMetricsReadingSummary>,
        fan_speeds_percent: Option<Vec<EnvironmentMetricsReadingSummary>>,
        power_watts: Option<EnvironmentMetricsReadingSummary>,
        energyk_wh: Option<EnvironmentMetricsReadingSummary>,
        power_load_percent: Option<EnvironmentMetricsReadingSummary>,
        power_limit_watts: Option<EnvironmentMetricsControlSummary>,
        dew_point_celsius: Option<EnvironmentMetricsReadingSummary>,
        absolute_humidity: Option<EnvironmentMetricsReadingSummary>,
        energy_joules: Option<EnvironmentMetricsReadingSummary>,
        ambient_temperature_celsius: Option<EnvironmentMetricsReadingSummary>,
        voltage: Option<EnvironmentMetricsReadingSummary>,
        current_amps: Option<EnvironmentMetricsReadingSummary>,
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
    #[error(
        "resource {resource_id} has an {feature} snapshot that is not yet projectable in this layer"
    )]
    NotYetProjectable {
        resource_id: ResourceId,
        feature: ResourceFeature,
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
        ResourceFeature::OemNvidiaSystemConfigProfile => {
            project_oem_nvidia_system_config_profile(snapshot, payload)?
        }
        ResourceFeature::OemNvidiaPowerCompliance => {
            project_oem_nvidia_power_compliance(snapshot, payload)?
        }
        ResourceFeature::OemNvidiaManagedEntity => {
            project_oem_nvidia_managed_entity(snapshot, payload)?
        }
        ResourceFeature::OemLenovoSecurityService => {
            project_oem_lenovo_security_service(snapshot, payload)?
        }
        ResourceFeature::OemAmiServiceRoot
        | ResourceFeature::OemAmiConfigBmc
        | ResourceFeature::OemHpeILoServiceExt
        | ResourceFeature::OemHpeManager
        | ResourceFeature::OemLiteOnPowerSupply
        | ResourceFeature::OemDeltaPowerSupply => {
            // The typed projections of the 0.5 OEM read families (`AmiServiceRoot`,
            // `ConfigBmc`, `HpeiLoServiceExt`, `HpeiLo`, `LiteonPowerSupply`, and
            // `DeltaPowerSupply`) land with the resource-details slice; the six
            // families share the single arm because they all keep the compiled
            // snapshots countable and storable while the details projection stays
            // deferred, reported as a controlled error instead of panicking.
            return Err(EndpointResourceInventoryQueryError::NotYetProjectable {
                resource_id: snapshot.resource_id(),
                feature: snapshot.feature(),
            });
        }
        ResourceFeature::Processors => project_processor(snapshot, payload)?,
        ResourceFeature::Memory => project_memory(snapshot, payload)?,
        ResourceFeature::Storages => project_storage(snapshot, payload)?,
        ResourceFeature::NetworkAdapters => project_network_adapter(snapshot, payload)?,
        ResourceFeature::NetworkDeviceFunctions => {
            project_network_device_function(snapshot, payload)?
        }
        ResourceFeature::PowerEquipment => project_power_equipment(snapshot, payload)?,
        ResourceFeature::PowerSupplies => project_power_supply(snapshot, payload)?,
        ResourceFeature::EnvironmentMetrics => project_environment_metrics(snapshot, payload)?,
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

fn project_oem_lenovo_security_service<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<OemLenovoSecurityServicePayload, _, RepositoryError>(
        snapshot,
        payload,
        |parsed| CoreResourceDetails::OemLenovoSecurityService {
            fw_rollback: parsed.fw_rollback,
        },
    )
}

/// Projects one NVIDIA system-config-profile chain snapshot into its details
/// shape.
///
/// The one family code covers the whole chain (the profile service document,
/// its status singleton, each profile member, and each profile file), so the
/// snapshot payload carries the chain document's kind — written by the infra
/// projection, which knows the compiled decode target — and this projector
/// routes on it. A payload without a recognizable `DocumentType` is one odd
/// snapshot and fails the projection exactly like an unreadable one.
// The router projects the four chain document kinds of the one family code
// in one place; the four arms exceed the pedantic line budget, so the lint
// is scoped to this router exactly like the fixture-sequence tests.
#[allow(clippy::too_many_lines)]
fn project_oem_nvidia_system_config_profile<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    let envelope = deserialize_payload::<OemNvidiaSystemConfigProfileEnvelope, RepositoryError>(
        snapshot, payload,
    )?;
    match envelope.document_type {
        OemNvidiaSystemConfigProfileDocument::SystemConfigProfile => {
            let parsed = deserialize_payload::<OemNvidiaSystemConfigProfilePayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaSystemConfigProfile {
                    truststore: parsed.truststore.map(
                        |OemNvidiaSystemConfigProfileTruststorePayload {
                             nvidia_certificates,
                             oem_certificates,
                         }| {
                            OemNvidiaSystemConfigProfileTruststore::new(
                                nvidia_certificates,
                                oem_certificates,
                            )
                        },
                    ),
                },
            ))
        }
        OemNvidiaSystemConfigProfileDocument::SystemConfigProfileStatus => {
            let parsed = deserialize_payload::<
                OemNvidiaSystemConfigProfileStatusPayload,
                RepositoryError,
            >(snapshot, payload)?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaSystemConfigProfileStatus {
                    pending_list_activation: parsed
                        .pending_list
                        .and_then(|pending_list| pending_list.activation),
                    active_profile_index: parsed.active_profile_index,
                    bmc_profile_version: parsed.bmc_profile_version,
                    factory_reset_status: parsed.factory_reset_status,
                    default_profile_index: parsed.default_profile_index,
                },
            ))
        }
        OemNvidiaSystemConfigProfileDocument::SystemProfile => {
            let parsed = deserialize_payload::<OemNvidiaSystemProfilePayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaSystemProfile {
                    default: parsed.default,
                    owner: parsed.owner,
                    uuid: parsed.uuid,
                    version: parsed.version,
                    profile_name: parsed.profile_name,
                },
            ))
        }
        OemNvidiaSystemConfigProfileDocument::SystemProfileFile => {
            let parsed = deserialize_payload::<OemNvidiaSystemProfileFilePayload, RepositoryError>(
                snapshot, payload,
            )?;
            let common = nvidia_common_from_snapshot(snapshot, &parsed);
            let OemNvidiaSystemProfileFileContentPayload { metadata, profile } = parsed
                .profile_file
                .unwrap_or(OemNvidiaSystemProfileFileContentPayload {
                    metadata: None,
                    profile: None,
                });
            let OemNvidiaSystemProfileFileMetadataPayload {
                activate,
                delete,
                origin_profile_uuid,
                more_profiles,
                project_name,
                uuid,
            } = metadata.unwrap_or(OemNvidiaSystemProfileFileMetadataPayload {
                activate: None,
                delete: None,
                origin_profile_uuid: None,
                more_profiles: None,
                project_name: None,
                uuid: None,
            });
            Ok((
                common,
                CoreResourceDetails::OemNvidiaSystemProfileFile {
                    metadata_activate: activate,
                    metadata_delete: delete,
                    metadata_origin_profile_uuid: origin_profile_uuid,
                    metadata_more_profiles: more_profiles,
                    metadata_project_name: project_name,
                    metadata_uuid: uuid,
                    profile,
                },
            ))
        }
    }
}

// The router projects the eight chain document kinds of the one
// power-compliance family code in one place; the eight arms exceed the
// pedantic line budget, so the lint is scoped to this router exactly like
// the system-config-profile router.
#[allow(clippy::too_many_lines)]
fn project_oem_nvidia_power_compliance<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    let envelope = deserialize_payload::<OemNvidiaPowerComplianceEnvelope, RepositoryError>(
        snapshot, payload,
    )?;
    match envelope.document_type {
        OemNvidiaPowerComplianceDocument::PowerComplianceManager => {
            let parsed = deserialize_payload::<OemNvidiaPowerCompliancePayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPowerCompliance {
                    manager_type: parsed.manager_type,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::PowerDomain => {
            let parsed = deserialize_payload::<OemNvidiaPowerDomainPayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPowerDomain {
                    value: parsed.value,
                    r#type: parsed.r#type,
                    unit: parsed.unit,
                    sensor_reading_type: parsed.sensor_reading_type,
                    sensor_impl: parsed.sensor_impl,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::PowerPolicy => {
            let parsed = deserialize_payload::<OemNvidiaPowerPolicyPayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPowerPolicy {
                    auto_deassert_power_brake: parsed.auto_deassert_power_brake,
                    min: parsed.min,
                    max: parsed.max,
                    r#type: parsed.r#type,
                    unit: parsed.unit,
                    policy_actions: parsed.policy_actions,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::ManagedEntityGroup => {
            let parsed = deserialize_payload::<OemNvidiaManagedEntityGroupPayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaManagedEntityGroup {
                    current_managed_entity_id: parsed.current_managed_entity_id,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::PowerStateGroup => {
            let parsed = deserialize_payload::<OemNvidiaPowerStateGroupPayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPowerStateGroup {
                    psc_id: parsed.psc_id,
                    generated_watts: parsed.generated_watts,
                    number_of_pscs: parsed.number_of_pscs,
                    number_of_local_psus: parsed.number_of_local_psus,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::PscState => {
            let parsed = deserialize_payload::<OemNvidiaPscStatePayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPscState {
                    psc_id: parsed.psc_id,
                    num_of_operational_psus: parsed.num_of_operational_psus,
                    power_brake_assert: parsed.power_brake_assert,
                    milliseconds_since_last_heartbeat: parsed.milliseconds_since_last_heartbeat,
                    status: parsed.status,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::PsuState => {
            let parsed = deserialize_payload::<OemNvidiaPsuStatePayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPsuState {
                    psu_id: parsed.psu_id,
                    presence: parsed.presence,
                    input1active: parsed.input1active,
                    input2active: parsed.input2active,
                },
            ))
        }
        OemNvidiaPowerComplianceDocument::PsuRedundancy => {
            let parsed = deserialize_payload::<OemNvidiaPsuRedundancyPayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaPsuRedundancy {
                    max_num_supported: parsed.max_num_supported,
                    min_num_needed: parsed.min_num_needed,
                    redundancy_setting: parsed.redundancy_setting,
                },
            ))
        }
    }
}

fn project_oem_nvidia_managed_entity<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    let envelope =
        deserialize_payload::<OemNvidiaManagedEntityEnvelope, RepositoryError>(snapshot, payload)?;
    match envelope.document_type {
        OemNvidiaManagedEntityDocument::ManagedEntity => {
            let parsed = deserialize_payload::<OemNvidiaManagedEntityPayload, RepositoryError>(
                snapshot, payload,
            )?;
            Ok((
                nvidia_common_from_snapshot(snapshot, &parsed),
                CoreResourceDetails::OemNvidiaManagedEntity {
                    transport_protocol: parsed.transport_protocol,
                    ipv4_address: parsed.ipv4_address,
                    ipv6_address: parsed.ipv6_address,
                    port: parsed.port,
                },
            ))
        }
    }
}

/// Derives the common identity of one NVIDIA chain snapshot.
///
/// The compiled NVIDIA documents carry `Id` / `Name` / `Description` on
/// their `resource::Resource` base, so the infra projection writes them; a
/// stored snapshot without them (an odd snapshot whose common fields were
/// never written) falls back to the Supermicro precedent — the final segment
/// of the snapshot's `@odata.id`, the Redfish `Id` per DSP0266 — instead of
/// becoming unreadable.
fn nvidia_common_from_snapshot(
    snapshot: &ResourceSnapshot,
    parsed: &impl NvidiaCommonFields,
) -> CoreResourceCommon {
    match parsed.id() {
        Some(id) => CoreResourceCommon {
            id: id.to_owned(),
            name: parsed.name().map_or_else(|| id.to_owned(), str::to_owned),
            description: parsed.description().map(str::to_owned),
        },
        None => common_from_odata_id(snapshot.odata_id()),
    }
}

/// The common identity fields every NVIDIA chain payload carries (each
/// optional, with the `@odata.id` fallback when absent).
trait NvidiaCommonFields {
    fn id(&self) -> Option<&str>;
    fn name(&self) -> Option<&str>;
    fn description(&self) -> Option<&str>;
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

fn project_network_device_function<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<NetworkDeviceFunctionPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::NetworkDeviceFunction {
            net_dev_func_type: parsed.net_dev_func_type,
            device_enabled: parsed.device_enabled,
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

fn project_power_equipment<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    // The `PowerEquipment` feature covers both the root service document and
    // its `PowerShelves` members, so the payload union carries every
    // optional field of either shape and the root document decodes with the
    // shelf fields absent.
    project_typed::<PowerEquipmentPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::PowerEquipment {
            equipment_type: parsed.equipment_type,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            part_number: parsed.part_number,
            serial_number: parsed.serial_number,
            version: parsed.version,
            firmware_version: parsed.firmware_version,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
    })
}

fn project_power_supply<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<PowerSupplyPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::PowerSupply {
            power_supply_type: parsed.power_supply_type,
            power_capacity_watts: parsed.power_capacity_watts,
            manufacturer: parsed.manufacturer,
            model: parsed.model,
            firmware_version: parsed.firmware_version,
            serial_number: parsed.serial_number,
            part_number: parsed.part_number,
            status: parsed.status.map(ResourceStatusPayload::into_summary),
        }
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

fn project_environment_metrics<RepositoryError>(
    snapshot: &ResourceSnapshot,
    payload: &str,
) -> Result<
    (CoreResourceCommon, CoreResourceDetails),
    EndpointResourceInventoryQueryError<RepositoryError>,
>
where
    RepositoryError: Error + 'static,
{
    project_typed::<EnvironmentMetricsPayload, _, RepositoryError>(snapshot, payload, |parsed| {
        CoreResourceDetails::EnvironmentMetrics {
            temperature_celsius: parsed.temperature_celsius.map(into_reading_summary),
            humidity_percent: parsed.humidity_percent.map(into_reading_summary),
            fan_speeds_percent: parsed
                .fan_speeds_percent
                .map(|speeds| speeds.into_iter().map(into_reading_summary).collect()),
            power_watts: parsed.power_watts.map(into_reading_summary),
            energyk_wh: parsed.energyk_wh.map(into_reading_summary),
            power_load_percent: parsed.power_load_percent.map(into_reading_summary),
            power_limit_watts: parsed.power_limit_watts.map(into_control_summary),
            dew_point_celsius: parsed.dew_point_celsius.map(into_reading_summary),
            absolute_humidity: parsed.absolute_humidity.map(into_reading_summary),
            energy_joules: parsed.energy_joules.map(into_reading_summary),
            ambient_temperature_celsius: parsed
                .ambient_temperature_celsius
                .map(into_reading_summary),
            voltage: parsed.voltage.map(into_reading_summary),
            current_amps: parsed.current_amps.map(into_reading_summary),
        }
    })
}

fn into_reading_summary(
    parsed: EnvironmentMetricsReadingPayload,
) -> EnvironmentMetricsReadingSummary {
    EnvironmentMetricsReadingSummary::new(parsed.data_source_uri, parsed.reading)
}

fn into_control_summary(
    parsed: EnvironmentMetricsControlPayload,
) -> EnvironmentMetricsControlSummary {
    EnvironmentMetricsControlSummary::new(parsed.data_source_uri, parsed.set_point)
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

/// The §0.5.0 Lenovo `SecurityService` snapshot payload, decoded exactly as
/// the infra projection wrote it: the common identity fields (required
/// because the compiled base `resource::Resource` requires `Id` / `Name`)
/// plus the flattened `FWRollback` enum spelling the upstream
/// `LenovoSecurityService::fw_rollback` wrapper surface projects, verbatim
/// per §12.3. `deny_unknown_fields` keeps the snapshot contract strict, so a
/// future extra wire field would make stored snapshots unreadable exactly
/// like an extra top-level key would.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemLenovoSecurityServicePayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "FWRollback")]
    fw_rollback: Option<String>,
}

impl CommonPayload for OemLenovoSecurityServicePayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// The chain document kinds of the §0.5.0 NVIDIA system-config-profile
/// family, written into every chain snapshot payload by the infra projection
/// (which knows the compiled decode target) and consumed here to route the
/// one family code to the right details shape. The wire spellings are the
/// `snake_case` type names, matching the infra's serialization. The four
/// kinds share the `System` prefix by construction (the compiled type names
/// all begin with `System`), so the pedantic prefix lint is scoped off.
#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
enum OemNvidiaSystemConfigProfileDocument {
    SystemConfigProfile,
    SystemConfigProfileStatus,
    SystemProfile,
    SystemProfileFile,
}

/// The routing envelope of one NVIDIA chain snapshot: only the
/// `DocumentType` discriminator, deliberately lenient (no
/// `deny_unknown_fields`) because the kind-specific payload fields follow in
/// the same document and each kind payload is decoded strictly afterwards.
#[derive(Deserialize)]
struct OemNvidiaSystemConfigProfileEnvelope {
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaSystemConfigProfileDocument,
}

/// The §0.5.0 NVIDIA `SystemConfigProfile` chain-root snapshot payload,
/// decoded exactly as the infra projection wrote it: the common identity
/// fields plus the `Truststore` link-presence metadata. `deny_unknown_fields`
/// keeps the snapshot contract strict, so a future extra wire field would
/// make stored snapshots unreadable exactly like an extra top-level key
/// would. The common fields are optional with an `@odata.id`-derived
/// fallback, so an odd snapshot without them stays projectable.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemConfigProfilePayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    // The discriminator is declared (and strictly parsed) so
    // `deny_unknown_fields` accepts the key; the router reads the same value
    // from the envelope, so this copy is intentionally never read.
    #[allow(dead_code)]
    // The discriminator is declared (and strictly parsed) so
    // `deny_unknown_fields` accepts the key; the router reads the same value
    // from the envelope, so this copy is intentionally never read.
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaSystemConfigProfileDocument,
    #[serde(rename = "Truststore")]
    truststore: Option<OemNvidiaSystemConfigProfileTruststorePayload>,
}

impl NvidiaCommonFields for OemNvidiaSystemConfigProfilePayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The `Truststore` metadata of the chain-root payload: link presence only,
/// never the certificate payloads behind the links.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemConfigProfileTruststorePayload {
    #[serde(rename = "NvidiaCertificates")]
    nvidia_certificates: Option<bool>,
    #[serde(rename = "OemCertificates")]
    oem_certificates: Option<bool>,
}

/// The §0.5.0 NVIDIA `SystemConfigProfileStatus` snapshot payload, decoded
/// exactly as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemConfigProfileStatusPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    // The discriminator is declared (and strictly parsed) so
    // `deny_unknown_fields` accepts the key; the router reads the same value
    // from the envelope, so this copy is intentionally never read.
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaSystemConfigProfileDocument,
    #[serde(rename = "PendingList")]
    pending_list: Option<OemNvidiaSystemConfigProfilePendingListPayload>,
    #[serde(rename = "ActiveProfileIndex")]
    active_profile_index: Option<i64>,
    #[serde(rename = "BmcProfileVersion")]
    bmc_profile_version: Option<i64>,
    #[serde(rename = "FactoryResetStatus")]
    factory_reset_status: Option<String>,
    #[serde(rename = "DefaultProfileIndex")]
    default_profile_index: Option<i64>,
}

impl NvidiaCommonFields for OemNvidiaSystemConfigProfileStatusPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The `PendingList` member of the status payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemConfigProfilePendingListPayload {
    #[serde(rename = "Activation")]
    activation: Option<String>,
}

/// The §0.5.0 NVIDIA `SystemProfile` snapshot payload, decoded exactly as
/// the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemProfilePayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    // The discriminator is declared (and strictly parsed) so
    // `deny_unknown_fields` accepts the key; the router reads the same value
    // from the envelope, so this copy is intentionally never read.
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaSystemConfigProfileDocument,
    #[serde(rename = "Default")]
    default: Option<bool>,
    #[serde(rename = "Owner")]
    owner: Option<String>,
    #[serde(rename = "UUID")]
    uuid: Option<String>,
    #[serde(rename = "Version")]
    version: Option<i64>,
    #[serde(rename = "ProfileName")]
    profile_name: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaSystemProfilePayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `SystemProfileFile` snapshot payload, decoded exactly
/// as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemProfileFilePayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    // The discriminator is declared (and strictly parsed) so
    // `deny_unknown_fields` accepts the key; the router reads the same value
    // from the envelope, so this copy is intentionally never read.
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaSystemConfigProfileDocument,
    #[serde(rename = "ProfileFile")]
    profile_file: Option<OemNvidiaSystemProfileFileContentPayload>,
}

impl NvidiaCommonFields for OemNvidiaSystemProfileFilePayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The `ProfileFile` member of the profile file payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemProfileFileContentPayload {
    #[serde(rename = "Metadata")]
    metadata: Option<OemNvidiaSystemProfileFileMetadataPayload>,
    #[serde(rename = "Profile")]
    profile: Option<String>,
}

/// The `Metadata` member of the profile file payload, mirroring the compiled
/// fields including the vendor's `More_Profiles` underscore spelling.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaSystemProfileFileMetadataPayload {
    #[serde(rename = "Activate")]
    activate: Option<bool>,
    #[serde(rename = "Delete")]
    delete: Option<bool>,
    #[serde(rename = "OriginProfileUUID")]
    origin_profile_uuid: Option<String>,
    #[serde(rename = "More_Profiles")]
    more_profiles: Option<bool>,
    #[serde(rename = "ProjectName")]
    project_name: Option<String>,
    #[serde(rename = "UUID")]
    uuid: Option<String>,
}

/// The chain document kinds of the §0.5.0 NVIDIA power-compliance family,
/// written into every chain snapshot payload by the infra projection (which
/// knows the compiled decode target) and consumed here to route the one
/// family code to the right details shape. The wire spellings are the
/// `snake_case` type names, matching the infra's serialization.
#[derive(Clone, Copy, Debug, Deserialize)]
#[allow(clippy::enum_variant_names)]
#[serde(rename_all = "snake_case")]
enum OemNvidiaPowerComplianceDocument {
    PowerComplianceManager,
    PowerDomain,
    PowerPolicy,
    ManagedEntityGroup,
    PowerStateGroup,
    PscState,
    PsuState,
    PsuRedundancy,
}

/// The chain document kinds of the §0.5.0 NVIDIA managed-entity family:
/// exactly one compiled decode target carries the chain, so the discriminator
/// has a single arm (kept as an enum so the routing envelope stays uniform).
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OemNvidiaManagedEntityDocument {
    ManagedEntity,
}

/// The routing envelope of one power-compliance chain snapshot: only the
/// `DocumentType` discriminator, deliberately lenient (no
/// `deny_unknown_fields`) because the kind-specific payload fields follow in
/// the same document and each kind payload is decoded strictly afterwards.
#[derive(Deserialize)]
struct OemNvidiaPowerComplianceEnvelope {
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
}

/// The routing envelope of one managed-entity chain snapshot.
#[derive(Deserialize)]
struct OemNvidiaManagedEntityEnvelope {
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaManagedEntityDocument,
}

/// The §0.5.0 NVIDIA `NvidiaPowerComplianceManager` chain-root snapshot
/// payload, decoded exactly as the infra projection wrote it: the common
/// identity fields plus the `ManagerType` enumeration spelling.
/// `deny_unknown_fields` keeps the snapshot contract strict, so a future
/// extra wire field would make stored snapshots unreadable exactly like an
/// extra top-level key would. The common fields are optional with an
/// `@odata.id`-derived fallback, so an odd snapshot without them stays
/// projectable.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPowerCompliancePayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    // The discriminator is declared (and strictly parsed) so
    // `deny_unknown_fields` accepts the key; the router reads the same value
    // from the envelope, so this copy is intentionally never read.
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "ManagerType")]
    manager_type: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaPowerCompliancePayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaPowerDomain` snapshot payload, decoded exactly
/// as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPowerDomainPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "Value")]
    value: Option<i64>,
    #[serde(rename = "Type")]
    r#type: Option<String>,
    #[serde(rename = "Unit")]
    unit: Option<String>,
    #[serde(rename = "SensorReadingType")]
    sensor_reading_type: Option<String>,
    #[serde(rename = "SensorImpl")]
    sensor_impl: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaPowerDomainPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaPowerPolicy` snapshot payload, decoded exactly
/// as the infra projection wrote it (shared by the `ACLossPolicy` and
/// `PSUCompliancePolicy` singletons).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPowerPolicyPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "AutoDeassertPowerBrake")]
    auto_deassert_power_brake: Option<bool>,
    #[serde(rename = "Min")]
    min: Option<i64>,
    #[serde(rename = "Max")]
    max: Option<i64>,
    #[serde(rename = "Type")]
    r#type: Option<String>,
    #[serde(rename = "Unit")]
    unit: Option<String>,
    #[serde(rename = "PolicyActions")]
    policy_actions: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaPowerPolicyPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaManagedEntityGroup` snapshot payload, decoded
/// exactly as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaManagedEntityGroupPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "CurrentManagedEntityId")]
    current_managed_entity_id: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaManagedEntityGroupPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaPowerStateGroup` snapshot payload, decoded
/// exactly as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPowerStateGroupPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "PscId")]
    psc_id: Option<String>,
    #[serde(rename = "GeneratedWatts")]
    generated_watts: Option<i64>,
    #[serde(rename = "NumberOfPscs")]
    number_of_pscs: Option<i64>,
    #[serde(rename = "NumberOfLocalPsus")]
    number_of_local_psus: Option<i64>,
}

impl NvidiaCommonFields for OemNvidiaPowerStateGroupPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaPscState` snapshot payload, decoded exactly as
/// the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPscStatePayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "PscId")]
    psc_id: Option<String>,
    #[serde(rename = "NumOfOperationalPsus")]
    num_of_operational_psus: Option<i64>,
    #[serde(rename = "PowerBrakeAssert")]
    power_brake_assert: Option<bool>,
    #[serde(rename = "MillisecondsSinceLastHeartbeat")]
    milliseconds_since_last_heartbeat: Option<i64>,
    #[serde(rename = "Status")]
    status: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaPscStatePayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaPsuState` snapshot payload, decoded exactly as
/// the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPsuStatePayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "PsuId")]
    psu_id: Option<String>,
    #[serde(rename = "Presence")]
    presence: Option<bool>,
    #[serde(rename = "Input1Active")]
    input1active: Option<bool>,
    #[serde(rename = "Input2Active")]
    input2active: Option<bool>,
}

impl NvidiaCommonFields for OemNvidiaPsuStatePayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaPsuRedundancy` snapshot payload, decoded exactly
/// as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaPsuRedundancyPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaPowerComplianceDocument,
    #[serde(rename = "MaxNumSupported")]
    max_num_supported: Option<String>,
    #[serde(rename = "MinNumNeeded")]
    min_num_needed: Option<String>,
    #[serde(rename = "RedundancySetting")]
    redundancy_setting: Option<String>,
}

impl NvidiaCommonFields for OemNvidiaPsuRedundancyPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
    }
}

/// The §0.5.0 NVIDIA `NvidiaManagedEntity` snapshot payload, decoded exactly
/// as the infra projection wrote it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OemNvidiaManagedEntityPayload {
    #[serde(rename = "Id")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "DocumentType")]
    document_type: OemNvidiaManagedEntityDocument,
    #[serde(rename = "TransportProtocol")]
    transport_protocol: Option<String>,
    #[serde(rename = "IPv4Address")]
    ipv4_address: Option<String>,
    #[serde(rename = "IPv6Address")]
    ipv6_address: Option<String>,
    #[serde(rename = "Port")]
    port: Option<i64>,
}

impl NvidiaCommonFields for OemNvidiaManagedEntityPayload {
    fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn description(&self) -> Option<&str> {
        self.description.as_deref()
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

/// The §2.1 `network-device-functions` family member payload.
///
/// The field set is exactly the `NetworkDeviceFunctionPayload` infra writes,
/// so an extra field here would make every stored snapshot unreadable at
/// projection time; `NetDevFuncType` stays the compiled
/// `NetworkDeviceTechnology` enumeration string.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkDeviceFunctionPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "NetDevFuncType")]
    net_dev_func_type: Option<String>,
    #[serde(rename = "DeviceEnabled")]
    device_enabled: Option<bool>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for NetworkDeviceFunctionPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// The §2.1 `power-equipment` family member payload.
///
/// The family covers both the `PowerEquipment` service document (which
/// carries `Status` beside its common identity) and its `PowerShelves`
/// members (which add `EquipmentType` and the hardware identity properties),
/// so this payload is the union of both infra projections with every
/// shelf-only field optional: the root document decodes with those fields
/// absent, and `deny_unknown_fields` keeps the wire shapes honest.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerEquipmentPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "EquipmentType")]
    equipment_type: Option<String>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "PartNumber")]
    part_number: Option<String>,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "Version")]
    version: Option<String>,
    #[serde(rename = "FirmwareVersion")]
    firmware_version: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for PowerEquipmentPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// The §2.1 `power-supplies` family member payload.
///
/// The field set is exactly the `PowerSupplyPayload` infra writes;
/// `PowerSupplyType` stays the compiled `PowerSupplyType` enumeration string
/// and `PowerCapacityWatts` the compiled `Edm.Decimal` reading.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PowerSupplyPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "PowerSupplyType")]
    power_supply_type: Option<String>,
    #[serde(rename = "PowerCapacityWatts")]
    power_capacity_watts: Option<f64>,
    #[serde(rename = "Manufacturer")]
    manufacturer: Option<String>,
    #[serde(rename = "Model")]
    model: Option<String>,
    #[serde(rename = "FirmwareVersion")]
    firmware_version: Option<String>,
    #[serde(rename = "SerialNumber")]
    serial_number: Option<String>,
    #[serde(rename = "PartNumber")]
    part_number: Option<String>,
    #[serde(rename = "Status")]
    status: Option<ResourceStatusPayload>,
}

impl CommonPayload for PowerSupplyPayload {
    fn common(&self) -> CoreResourceCommon {
        CoreResourceCommon {
            id: self.id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
        }
    }
}

/// One embedded sensor excerpt of the §2.1 `environment-metrics` payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentMetricsReadingPayload {
    #[serde(rename = "DataSourceUri")]
    data_source_uri: Option<String>,
    #[serde(rename = "Reading")]
    reading: Option<f64>,
}

/// The embedded power-limit control excerpt of the §2.1
/// `environment-metrics` payload.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentMetricsControlPayload {
    #[serde(rename = "DataSourceUri")]
    data_source_uri: Option<String>,
    #[serde(rename = "SetPoint")]
    set_point: Option<f64>,
}

/// The §2.1 `environment-metrics` singleton payload.
///
/// The field set is exactly the `EnvironmentMetricsPayload` infra writes —
/// every embedded measurement the schema declares, through its excerpt
/// reading shape — so an extra field here would make every stored snapshot
/// unreadable at projection time.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentMetricsPayload {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Description")]
    description: Option<String>,
    #[serde(rename = "TemperatureCelsius")]
    temperature_celsius: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "HumidityPercent")]
    humidity_percent: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "FanSpeedsPercent")]
    fan_speeds_percent: Option<Vec<EnvironmentMetricsReadingPayload>>,
    #[serde(rename = "PowerWatts")]
    power_watts: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "EnergykWh")]
    energyk_wh: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "PowerLoadPercent")]
    power_load_percent: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "PowerLimitWatts")]
    power_limit_watts: Option<EnvironmentMetricsControlPayload>,
    #[serde(rename = "DewPointCelsius")]
    dew_point_celsius: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "AbsoluteHumidity")]
    absolute_humidity: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "EnergyJoules")]
    energy_joules: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "AmbientTemperatureCelsius")]
    ambient_temperature_celsius: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "Voltage")]
    voltage: Option<EnvironmentMetricsReadingPayload>,
    #[serde(rename = "CurrentAmps")]
    current_amps: Option<EnvironmentMetricsReadingPayload>,
}

impl CommonPayload for EnvironmentMetricsPayload {
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
    // The contract walk pins every projected field of all four families and
    // both PowerEquipment payload shapes, so the line count is the coverage.
    #[allow(clippy::too_many_lines)]
    async fn projects_the_four_standard_families_without_losing_source_values()
    -> Result<(), Box<dyn Error>> {
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
                    ResourceFeature::NetworkDeviceFunctions,
                    "/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions/1",
                    r#"{"Id":"1","Name":"Adapter One Function One","NetDevFuncType":"Ethernet","DeviceEnabled":true,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::PowerEquipment,
                    "/redfish/v1/PowerEquipment",
                    r#"{"Id":"PowerEquipment","Name":"Power Equipment","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::PowerEquipment,
                    "/redfish/v1/PowerEquipment/PowerShelves/1",
                    r#"{"Id":"1","Name":"Power Shelf One","EquipmentType":"PowerShelf","Manufacturer":"Rutilus Test","Model":"PDU-30K","PartNumber":"PDU-PART-1","SerialNumber":"PDU-1","Version":"2.0","FirmwareVersion":"3.1.4","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::PowerSupplies,
                    "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1",
                    r#"{"Id":"1","Name":"Power Supply One","PowerSupplyType":"AC","PowerCapacityWatts":1600.0,"Manufacturer":"Rutilus Test","Model":"PSU-1600","FirmwareVersion":"1.0.0","SerialNumber":"PSU-1","PartNumber":"PSU-PART-1","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::EnvironmentMetrics,
                    "/redfish/v1/Chassis/1/EnvironmentMetrics",
                    r#"{"Id":"EnvironmentMetrics","Name":"Environment Metrics","TemperatureCelsius":{"DataSourceUri":"/redfish/v1/Chassis/1/Sensors/InletTemp","Reading":27.5},"FanSpeedsPercent":[{"DataSourceUri":"/redfish/v1/Chassis/1/Sensors/Fan1","Reading":45.0}],"PowerLimitWatts":{"DataSourceUri":"/redfish/v1/Chassis/1/Controls/PowerLimit","SetPoint":800.0}}"#,
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
        assert_eq!(result.resources().len(), 6);
        assert_eq!(result.resources()[0].common().name(), "Root");

        // `EndpointInventoryItem` sorts its snapshots by `@odata.id`, so the
        // resources are looked up by their stable identifiers.
        let function = &result
            .resources()
            .iter()
            .find(|resource| {
                resource.odata_id().as_str()
                    == "/redfish/v1/Chassis/1/NetworkAdapters/1/NetworkDeviceFunctions/1"
            })
            .ok_or("the network device function must be projected")?;
        assert_eq!(function.feature(), ResourceFeature::NetworkDeviceFunctions);
        assert_eq!(function.common().name(), "Adapter One Function One");
        assert_eq!(
            function.details(),
            &CoreResourceDetails::NetworkDeviceFunction {
                net_dev_func_type: Some("Ethernet".to_owned()),
                device_enabled: Some(true),
                status: Some(ResourceStatusSummary {
                    state: Some("Enabled".to_owned()),
                    health: Some("OK".to_owned()),
                    health_rollup: Some("OK".to_owned()),
                }),
            }
        );

        let equipment_root = &result
            .resources()
            .iter()
            .find(|resource| resource.odata_id().as_str() == "/redfish/v1/PowerEquipment")
            .ok_or("the power equipment root document must be projected")?;
        assert_eq!(equipment_root.feature(), ResourceFeature::PowerEquipment);
        assert_eq!(equipment_root.common().name(), "Power Equipment");
        assert_eq!(
            equipment_root.details(),
            &CoreResourceDetails::PowerEquipment {
                equipment_type: None,
                manufacturer: None,
                model: None,
                part_number: None,
                serial_number: None,
                version: None,
                firmware_version: None,
                status: Some(ResourceStatusSummary {
                    state: Some("Enabled".to_owned()),
                    health: Some("OK".to_owned()),
                    health_rollup: Some("OK".to_owned()),
                }),
            }
        );

        let equipment_shelf = &result
            .resources()
            .iter()
            .find(|resource| {
                resource.odata_id().as_str() == "/redfish/v1/PowerEquipment/PowerShelves/1"
            })
            .ok_or("the power equipment shelf member must be projected")?;
        assert_eq!(equipment_shelf.feature(), ResourceFeature::PowerEquipment);
        assert_eq!(equipment_shelf.common().name(), "Power Shelf One");
        assert_eq!(
            equipment_shelf.details(),
            &CoreResourceDetails::PowerEquipment {
                equipment_type: Some("PowerShelf".to_owned()),
                manufacturer: Some("Rutilus Test".to_owned()),
                model: Some("PDU-30K".to_owned()),
                part_number: Some("PDU-PART-1".to_owned()),
                serial_number: Some("PDU-1".to_owned()),
                version: Some("2.0".to_owned()),
                firmware_version: Some("3.1.4".to_owned()),
                status: Some(ResourceStatusSummary {
                    state: Some("Enabled".to_owned()),
                    health: Some("OK".to_owned()),
                    health_rollup: Some("OK".to_owned()),
                }),
            }
        );

        let supply = &result
            .resources()
            .iter()
            .find(|resource| {
                resource.odata_id().as_str()
                    == "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1"
            })
            .ok_or("the power supply must be projected")?;
        assert_eq!(supply.feature(), ResourceFeature::PowerSupplies);
        assert_eq!(supply.common().name(), "Power Supply One");
        assert_eq!(
            supply.details(),
            &CoreResourceDetails::PowerSupply {
                power_supply_type: Some("AC".to_owned()),
                power_capacity_watts: Some(1600.0),
                manufacturer: Some("Rutilus Test".to_owned()),
                model: Some("PSU-1600".to_owned()),
                firmware_version: Some("1.0.0".to_owned()),
                serial_number: Some("PSU-1".to_owned()),
                part_number: Some("PSU-PART-1".to_owned()),
                status: Some(ResourceStatusSummary {
                    state: Some("Enabled".to_owned()),
                    health: Some("OK".to_owned()),
                    health_rollup: Some("OK".to_owned()),
                }),
            }
        );

        let metrics = &result
            .resources()
            .iter()
            .find(|resource| {
                resource.odata_id().as_str() == "/redfish/v1/Chassis/1/EnvironmentMetrics"
            })
            .ok_or("the environment metrics singleton must be projected")?;
        assert_eq!(metrics.feature(), ResourceFeature::EnvironmentMetrics);
        assert_eq!(metrics.common().name(), "Environment Metrics");
        assert_eq!(
            metrics.details(),
            &CoreResourceDetails::EnvironmentMetrics {
                temperature_celsius: Some(EnvironmentMetricsReadingSummary::new(
                    Some("/redfish/v1/Chassis/1/Sensors/InletTemp".to_owned()),
                    Some(27.5),
                )),
                humidity_percent: None,
                fan_speeds_percent: Some(vec![EnvironmentMetricsReadingSummary::new(
                    Some("/redfish/v1/Chassis/1/Sensors/Fan1".to_owned()),
                    Some(45.0),
                )]),
                power_watts: None,
                energyk_wh: None,
                power_load_percent: None,
                power_limit_watts: Some(EnvironmentMetricsControlSummary::new(
                    Some("/redfish/v1/Chassis/1/Controls/PowerLimit".to_owned()),
                    Some(800.0),
                )),
                dew_point_celsius: None,
                absolute_humidity: None,
                energy_joules: None,
                ambient_temperature_celsius: None,
                voltage: None,
                current_amps: None,
            }
        );
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

    // The whole NVIDIA chain is asserted in one test so the four document
    // kinds and the `@odata.id` fallback stay one contract; the snapshots
    // exceed the pedantic line budget, so the lint is scoped here exactly
    // like the other OEM family tests.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn projects_oem_nvidia_chain_without_losing_source_values() -> Result<(), Box<dyn Error>>
    {
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
                // The whole chain shares the one family code; the
                // `DocumentType` discriminator written by the infra
                // projection routes each snapshot to its details shape.
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemNvidiaSystemConfigProfile,
                    "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
                    r#"{"Id":"SystemConfigProfile","Name":"NVIDIA System Config Profile","Description":"Profile service","DocumentType":"system_config_profile","Truststore":{"NvidiaCertificates":true,"OemCertificates":false}}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemNvidiaSystemConfigProfile,
                    "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
                    r#"{"Id":"Status","Name":"System Config Profile Status","Description":"Profile service status","DocumentType":"system_config_profile_status","PendingList":{"Activation":"profile-1"},"ActiveProfileIndex":1,"BmcProfileVersion":2,"FactoryResetStatus":"Idle","DefaultProfileIndex":1}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemNvidiaSystemConfigProfile,
                    "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
                    r#"{"Id":"1","Name":"Default Profile","Description":"Factory default profile","DocumentType":"system_profile","Default":true,"Owner":"Nvidia","UUID":"11111111-2222-3333-4444-555555555555","Version":1,"ProfileName":"default-profile"}"#,
                    observed_at,
                    generation,
                )?,
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemNvidiaSystemConfigProfile,
                    "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
                    r#"{"Id":"ProfileFile","Name":"Profile File","Description":"Signed profile file","DocumentType":"system_profile_file","ProfileFile":{"Metadata":{"Activate":true,"Delete":false,"OriginProfileUUID":"11111111-2222-3333-4444-555555555555","More_Profiles":false,"ProjectName":"BlueField","UUID":"11111111-2222-3333-4444-555555555555"},"Profile":"eyJwcm9maWxlIjogInRlc3QifQ=="}}"#,
                    observed_at,
                    generation,
                )?,
                // A chain snapshot whose common identity fields are missing
                // stays projectable through the `@odata.id` fallback, and a
                // chain document whose every detail field is absent still
                // projects `None` details instead of failing.
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemNvidiaSystemConfigProfile,
                    "/redfish/v1/Systems/2/Oem/Nvidia/SystemConfigProfile/Status",
                    r#"{"DocumentType":"system_config_profile_status"}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 6);
        let chain_root = &result.resources()[1];
        assert_eq!(
            chain_root.feature(),
            ResourceFeature::OemNvidiaSystemConfigProfile
        );
        assert_eq!(
            chain_root.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
        );
        assert_eq!(chain_root.common().id(), "SystemConfigProfile");
        assert_eq!(chain_root.common().name(), "NVIDIA System Config Profile");
        assert_eq!(
            chain_root.details(),
            &CoreResourceDetails::OemNvidiaSystemConfigProfile {
                truststore: Some(OemNvidiaSystemConfigProfileTruststore::new(
                    Some(true),
                    Some(false),
                )),
            }
        );
        let profile = &result.resources()[2];
        assert_eq!(
            profile.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"
        );
        assert_eq!(
            profile.details(),
            &CoreResourceDetails::OemNvidiaSystemProfile {
                default: Some(true),
                owner: Some("Nvidia".to_owned()),
                uuid: Some("11111111-2222-3333-4444-555555555555".to_owned()),
                version: Some(1),
                profile_name: Some("default-profile".to_owned()),
            }
        );
        let profile_file = &result.resources()[3];
        assert_eq!(
            profile_file.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
        );
        assert_eq!(
            profile_file.details(),
            &CoreResourceDetails::OemNvidiaSystemProfileFile {
                metadata_activate: Some(true),
                metadata_delete: Some(false),
                metadata_origin_profile_uuid: Some(
                    "11111111-2222-3333-4444-555555555555".to_owned(),
                ),
                metadata_more_profiles: Some(false),
                metadata_project_name: Some("BlueField".to_owned()),
                metadata_uuid: Some("11111111-2222-3333-4444-555555555555".to_owned()),
                profile: Some("eyJwcm9maWxlIjogInRlc3QifQ==".to_owned()),
            }
        );
        let status = &result.resources()[4];
        assert_eq!(
            status.odata_id().as_str(),
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"
        );
        assert_eq!(
            status.details(),
            &CoreResourceDetails::OemNvidiaSystemConfigProfileStatus {
                pending_list_activation: Some("profile-1".to_owned()),
                active_profile_index: Some(1),
                bmc_profile_version: Some(2),
                factory_reset_status: Some("Idle".to_owned()),
                default_profile_index: Some(1),
            }
        );
        // The common identity is derived from the `@odata.id` when the
        // payload carries none, exactly like the Supermicro fallback.
        let fallback_status = &result.resources()[5];
        assert_eq!(
            fallback_status.common().id(),
            "Status",
            "the @odata.id final segment must stand in for the missing Id"
        );
        assert_eq!(fallback_status.common().name(), "Status");
        assert_eq!(fallback_status.common().description(), None);
        assert_eq!(
            fallback_status.details(),
            &CoreResourceDetails::OemNvidiaSystemConfigProfileStatus {
                pending_list_activation: None,
                active_profile_index: None,
                bmc_profile_version: None,
                factory_reset_status: None,
                default_profile_index: None,
            }
        );
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

    #[tokio::test]
    async fn projects_oem_lenovo_security_service_without_losing_source_values()
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
                    ResourceFeature::OemLenovoSecurityService,
                    "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService",
                    r#"{"Id":"SecurityService","Name":"Lenovo Security Service","Description":"Lenovo security service","FWRollback":"Enabled"}"#,
                    observed_at,
                    generation,
                )?,
                // A document whose `Configurator` segment was absent still
                // projects with `None` details, not an unreadable one.
                snapshot(
                    endpoint_id,
                    ResourceFeature::OemLenovoSecurityService,
                    "/redfish/v1/Managers/2/Oem/Lenovo/SecurityService",
                    r#"{"Id":"SecurityService","Name":"Lenovo Security Service"}"#,
                    observed_at,
                    generation,
                )?,
            ],
        )?;
        let query =
            EndpointResourceInventoryQuery::new(MockRepository::ok(vec![item]), endpoint_id);
        let result = query.execute().await?.ok_or("endpoint must exist")?;

        assert_eq!(result.resources().len(), 3);
        // The inventory orders snapshots by `@odata.id`, so the manager-1
        // document sorts before the manager-2 document.
        let security = &result.resources()[1];
        assert_eq!(
            security.feature(),
            ResourceFeature::OemLenovoSecurityService
        );
        assert_eq!(
            security.odata_id().as_str(),
            "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService"
        );
        assert_eq!(security.common().id(), "SecurityService");
        assert_eq!(security.common().name(), "Lenovo Security Service");
        assert_eq!(
            security.common().description(),
            Some("Lenovo security service")
        );
        assert_eq!(
            security.details(),
            &CoreResourceDetails::OemLenovoSecurityService {
                fw_rollback: Some("Enabled".to_owned()),
            }
        );
        assert_eq!(
            result.resources()[2].details(),
            &CoreResourceDetails::OemLenovoSecurityService { fw_rollback: None }
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
