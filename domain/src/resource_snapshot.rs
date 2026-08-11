use std::{error::Error, fmt, str::FromStr};

use serde_json::Value;
use time::OffsetDateTime;

use crate::{EndpointId, ResourceId};

const MAX_ODATA_ID_BYTES: usize = 4 * 1024;
const MAX_ODATA_TYPE_BYTES: usize = 512;
const MAX_ETAG_BYTES: usize = 512;
const MAX_TYPED_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// The typed Redfish feature that produced a resource snapshot.
///
/// Every variant's `as_str()` code is the §2.1 feature name and equals the
/// matching [`EndpointCapability`] product code, so snapshot and ledger
/// projections never translate the same wire string twice. The deliberate
/// exceptions are the subsidiary read surfaces under the service features:
/// [`Self::SoftwareInventory`] under `update-service`, [`Self::EventSubscription`]
/// under `event-service`, [`Self::MetricDefinition`] and [`Self::MetricReport`]
/// under `telemetry-service`, and [`Self::Task`] under `task-service`. Each
/// subsidiary family code is narrower than its service capability code, which
/// also covers the operations of the same family (see the ledger-consistency
/// test).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ResourceFeature {
    ServiceRoot,
    Systems,
    Chassis,
    Managers,
    /// The §2.1 `oem-dell-attributes` read surface, added as a typed resource
    /// family in the 0.5 slice. The family reads the manager-scoped Dell
    /// `Attributes` document through the `Dell` OEM namespace. The family
    /// code is `dell-attributes` (not `oem-dell-attributes`, which stays the
    /// capability code, and not `oem-dell`, which stays the namespace
    /// capability code): the one `oem-dell-attributes` capability covers the
    /// `Attributes` read surface and the namespace advertisement that
    /// precedes it, so this variant addresses only the read surface and must
    /// not be mistaken for a capability code (see the ledger-consistency
    /// test).
    OemDell,
    /// The §2.1 `oem-supermicro` read surface, added as a typed resource
    /// family in the 0.5 slice. The family reads the manager-scoped Supermicro
    /// `SysLockdown` document through the `Supermicro` OEM namespace. The
    /// family code is `supermicro-sys-lockdown` (not `oem-supermicro`, which
    /// stays the namespace capability code, and not `oem-supermicro-sys-lockdown`,
    /// which stays unallocated in the capability space): the one
    /// `oem-supermicro` capability covers the namespace advertisement that
    /// precedes the read, so this variant addresses only the read surface and
    /// must not be mistaken for a capability code (see the ledger-consistency
    /// test).
    OemSmcSysLockdown,
    /// The §2.1 `oem-supermicro` read surface, added as a typed resource
    /// family in the 0.5 slice. The family reads the manager-scoped Supermicro
    /// `KCSInterface` document through the `Supermicro` OEM namespace. The
    /// family code is `supermicro-kcs-interface` (not `oem-supermicro`, which
    /// stays the namespace capability code, and not
    /// `oem-supermicro-kcs-interface`, which stays unallocated in the
    /// capability space): the one `oem-supermicro` capability covers the
    /// namespace advertisement that precedes the read, so this variant
    /// addresses only the read surface and must not be mistaken for a
    /// capability code (see the ledger-consistency test).
    OemSmcKcsInterface,
    /// The §2.1 `oem-nvidia-profiles` read surface, added as a typed resource
    /// family in the 0.5 slice. The family reads the system-scoped NVIDIA
    /// `SystemConfigProfile` chain — the profile service document, its status
    /// singleton, the profile collection, and each member's `ProfileFile`
    /// document — through the `Nvidia` OEM namespace of the `ComputerSystem`
    /// document. One family covers the whole chain because the chain's root
    /// document decides whether the chain exists at all (unlike the
    /// one-document-per-family Dell/SMC precedent, the chain members cannot
    /// exist without their root). The family code is
    /// `nvidia-system-config-profile` (not `oem-nvidia-profiles`, which stays
    /// the capability code, and not `oem-nvidia`, which stays the namespace
    /// capability code): the one `oem-nvidia-profiles` capability covers the
    /// read surface and the namespace advertisement that precedes it, so this
    /// variant addresses only the read surface and must not be mistaken for a
    /// capability code (see the ledger-consistency test).
    OemNvidiaSystemConfigProfile,
    /// The §2.1 `oem-nvidia-power-management` read surface, added as a typed
    /// resource family in the 0.5 slice. The family reads the manager-scoped
    /// NVIDIA `NvidiaPowerComplianceManager` chain — the compliance manager
    /// document, its `PowerDomains` collection members, the `ACLossPolicy` /
    /// `PSUCompliancePolicy` singletons, the `ManagedEntityGroups` collection
    /// members, the `PowerStateGroup` document with its `PowerShelfControllers`
    /// and `PowerSupplies` collection members, and the `PSURedundancy`
    /// singleton — through the `Nvidia` OEM namespace of the `Manager`
    /// document. One family covers the whole chain because the chain's root
    /// document (the `NvidiaPowerComplianceManager` behind the
    /// `PowerCompliance` navigation) decides whether the chain exists at all.
    /// The family code is `nvidia-power-compliance` (not
    /// `oem-nvidia-power-management`, which stays the capability code, and
    /// not `oem-nvidia`, which stays the namespace capability code): the one
    /// `oem-nvidia-power-management` capability covers the read surface and
    /// the namespace advertisement that precedes it, so this variant
    /// addresses only the read surface and must not be mistaken for a
    /// capability code (see the ledger-consistency test).
    OemNvidiaPowerCompliance,
    /// The §2.1 `oem-nvidia-power-management` read surface, added as a typed
    /// resource family in the 0.5 slice. The family reads the manager-scoped
    /// NVIDIA managed-entity chain — the `NvidiaManagedEntityGroupCollection`
    /// behind the compliance manager's `ManagedEntityGroups` navigation (the
    /// chain's entry navigation, whose presence decides whether the chain
    /// exists at all) and, through each group member's `ManagedEntities`
    /// navigation, the `NvidiaManagedEntity` members — through the `Nvidia`
    /// OEM namespace of the `Manager` document. The family code is
    /// `nvidia-managed-entity` (not `oem-nvidia-power-management`, which
    /// stays the capability code, and not `oem-nvidia`, which stays the
    /// namespace capability code): the one `oem-nvidia-power-management`
    /// capability covers the read surface and the namespace advertisement
    /// that precedes it, so this variant addresses only the read surface and
    /// must not be mistaken for a capability code (see the
    /// ledger-consistency test).
    OemNvidiaManagedEntity,
    /// The §2.1 `oem-lenovo` read surface, added as a typed resource family
    /// in the 0.5 slice. The family reads the manager-scoped Lenovo
    /// `SecurityService` document through the `Lenovo` OEM namespace of the
    /// `Manager` document: the `Oem.Lenovo` segment decodes through the
    /// untagged dual-version `LenovoManagerProperties` schema (`v0_1_0` with
    /// the boolean `KCSEnabled` / `v1_0_0` with the state-string
    /// `KCSEnabled`, the
    /// same serde fallback the upstream `LenovoManager` wrapper performs), and
    /// the `Security` navigation is resolved through the same typed
    /// `NavProperty` fetch the upstream `security()` wrapper performs. The
    /// family code is `lenovo-security-service` (not `oem-lenovo`, which stays
    /// the namespace capability code): the one `oem-lenovo` capability covers
    /// the namespace advertisement that precedes the read, so this variant
    /// addresses only the read surface and must not be mistaken for a
    /// capability code (see the ledger-consistency test).
    OemLenovoSecurityService,
    /// The §2.1 `processors` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Processors,
    /// The §2.1 `memory` feature, added as a typed resource family in the 0.2
    /// snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Memory,
    /// The §2.1 `storages` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Storages,
    /// The §2.1 `network-adapters` feature, added as a typed resource family
    /// in the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    NetworkAdapters,
    /// The §2.1 `ethernet-interfaces` feature, added as a typed resource
    /// family in the 0.2 snapshot; the code matches the `EndpointCapability`
    /// product code so both inventories address the same wire surface.
    EthernetInterfaces,
    /// The §2.1 `accounts` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Accounts,
    /// The §2.1 `bios` feature, added as a typed resource family in the 0.2
    /// snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Bios,
    /// The §2.1 `boot-options` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    BootOptions,
    /// The §2.1 `secure-boot` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    SecureBoot,
    /// The §2.1 `power` feature, added as a typed resource family in the 0.2
    /// snapshot; the code matches the `EndpointCapability` product code so
    /// both inventories address the same wire surface.
    Power,
    /// The §2.1 `thermal` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code
    /// so both inventories address the same wire surface.
    Thermal,
    /// The §2.1 `sensors` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code
    /// so both inventories address the same wire surface.
    Sensors,
    /// The §2.1 `controls` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code
    /// so both inventories address the same wire surface.
    Controls,
    /// The §2.1 `log-services` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    LogServices,
    /// The §2.1 `manager-network-protocol` feature, added as a typed resource
    /// family in the 0.2 snapshot; the code matches the `EndpointCapability`
    /// product code so both inventories address the same wire surface.
    ManagerNetworkProtocol,
    /// The §2.1 `host-interfaces` feature, added as a typed resource family
    /// in the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    HostInterfaces,
    /// The §2.1 `pcie-devices` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    PcieDevices,
    /// The §2.1 `assembly` feature, added as a typed resource family in the
    /// 0.2 snapshot; the code matches the `EndpointCapability` product code
    /// so both inventories address the same wire surface.
    Assembly,
    /// The §2.1 `update-service` read surface, added as a typed resource
    /// family in the 0.2 snapshot. The family code is `software-inventory`
    /// (not `update-service`, which stays the capability code): one
    /// `update-service` capability covers both the `SoftwareInventory` read
    /// surface and the update operations, so this variant addresses only the
    /// read surface and must not be mistaken for a capability code.
    SoftwareInventory,
    /// The §2.1 `event-service` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    EventService,
    /// One subscription under the §2.1 `event-service` read surface, added as
    /// a typed resource family in the 0.2 snapshot. The family code is
    /// `event-subscription` (not `event-service`, which stays the capability
    /// code): one `event-service` capability covers both the subscription read
    /// surface and the event operations, so this variant addresses only the
    /// read surface and must not be mistaken for a capability code. Redfish
    /// models subscriptions as `EventDestination` resources; nv-redfish 0.13
    /// does not compile that type, and infra decodes the `Subscriptions` leaf
    /// with a local minimal schema.
    EventSubscription,
    /// The §2.1 `telemetry-service` feature, added as a typed resource family
    /// in the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    TelemetryService,
    /// One metric definition under the §2.1 `telemetry-service` read surface,
    /// added as a typed resource family in the 0.2 snapshot. The family code
    /// is `metric-definition` (not `telemetry-service`, which stays the
    /// capability code): one `telemetry-service` capability covers both the
    /// definition read surface and the telemetry operations, so this variant
    /// addresses only the read surface and must not be mistaken for a
    /// capability code.
    MetricDefinition,
    /// One metric report under the §2.1 `telemetry-service` read surface,
    /// added as a typed resource family in the 0.2 snapshot. The family code
    /// is `metric-report` (not `telemetry-service`, which stays the
    /// capability code): one `telemetry-service` capability covers both the
    /// report read surface and the telemetry operations, so this variant
    /// addresses only the read surface and must not be mistaken for a
    /// capability code.
    MetricReport,
    /// The §2.1 `task-service` feature, added as a typed resource family in
    /// the 0.2 snapshot; the code matches the `EndpointCapability` product
    /// code so both inventories address the same wire surface.
    TaskService,
    /// One task under the §2.1 `task-service` read surface, added as a typed
    /// resource family in the 0.2 snapshot. The family code is `task` (not
    /// `task-service`, which stays the capability code): one `task-service`
    /// capability covers both the task read surface and the task operations,
    /// so this variant addresses only the read surface and must not be
    /// mistaken for a capability code.
    Task,
}

impl ResourceFeature {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceRoot => "service-root",
            Self::Systems => "systems",
            Self::Chassis => "chassis",
            Self::Managers => "managers",
            Self::OemDell => "dell-attributes",
            Self::OemSmcSysLockdown => "supermicro-sys-lockdown",
            Self::OemSmcKcsInterface => "supermicro-kcs-interface",
            Self::OemNvidiaSystemConfigProfile => "nvidia-system-config-profile",
            Self::OemNvidiaPowerCompliance => "nvidia-power-compliance",
            Self::OemNvidiaManagedEntity => "nvidia-managed-entity",
            Self::OemLenovoSecurityService => "lenovo-security-service",
            Self::Processors => "processors",
            Self::Memory => "memory",
            Self::Storages => "storages",
            Self::NetworkAdapters => "network-adapters",
            Self::EthernetInterfaces => "ethernet-interfaces",
            Self::Accounts => "accounts",
            Self::Bios => "bios",
            Self::BootOptions => "boot-options",
            Self::SecureBoot => "secure-boot",
            Self::Power => "power",
            Self::Thermal => "thermal",
            Self::Sensors => "sensors",
            Self::Controls => "controls",
            Self::LogServices => "log-services",
            Self::ManagerNetworkProtocol => "manager-network-protocol",
            Self::HostInterfaces => "host-interfaces",
            Self::PcieDevices => "pcie-devices",
            Self::Assembly => "assembly",
            Self::SoftwareInventory => "software-inventory",
            Self::EventService => "event-service",
            Self::EventSubscription => "event-subscription",
            Self::TelemetryService => "telemetry-service",
            Self::MetricDefinition => "metric-definition",
            Self::MetricReport => "metric-report",
            Self::TaskService => "task-service",
            Self::Task => "task",
        }
    }
}

impl fmt::Display for ResourceFeature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceFeature {
    type Err = ResourceFeatureParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "service-root" => Ok(Self::ServiceRoot),
            "systems" => Ok(Self::Systems),
            "chassis" => Ok(Self::Chassis),
            "managers" => Ok(Self::Managers),
            "dell-attributes" => Ok(Self::OemDell),
            "supermicro-sys-lockdown" => Ok(Self::OemSmcSysLockdown),
            "supermicro-kcs-interface" => Ok(Self::OemSmcKcsInterface),
            "nvidia-system-config-profile" => Ok(Self::OemNvidiaSystemConfigProfile),
            "nvidia-power-compliance" => Ok(Self::OemNvidiaPowerCompliance),
            "nvidia-managed-entity" => Ok(Self::OemNvidiaManagedEntity),
            "lenovo-security-service" => Ok(Self::OemLenovoSecurityService),
            "processors" => Ok(Self::Processors),
            "memory" => Ok(Self::Memory),
            "storages" => Ok(Self::Storages),
            "network-adapters" => Ok(Self::NetworkAdapters),
            "ethernet-interfaces" => Ok(Self::EthernetInterfaces),
            "accounts" => Ok(Self::Accounts),
            "bios" => Ok(Self::Bios),
            "boot-options" => Ok(Self::BootOptions),
            "secure-boot" => Ok(Self::SecureBoot),
            "power" => Ok(Self::Power),
            "thermal" => Ok(Self::Thermal),
            "sensors" => Ok(Self::Sensors),
            "controls" => Ok(Self::Controls),
            "log-services" => Ok(Self::LogServices),
            "manager-network-protocol" => Ok(Self::ManagerNetworkProtocol),
            "host-interfaces" => Ok(Self::HostInterfaces),
            "pcie-devices" => Ok(Self::PcieDevices),
            "assembly" => Ok(Self::Assembly),
            "software-inventory" => Ok(Self::SoftwareInventory),
            "event-service" => Ok(Self::EventService),
            "event-subscription" => Ok(Self::EventSubscription),
            "telemetry-service" => Ok(Self::TelemetryService),
            "metric-definition" => Ok(Self::MetricDefinition),
            "metric-report" => Ok(Self::MetricReport),
            "task-service" => Ok(Self::TaskService),
            "task" => Ok(Self::Task),
            _ => Err(ResourceFeatureParseError),
        }
    }
}

/// A persisted resource feature is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceFeatureParseError;

impl fmt::Display for ResourceFeatureParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown resource feature code")
    }
}

impl Error for ResourceFeatureParseError {}

/// An opaque Redfish `@odata.id` discovered through typed navigation.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceODataId(String);

impl ResourceODataId {
    /// Validates a discovered identifier without interpreting or constructing
    /// a resource path.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceODataIdError`] for empty, whitespace-padded,
    /// control-containing, or oversized values.
    pub fn parse(value: &str) -> Result<Self, ResourceODataIdError> {
        validate_exact_text(value, MAX_ODATA_ID_BYTES).map_err(map_odata_id_error)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceODataId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceODataId {
    type Err = ResourceODataIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a discovered `@odata.id` cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceODataIdError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ResourceODataIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_exact_text_error(formatter, "resource @odata.id", exact_from_odata_id(*self))
    }
}

impl Error for ResourceODataIdError {}

/// An exact Redfish `@odata.type` observed in a typed resource payload.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceODataType(String);

impl ResourceODataType {
    /// Validates an observed type annotation.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceODataTypeError`] for malformed text or when the value
    /// does not begin with the Redfish `#` type marker.
    pub fn parse(value: &str) -> Result<Self, ResourceODataTypeError> {
        validate_exact_text(value, MAX_ODATA_TYPE_BYTES).map_err(map_odata_type_error)?;
        if !value.starts_with('#') {
            return Err(ResourceODataTypeError::MissingTypeMarker);
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceODataType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceODataType {
    type Err = ResourceODataTypeError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why an observed Redfish type annotation is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceODataTypeError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
    MissingTypeMarker,
}

impl fmt::Display for ResourceODataTypeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingTypeMarker => {
                formatter.write_str("resource @odata.type must begin with '#'")
            }
            other => write_exact_text_error(
                formatter,
                "resource @odata.type",
                exact_from_odata_type(*other),
            ),
        }
    }
}

impl Error for ResourceODataTypeError {}

/// An opaque Redfish entity tag used for later conditional operations.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ResourceEtag(String);

impl ResourceEtag {
    /// Validates an observed entity tag without changing its exact value.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceEtagError`] for empty, whitespace-padded,
    /// control-containing, or oversized values.
    pub fn parse(value: &str) -> Result<Self, ResourceEtagError> {
        validate_exact_text(value, MAX_ETAG_BYTES).map_err(map_etag_error)?;
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceEtag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for ResourceEtag {
    type Err = ResourceEtagError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why an observed Redfish entity tag is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceEtagError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for ResourceEtagError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_exact_text_error(formatter, "resource ETag", exact_from_etag(*self))
    }
}

impl Error for ResourceEtagError {}

/// A bounded JSON object produced after successful typed Redfish decoding.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceSnapshotPayload(String);

impl ResourceSnapshotPayload {
    /// Parses and canonicalizes a typed resource projection.
    ///
    /// # Errors
    ///
    /// Returns [`ResourceSnapshotPayloadError`] when the payload exceeds four
    /// MiB, is not valid JSON, or is not a JSON object.
    pub fn parse(value: &str) -> Result<Self, ResourceSnapshotPayloadError> {
        let actual = value.len();
        if actual > MAX_TYPED_PAYLOAD_BYTES {
            return Err(ResourceSnapshotPayloadError::TooLarge {
                actual,
                maximum: MAX_TYPED_PAYLOAD_BYTES,
            });
        }
        let parsed: Value =
            serde_json::from_str(value).map_err(ResourceSnapshotPayloadError::InvalidJson)?;
        if !parsed.is_object() {
            return Err(ResourceSnapshotPayloadError::NotObject);
        }
        let canonical =
            serde_json::to_string(&parsed).map_err(ResourceSnapshotPayloadError::Canonicalize)?;
        Ok(Self(canonical))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ResourceSnapshotPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceSnapshotPayload")
            .field("bytes", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Why a typed resource projection cannot be stored.
#[derive(Debug)]
pub enum ResourceSnapshotPayloadError {
    TooLarge { actual: usize, maximum: usize },
    InvalidJson(serde_json::Error),
    NotObject,
    Canonicalize(serde_json::Error),
}

impl fmt::Display for ResourceSnapshotPayloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { actual, maximum } => write!(
                formatter,
                "typed resource payload has {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidJson(_) => formatter.write_str("typed resource payload is not valid JSON"),
            Self::NotObject => formatter.write_str("typed resource payload must be a JSON object"),
            Self::Canonicalize(_) => {
                formatter.write_str("typed resource payload could not be canonicalized")
            }
        }
    }
}

impl Error for ResourceSnapshotPayloadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidJson(source) | Self::Canonicalize(source) => Some(source),
            Self::TooLarge { .. } | Self::NotObject => None,
        }
    }
}

/// A positive, SQLite-compatible endpoint refresh generation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RefreshGeneration(u64);

impl RefreshGeneration {
    /// Validates a generation for storage in a signed `SQLite` integer.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshGenerationError`] for zero or values above `i64::MAX`.
    pub fn new(value: u64) -> Result<Self, RefreshGenerationError> {
        if value == 0 {
            return Err(RefreshGenerationError::Zero);
        }
        if value > i64::MAX as u64 {
            return Err(RefreshGenerationError::TooLarge { value });
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Why a refresh generation cannot be represented safely.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshGenerationError {
    Zero,
    TooLarge { value: u64 },
}

impl fmt::Display for RefreshGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("refresh generation must be positive"),
            Self::TooLarge { value } => write!(
                formatter,
                "refresh generation {value} exceeds SQLite's signed integer range"
            ),
        }
    }
}

impl Error for RefreshGenerationError {}

/// One immutable, typed observation of a discovered Redfish resource.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceSnapshot {
    resource_id: ResourceId,
    endpoint_id: EndpointId,
    feature: ResourceFeature,
    odata_id: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    etag: Option<ResourceEtag>,
    payload: ResourceSnapshotPayload,
    observed_at: OffsetDateTime,
    generation: RefreshGeneration,
}

impl ResourceSnapshot {
    #[must_use]
    pub fn new(
        resource_id: ResourceId,
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: ResourceODataId,
        payload: ResourceSnapshotPayload,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Self {
        Self {
            resource_id,
            endpoint_id,
            feature,
            odata_id,
            odata_type: None,
            etag: None,
            payload,
            observed_at,
            generation,
        }
    }

    #[must_use]
    pub fn with_odata_type(mut self, odata_type: ResourceODataType) -> Self {
        self.odata_type = Some(odata_type);
        self
    }

    #[must_use]
    pub fn with_etag(mut self, etag: ResourceEtag) -> Self {
        self.etag = Some(etag);
        self
    }

    #[must_use]
    pub const fn resource_id(&self) -> ResourceId {
        self.resource_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
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
    pub const fn payload(&self) -> &ResourceSnapshotPayload {
        &self.payload
    }

    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    #[must_use]
    pub const fn generation(&self) -> RefreshGeneration {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactTextError {
    Empty,
    SurroundingWhitespace,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

fn validate_exact_text(value: &str, maximum: usize) -> Result<(), ExactTextError> {
    if value.is_empty() {
        return Err(ExactTextError::Empty);
    }
    if value.trim() != value {
        return Err(ExactTextError::SurroundingWhitespace);
    }
    if value.chars().any(char::is_control) {
        return Err(ExactTextError::ControlCharacter);
    }
    let actual = value.len();
    if actual > maximum {
        return Err(ExactTextError::TooLong { actual, maximum });
    }
    Ok(())
}

fn map_odata_id_error(error: ExactTextError) -> ResourceODataIdError {
    match error {
        ExactTextError::Empty => ResourceODataIdError::Empty,
        ExactTextError::SurroundingWhitespace => ResourceODataIdError::SurroundingWhitespace,
        ExactTextError::ControlCharacter => ResourceODataIdError::ControlCharacter,
        ExactTextError::TooLong { actual, maximum } => {
            ResourceODataIdError::TooLong { actual, maximum }
        }
    }
}

fn exact_from_odata_id(error: ResourceODataIdError) -> ExactTextError {
    match error {
        ResourceODataIdError::Empty => ExactTextError::Empty,
        ResourceODataIdError::SurroundingWhitespace => ExactTextError::SurroundingWhitespace,
        ResourceODataIdError::ControlCharacter => ExactTextError::ControlCharacter,
        ResourceODataIdError::TooLong { actual, maximum } => {
            ExactTextError::TooLong { actual, maximum }
        }
    }
}

fn map_odata_type_error(error: ExactTextError) -> ResourceODataTypeError {
    match error {
        ExactTextError::Empty => ResourceODataTypeError::Empty,
        ExactTextError::SurroundingWhitespace => ResourceODataTypeError::SurroundingWhitespace,
        ExactTextError::ControlCharacter => ResourceODataTypeError::ControlCharacter,
        ExactTextError::TooLong { actual, maximum } => {
            ResourceODataTypeError::TooLong { actual, maximum }
        }
    }
}

fn exact_from_odata_type(error: ResourceODataTypeError) -> ExactTextError {
    match error {
        ResourceODataTypeError::Empty | ResourceODataTypeError::MissingTypeMarker => {
            ExactTextError::Empty
        }
        ResourceODataTypeError::SurroundingWhitespace => ExactTextError::SurroundingWhitespace,
        ResourceODataTypeError::ControlCharacter => ExactTextError::ControlCharacter,
        ResourceODataTypeError::TooLong { actual, maximum } => {
            ExactTextError::TooLong { actual, maximum }
        }
    }
}

fn map_etag_error(error: ExactTextError) -> ResourceEtagError {
    match error {
        ExactTextError::Empty => ResourceEtagError::Empty,
        ExactTextError::SurroundingWhitespace => ResourceEtagError::SurroundingWhitespace,
        ExactTextError::ControlCharacter => ResourceEtagError::ControlCharacter,
        ExactTextError::TooLong { actual, maximum } => {
            ResourceEtagError::TooLong { actual, maximum }
        }
    }
}

fn exact_from_etag(error: ResourceEtagError) -> ExactTextError {
    match error {
        ResourceEtagError::Empty => ExactTextError::Empty,
        ResourceEtagError::SurroundingWhitespace => ExactTextError::SurroundingWhitespace,
        ResourceEtagError::ControlCharacter => ExactTextError::ControlCharacter,
        ResourceEtagError::TooLong { actual, maximum } => {
            ExactTextError::TooLong { actual, maximum }
        }
    }
}

fn write_exact_text_error(
    formatter: &mut fmt::Formatter<'_>,
    field: &str,
    error: ExactTextError,
) -> fmt::Result {
    match error {
        ExactTextError::Empty => write!(formatter, "{field} cannot be empty"),
        ExactTextError::SurroundingWhitespace => {
            write!(formatter, "{field} cannot contain surrounding whitespace")
        }
        ExactTextError::ControlCharacter => {
            write!(formatter, "{field} cannot contain control characters")
        }
        ExactTextError::TooLong { actual, maximum } => {
            write!(
                formatter,
                "{field} has {actual} bytes; maximum is {maximum}"
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{EndpointCapability, EndpointCapabilityParseError};

    use super::*;

    #[test]
    fn resource_feature_codes_are_stable() {
        let features = [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Chassis,
            ResourceFeature::Managers,
            ResourceFeature::OemDell,
            ResourceFeature::OemSmcSysLockdown,
            ResourceFeature::OemSmcKcsInterface,
            ResourceFeature::OemNvidiaSystemConfigProfile,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaManagedEntity,
            ResourceFeature::OemLenovoSecurityService,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::Storages,
            ResourceFeature::NetworkAdapters,
            ResourceFeature::EthernetInterfaces,
            ResourceFeature::Accounts,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::PcieDevices,
            ResourceFeature::Assembly,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ];

        for feature in features {
            assert_eq!(feature.as_str().parse(), Ok(feature));
        }
        assert_eq!(
            "unknown".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
    }

    // The exhaustive per-family assertions below exceed the pedantic
    // line budget because every mapped pair is spelled out on the wire.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn typed_family_codes_round_trip_and_match_the_capability_ledger() {
        // The snapshot feature and the §2.1 capability ledger must speak the
        // same wire string, so persistence and protocol layers never translate
        // between two inventories for the same surface. Every typed resource
        // family (0.2 Processors/Memory, the Storage/Network/Accounts
        // iteration, and the Manager-facing LogServices/ManagerNetworkProtocol/
        // HostInterfaces iteration) is asserted here so a new family cannot
        // land with a private code.
        let families = [
            (ResourceFeature::Processors, EndpointCapability::Processors),
            (ResourceFeature::Memory, EndpointCapability::Memory),
            (ResourceFeature::Storages, EndpointCapability::Storages),
            (
                ResourceFeature::NetworkAdapters,
                EndpointCapability::NetworkAdapters,
            ),
            (
                ResourceFeature::EthernetInterfaces,
                EndpointCapability::EthernetInterfaces,
            ),
            (ResourceFeature::Accounts, EndpointCapability::Accounts),
            (ResourceFeature::Bios, EndpointCapability::Bios),
            (
                ResourceFeature::BootOptions,
                EndpointCapability::BootOptions,
            ),
            (ResourceFeature::SecureBoot, EndpointCapability::SecureBoot),
            // The 0.2 Chassis telemetry families project the same four
            // §2.1 codes that the ledger already persists, so the feature
            // and capability inventories cannot drift on the wire.
            (ResourceFeature::Power, EndpointCapability::Power),
            (ResourceFeature::Thermal, EndpointCapability::Thermal),
            (ResourceFeature::Sensors, EndpointCapability::Sensors),
            (ResourceFeature::Controls, EndpointCapability::Controls),
            // The 0.2 Manager-facing families reuse the §2.1 codes the
            // ledger already persists for `log-services`,
            // `manager-network-protocol`, and `host-interfaces`, so the
            // feature and capability inventories cannot drift on the wire.
            (
                ResourceFeature::LogServices,
                EndpointCapability::LogServices,
            ),
            (
                ResourceFeature::ManagerNetworkProtocol,
                EndpointCapability::ManagerNetworkProtocol,
            ),
            (
                ResourceFeature::HostInterfaces,
                EndpointCapability::HostInterfaces,
            ),
            // The 0.2 read-surface families: `pcie-devices` and `assembly`
            // reuse the §2.1 codes the ledger already persists, so the
            // feature and capability inventories cannot drift on the wire.
            (
                ResourceFeature::PcieDevices,
                EndpointCapability::PcieDevices,
            ),
            (ResourceFeature::Assembly, EndpointCapability::Assembly),
            // The 0.2 service families reuse the §2.1 codes the ledger
            // already persists for `event-service`, `telemetry-service`, and
            // `task-service`, so the feature and capability inventories
            // cannot drift on the wire.
            (
                ResourceFeature::EventService,
                EndpointCapability::EventService,
            ),
            (
                ResourceFeature::TelemetryService,
                EndpointCapability::TelemetryService,
            ),
            (
                ResourceFeature::TaskService,
                EndpointCapability::TaskService,
            ),
        ];
        for (feature, capability) in families {
            assert_eq!(feature.as_str(), capability.as_str());
            assert_eq!(feature.as_str().parse(), Ok(feature));
            assert_eq!(
                feature.as_str().parse::<EndpointCapability>(),
                Ok(capability)
            );
        }
        // `software-inventory` is the resource family under the §2.1
        // `update-service` feature and deliberately has no capability code of
        // its own: the one `update-service` capability covers both the
        // SoftwareInventory read surface and the update operations. The
        // mapping is asserted explicitly (and the family code must not parse
        // as a capability) so the two inventories cannot silently drift into
        // aliasing each other.
        assert_eq!(
            ResourceFeature::SoftwareInventory.as_str(),
            "software-inventory"
        );
        assert_eq!(EndpointCapability::UpdateService.as_str(), "update-service");
        assert_eq!(
            ResourceFeature::SoftwareInventory
                .as_str()
                .parse::<ResourceFeature>(),
            Ok(ResourceFeature::SoftwareInventory)
        );
        assert_eq!(
            "update-service".parse::<EndpointCapability>(),
            Ok(EndpointCapability::UpdateService)
        );
        assert_eq!(
            ResourceFeature::SoftwareInventory
                .as_str()
                .parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        // The 0.2 subsidiary read surfaces under the three service features
        // follow the `software-inventory` precedent above: each family code is
        // narrower than its service capability code, so the mapping is
        // asserted explicitly (and the family codes must not parse as
        // capabilities) so the two inventories cannot silently drift into
        // aliasing each other.
        let subsidiary = [
            (
                ResourceFeature::EventSubscription,
                EndpointCapability::EventService,
            ),
            (
                ResourceFeature::MetricDefinition,
                EndpointCapability::TelemetryService,
            ),
            (
                ResourceFeature::MetricReport,
                EndpointCapability::TelemetryService,
            ),
            (ResourceFeature::Task, EndpointCapability::TaskService),
            // The 0.5 Dell Attributes family follows the same precedent: the
            // family reads the manager's Dell `Attributes` document, so it
            // maps to the `oem-dell-attributes` capability (the feature that
            // decodes that document) under the narrower family code
            // `dell-attributes` — never the `oem-dell` or
            // `oem-dell-attributes` capability codes, which stay with the
            // ledger.
            (
                ResourceFeature::OemDell,
                EndpointCapability::OemDellAttributes,
            ),
            // The 0.5 Supermicro families follow the same precedent: each
            // family reads one manager document inside the `Supermicro`
            // namespace, so both map to the `oem-supermicro` namespace
            // capability (the feature that advertises that namespace) under
            // the narrower family codes `supermicro-sys-lockdown` and
            // `supermicro-kcs-interface` — never the `oem-supermicro`
            // capability code, which stays with the ledger.
            (
                ResourceFeature::OemSmcSysLockdown,
                EndpointCapability::OemSupermicro,
            ),
            (
                ResourceFeature::OemSmcKcsInterface,
                EndpointCapability::OemSupermicro,
            ),
            // The 0.5 NVIDIA system-config-profile family follows the same
            // precedent: the family reads the system's NVIDIA profile chain
            // inside the `Nvidia` namespace, so it maps to the
            // `oem-nvidia-profiles` capability (the feature that reads
            // profile data) under the narrower family code
            // `nvidia-system-config-profile` — never the `oem-nvidia` or
            // `oem-nvidia-profiles` capability codes, which stay with the
            // ledger.
            (
                ResourceFeature::OemNvidiaSystemConfigProfile,
                EndpointCapability::OemNvidiaProfiles,
            ),
            // The 0.5 NVIDIA power-compliance and managed-entity families
            // follow the same precedent: each family reads one manager-scoped
            // chain inside the `Nvidia` namespace, so both map to the
            // `oem-nvidia-power-management` capability (the feature that
            // advertises that namespace) under the narrower family codes
            // `nvidia-power-compliance` and `nvidia-managed-entity` — never
            // the `oem-nvidia` or `oem-nvidia-power-management` capability
            // codes, which stay with the ledger.
            (
                ResourceFeature::OemNvidiaPowerCompliance,
                EndpointCapability::OemNvidiaPowerManagement,
            ),
            (
                ResourceFeature::OemNvidiaManagedEntity,
                EndpointCapability::OemNvidiaPowerManagement,
            ),
            // The 0.5 Lenovo SecurityService family follows the same
            // precedent: the family reads the manager's Lenovo
            // `SecurityService` document inside the `Lenovo` namespace, so it
            // maps to the `oem-lenovo` namespace capability (the feature that
            // advertises that namespace) under the narrower family code
            // `lenovo-security-service` — never the `oem-lenovo` capability
            // code, which stays with the ledger.
            (
                ResourceFeature::OemLenovoSecurityService,
                EndpointCapability::OemLenovo,
            ),
        ];
        for (feature, capability) in subsidiary {
            assert_ne!(feature.as_str(), capability.as_str());
            assert_eq!(feature.as_str().parse(), Ok(feature));
            assert_eq!(
                feature.as_str().parse::<EndpointCapability>(),
                Err(EndpointCapabilityParseError)
            );
            assert_eq!(capability.as_str().parse(), Ok(capability));
        }
        assert_eq!(
            ResourceFeature::EventSubscription.as_str(),
            "event-subscription"
        );
        assert_eq!(
            ResourceFeature::MetricDefinition.as_str(),
            "metric-definition"
        );
        assert_eq!(ResourceFeature::MetricReport.as_str(), "metric-report");
        assert_eq!(ResourceFeature::Task.as_str(), "task");
        // The 0.5 Dell Attributes family keeps its narrow `dell-attributes`
        // code; the `oem-dell` namespace capability and the
        // `oem-dell-attributes` feature capability stay with the ledger, so
        // the snapshot and capability inventories cannot silently drift into
        // aliasing each other.
        assert_eq!(ResourceFeature::OemDell.as_str(), "dell-attributes");
        assert_eq!(EndpointCapability::OemDell.as_str(), "oem-dell");
        assert_eq!(
            EndpointCapability::OemDellAttributes.as_str(),
            "oem-dell-attributes"
        );
        assert_eq!(
            "dell-attributes".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemDell)
        );
        assert_eq!(
            "dell-attributes".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "oem-dell-attributes".parse::<EndpointCapability>(),
            Ok(EndpointCapability::OemDellAttributes)
        );
        // The 0.5 Supermicro families keep their narrow
        // `supermicro-sys-lockdown` / `supermicro-kcs-interface` codes; the
        // `oem-supermicro` namespace capability stays with the ledger, so the
        // snapshot and capability inventories cannot silently drift into
        // aliasing each other.
        assert_eq!(
            ResourceFeature::OemSmcSysLockdown.as_str(),
            "supermicro-sys-lockdown"
        );
        assert_eq!(
            ResourceFeature::OemSmcKcsInterface.as_str(),
            "supermicro-kcs-interface"
        );
        assert_eq!(EndpointCapability::OemSupermicro.as_str(), "oem-supermicro");
        assert_eq!(
            "supermicro-sys-lockdown".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemSmcSysLockdown)
        );
        assert_eq!(
            "supermicro-sys-lockdown".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "supermicro-kcs-interface".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemSmcKcsInterface)
        );
        assert_eq!(
            "supermicro-kcs-interface".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "oem-supermicro".parse::<EndpointCapability>(),
            Ok(EndpointCapability::OemSupermicro)
        );
        assert_eq!(
            "oem-supermicro".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
        // The 0.5 NVIDIA system-config-profile family keeps its narrow
        // `nvidia-system-config-profile` code; the `oem-nvidia` namespace
        // capability and the `oem-nvidia-profiles` feature capability stay
        // with the ledger, so the snapshot and capability inventories cannot
        // silently drift into aliasing each other.
        assert_eq!(
            ResourceFeature::OemNvidiaSystemConfigProfile.as_str(),
            "nvidia-system-config-profile"
        );
        assert_eq!(EndpointCapability::OemNvidia.as_str(), "oem-nvidia");
        assert_eq!(
            EndpointCapability::OemNvidiaProfiles.as_str(),
            "oem-nvidia-profiles"
        );
        assert_eq!(
            "nvidia-system-config-profile".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemNvidiaSystemConfigProfile)
        );
        assert_eq!(
            "nvidia-system-config-profile".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "oem-nvidia-profiles".parse::<EndpointCapability>(),
            Ok(EndpointCapability::OemNvidiaProfiles)
        );
        assert_eq!(
            "oem-nvidia-profiles".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
        assert_eq!(
            "oem-nvidia".parse::<EndpointCapability>(),
            Ok(EndpointCapability::OemNvidia)
        );
        assert_eq!(
            "oem-nvidia".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
        // The 0.5 NVIDIA power-compliance and managed-entity families keep
        // their narrow `nvidia-power-compliance` / `nvidia-managed-entity`
        // codes; the `oem-nvidia` namespace capability and the
        // `oem-nvidia-power-management` feature capability stay with the
        // ledger, so the snapshot and capability inventories cannot silently
        // drift into aliasing each other.
        assert_eq!(
            ResourceFeature::OemNvidiaPowerCompliance.as_str(),
            "nvidia-power-compliance"
        );
        assert_eq!(
            ResourceFeature::OemNvidiaManagedEntity.as_str(),
            "nvidia-managed-entity"
        );
        assert_eq!(
            EndpointCapability::OemNvidiaPowerManagement.as_str(),
            "oem-nvidia-power-management"
        );
        assert_eq!(
            "nvidia-power-compliance".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemNvidiaPowerCompliance)
        );
        assert_eq!(
            "nvidia-power-compliance".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "nvidia-managed-entity".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemNvidiaManagedEntity)
        );
        assert_eq!(
            "nvidia-managed-entity".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "oem-nvidia-power-management".parse::<EndpointCapability>(),
            Ok(EndpointCapability::OemNvidiaPowerManagement)
        );
        assert_eq!(
            "oem-nvidia-power-management".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
        // The 0.5 Lenovo SecurityService family keeps its narrow
        // `lenovo-security-service` code; the `oem-lenovo` namespace
        // capability stays with the ledger, so the snapshot and capability
        // inventories cannot silently drift into aliasing each other.
        assert_eq!(
            ResourceFeature::OemLenovoSecurityService.as_str(),
            "lenovo-security-service"
        );
        assert_eq!(EndpointCapability::OemLenovo.as_str(), "oem-lenovo");
        assert_eq!(
            "lenovo-security-service".parse::<ResourceFeature>(),
            Ok(ResourceFeature::OemLenovoSecurityService)
        );
        assert_eq!(
            "lenovo-security-service".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
        assert_eq!(
            "oem-lenovo".parse::<EndpointCapability>(),
            Ok(EndpointCapability::OemLenovo)
        );
        assert_eq!(
            "oem-lenovo".parse::<ResourceFeature>(),
            Err(ResourceFeatureParseError)
        );
    }

    // The exhaustive near-miss spellings below exceed the pedantic line
    // budget because every rejected wire string is listed explicitly.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn rejects_unknown_and_near_miss_feature_codes() {
        // Singular forms and trailing punctuation would silently address a
        // different collection, so they must stay unparseable until a matching
        // resource family actually exists.
        for code in [
            "processor",
            "memories",
            "mem",
            "processors/",
            "memory-",
            "Processors",
            "Memory",
            "storage",
            "network-adapter",
            "ethernet-interface",
            "storages/",
            "network-adapters/",
            "ethernet-interfaces-",
            "Storages",
            "NetworkAdapters",
            "EthernetInterfaces",
            "account",
            "accounts/",
            "Accounts",
            "bios/",
            "BIOS",
            "bios-config",
            "boot-option",
            "boot-options/",
            "bootoptions",
            "BootOptions",
            "secure-boot/",
            "secureboot",
            "SecureBoot",
            "powers",
            "power/",
            "Power",
            "power-equipment",
            "power-supplies",
            "power-supply",
            "thermals",
            "thermal/",
            "Thermal",
            "temperature",
            "sensor",
            "sensors/",
            "Sensors",
            "control",
            "controls/",
            "Controls",
            "environment-metrics",
            "log-service",
            "log-services/",
            "logservice",
            "LogServices",
            "logs",
            "log",
            "manager-network-protocol/",
            "manager-networkprotocol",
            "manager-network-protocols",
            "manager-net-protocol",
            "ManagerNetworkProtocol",
            "manager-network",
            // The 0.5 Dell Attributes family: singular and snake_case forms
            // would address a different surface, and the `oem-dell` /
            // `oem-dell-attributes` capability codes must stay unparseable as
            // families so the ledger and the snapshot inventory never alias.
            "dell-attribute",
            "dell-attributes/",
            "dell_attributes",
            "dellattributes",
            "DellAttributes",
            "attributes",
            "oem-dell",
            "oem-dell-attribute",
            "oem-dell-attributes",
            // The 0.5 Supermicro families: singular and snake_case forms
            // would address a different surface, the vendor-less names would
            // collide with the product's vendor-prefixed family space, and
            // the `oem-supermicro` capability code (plus its hypothetical
            // per-document extensions) must stay unparseable as families so
            // the ledger and the snapshot inventory never alias.
            "supermicro-sys-lockdown/",
            "supermicro_sys_lockdown",
            "supermicrosyslockdown",
            "sys-lockdown",
            "sys_lockdown",
            "SysLockdown",
            "smc-sys-lockdown",
            "oem-supermicro-sys-lockdown",
            "supermicro-kcs-interface/",
            "supermicro_kcs_interface",
            "supermicrokcsinterface",
            "kcs-interface",
            "kcs_interface",
            "KCSInterface",
            "smc-kcs-interface",
            "oem-supermicro-kcs-interface",
            "oem-supermicro",
            // The 0.5 NVIDIA system-config-profile family: singular,
            // snake_case, and CamelCase forms would address a different
            // surface, the vendor-less names would collide with the
            // product's vendor-prefixed family space, and the `oem-nvidia` /
            // `oem-nvidia-profiles` capability codes (plus the hypothetical
            // per-surface extensions) must stay unparseable as families so
            // the ledger and the snapshot inventory never alias.
            "nvidia-system-config-profile/",
            "nvidia_system_config_profile",
            "nvidiasystemconfigprofile",
            "NvidiaSystemConfigProfile",
            "system-config-profile",
            "system_config_profile",
            "SystemConfigProfile",
            "nvidia-system-config-profiles",
            "nvidia-profile",
            "nvidia-profiles",
            "nvidia-system-profile",
            "oem-nvidia-system-config-profile",
            "oem-nvidia",
            "oem-nvidia-profiles",
            // The 0.5 NVIDIA power-compliance family: singular, snake_case,
            // and CamelCase forms would address a different surface, the
            // vendor-less names would collide with the product's
            // vendor-prefixed family space, and the `oem-nvidia` /
            // `oem-nvidia-power-management` capability codes (plus the
            // hypothetical per-surface extensions) must stay unparseable as
            // families so the ledger and the snapshot inventory never alias.
            "nvidia-power-compliance/",
            "nvidia_power_compliance",
            "nvidiapowercompliance",
            "NvidiaPowerCompliance",
            "power-compliance",
            "power_compliance",
            "PowerCompliance",
            "nvidia-power-compliances",
            "nvidia-power",
            "oem-nvidia-power-compliance",
            "oem-nvidia-power-management",
            // The 0.5 NVIDIA managed-entity family: singular, snake_case, and
            // CamelCase forms would address a different surface, the
            // vendor-less names would collide with the product's
            // vendor-prefixed family space, and the `oem-nvidia` /
            // `oem-nvidia-power-management` capability codes (plus the
            // hypothetical per-surface extensions) must stay unparseable as
            // families so the ledger and the snapshot inventory never alias.
            "nvidia-managed-entity/",
            "nvidia_managed_entity",
            "nvidiamanagedentity",
            "NvidiaManagedEntity",
            "managed-entity",
            "managed_entity",
            "ManagedEntity",
            "nvidia-managed-entities",
            "nvidia-managed-entity-group",
            "oem-nvidia-managed-entity",
            // The 0.5 Lenovo SecurityService family: singular, snake_case, and
            // CamelCase forms would address a different surface, the
            // vendor-less names would collide with the product's
            // vendor-prefixed family space, and the `oem-lenovo` capability
            // code (plus its hypothetical per-surface extensions) must stay
            // unparseable as families so the ledger and the snapshot
            // inventory never alias.
            "lenovo-security-service/",
            "lenovo_security_service",
            "lenovosecurityservice",
            "LenovoSecurityService",
            "security-service",
            "security_service",
            "SecurityService",
            "lenovo-security-services",
            "lenovo-security",
            "lenovo-sec",
            "oem-lenovo",
            "oem-lenovo-security-service",
            "host-interface",
            "host-interfaces/",
            "hostinterface",
            "HostInterfaces",
            "host-interfaces-",
            "pcie-device",
            "pcie-devices/",
            "pcie",
            "PcieDevices",
            "PCIeDevice",
            "assemblies",
            "assembly/",
            "Assembly",
            "assembly-data",
            "software-inventories",
            "software-inventory/",
            "software-inventory-",
            "SoftwareInventory",
            "software",
            "update-service",
            "update-service-deprecated",
            "ports",
            "bmc-http",
            "event-services",
            "eventservice",
            "event_service",
            "EventService",
            "event-service/",
            "event",
            "events",
            "event-destination",
            "event-destinations",
            "subscription",
            "subscriptions",
            "event-subscriptions",
            "eventsubscription",
            "event_subscription",
            "EventSubscription",
            "event-subscription/",
            "telemetry-services",
            "telemetryservice",
            "telemetry_service",
            "TelemetryService",
            "telemetry-service/",
            "metric-definitions",
            "metricdefinition",
            "metric_definition",
            "MetricDefinition",
            "metric-definition/",
            "metric",
            "metrics",
            "metric-reports",
            "metricreport",
            "metric_report",
            "MetricReport",
            "metric-report/",
            "task-services",
            "taskservice",
            "task_service",
            "TaskService",
            "task-service/",
            "tasks",
            "task/",
            "Task",
            "subtask",
            "subtasks",
        ] {
            assert_eq!(
                code.parse::<ResourceFeature>(),
                Err(ResourceFeatureParseError),
                "{code} must not parse as a resource feature"
            );
        }
    }

    #[test]
    fn validates_exact_redfish_metadata_without_constructing_paths() -> Result<(), Box<dyn Error>> {
        let odata_id = ResourceODataId::parse("/redfish/v1/Systems/System.Embedded.1")?;
        let odata_type = ResourceODataType::parse("#ComputerSystem.v1_20_0.ComputerSystem")?;
        let etag = ResourceEtag::parse("W/\"generation-7\"")?;

        assert_eq!(odata_id.as_str(), "/redfish/v1/Systems/System.Embedded.1");
        assert_eq!(
            odata_type.as_str(),
            "#ComputerSystem.v1_20_0.ComputerSystem"
        );
        assert_eq!(etag.as_str(), "W/\"generation-7\"");
        assert_eq!(
            ResourceODataId::parse(" /redfish/v1/Systems/1"),
            Err(ResourceODataIdError::SurroundingWhitespace)
        );
        assert_eq!(
            ResourceODataType::parse("ComputerSystem.v1_20_0.ComputerSystem"),
            Err(ResourceODataTypeError::MissingTypeMarker)
        );
        assert_eq!(
            ResourceEtag::parse("generation\n7"),
            Err(ResourceEtagError::ControlCharacter)
        );
        Ok(())
    }

    #[test]
    fn canonicalizes_only_bounded_json_objects() -> Result<(), Box<dyn Error>> {
        let payload = ResourceSnapshotPayload::parse(r#"{ "Name": "System", "Id": "1" }"#)?;

        assert_eq!(payload.as_str(), r#"{"Id":"1","Name":"System"}"#);
        assert_eq!(
            format!("{payload:?}"),
            "ResourceSnapshotPayload { bytes: 26, .. }"
        );
        assert!(matches!(
            ResourceSnapshotPayload::parse("not json"),
            Err(ResourceSnapshotPayloadError::InvalidJson(_))
        ));
        assert!(matches!(
            ResourceSnapshotPayload::parse("[]"),
            Err(ResourceSnapshotPayloadError::NotObject)
        ));
        assert!(matches!(
            ResourceSnapshotPayload::parse(&format!(
                "{{\"value\":\"{}\"}}",
                "x".repeat(MAX_TYPED_PAYLOAD_BYTES)
            )),
            Err(ResourceSnapshotPayloadError::TooLarge { .. })
        ));
        Ok(())
    }

    #[test]
    fn snapshots_keep_identity_metadata_and_generation_together() -> Result<(), Box<dyn Error>> {
        let observed_at = OffsetDateTime::now_utc();
        let generation = RefreshGeneration::new(7)?;
        let snapshot = ResourceSnapshot::new(
            ResourceId::generate(),
            EndpointId::generate(),
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(r#"{"Id":"1","Name":"System"}"#)?,
            observed_at,
            generation,
        )
        .with_odata_type(ResourceODataType::parse(
            "#ComputerSystem.v1_20_0.ComputerSystem",
        )?)
        .with_etag(ResourceEtag::parse("\"seven\"")?);

        assert_eq!(snapshot.feature(), ResourceFeature::Systems);
        assert_eq!(snapshot.odata_id().as_str(), "/redfish/v1/Systems/1");
        assert_eq!(
            snapshot.odata_type().map(ResourceODataType::as_str),
            Some("#ComputerSystem.v1_20_0.ComputerSystem")
        );
        assert_eq!(snapshot.etag().map(ResourceEtag::as_str), Some("\"seven\""));
        assert_eq!(snapshot.payload().as_str(), r#"{"Id":"1","Name":"System"}"#);
        assert_eq!(snapshot.observed_at(), observed_at);
        assert_eq!(snapshot.generation(), generation);
        Ok(())
    }

    #[test]
    fn refresh_generations_are_positive_and_sqlite_compatible() {
        assert_eq!(RefreshGeneration::new(0), Err(RefreshGenerationError::Zero));
        assert_eq!(RefreshGeneration::new(1).map(RefreshGeneration::get), Ok(1));
        assert!(matches!(
            RefreshGeneration::new(i64::MAX as u64 + 1),
            Err(RefreshGenerationError::TooLarge { .. })
        ));
    }
}
