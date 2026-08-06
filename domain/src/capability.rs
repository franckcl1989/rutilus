use std::{error::Error, fmt, str::FromStr};

/// A standard Redfish capability tracked by the capability ledger.
///
/// Each variant maps to one public `nv-redfish` feature. The variants are the
/// complete §2.1 standard-feature inventory (30 entries), declared in the same
/// order as the design document, so the 0.2 ledger can enumerate every
/// capability the product may compile. Persisted identity is the `as_str()`
/// product code, which is stable across milestones: the 0.1 codes
/// ("session-service", "systems", "chassis", "managers") keep their values
/// even where the upstream feature has since been renamed (see `Systems`).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EndpointCapability {
    Accounts,
    Assembly,
    Bios,
    BootOptions,
    Chassis,
    /// The `computer-systems` feature under its stable 0.1 product code
    /// "systems".
    Systems,
    Controls,
    EnvironmentMetrics,
    EthernetInterfaces,
    EventService,
    HostInterfaces,
    LogServices,
    ManagerNetworkProtocol,
    Managers,
    Memory,
    NetworkAdapters,
    NetworkDeviceFunctions,
    PcieDevices,
    Power,
    PowerEquipment,
    PowerSupplies,
    Processors,
    SecureBoot,
    Sensors,
    SessionService,
    Storages,
    TaskService,
    TelemetryService,
    Thermal,
    UpdateService,
}

impl EndpointCapability {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Assembly => "assembly",
            Self::Bios => "bios",
            Self::BootOptions => "boot-options",
            Self::Chassis => "chassis",
            Self::Systems => "systems",
            Self::Controls => "controls",
            Self::EnvironmentMetrics => "environment-metrics",
            Self::EthernetInterfaces => "ethernet-interfaces",
            Self::EventService => "event-service",
            Self::HostInterfaces => "host-interfaces",
            Self::LogServices => "log-services",
            Self::ManagerNetworkProtocol => "manager-network-protocol",
            Self::Managers => "managers",
            Self::Memory => "memory",
            Self::NetworkAdapters => "network-adapters",
            Self::NetworkDeviceFunctions => "network-device-functions",
            Self::PcieDevices => "pcie-devices",
            Self::Power => "power",
            Self::PowerEquipment => "power-equipment",
            Self::PowerSupplies => "power-supplies",
            Self::Processors => "processors",
            Self::SecureBoot => "secure-boot",
            Self::Sensors => "sensors",
            Self::SessionService => "session-service",
            Self::Storages => "storages",
            Self::TaskService => "task-service",
            Self::TelemetryService => "telemetry-service",
            Self::Thermal => "thermal",
            Self::UpdateService => "update-service",
        }
    }

    /// Returns the public upstream feature that compiles this capability.
    #[must_use]
    pub const fn upstream_feature(self) -> &'static str {
        match self {
            Self::Accounts => "accounts",
            Self::Assembly => "assembly",
            Self::Bios => "bios",
            Self::BootOptions => "boot-options",
            Self::Chassis => "chassis",
            Self::Systems => "computer-systems",
            Self::Controls => "controls",
            Self::EnvironmentMetrics => "environment-metrics",
            Self::EthernetInterfaces => "ethernet-interfaces",
            Self::EventService => "event-service",
            Self::HostInterfaces => "host-interfaces",
            Self::LogServices => "log-services",
            Self::ManagerNetworkProtocol => "manager-network-protocol",
            Self::Managers => "managers",
            Self::Memory => "memory",
            Self::NetworkAdapters => "network-adapters",
            Self::NetworkDeviceFunctions => "network-device-functions",
            Self::PcieDevices => "pcie-devices",
            Self::Power => "power",
            Self::PowerEquipment => "power-equipment",
            Self::PowerSupplies => "power-supplies",
            Self::Processors => "processors",
            Self::SecureBoot => "secure-boot",
            Self::Sensors => "sensors",
            Self::SessionService => "session-service",
            Self::Storages => "storages",
            Self::TaskService => "task-service",
            Self::TelemetryService => "telemetry-service",
            Self::Thermal => "thermal",
            Self::UpdateService => "update-service",
        }
    }

    /// Returns the capability-ledger classification required by the product
    /// design §2.4.
    ///
    /// Session and Task services back product operations instead of presenting
    /// data, so they are Infrastructure. Every remaining standard feature maps
    /// to a viewable or operable surface (§12.2) and is `UserFacing` —
    /// including `UpdateService`, whose `SoftwareInventory` and update
    /// operations are operator-visible rather than internal plumbing. No
    /// standard feature is classified as `LegacyCompatibility` or `Internal`
    /// in the 0.2 ledger.
    #[must_use]
    pub const fn classification(self) -> CapabilityClassification {
        match self {
            Self::SessionService | Self::TaskService => CapabilityClassification::Infrastructure,
            Self::Accounts
            | Self::Assembly
            | Self::Bios
            | Self::BootOptions
            | Self::Chassis
            | Self::Systems
            | Self::Controls
            | Self::EnvironmentMetrics
            | Self::EthernetInterfaces
            | Self::EventService
            | Self::HostInterfaces
            | Self::LogServices
            | Self::ManagerNetworkProtocol
            | Self::Managers
            | Self::Memory
            | Self::NetworkAdapters
            | Self::NetworkDeviceFunctions
            | Self::PcieDevices
            | Self::Power
            | Self::PowerEquipment
            | Self::PowerSupplies
            | Self::Processors
            | Self::SecureBoot
            | Self::Sensors
            | Self::Storages
            | Self::TelemetryService
            | Self::Thermal
            | Self::UpdateService => CapabilityClassification::UserFacing,
        }
    }

    /// Returns the §12.2 Endpoint page that presents this capability.
    ///
    /// Page assignment follows the §3.1 product-domain mapping. Control
    /// resources govern actuators on power/environment equipment (power
    /// capping, fan control) and are presented under Power;
    /// `EnvironmentMetrics` aggregates temperature, fan, and power readings and
    /// is presented with the Sensors measurements page. Manager
    /// network-protocol settings stay on the Managers page (BMC information,
    /// firmware, and network protocols per §3.1).
    #[must_use]
    pub const fn ui_location(self) -> UiLocation {
        match self {
            Self::Accounts => UiLocation::Accounts,
            Self::Assembly => UiLocation::Assembly,
            Self::Bios => UiLocation::Bios,
            Self::BootOptions => UiLocation::Boot,
            Self::Chassis => UiLocation::Chassis,
            Self::Controls | Self::Power | Self::PowerEquipment | Self::PowerSupplies => {
                UiLocation::Power
            }
            Self::EnvironmentMetrics | Self::Sensors => UiLocation::Sensors,
            Self::EthernetInterfaces
            | Self::HostInterfaces
            | Self::NetworkAdapters
            | Self::NetworkDeviceFunctions => UiLocation::Network,
            Self::EventService => UiLocation::Events,
            Self::LogServices => UiLocation::Logs,
            Self::ManagerNetworkProtocol | Self::Managers => UiLocation::Managers,
            Self::Memory => UiLocation::Memory,
            Self::PcieDevices => UiLocation::Pcie,
            Self::Processors => UiLocation::Processors,
            Self::SecureBoot => UiLocation::SecureBoot,
            Self::SessionService => UiLocation::Infrastructure,
            Self::Storages => UiLocation::Storage,
            Self::TaskService => UiLocation::Tasks,
            Self::TelemetryService => UiLocation::Telemetry,
            Self::Thermal => UiLocation::Thermal,
            Self::UpdateService => UiLocation::Update,
            Self::Systems => UiLocation::Systems,
        }
    }
}

/// The complete §2.1 standard-feature inventory in design-document order.
///
/// This is the canonical enumeration for every ledger projection: the 0.2
/// Endpoint capability page renders exactly these 30 entries, and an entry
/// without a persisted observation still appears so the UI can explain why
/// the feature is missing instead of hiding it. The order must stay aligned
/// with §2.1, so queries, persistence round-trips, and the capability page
/// all enumerate the ledger identically.
pub const CAPABILITY_LEDGER_ORDER: [EndpointCapability; 30] = [
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

impl fmt::Display for EndpointCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EndpointCapability {
    type Err = EndpointCapabilityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "accounts" => Ok(Self::Accounts),
            "assembly" => Ok(Self::Assembly),
            "bios" => Ok(Self::Bios),
            "boot-options" => Ok(Self::BootOptions),
            "chassis" => Ok(Self::Chassis),
            "systems" => Ok(Self::Systems),
            "controls" => Ok(Self::Controls),
            "environment-metrics" => Ok(Self::EnvironmentMetrics),
            "ethernet-interfaces" => Ok(Self::EthernetInterfaces),
            "event-service" => Ok(Self::EventService),
            "host-interfaces" => Ok(Self::HostInterfaces),
            "log-services" => Ok(Self::LogServices),
            "manager-network-protocol" => Ok(Self::ManagerNetworkProtocol),
            "managers" => Ok(Self::Managers),
            "memory" => Ok(Self::Memory),
            "network-adapters" => Ok(Self::NetworkAdapters),
            "network-device-functions" => Ok(Self::NetworkDeviceFunctions),
            "pcie-devices" => Ok(Self::PcieDevices),
            "power" => Ok(Self::Power),
            "power-equipment" => Ok(Self::PowerEquipment),
            "power-supplies" => Ok(Self::PowerSupplies),
            "processors" => Ok(Self::Processors),
            "secure-boot" => Ok(Self::SecureBoot),
            "sensors" => Ok(Self::Sensors),
            "session-service" => Ok(Self::SessionService),
            "storages" => Ok(Self::Storages),
            "task-service" => Ok(Self::TaskService),
            "telemetry-service" => Ok(Self::TelemetryService),
            "thermal" => Ok(Self::Thermal),
            "update-service" => Ok(Self::UpdateService),
            _ => Err(EndpointCapabilityParseError),
        }
    }
}

/// A persisted capability code is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCapabilityParseError;

impl fmt::Display for EndpointCapabilityParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown endpoint capability code")
    }
}

impl Error for EndpointCapabilityParseError {}

/// Product-facing classification for one capability-ledger entry (§2.4).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityClassification {
    /// Users can view or operate the capability's product surface.
    UserFacing,
    /// Session, Task, and transport capabilities that back product operations.
    Infrastructure,
    /// Upstream features kept for legacy device compatibility. No standard
    /// feature maps here in the 0.2 ledger.
    LegacyCompatibility,
    /// Capabilities used only inside the product (for example, patch
    /// helpers). No feature maps here in the 0.2 ledger.
    Internal,
}

/// The §12.2 Endpoint page that presents one capability surface.
///
/// Values mirror the design document's capability-driven Endpoint navigation.
/// Pages without a capability mapping yet (Overview, Oem, Diagnostics) are
/// retained so the navigation model stays complete as later milestones add
/// OEM and diagnostics surfaces.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum UiLocation {
    Overview,
    Systems,
    Chassis,
    Managers,
    Assembly,
    Processors,
    Memory,
    Pcie,
    Network,
    Power,
    Thermal,
    Sensors,
    Bios,
    Boot,
    SecureBoot,
    Storage,
    Accounts,
    Logs,
    Events,
    Telemetry,
    Update,
    Tasks,
    /// Vendor-proprietary surfaces; no standard feature maps here yet.
    Oem,
    /// Read-only diagnostic surfaces; no capability maps here yet.
    Diagnostics,
    /// Session and transport surfaces shown outside the endpoint data pages.
    Infrastructure,
}

impl UiLocation {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Overview => "overview",
            Self::Systems => "systems",
            Self::Chassis => "chassis",
            Self::Managers => "managers",
            Self::Assembly => "assembly",
            Self::Processors => "processors",
            Self::Memory => "memory",
            Self::Pcie => "pcie",
            Self::Network => "network",
            Self::Power => "power",
            Self::Thermal => "thermal",
            Self::Sensors => "sensors",
            Self::Bios => "bios",
            Self::Boot => "boot",
            Self::SecureBoot => "secure-boot",
            Self::Storage => "storage",
            Self::Accounts => "accounts",
            Self::Logs => "logs",
            Self::Events => "events",
            Self::Telemetry => "telemetry",
            Self::Update => "update",
            Self::Tasks => "tasks",
            Self::Oem => "oem",
            Self::Diagnostics => "diagnostics",
            Self::Infrastructure => "infrastructure",
        }
    }
}

impl fmt::Display for UiLocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for UiLocation {
    type Err = UiLocationParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "overview" => Ok(Self::Overview),
            "systems" => Ok(Self::Systems),
            "chassis" => Ok(Self::Chassis),
            "managers" => Ok(Self::Managers),
            "assembly" => Ok(Self::Assembly),
            "processors" => Ok(Self::Processors),
            "memory" => Ok(Self::Memory),
            "pcie" => Ok(Self::Pcie),
            "network" => Ok(Self::Network),
            "power" => Ok(Self::Power),
            "thermal" => Ok(Self::Thermal),
            "sensors" => Ok(Self::Sensors),
            "bios" => Ok(Self::Bios),
            "boot" => Ok(Self::Boot),
            "secure-boot" => Ok(Self::SecureBoot),
            "storage" => Ok(Self::Storage),
            "accounts" => Ok(Self::Accounts),
            "logs" => Ok(Self::Logs),
            "events" => Ok(Self::Events),
            "telemetry" => Ok(Self::Telemetry),
            "update" => Ok(Self::Update),
            "tasks" => Ok(Self::Tasks),
            "oem" => Ok(Self::Oem),
            "diagnostics" => Ok(Self::Diagnostics),
            "infrastructure" => Ok(Self::Infrastructure),
            _ => Err(UiLocationParseError),
        }
    }
}

/// A persisted UI location is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UiLocationParseError;

impl fmt::Display for UiLocationParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown endpoint UI location")
    }
}

impl Error for UiLocationParseError {}

/// The final state obtained from the compiled, advertised, and usable
/// capability layers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityState {
    Supported,
    ReadOnly,
    Unauthorized,
    TemporarilyUnavailable,
    SchemaIncompatible,
    NotAdvertised,
    NotCompiled,
}

impl CapabilityState {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::ReadOnly => "read-only",
            Self::Unauthorized => "unauthorized",
            Self::TemporarilyUnavailable => "temporarily-unavailable",
            Self::SchemaIncompatible => "schema-incompatible",
            Self::NotAdvertised => "not-advertised",
            Self::NotCompiled => "not-compiled",
        }
    }

    /// Reports whether the current binary includes the upstream feature.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        !matches!(self, Self::NotCompiled)
    }

    /// Reports whether the endpoint advertised the capability after accounting
    /// for the current binary's compiled surface.
    #[must_use]
    pub const fn is_advertised(self) -> bool {
        !matches!(self, Self::NotCompiled | Self::NotAdvertised)
    }

    /// Reports whether the capability can currently serve product reads.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Supported | Self::ReadOnly)
    }
}

impl fmt::Display for CapabilityState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CapabilityState {
    type Err = CapabilityStateParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "supported" => Ok(Self::Supported),
            "read-only" => Ok(Self::ReadOnly),
            "unauthorized" => Ok(Self::Unauthorized),
            "temporarily-unavailable" => Ok(Self::TemporarilyUnavailable),
            "schema-incompatible" => Ok(Self::SchemaIncompatible),
            "not-advertised" => Ok(Self::NotAdvertised),
            "not-compiled" => Ok(Self::NotCompiled),
            _ => Err(CapabilityStateParseError),
        }
    }
}

/// A persisted capability state is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityStateParseError;

impl fmt::Display for CapabilityStateParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown endpoint capability state")
    }
}

impl Error for CapabilityStateParseError {}

/// One endpoint's observed state for one compiled product capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointCapabilityObservation {
    capability: EndpointCapability,
    state: CapabilityState,
}

impl EndpointCapabilityObservation {
    #[must_use]
    pub const fn new(capability: EndpointCapability, state: CapabilityState) -> Self {
        Self { capability, state }
    }

    #[must_use]
    pub const fn capability(self) -> EndpointCapability {
        self.capability
    }

    #[must_use]
    pub const fn state(self) -> CapabilityState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §2.1 standard-feature inventory, in design-document order. The
    /// ledger must map exactly this set and nothing else.
    const STANDARD_FEATURES: [&str; 30] = [
        "accounts",
        "assembly",
        "bios",
        "boot-options",
        "chassis",
        "computer-systems",
        "controls",
        "environment-metrics",
        "ethernet-interfaces",
        "event-service",
        "host-interfaces",
        "log-services",
        "manager-network-protocol",
        "managers",
        "memory",
        "network-adapters",
        "network-device-functions",
        "pcie-devices",
        "power",
        "power-equipment",
        "power-supplies",
        "processors",
        "secure-boot",
        "sensors",
        "session-service",
        "storages",
        "task-service",
        "telemetry-service",
        "thermal",
        "update-service",
    ];

    /// Every §12.2 Endpoint page, in navigation order.
    const UI_LOCATIONS: [UiLocation; 25] = [
        UiLocation::Overview,
        UiLocation::Systems,
        UiLocation::Chassis,
        UiLocation::Managers,
        UiLocation::Assembly,
        UiLocation::Processors,
        UiLocation::Memory,
        UiLocation::Pcie,
        UiLocation::Network,
        UiLocation::Power,
        UiLocation::Thermal,
        UiLocation::Sensors,
        UiLocation::Bios,
        UiLocation::Boot,
        UiLocation::SecureBoot,
        UiLocation::Storage,
        UiLocation::Accounts,
        UiLocation::Logs,
        UiLocation::Events,
        UiLocation::Telemetry,
        UiLocation::Update,
        UiLocation::Tasks,
        UiLocation::Oem,
        UiLocation::Diagnostics,
        UiLocation::Infrastructure,
    ];

    const STATES: [CapabilityState; 7] = [
        CapabilityState::Supported,
        CapabilityState::ReadOnly,
        CapabilityState::Unauthorized,
        CapabilityState::TemporarilyUnavailable,
        CapabilityState::SchemaIncompatible,
        CapabilityState::NotAdvertised,
        CapabilityState::NotCompiled,
    ];

    #[test]
    fn capability_ledger_covers_every_standard_feature_exactly_once() {
        assert_eq!(CAPABILITY_LEDGER_ORDER.len(), STANDARD_FEATURES.len());
        let mut upstream_features = Vec::new();
        for capability in CAPABILITY_LEDGER_ORDER {
            let feature = capability.upstream_feature();
            assert!(
                !feature.is_empty(),
                "{} must name a non-empty upstream feature",
                capability.as_str()
            );
            assert!(
                STANDARD_FEATURES.contains(&feature),
                "upstream feature {feature} is not in the §2.1 inventory"
            );
            assert!(
                !upstream_features.contains(&feature),
                "upstream feature {feature} is mapped by more than one capability"
            );
            upstream_features.push(feature);
        }
        for feature in STANDARD_FEATURES {
            assert!(
                CAPABILITY_LEDGER_ORDER
                    .iter()
                    .any(|capability| capability.upstream_feature() == feature),
                "§2.1 feature {feature} has no capability variant"
            );
        }
    }

    #[test]
    fn capability_codes_are_unique_non_empty_and_round_trip() {
        let mut seen = Vec::new();
        for capability in CAPABILITY_LEDGER_ORDER {
            let code = capability.as_str();
            assert!(!code.is_empty(), "capability codes must not be empty");
            assert!(
                !seen.contains(&code),
                "product code {code} is used by more than one capability"
            );
            seen.push(code);
            assert_eq!(code.parse(), Ok(capability));
        }
        assert_eq!(
            "unknown".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
    }

    #[test]
    fn classification_is_stable_and_matches_the_design() {
        for capability in CAPABILITY_LEDGER_ORDER {
            let expected = match capability {
                EndpointCapability::SessionService | EndpointCapability::TaskService => {
                    CapabilityClassification::Infrastructure
                }
                _ => CapabilityClassification::UserFacing,
            };
            assert_eq!(capability.classification(), expected);
            assert!(
                !matches!(
                    capability.classification(),
                    CapabilityClassification::LegacyCompatibility
                        | CapabilityClassification::Internal
                ),
                "{} must not use a reserved classification in the 0.2 ledger",
                capability.as_str()
            );
        }
    }

    #[test]
    fn every_capability_maps_to_a_stable_ui_location() {
        for capability in CAPABILITY_LEDGER_ORDER {
            let location = capability.ui_location();
            assert_eq!(location.as_str().parse(), Ok(location));
        }
        assert_eq!(
            EndpointCapability::SessionService.ui_location(),
            UiLocation::Infrastructure
        );
        assert_eq!(
            EndpointCapability::TaskService.ui_location(),
            UiLocation::Tasks
        );
    }

    #[test]
    fn ui_location_codes_are_unique_non_empty_and_round_trip() {
        let mut seen = Vec::new();
        for location in UI_LOCATIONS {
            let code = location.as_str();
            assert!(!code.is_empty(), "UI location codes must not be empty");
            assert!(
                !seen.contains(&code),
                "UI location code {code} is used by more than one page"
            );
            seen.push(code);
            assert_eq!(code.parse(), Ok(location));
        }
        assert_eq!("unknown".parse::<UiLocation>(), Err(UiLocationParseError));
    }

    #[test]
    fn final_states_preserve_compiled_advertised_and_usable_layers() {
        for state in STATES {
            assert_eq!(state.as_str().parse(), Ok(state));
        }

        assert!(CapabilityState::Supported.is_usable());
        assert!(CapabilityState::ReadOnly.is_usable());
        assert!(CapabilityState::Unauthorized.is_advertised());
        assert!(CapabilityState::SchemaIncompatible.is_advertised());
        assert!(!CapabilityState::NotAdvertised.is_advertised());
        assert!(CapabilityState::NotAdvertised.is_compiled());
        assert!(!CapabilityState::NotCompiled.is_compiled());
        assert!(!CapabilityState::NotCompiled.is_advertised());
        assert!(!CapabilityState::TemporarilyUnavailable.is_usable());
        assert_eq!(
            "unknown".parse::<CapabilityState>(),
            Err(CapabilityStateParseError)
        );
    }

    #[test]
    fn observations_keep_capability_and_state_together() {
        let observation = EndpointCapabilityObservation::new(
            EndpointCapability::Managers,
            CapabilityState::ReadOnly,
        );

        assert_eq!(observation.capability(), EndpointCapability::Managers);
        assert_eq!(observation.state(), CapabilityState::ReadOnly);
    }
}
