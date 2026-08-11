use std::{error::Error, fmt, str::FromStr};

/// A Redfish capability tracked by the capability ledger.
///
/// Each variant maps to one public `nv-redfish` feature. The standard variants
/// are the complete §2.1 standard-feature inventory (30 entries) in
/// design-document order followed by the three capabilities nv-redfish 0.13.0
/// adds to the compiled standard surface (`ports`, `bmc-http`,
/// `update-service-deprecated`, §2.3); the OEM variants are the complete §2.1
/// OEM-feature inventory (14 entries) in the compiled-feature order of
/// `COMPILED_OEM_FEATURES`, so the ledger can enumerate every capability the
/// product may compile. Persisted identity is the `as_str()` product code,
/// which is stable across milestones: the 0.1 codes ("session-service",
/// "systems", "chassis", "managers") keep their values even where the upstream
/// feature has since been renamed (see `Systems`), while every OEM code equals
/// its `nv-redfish` feature name because the feature set is the contract the
/// 0.8.0 baseline freezes (§2.3).
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
    /// The `ports` standard feature, the 30th member of the `std-redfish`
    /// capability group that nv-redfish 0.13.0 adds (the 0.12.1 baseline
    /// compiled only 29). The §3.1 `PCIe 与网络` mapping presents it under the
    /// Network page: `nv-redfish` navigates the typed `Port` surface from the
    /// decoded `NetworkAdapter` member, so the §11.3 advertised layer observes
    /// the adapter's `Ports` link.
    Ports,
    /// The `bmc-http` transport feature (§3.1 服务与连接). It is the HTTP
    /// `Bmc` implementation every gateway connection runs on, so it is
    /// `Infrastructure`: a transport capability that backs product operations
    /// instead of presenting data, presented outside the endpoint data pages
    /// like `SessionService`.
    BmcHttp,
    /// The deprecated `HttpPushUri` raw-binary upload surface
    /// (`update-service-deprecated`). nv-redfish 0.13 keeps it as a
    /// legacy-compatibility feature (§0.4.0 上游保留的 Legacy Update 兼容), and
    /// infra-redfish compiles it for the §14.3 update path, so the ledger
    /// records it as `LegacyCompatibility` under the Update page.
    UpdateServiceDeprecated,
    /// The §2.1 AMI OEM feature (`oem-ami`). Its advertisement is the `Ami`
    /// namespace key in the `Oem` segment of a decoded resource; the
    /// per-resource extension surfaces (Service Root, `ConfigBMC`) are read
    /// from that namespace in the read slice.
    OemAmi,
    /// The §2.1 Dell OEM feature (`oem-dell`). Its advertisement is the
    /// `Dell` namespace key in the `Oem` segment of a decoded resource.
    OemDell,
    /// The §2.1 Dell Attributes OEM feature (`oem-dell-attributes`). It
    /// compiles as a feature superset of `oem-dell` and reads the `Attributes`
    /// resource inside the same `Dell` namespace, so this slice observes the
    /// namespace advertisement only; the `Attributes` resource itself is read
    /// in the read slice.
    OemDellAttributes,
    /// The §2.1 Delta OEM feature (`oem-delta`). Its advertisement is the
    /// `deltaenergysystems` namespace key in the `Oem` segment of a decoded
    /// resource (the key used by `nv-redfish` itself for Delta power
    /// supplies).
    OemDelta,
    /// The §2.1 HPE OEM feature (`oem-hpe`). Its advertisement is the `Hpe`
    /// namespace key in the `Oem` segment of a decoded resource.
    OemHpe,
    /// The §2.1 Lenovo OEM feature (`oem-lenovo`). Its advertisement is the
    /// `Lenovo` namespace key in the `Oem` segment of a decoded resource.
    OemLenovo,
    /// The §2.1 `LiteOn` OEM feature (`oem-liteon`). Unlike every other vendor
    /// feature it is not advertised by an `Oem` namespace key: `nv-redfish`
    /// 0.13 gates `LiteOn` support on the chassis `Manufacturer` hardware-id
    /// value "LITE-ON TECHNOLOGY CORP.", and the probe mirrors that exact
    /// signal (§11.3 advertised through decoded resources).
    OemLiteOn,
    /// The §2.1 NVIDIA OEM feature (`oem-nvidia`). Its advertisement is the
    /// `Nvidia` namespace key in the `Oem` segment of a decoded resource.
    OemNvidia,
    /// The §2.1 NVIDIA CPER OEM feature (`oem-nvidia-cper`). It compiles as a
    /// feature superset of `oem-nvidia` and reads CPER records inside the same
    /// `Nvidia` namespace, so this slice observes the namespace advertisement
    /// only; CPER record presence is verified in the read slice.
    OemNvidiaCper,
    /// The §2.1 NVIDIA Fabrics OEM feature (`oem-nvidia-fabrics`). It compiles
    /// as a feature superset of `oem-nvidia` and reads fabric data inside the
    /// same `Nvidia` namespace, so this slice observes the namespace
    /// advertisement only; fabric surface presence is verified in the read
    /// slice.
    OemNvidiaFabrics,
    /// The §2.1 NVIDIA Power Management OEM feature
    /// (`oem-nvidia-power-management`). It compiles as a feature superset of
    /// `oem-nvidia` and reads power-management data inside the same `Nvidia`
    /// namespace, so this slice observes the namespace advertisement only;
    /// power-management surface presence is verified in the read slice.
    OemNvidiaPowerManagement,
    /// The §2.1 NVIDIA Profiles OEM feature (`oem-nvidia-profiles`). It
    /// compiles as a feature superset of `oem-nvidia` and reads profile data
    /// inside the same `Nvidia` namespace, so this slice observes the
    /// namespace advertisement only; profile surface presence is verified in
    /// the read slice.
    OemNvidiaProfiles,
    /// The §2.1 NVIDIA Security OEM feature (`oem-nvidia-security`). It
    /// compiles as a feature superset of `oem-nvidia` and reads security data
    /// inside the same `Nvidia` namespace, so this slice observes the
    /// namespace advertisement only; security surface presence is verified in
    /// the read slice.
    OemNvidiaSecurity,
    /// The §2.1 Supermicro OEM feature (`oem-supermicro`). Its advertisement
    /// is the `Supermicro` namespace key in the `Oem` segment of a decoded
    /// resource.
    OemSupermicro,
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
            Self::Ports => "ports",
            Self::BmcHttp => "bmc-http",
            Self::UpdateServiceDeprecated => "update-service-deprecated",
            Self::OemAmi => "oem-ami",
            Self::OemDell => "oem-dell",
            Self::OemDellAttributes => "oem-dell-attributes",
            Self::OemDelta => "oem-delta",
            Self::OemHpe => "oem-hpe",
            Self::OemLenovo => "oem-lenovo",
            Self::OemLiteOn => "oem-liteon",
            Self::OemNvidia => "oem-nvidia",
            Self::OemNvidiaCper => "oem-nvidia-cper",
            Self::OemNvidiaFabrics => "oem-nvidia-fabrics",
            Self::OemNvidiaPowerManagement => "oem-nvidia-power-management",
            Self::OemNvidiaProfiles => "oem-nvidia-profiles",
            Self::OemNvidiaSecurity => "oem-nvidia-security",
            Self::OemSupermicro => "oem-supermicro",
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
            Self::Ports => "ports",
            Self::BmcHttp => "bmc-http",
            Self::UpdateServiceDeprecated => "update-service-deprecated",
            // OEM product codes are the upstream feature names: the compiled
            // feature set is the contract the 0.8.0 baseline freezes (§2.3),
            // so there is no legacy code to preserve and both inventories must
            // address the same wire surface.
            Self::OemAmi => "oem-ami",
            Self::OemDell => "oem-dell",
            Self::OemDellAttributes => "oem-dell-attributes",
            Self::OemDelta => "oem-delta",
            Self::OemHpe => "oem-hpe",
            Self::OemLenovo => "oem-lenovo",
            Self::OemLiteOn => "oem-liteon",
            Self::OemNvidia => "oem-nvidia",
            Self::OemNvidiaCper => "oem-nvidia-cper",
            Self::OemNvidiaFabrics => "oem-nvidia-fabrics",
            Self::OemNvidiaPowerManagement => "oem-nvidia-power-management",
            Self::OemNvidiaProfiles => "oem-nvidia-profiles",
            Self::OemNvidiaSecurity => "oem-nvidia-security",
            Self::OemSupermicro => "oem-supermicro",
        }
    }

    /// Returns the capability-ledger classification required by the product
    /// design §2.4.
    ///
    /// Session and Task services back product operations instead of presenting
    /// data, so they are Infrastructure. Every remaining standard feature maps
    /// to a viewable or operable surface (§12.2) and is `UserFacing` —
    /// including `UpdateService`, whose `SoftwareInventory` and update
    /// operations are operator-visible rather than internal plumbing. Every
    /// OEM capability is `UserFacing` too: the §12.2 Oem page presents the
    /// vendor-namespace data that the compiled feature decodes, and §11.5
    /// forbids private OEM access paths, so an OEM capability is either a
    /// presented surface or `UnsupportedByNvRedfishBaseline` (absent from the
    /// ledger entirely). `UpdateServiceDeprecated` is the first
    /// `LegacyCompatibility` entry: upstream keeps the raw `HttpPushUri`
    /// upload for legacy device compatibility (§0.4.0), and §14.3 compiles it
    /// for endpoints that advertise no multipart surface. No capability is
    /// classified as `Internal` in the 0.2 ledger.
    #[must_use]
    pub const fn classification(self) -> CapabilityClassification {
        match self {
            Self::SessionService | Self::TaskService | Self::BmcHttp => {
                CapabilityClassification::Infrastructure
            }
            Self::UpdateServiceDeprecated => CapabilityClassification::LegacyCompatibility,
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
            | Self::UpdateService
            | Self::Ports
            | Self::OemAmi
            | Self::OemDell
            | Self::OemDellAttributes
            | Self::OemDelta
            | Self::OemHpe
            | Self::OemLenovo
            | Self::OemLiteOn
            | Self::OemNvidia
            | Self::OemNvidiaCper
            | Self::OemNvidiaFabrics
            | Self::OemNvidiaPowerManagement
            | Self::OemNvidiaProfiles
            | Self::OemNvidiaSecurity
            | Self::OemSupermicro => CapabilityClassification::UserFacing,
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
    /// firmware, and network protocols per §3.1). The 0.13.0 additions follow
    /// the same mapping: `Ports` joins the Network page (`PCIe 与网络`),
    /// `BmcHttp` stays outside the data pages like `SessionService` (服务与连
    /// 接), and `UpdateServiceDeprecated` stays on the Update page that already
    /// presents the legacy upload surface.
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
            | Self::NetworkDeviceFunctions
            | Self::Ports => UiLocation::Network,
            Self::EventService => UiLocation::Events,
            Self::LogServices => UiLocation::Logs,
            Self::ManagerNetworkProtocol | Self::Managers => UiLocation::Managers,
            Self::Memory => UiLocation::Memory,
            Self::PcieDevices => UiLocation::Pcie,
            Self::Processors => UiLocation::Processors,
            Self::SecureBoot => UiLocation::SecureBoot,
            Self::SessionService | Self::BmcHttp => UiLocation::Infrastructure,
            Self::Storages => UiLocation::Storage,
            Self::TaskService => UiLocation::Tasks,
            Self::TelemetryService => UiLocation::Telemetry,
            Self::Thermal => UiLocation::Thermal,
            Self::UpdateService | Self::UpdateServiceDeprecated => UiLocation::Update,
            Self::Systems => UiLocation::Systems,
            // Every OEM capability is presented on the single §12.2 Oem page:
            // the page is vendor-driven (sections per present namespace), so
            // per-vendor pages would duplicate navigation for devices that
            // carry several vendor extensions.
            Self::OemAmi
            | Self::OemDell
            | Self::OemDellAttributes
            | Self::OemDelta
            | Self::OemHpe
            | Self::OemLenovo
            | Self::OemLiteOn
            | Self::OemNvidia
            | Self::OemNvidiaCper
            | Self::OemNvidiaFabrics
            | Self::OemNvidiaPowerManagement
            | Self::OemNvidiaProfiles
            | Self::OemNvidiaSecurity
            | Self::OemSupermicro => UiLocation::Oem,
        }
    }
}

/// The complete §2.1 capability inventory: the 33 standard features (the 30
/// §2.1 entries in design-document order followed by the three capabilities
/// nv-redfish 0.13.0 adds to the compiled standard surface: `ports`,
/// `bmc-http`, and `update-service-deprecated`) followed by the 14 OEM
/// features in the compiled feature order of [`OEM_CAPABILITY_LEDGER_ORDER`].
///
/// This is the canonical enumeration for every ledger projection: the Endpoint
/// capability page renders exactly these 47 entries, and an entry without a
/// persisted observation still appears so the UI can explain why the feature
/// is missing instead of hiding it. The order must stay aligned with §2.1 and
/// with the compiled OEM feature order, so queries, persistence round-trips,
/// and the capability page all enumerate the ledger identically.
pub const CAPABILITY_LEDGER_ORDER: [EndpointCapability; 47] = [
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
    EndpointCapability::Ports,
    EndpointCapability::BmcHttp,
    EndpointCapability::UpdateServiceDeprecated,
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

/// The complete §2.1 OEM-feature inventory in the compiled feature order.
///
/// This is the canonical enumeration for the OEM section of the capability
/// ledger and the one-to-one contract with the infra `COMPILED_OEM_FEATURES`
/// constant: `infra-redfish` asserts its compiled feature list equals exactly
/// these codes in exactly this order, so the domain ledger and the linked
/// binary cannot drift. The order mirrors the `nv-redfish` feature table
/// (`oem-ami`, `oem-dell`, `oem-dell-attributes`, `oem-delta`, `oem-hpe`,
/// `oem-lenovo`, `oem-liteon`, `oem-nvidia` and its five sub-features,
/// `oem-supermicro`), which is also the order the 0.8.0 baseline freezes
/// (§2.3).
pub const OEM_CAPABILITY_LEDGER_ORDER: [EndpointCapability; 14] = [
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
            "ports" => Ok(Self::Ports),
            "bmc-http" => Ok(Self::BmcHttp),
            "update-service-deprecated" => Ok(Self::UpdateServiceDeprecated),
            "oem-ami" => Ok(Self::OemAmi),
            "oem-dell" => Ok(Self::OemDell),
            "oem-dell-attributes" => Ok(Self::OemDellAttributes),
            "oem-delta" => Ok(Self::OemDelta),
            "oem-hpe" => Ok(Self::OemHpe),
            "oem-lenovo" => Ok(Self::OemLenovo),
            "oem-liteon" => Ok(Self::OemLiteOn),
            "oem-nvidia" => Ok(Self::OemNvidia),
            "oem-nvidia-cper" => Ok(Self::OemNvidiaCper),
            "oem-nvidia-fabrics" => Ok(Self::OemNvidiaFabrics),
            "oem-nvidia-power-management" => Ok(Self::OemNvidiaPowerManagement),
            "oem-nvidia-profiles" => Ok(Self::OemNvidiaProfiles),
            "oem-nvidia-security" => Ok(Self::OemNvidiaSecurity),
            "oem-supermicro" => Ok(Self::OemSupermicro),
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
    /// Vendor-proprietary surfaces; every §2.1 OEM capability maps here.
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
    use crate::resource_snapshot::{ResourceFeature, ResourceFeatureParseError};

    /// The standard-feature inventory: the §2.1 entries in design-document
    /// order followed by the three capabilities nv-redfish 0.13.0 adds to the
    /// compiled standard surface (`ports`, `bmc-http`,
    /// `update-service-deprecated`). The ledger must map exactly this set and
    /// nothing else.
    const STANDARD_FEATURES: [&str; 33] = [
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
        "ports",
        "bmc-http",
        "update-service-deprecated",
    ];

    /// The §2.1 OEM-feature inventory, in the compiled-feature order of the
    /// infra `COMPILED_OEM_FEATURES` constant. The OEM ledger must map exactly
    /// this set and nothing else; `infra-redfish` asserts the mirror image on
    /// its own constant.
    const OEM_FEATURES: [&str; 14] = [
        "oem-ami",
        "oem-dell",
        "oem-dell-attributes",
        "oem-delta",
        "oem-hpe",
        "oem-lenovo",
        "oem-liteon",
        "oem-nvidia",
        "oem-nvidia-cper",
        "oem-nvidia-fabrics",
        "oem-nvidia-power-management",
        "oem-nvidia-profiles",
        "oem-nvidia-security",
        "oem-supermicro",
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
        assert_eq!(CAPABILITY_LEDGER_ORDER.len(), 47);
        let mut upstream_features = Vec::new();
        for capability in CAPABILITY_LEDGER_ORDER {
            let feature = capability.upstream_feature();
            assert!(
                !feature.is_empty(),
                "{} must name a non-empty upstream feature",
                capability.as_str()
            );
            if OEM_CAPABILITY_LEDGER_ORDER.contains(&capability) {
                assert!(
                    OEM_FEATURES.contains(&feature),
                    "OEM upstream feature {feature} is not in the §2.1 OEM inventory"
                );
            } else {
                assert!(
                    STANDARD_FEATURES.contains(&feature),
                    "upstream feature {feature} is not in the §2.1 inventory"
                );
            }
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
    fn oem_ledger_covers_every_compiled_oem_feature_exactly_once() {
        let mut product_codes = Vec::new();
        for capability in OEM_CAPABILITY_LEDGER_ORDER {
            let feature = capability.upstream_feature();
            assert!(
                OEM_FEATURES.contains(&feature),
                "OEM upstream feature {feature} is not in the §2.1 OEM inventory"
            );
            // OEM product codes are the feature names: the compiled feature
            // set is the contract the 0.8.0 baseline freezes, so the domain
            // ledger and the linked binary must address the same wire string.
            assert_eq!(
                capability.as_str(),
                feature,
                "{} must keep its upstream feature name as its product code",
                capability.as_str()
            );
            assert!(
                !product_codes.contains(&capability.as_str()),
                "product code {} is used by more than one OEM capability",
                capability.as_str()
            );
            product_codes.push(capability.as_str());
        }
        for feature in OEM_FEATURES {
            assert!(
                OEM_CAPABILITY_LEDGER_ORDER
                    .iter()
                    .any(|capability| capability.upstream_feature() == feature),
                "§2.1 OEM feature {feature} has no capability variant"
            );
        }
        // The full ledger appends the OEM inventory after the 33 standard
        // entries, so every projection shares one canonical order: the
        // standard section keeps the §2.1 order (plus the 0.13.0 additions)
        // and the OEM section follows the compiled feature order.
        assert_eq!(
            &CAPABILITY_LEDGER_ORDER[33..],
            &OEM_CAPABILITY_LEDGER_ORDER[..]
        );
        for (capability, feature) in CAPABILITY_LEDGER_ORDER[..33].iter().zip(STANDARD_FEATURES) {
            assert_eq!(capability.upstream_feature(), feature);
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
                EndpointCapability::SessionService
                | EndpointCapability::TaskService
                | EndpointCapability::BmcHttp => CapabilityClassification::Infrastructure,
                EndpointCapability::UpdateServiceDeprecated => {
                    CapabilityClassification::LegacyCompatibility
                }
                _ => CapabilityClassification::UserFacing,
            };
            assert_eq!(capability.classification(), expected);
            assert!(
                !matches!(
                    capability.classification(),
                    CapabilityClassification::Internal
                ),
                "{} must not use the reserved Internal classification in the 0.2 ledger",
                capability.as_str()
            );
        }
        // §2.4 classifies every OEM capability as UserFacing: the §12.2 Oem
        // page presents the vendor-namespace data that the compiled feature
        // decodes, and §11.5 leaves no other legal handling for compiled OEM
        // data than presenting it through the upstream types.
        for capability in OEM_CAPABILITY_LEDGER_ORDER {
            assert_eq!(
                capability.classification(),
                CapabilityClassification::UserFacing,
                "{} must be UserFacing",
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
        assert_eq!(
            EndpointCapability::BmcHttp.ui_location(),
            UiLocation::Infrastructure
        );
        assert_eq!(EndpointCapability::Ports.ui_location(), UiLocation::Network);
        assert_eq!(
            EndpointCapability::UpdateServiceDeprecated.ui_location(),
            UiLocation::Update
        );
        // Every OEM capability lands on the single §12.2 Oem page.
        for capability in OEM_CAPABILITY_LEDGER_ORDER {
            assert_eq!(
                capability.ui_location(),
                UiLocation::Oem,
                "{} must be presented on the Oem page",
                capability.as_str()
            );
        }
    }

    #[test]
    fn oem_capability_codes_stay_distinct_from_resource_family_codes() {
        // The 0.5 slice adds the first OEM resource family (`OemDell`, the
        // Dell `Attributes` document read) under the narrower family code
        // `dell-attributes`. The remaining OEM surfaces (CPER, fabrics, power
        // management, profiles, security, and the other vendor pages) arrive
        // with the read slice. Either way, no OEM capability code may parse
        // as a `ResourceFeature`: families address the read surface under
        // surface codes, so the two inventories cannot silently drift into
        // aliasing each other. A new OEM family must extend this assertion's
        // exclusion list if it ever needs a code from the capability space.
        for capability in OEM_CAPABILITY_LEDGER_ORDER {
            assert_eq!(
                capability.as_str().parse::<ResourceFeature>(),
                Err(ResourceFeatureParseError),
                "{} must not be addressable as a resource family code",
                capability.as_str()
            );
        }
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
