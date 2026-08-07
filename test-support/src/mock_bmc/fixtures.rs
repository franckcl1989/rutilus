//! Static Redfish JSON documents of the Mock BMC fixture tree.
//!
//! Every document mirrors the shapes `rutilus-infra-redfish`'s own tests
//! already decode with `nv-redfish` 0.13 (same `@odata.type` versions, same
//! field sets, same enum spellings), so the mock cannot drift from what the
//! product actually parses. The tree is deliberately small: one System with
//! two Processors, one Memory module, one Bios singleton, one Boot Option,
//! one Secure Boot singleton, and one `PCIeDevice`; one Chassis with one
//! Power and one Thermal singleton plus one Sensor and one Control member
//! and one `Assembly` document with a single assembly member; one Manager
//! with its `LogServices`, `NetworkProtocol`, and `HostInterfaces` surface;
//! the `SessionService`; one `AccountService` with a single account; one
//! `UpdateService` with a single software-inventory member; and the three
//! root services behind the 0.2 event, telemetry, and task families
//! (`EventService` with one subscription, `TelemetryService` with one metric
//! definition and one metric report, and `TaskService` with one task). Links
//! the tree does not serve are omitted entirely, so the capability probe
//! reports `NotAdvertised` for them instead of guessing paths.
//!
//! Vendor profiles (0.5.0) pick among the documents at the profile level:
//! the default [`super::profile::MockProfile::Rutilus`] tree is exactly the
//! const set below, while the Dell profile swaps the Service Root identity
//! strings ([`SERVICE_ROOT_DELL`]), adds the `Oem.Dell` segment to the
//! manager document ([`MANAGER_DELL`]), and serves the §11.5
//! `DellAttributes` document ([`DELL_ATTRIBUTES`]); the NVIDIA profile swaps
//! the Service Root identity strings ([`SERVICE_ROOT_NVIDIA`]), adds the
//! `Oem.Nvidia` segment to the System document ([`SYSTEM_NVIDIA`]) and to
//! the manager document ([`MANAGER_NVIDIA`]), and serves the §11.5
//! system-config-profile chain ([`NVIDIA_SYSTEM_CONFIG_PROFILE`],
//! [`NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS`], [`NVIDIA_PROFILES_COLLECTION`],
//! [`NVIDIA_SYSTEM_PROFILE_1`], and [`NVIDIA_SYSTEM_PROFILE_FILE_1`]) plus
//! the manager-scoped power-compliance and managed-entity chains
//! ([`NVIDIA_POWER_COMPLIANCE`] and its sub-documents); everything else is
//! shared. [`service_root`], [`manager`], and [`system`] select the
//! profile-specific documents, and the route table gates the vendor routes
//! on the profile, so no vendor surface can leak into another profile.

use super::profile::MockProfile;

/// `GET /redfish/v1` -- the Service Root.
///
/// The core navigation links and the 0.2 root services behind the
/// `software-inventory`, `event-service`, `telemetry-service`, and
/// `task-service` read surfaces are advertised; the remaining root services
/// (`PowerEquipment`, `UpdateService` operations, and friends) stay absent
/// so the probe reports them as `NotAdvertised`.
pub(crate) const SERVICE_ROOT: &str = r##"{
    "@odata.id":"/redfish/v1/",
    "@odata.type":"#ServiceRoot.v1_16_0.ServiceRoot",
    "@odata.etag":"W/\"root-1\"",
    "Id":"RootService",
    "Name":"Root Service",
    "RedfishVersion":"1.20.0",
    "Vendor":"Rutilus Test",
    "Product":"Mock BMC",
    "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
    "SessionService":{"@odata.id":"/redfish/v1/SessionService"},
    "Systems":{"@odata.id":"/redfish/v1/Systems"},
    "Chassis":{"@odata.id":"/redfish/v1/Chassis"},
    "Managers":{"@odata.id":"/redfish/v1/Managers"},
    "AccountService":{"@odata.id":"/redfish/v1/AccountService"},
    "UpdateService":{"@odata.id":"/redfish/v1/UpdateService"},
    "EventService":{"@odata.id":"/redfish/v1/EventService"},
    "TelemetryService":{"@odata.id":"/redfish/v1/TelemetryService"},
    "Tasks":{"@odata.id":"/redfish/v1/TaskService"}
}"##;

/// `GET /redfish/v1` -- the Service Root of the Dell vendor profile.
///
/// Only the identity strings differ from the default profile: a real Dell
/// iDRAC identifies itself as Vendor "Dell Inc." and carries the `PowerEdge`
/// model as the product. The navigation surface is byte-identical to
/// [`SERVICE_ROOT`], and no `Oem` segment is served here because the Dell
/// namespace lives on the manager document, exactly where `nv-redfish` 0.13
/// and the gateway's probe look for it.
pub(crate) const SERVICE_ROOT_DELL: &str = r##"{
    "@odata.id":"/redfish/v1/",
    "@odata.type":"#ServiceRoot.v1_16_0.ServiceRoot",
    "@odata.etag":"W/\"root-1\"",
    "Id":"RootService",
    "Name":"Root Service",
    "RedfishVersion":"1.20.0",
    "Vendor":"Dell Inc.",
    "Product":"PowerEdge R750",
    "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
    "SessionService":{"@odata.id":"/redfish/v1/SessionService"},
    "Systems":{"@odata.id":"/redfish/v1/Systems"},
    "Chassis":{"@odata.id":"/redfish/v1/Chassis"},
    "Managers":{"@odata.id":"/redfish/v1/Managers"},
    "AccountService":{"@odata.id":"/redfish/v1/AccountService"},
    "UpdateService":{"@odata.id":"/redfish/v1/UpdateService"},
    "EventService":{"@odata.id":"/redfish/v1/EventService"},
    "TelemetryService":{"@odata.id":"/redfish/v1/TelemetryService"},
    "Tasks":{"@odata.id":"/redfish/v1/TaskService"}
}"##;

/// `GET /redfish/v1/SessionService` -- the session service, enabled so the
/// gateway prefers the Session transport over Basic.
pub(crate) const SESSION_SERVICE: &str = r#"{
    "@odata.id":"/redfish/v1/SessionService",
    "Id":"SessionService",
    "Name":"Session Service",
    "ServiceEnabled":true,
    "Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}
}"#;

/// `GET /redfish/v1/AccountService` -- the account service, advertising the
/// 0.2 `accounts` family through its `Accounts` collection link. The
/// document mirrors the probe fixture shape `rutilus-infra-redfish` already
/// decodes (no `@odata.type` is served because the type is known from the
/// Service Root navigation).
pub(crate) const ACCOUNT_SERVICE: &str = r#"{
    "@odata.id":"/redfish/v1/AccountService",
    "Id":"AccountService",
    "Name":"Account Service",
    "Accounts":{"@odata.id":"/redfish/v1/AccountService/Accounts"}
}"#;

/// `GET /redfish/v1/AccountService/Accounts` -- the manager account
/// collection with the single built-in account member.
pub(crate) const ACCOUNTS_COLLECTION: &str = r##"{
    "@odata.type":"#ManagerAccountCollection.ManagerAccountCollection",
    "@odata.id":"/redfish/v1/AccountService/Accounts",
    "Name":"Account Collection",
    "Members":[{"@odata.id":"/redfish/v1/AccountService/Accounts/admin"}]
}"##;

/// `GET /redfish/v1/AccountService/Accounts/admin` -- the built-in
/// administrator account. `AccountTypes` is `Redfish.Required` in the
/// schema and must stay present to decode, matching the full member shape
/// `rutilus-infra-redfish` projects in its own tests.
pub(crate) const ACCOUNT_ADMIN: &str = r##"{
    "@odata.type":"#ManagerAccount.v1_12_0.ManagerAccount",
    "@odata.id":"/redfish/v1/AccountService/Accounts/admin",
    "@odata.etag":"W/\"account-1\"",
    "Id":"admin",
    "Name":"Administrator Account",
    "Description":"Built-in administrator account",
    "UserName":"admin",
    "RoleId":"Administrator",
    "Enabled":true,
    "Locked":false,
    "AccountTypes":["Redfish","IPMI"]
}"##;

/// `GET /redfish/v1/Systems` -- the computer system collection.
pub(crate) const SYSTEMS_COLLECTION: &str = r##"{
    "@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",
    "@odata.id":"/redfish/v1/Systems",
    "Name":"Computer System Collection",
    "Members":[{"@odata.id":"/redfish/v1/Systems/1"}]
}"##;

/// `GET /redfish/v1/Systems/1/Bios` -- the BIOS configuration singleton.
///
/// The full `Attributes` bag is served (the schema decodes it) but stays
/// outside the typed snapshot contract, exactly like the
/// `rutilus-infra-redfish` fixture the product's decoder already accepts.
pub(crate) const BIOS: &str = r##"{
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

/// `GET /redfish/v1/Systems/1/BootOptions` -- the boot option collection
/// with the single PXE member.
pub(crate) const BOOT_OPTIONS_COLLECTION: &str = r##"{
    "@odata.type":"#BootOptionCollection.BootOptionCollection",
    "@odata.id":"/redfish/v1/Systems/1/BootOptions",
    "Name":"Boot Option Collection",
    "Members":[{"@odata.id":"/redfish/v1/Systems/1/BootOptions/PXE-1"}]
}"##;

/// `GET /redfish/v1/Systems/1/BootOptions/PXE-1` -- the PXE boot option with
/// every optional contract field populated, mirroring the full member shape
/// `rutilus-infra-redfish` projects in its own tests.
pub(crate) const BOOT_OPTION_PXE1: &str = r##"{
    "@odata.type":"#BootOption.v1_1_0.BootOption",
    "@odata.id":"/redfish/v1/Systems/1/BootOptions/PXE-1",
    "@odata.etag":"W/\"boot-option-1\"",
    "Id":"PXE-1",
    "Name":"Network Boot Option",
    "Description":"PXE boot option",
    "BootOptionReference":"Boot0001",
    "DisplayName":"PXE Network Boot",
    "BootOptionEnabled":true,
    "UefiDevicePath":"PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)",
    "Alias":"Pxe"
}"##;

/// `GET /redfish/v1/Systems/1/SecureBoot` -- the Secure Boot configuration
/// singleton with every optional contract field populated, matching the
/// full shape `rutilus-infra-redfish` projects in its own tests.
pub(crate) const SECURE_BOOT: &str = r##"{
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

/// `GET /redfish/v1/Systems/1` -- the compute system, advertising the 0.2
/// Bios, `BootOptions`, `SecureBoot`, `Processors`, `Memory`, and
/// `PcieDevices` families through typed navigation links. `PCIeDevices` is
/// an in-document array of typed links (the presence-type shape the
/// `ComputerSystem` schema uses instead of a collection resource), exactly
/// like the `rutilus-infra-redfish` fixture the product's decoder accepts.
pub(crate) const SYSTEM: &str = r#"{
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "Bios":{"@odata.id":"/redfish/v1/Systems/1/Bios"},
    "Boot":{"BootOptions":{"@odata.id":"/redfish/v1/Systems/1/BootOptions"}},
    "SecureBoot":{"@odata.id":"/redfish/v1/Systems/1/SecureBoot"},
    "Processors":{"@odata.id":"/redfish/v1/Systems/1/Processors"},
    "Memory":{"@odata.id":"/redfish/v1/Systems/1/Memory"},
    "PCIeDevices":[
        {"@odata.id":"/redfish/v1/Systems/1/PCIeDevices/GPU1"}
    ]
}"#;

/// `GET /redfish/v1/Systems/1` -- the compute system of the NVIDIA vendor
/// profile.
///
/// Exactly the default system surface plus the `Oem.Nvidia` segment that
/// advertises the NVIDIA OEM namespace and carries the inline
/// `NvidiaComputerSystem` object with the `SystemConfigProfile` navigation:
/// the capability probe decides the `oem-nvidia*` capabilities from the
/// decoded `Oem` keys (§11.3 advertised layer) and the gateway's §11.5
/// system-config-profile read gates on the discriminated `NvidiaComputerSystem`
/// segment, so this one addition switches both layers on.
pub(crate) const SYSTEM_NVIDIA: &str = r##"{
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "Bios":{"@odata.id":"/redfish/v1/Systems/1/Bios"},
    "Boot":{"BootOptions":{"@odata.id":"/redfish/v1/Systems/1/BootOptions"}},
    "SecureBoot":{"@odata.id":"/redfish/v1/Systems/1/SecureBoot"},
    "Processors":{"@odata.id":"/redfish/v1/Systems/1/Processors"},
    "Memory":{"@odata.id":"/redfish/v1/Systems/1/Memory"},
    "PCIeDevices":[
        {"@odata.id":"/redfish/v1/Systems/1/PCIeDevices/GPU1"}
    ],
    "Oem":{"Nvidia":{
        "@odata.type":"#NvidiaComputerSystem.v1_0_0.NvidiaComputerSystem",
        "SystemConfigProfile":{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"}
    }}
}"##;

/// `GET /redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile` -- the §11.5
/// NVIDIA system-config-profile chain root of the NVIDIA vendor profile.
///
/// The document mirrors the fixture `rutilus-infra-redfish` decodes in its
/// own NVIDIA tests (the typed base fields, the `Truststore` certificate-store
/// links whose documents the product never fetches, and the `Status` /
/// `Profiles` navigations), so the gateway's typed navigation into the
/// compiled `NvidiaSystemConfigProfile` schema succeeds against the mock.
pub(crate) const NVIDIA_SYSTEM_CONFIG_PROFILE: &str = r#"{
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

/// `GET /redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status` -- the
/// profile service status singleton of the NVIDIA vendor profile.
pub(crate) const NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS: &str = r#"{
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

/// `GET /redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles` -- the
/// profile collection of the NVIDIA vendor profile with the single member.
pub(crate) const NVIDIA_PROFILES_COLLECTION: &str = r##"{
    "@odata.type":"#NvidiaSystemProfileCollection.NvidiaSystemProfileCollection",
    "@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles",
    "Id":"Profiles",
    "Name":"System Profile Collection",
    "Members":[{"@odata.id":"/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"}]
}"##;

/// `GET /redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1` --
/// the default profile member of the NVIDIA vendor profile.
pub(crate) const NVIDIA_SYSTEM_PROFILE_1: &str = r#"{
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

/// `GET /redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile`
/// -- the profile file document of the NVIDIA vendor profile, carrying the
/// `Metadata` section and the base64 `Profile` content.
pub(crate) const NVIDIA_SYSTEM_PROFILE_FILE_1: &str = r#"{
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

/// `GET /redfish/v1/Systems/1/Processors` -- the processor collection.
pub(crate) const PROCESSORS_COLLECTION: &str = r##"{
    "@odata.type":"#ProcessorCollection.ProcessorCollection",
    "@odata.id":"/redfish/v1/Systems/1/Processors",
    "Name":"Processor Collection",
    "Members":[
        {"@odata.id":"/redfish/v1/Systems/1/Processors/CPU1"},
        {"@odata.id":"/redfish/v1/Systems/1/Processors/CPU2"}
    ]
}"##;

/// `GET /redfish/v1/Systems/1/Processors/CPU1` -- the primary processor.
pub(crate) const PROCESSOR_CPU1: &str = r##"{
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

/// `GET /redfish/v1/Systems/1/Processors/CPU2` -- the second processor.
pub(crate) const PROCESSOR_CPU2: &str = r##"{
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

/// `GET /redfish/v1/Systems/1/Memory` -- the memory module collection.
pub(crate) const MEMORY_COLLECTION: &str = r##"{
    "@odata.type":"#MemoryCollection.MemoryCollection",
    "@odata.id":"/redfish/v1/Systems/1/Memory",
    "Name":"Memory Collection",
    "Members":[{"@odata.id":"/redfish/v1/Systems/1/Memory/DIMM1"}]
}"##;

/// `GET /redfish/v1/Systems/1/Memory/DIMM1` -- the main memory module.
pub(crate) const MEMORY_DIMM1: &str = r##"{
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

/// `GET /redfish/v1/Chassis` -- the chassis collection.
pub(crate) const CHASSIS_COLLECTION: &str = r##"{
    "@odata.type":"#ChassisCollection.ChassisCollection",
    "@odata.id":"/redfish/v1/Chassis",
    "Name":"Chassis Collection",
    "Members":[{"@odata.id":"/redfish/v1/Chassis/1"}]
}"##;

/// `GET /redfish/v1/Chassis/1` -- the rack chassis, advertising the 0.2
/// telemetry and assembly families through typed navigation links. The
/// `Power` and `Thermal` singletons plus the `Sensors` and `Controls`
/// collections and the `Assembly` document are served so the capability
/// probe reports them `Supported` and the typed resource read carries their
/// readings; links the tree does not serve (`NetworkAdapters`,
/// `PowerSubsystem`, ...) stay absent so the probe reports those features as
/// `NotAdvertised`.
pub(crate) const CHASSIS: &str = r#"{
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "Power":{"@odata.id":"/redfish/v1/Chassis/1/Power"},
    "Thermal":{"@odata.id":"/redfish/v1/Chassis/1/Thermal"},
    "Sensors":{"@odata.id":"/redfish/v1/Chassis/1/Sensors"},
    "Controls":{"@odata.id":"/redfish/v1/Chassis/1/Controls"},
    "Assembly":{"@odata.id":"/redfish/v1/Chassis/1/Assembly"}
}"#;

/// `GET /redfish/v1/Chassis/1/Power` -- the chassis power control singleton.
///
/// The single `PowerControl` entry carries realistic consumed and capacity
/// readings so the document decodes like a real BMC; the typed `power`
/// family deliberately projects no details (the nested reading arrays stay
/// out of the strictly projectable field set), matching the member shape
/// `rutilus-infra-redfish` decodes in its own tests.
pub(crate) const POWER: &str = r##"{
    "@odata.type":"#Power.v1_17_0.Power",
    "@odata.id":"/redfish/v1/Chassis/1/Power",
    "@odata.etag":"W/\"power-1\"",
    "Id":"Power",
    "Name":"Power",
    "Description":"Chassis power control",
    "PowerControl":[
        {
            "@odata.id":"/redfish/v1/Chassis/1/Power#/PowerControl/0",
            "MemberId":"0",
            "Name":"Chassis Power Control",
            "PowerConsumedWatts":320.0,
            "PowerRequestedWatts":360.0,
            "PowerCapacityWatts":800.0,
            "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
        }
    ]
}"##;

/// `GET /redfish/v1/Chassis/1/Thermal` -- the chassis thermal singleton.
///
/// The single `Temperatures` entry carries a realistic inlet temperature
/// reading so the document decodes like a real BMC; the typed `thermal`
/// family projects only the resource-level `Status` (the nested temperature
/// array stays out of the strictly projectable field set), matching the
/// member shape `rutilus-infra-redfish` decodes in its own tests.
pub(crate) const THERMAL: &str = r##"{
    "@odata.type":"#Thermal.v1_7_2.Thermal",
    "@odata.id":"/redfish/v1/Chassis/1/Thermal",
    "@odata.etag":"W/\"thermal-1\"",
    "Id":"Thermal",
    "Name":"Thermal",
    "Description":"Chassis temperature and fan monitoring",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "Temperatures":[
        {
            "@odata.id":"/redfish/v1/Chassis/1/Thermal#/Temperatures/0",
            "MemberId":"0",
            "Name":"Chassis Inlet Temperature",
            "ReadingCelsius":27.5,
            "UpperThresholdCritical":45.0,
            "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
        }
    ]
}"##;

/// `GET /redfish/v1/Chassis/1/Sensors` -- the sensor collection with the
/// single inlet-temperature sensor member.
pub(crate) const SENSORS_COLLECTION: &str = r##"{
    "@odata.type":"#SensorCollection.SensorCollection",
    "@odata.id":"/redfish/v1/Chassis/1/Sensors",
    "Name":"Sensor Collection",
    "Members":[{"@odata.id":"/redfish/v1/Chassis/1/Sensors/InletTemp"}]
}"##;

/// `GET /redfish/v1/Chassis/1/Sensors/InletTemp` -- the inlet temperature
/// sensor with every optional contract field populated, matching the full
/// member shape `rutilus-infra-redfish` projects in its own tests.
pub(crate) const SENSOR_INLET_TEMP: &str = r##"{
    "@odata.type":"#Sensor.v1_9_0.Sensor",
    "@odata.id":"/redfish/v1/Chassis/1/Sensors/InletTemp",
    "@odata.etag":"W/\"sensor-inlet-1\"",
    "Id":"InletTemp",
    "Name":"Chassis Inlet Temperature",
    "Description":"Temperature of air entering the chassis",
    "ReadingType":"Temperature",
    "Reading":27.5,
    "ReadingUnits":"Cel",
    "PhysicalContext":"Intake",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
}"##;

/// `GET /redfish/v1/Chassis/1/Controls` -- the control collection with the
/// single fan-duty-cycle control member.
pub(crate) const CONTROLS_COLLECTION: &str = r##"{
    "@odata.type":"#ControlCollection.ControlCollection",
    "@odata.id":"/redfish/v1/Chassis/1/Controls",
    "Name":"Control Collection",
    "Members":[{"@odata.id":"/redfish/v1/Chassis/1/Controls/FanDuty"}]
}"##;

/// `GET /redfish/v1/Chassis/1/Controls/FanDuty` -- the fan duty-cycle control
/// with every optional contract field populated, matching the full member
/// shape `rutilus-infra-redfish` projects in its own tests.
pub(crate) const CONTROL_FAN_DUTY: &str = r##"{
    "@odata.type":"#Control.v1_3_0.Control",
    "@odata.id":"/redfish/v1/Chassis/1/Controls/FanDuty",
    "@odata.etag":"W/\"control-fan-1\"",
    "Id":"FanDuty",
    "Name":"Chassis Fan Duty",
    "Description":"Fan duty-cycle control for the chassis fans",
    "ControlType":"DutyCycle",
    "SetPointType":"Single",
    "ControlMode":"Automatic",
    "SetPoint":30.0,
    "SetPointUnits":"Percent",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
}"##;

/// `GET /redfish/v1/Managers` -- the manager collection.
pub(crate) const MANAGERS_COLLECTION: &str = r##"{
    "@odata.type":"#ManagerCollection.ManagerCollection",
    "@odata.id":"/redfish/v1/Managers",
    "Name":"Manager Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1"}]
}"##;

/// `GET /redfish/v1/Managers/1` -- the BMC manager.
///
/// The 0.2 manager surface (`LogServices`, `NetworkProtocol`,
/// `HostInterfaces`) is advertised through typed navigation links; the
/// `EthernetInterfaces` link stays absent on purpose, so the probe observes
/// that feature as `NotAdvertised` rather than following a guessed path.
pub(crate) const MANAGER: &str = r#"{
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "HostInterfaces":{"@odata.id":"/redfish/v1/Managers/1/HostInterfaces"},
    "NetworkProtocol":{"@odata.id":"/redfish/v1/Managers/1/NetworkProtocol"},
    "LogServices":{"@odata.id":"/redfish/v1/Managers/1/LogServices"}
}"#;

/// `GET /redfish/v1/Managers/1` -- the BMC manager of the Dell vendor
/// profile.
///
/// Exactly the default manager surface plus the `Oem.Dell` segment that
/// advertises the Dell OEM namespace: the capability probe decides
/// `oem-dell` from the decoded `Oem` keys (§11.3 advertised layer) and the
/// gateway's §11.5 `DellAttributes` read gates on the literal `Dell` key, so
/// this one addition switches both layers on. The document mirrors the
/// `MANAGER_WITH_DELL_OEM_BODY` fixture `rutilus-infra-redfish` decodes in
/// its own Dell tests.
pub(crate) const MANAGER_DELL: &str = r#"{
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "HostInterfaces":{"@odata.id":"/redfish/v1/Managers/1/HostInterfaces"},
    "NetworkProtocol":{"@odata.id":"/redfish/v1/Managers/1/NetworkProtocol"},
    "LogServices":{"@odata.id":"/redfish/v1/Managers/1/LogServices"},
    "Oem":{"Dell":{}}
}"#;

/// `GET /redfish/v1/Managers/1/Oem/Dell/DellAttributes/1` -- the §11.5 Dell
/// `DellAttributes` document of the Dell vendor profile.
///
/// The document mirrors the `DELL_ATTRIBUTES_BODY` fixture
/// `rutilus-infra-redfish` decodes in its own Dell tests (the typed base
/// fields `Id`, `Name`, and `Description` plus the identity `Attributes`
/// bag), so the gateway's typed navigation into the compiled
/// `DellAttributes` schema succeeds against the mock. The five pinned
/// identity attributes match the upstream fixture values; the extra
/// `BiosVersion` bag entry exercises the unprojected-key path, exactly like
/// the infra fixture.
pub(crate) const DELL_ATTRIBUTES: &str = r#"{
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

/// `GET /redfish/v1/Managers/1` -- the BMC manager of the NVIDIA vendor
/// profile.
///
/// Exactly the default manager surface plus the `Oem.Nvidia` segment that
/// advertises the NVIDIA OEM namespace and carries the inline versioned
/// `NvidiaManager` object with the `PowerCompliance` navigation: the
/// capability probe decides the `oem-nvidia*` capabilities from the decoded
/// `Oem` keys (§11.3 advertised layer) and the gateway's §11.5
/// power-compliance and managed-entity reads gate on the discriminated
/// `NvidiaManager.v1_9_0` segment, so this one addition switches both layers
/// on for the manager surface.
pub(crate) const MANAGER_NVIDIA: &str = r##"{
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "HostInterfaces":{"@odata.id":"/redfish/v1/Managers/1/HostInterfaces"},
    "NetworkProtocol":{"@odata.id":"/redfish/v1/Managers/1/NetworkProtocol"},
    "LogServices":{"@odata.id":"/redfish/v1/Managers/1/LogServices"},
    "Oem":{"Nvidia":{
        "@odata.type":"#NvidiaManager.v1_9_0.NvidiaManager",
        "PowerCompliance":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"}
    }}
}"##;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance` -- the §11.5
/// NVIDIA `NvidiaPowerComplianceManager` chain root of the NVIDIA vendor
/// profile, carrying every sub-navigation of the power-compliance family.
///
/// The document mirrors the fixture `rutilus-infra-redfish` decodes in its
/// own NVIDIA manager tests (the typed base fields, the `ManagerType`
/// enumeration, and the six sub-navigations), so the gateway's typed
/// navigation into the compiled `NvidiaPowerComplianceManager` schema
/// succeeds against the mock.
pub(crate) const NVIDIA_POWER_COMPLIANCE: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains` --
/// the power domain collection with the single member.
pub(crate) const NVIDIA_POWER_DOMAINS_COLLECTION: &str = r##"{
    "@odata.type":"#NvidiaPowerDomainCollection.NvidiaPowerDomainCollection",
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains",
    "Id":"PowerDomains",
    "Name":"Power Domain Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1` --
/// the power domain member with every compiled scalar field populated.
pub(crate) const NVIDIA_POWER_DOMAIN_1: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy` --
/// the AC loss power policy singleton.
pub(crate) const NVIDIA_POWER_AC_LOSS_POLICY: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy`
/// -- the PSU compliance power policy singleton.
pub(crate) const NVIDIA_POWER_PSU_COMPLIANCE_POLICY: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups`
/// -- the managed entity group collection with the single member.
pub(crate) const NVIDIA_MANAGED_ENTITY_GROUPS_COLLECTION: &str = r##"{
    "@odata.type":"#NvidiaManagedEntityGroupCollection.NvidiaManagedEntityGroupCollection",
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups",
    "Id":"ManagedEntityGroups",
    "Name":"Managed Entity Group Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1`
/// -- the managed entity group member with its `ManagedEntities` navigation.
pub(crate) const NVIDIA_MANAGED_ENTITY_GROUP_1: &str = r#"{
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
    "@odata.etag":"W/\"nvidia-group-1\"",
    "Id":"1",
    "Name":"Managed Entity Group One",
    "Description":"BlueField group",
    "CurrentManagedEntityId":"BF1",
    "ManagedEntities":{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities"}
}"#;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities`
/// -- the managed entity collection with the single member.
pub(crate) const NVIDIA_MANAGED_ENTITIES_COLLECTION: &str = r##"{
    "@odata.type":"#NvidiaManagedEntityCollection.NvidiaManagedEntityCollection",
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities",
    "Id":"ManagedEntities",
    "Name":"Managed Entity Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1`
/// -- the managed entity member with every compiled scalar field populated.
pub(crate) const NVIDIA_MANAGED_ENTITY_1: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup` --
/// the power state group document with its two state collections.
pub(crate) const NVIDIA_POWER_STATE_GROUP: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers`
/// -- the power shelf controller state collection with the single member.
pub(crate) const NVIDIA_PSC_STATES_COLLECTION: &str = r##"{
    "@odata.type":"#NvidiaPscStateCollection.NvidiaPscStateCollection",
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers",
    "Id":"PowerShelfControllers",
    "Name":"Power Shelf Controller Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1`
/// -- the PSC state member with every compiled scalar field populated.
pub(crate) const NVIDIA_PSC_STATE_1: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies`
/// -- the power supply state collection with the single member.
pub(crate) const NVIDIA_PSU_STATES_COLLECTION: &str = r##"{
    "@odata.type":"#NvidiaPsuStateCollection.NvidiaPsuStateCollection",
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies",
    "Id":"PowerSupplies",
    "Name":"Power Supply Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1`
/// -- the PSU state member with every compiled scalar field populated.
pub(crate) const NVIDIA_PSU_STATE_1: &str = r#"{
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

/// `GET /redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy` --
/// the PSU redundancy singleton with every compiled scalar field populated.
pub(crate) const NVIDIA_PSU_REDUNDANCY: &str = r#"{
    "@odata.id":"/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
    "@odata.etag":"W/\"nvidia-redundancy-1\"",
    "Id":"PSURedundancy",
    "Name":"PSU Redundancy",
    "Description":"PSU redundancy settings",
    "MaxNumSupported":"4",
    "MinNumNeeded":"2",
    "RedundancySetting":"NPlusOne"
}"#;

/// `GET /redfish/v1/Managers/1/LogServices` -- the log service collection
/// with the single event-log member.
pub(crate) const LOG_SERVICES_COLLECTION: &str = r##"{
    "@odata.type":"#LogServiceCollection.LogServiceCollection",
    "@odata.id":"/redfish/v1/Managers/1/LogServices",
    "Name":"Log Service Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/LogServices/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/LogServices/1` -- the manager event log, with
/// every optional contract field populated. The `Entries` navigation is
/// omitted, exactly like every other link the tree does not serve, because
/// the strictly projectable field set never fetches the entry collection.
pub(crate) const LOG_SERVICE: &str = r##"{
    "@odata.type":"#LogService.v1_9_0.LogService",
    "@odata.id":"/redfish/v1/Managers/1/LogServices/1",
    "@odata.etag":"W/\"log-service-1\"",
    "Id":"1",
    "Name":"BMC Event Log",
    "Description":"Manager event log",
    "ServiceEnabled":true,
    "MaxNumberOfRecords":1000,
    "OverWritePolicy":"WrapsWhenFull",
    "LogEntryType":"Event",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
}"##;

/// `GET /redfish/v1/Managers/1/NetworkProtocol` -- the manager network
/// protocol singleton with its `HostName` and `FQDN` metadata plus realistic
/// per-protocol sections, matching the shape `rutilus-infra-redfish` decodes
/// in its own tests.
pub(crate) const MANAGER_NETWORK_PROTOCOL: &str = r##"{
    "@odata.type":"#ManagerNetworkProtocol.v1_12_0.ManagerNetworkProtocol",
    "@odata.id":"/redfish/v1/Managers/1/NetworkProtocol",
    "@odata.etag":"W/\"network-protocol-1\"",
    "Id":"NetworkProtocol",
    "Name":"Manager Network Protocol",
    "Description":"Manager network protocol settings",
    "HostName":"bmc-1",
    "FQDN":"bmc-1.example.com",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "HTTP":{"ProtocolEnabled":true,"Port":80},
    "HTTPS":{"ProtocolEnabled":true,"Port":443},
    "SSH":{"ProtocolEnabled":false,"Port":22},
    "SSDP":{"ProtocolEnabled":false,"Port":1900}
}"##;

/// `GET /redfish/v1/Managers/1/HostInterfaces` -- the host interface
/// collection with the single member.
pub(crate) const HOST_INTERFACES_COLLECTION: &str = r##"{
    "@odata.type":"#HostInterfaceCollection.HostInterfaceCollection",
    "@odata.id":"/redfish/v1/Managers/1/HostInterfaces",
    "Name":"Host Interface Collection",
    "Members":[{"@odata.id":"/redfish/v1/Managers/1/HostInterfaces/1"}]
}"##;

/// `GET /redfish/v1/Managers/1/HostInterfaces/1` -- the manager host
/// interface with every optional contract field populated; the
/// `HostInterface_v1` schema declares no `HostName` property, so the member
/// carries its own direct interface properties only. The
/// `ManagerEthernetInterface` link is omitted, exactly like every other link
/// the tree does not serve.
pub(crate) const HOST_INTERFACE: &str = r##"{
    "@odata.type":"#HostInterface.v1_3_3.HostInterface",
    "@odata.id":"/redfish/v1/Managers/1/HostInterfaces/1",
    "@odata.etag":"W/\"host-interface-1\"",
    "Id":"1",
    "Name":"Host Interface One",
    "Description":"Manager host interface",
    "HostInterfaceType":"NetworkHostInterface",
    "InterfaceEnabled":true,
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
}"##;

/// `GET /redfish/v1/Systems/1/PCIeDevices/GPU1` -- the single `PCIeDevice`
/// linked from the computer system, with every optional contract field
/// populated; the firmware and identity fields are decoded by the schema but
/// stay outside the strictly projectable field set, exactly like the
/// `rutilus-infra-redfish` fixture the product's decoder accepts.
pub(crate) const PCIE_DEVICE_GPU1: &str = r##"{
    "@odata.type":"#PCIeDevice.v1_12_0.PCIeDevice",
    "@odata.id":"/redfish/v1/Systems/1/PCIeDevices/GPU1",
    "@odata.etag":"W/\"pcie-device-1\"",
    "Id":"GPU1",
    "Name":"PCIe Device One",
    "Description":"GPU accelerator",
    "DeviceType":"SingleFunction",
    "Manufacturer":"Rutilus Test",
    "Model":"PCIE-GEN4-X16",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "FirmwareVersion":"1.2.3",
    "SerialNumber":"PCI-SN-1",
    "SKU":"PCI-SKU-1"
}"##;

/// `GET /redfish/v1/Chassis/1/Assembly` -- the chassis assembly document,
/// embedding the `Assemblies` link array. The document itself is never
/// projected, only its members are, so its own shape stays minimal; the
/// member link keeps the fragment-style `@odata.id` the `AssemblyData`
/// referenceable-member schema uses.
pub(crate) const ASSEMBLY: &str = r##"{
    "@odata.type":"#Assembly.v1_5_0.Assembly",
    "@odata.id":"/redfish/v1/Chassis/1/Assembly",
    "@odata.etag":"W/\"assembly-1\"",
    "Id":"Assembly",
    "Name":"Chassis Assembly",
    "Assemblies":[
        {"@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/0"}
    ]
}"##;

/// `GET /redfish/v1/Chassis/1/Assembly#/Assemblies/0` -- the single
/// `AssemblyData` member, with every optional contract field populated; the
/// FRU identity fields (`Model`, `SerialNumber`, `Version`) are decoded by
/// the schema but stay outside the strictly projectable field set, exactly
/// like the `rutilus-infra-redfish` fixture the product's decoder accepts.
///
/// The gateway requests this member through its fragment-style `@odata.id`
/// literally, so the mock routes the exact path including the fragment.
pub(crate) const ASSEMBLY_FAN: &str = r##"{
    "@odata.type":"#Assembly.v1_5_0.AssemblyData",
    "@odata.id":"/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
    "@odata.etag":"W/\"assembly-data-0\"",
    "MemberId":"0",
    "Name":"Fan Assembly",
    "Description":"Cooling fan",
    "Producer":"Rutilus Test",
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"},
    "Model":"FRU-MODEL-X",
    "SerialNumber":"FRU-1",
    "Version":"1.0"
}"##;

/// `GET /redfish/v1/UpdateService` -- the firmware update service,
/// advertising the `SoftwareInventory` collection behind the 0.2
/// `software-inventory` family; the update-operation fields are decoded by
/// the schema but stay outside the strictly projectable field set.
pub(crate) const UPDATE_SERVICE: &str = r#"{
    "@odata.id":"/redfish/v1/UpdateService",
    "@odata.etag":"W/\"update-service-1\"",
    "Id":"UpdateService",
    "Name":"Update Service",
    "Description":"Firmware update service",
    "ServiceEnabled":true,
    "MaxImageSizeBytes":2147483648,
    "SoftwareInventory":{"@odata.id":"/redfish/v1/UpdateService/SoftwareInventory"}
}"#;

/// `GET /redfish/v1/UpdateService/SoftwareInventory` -- the software
/// inventory collection with the single BIOS member.
pub(crate) const SOFTWARE_INVENTORIES_COLLECTION: &str = r##"{
    "@odata.type":"#SoftwareInventoryCollection.SoftwareInventoryCollection",
    "@odata.id":"/redfish/v1/UpdateService/SoftwareInventory",
    "Name":"Software Inventory Collection",
    "Members":[{"@odata.id":"/redfish/v1/UpdateService/SoftwareInventory/BIOS"}]
}"##;

/// `GET /redfish/v1/UpdateService/SoftwareInventory/BIOS` -- the BIOS
/// software inventory member with every optional contract field populated;
/// the update-lifecycle fields (`Updateable`, `Manufacturer`,
/// `LowestSupportedVersion`) are decoded by the schema but stay outside the
/// strictly projectable field set, exactly like the `rutilus-infra-redfish`
/// fixture the product's decoder accepts.
pub(crate) const SOFTWARE_INVENTORY_BIOS: &str = r##"{
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
    "Manufacturer":"Rutilus Test",
    "LowestSupportedVersion":"2.0.0"
}"##;

/// `GET /redfish/v1/EventService` -- the root event service, advertising its
/// `Subscriptions` collection behind the 0.2 `event-subscription` family; the
/// event-delivery fields are decoded by the schema but stay outside the
/// strictly projectable field set, exactly like the
/// `rutilus-infra-redfish` fixture the product's decoder accepts.
pub(crate) const EVENT_SERVICE: &str = r##"{
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

/// `GET /redfish/v1/EventService/Subscriptions` -- the event destination
/// collection with the single webhook subscription member.
pub(crate) const EVENT_SUBSCRIPTIONS_COLLECTION: &str = r##"{
    "@odata.type":"#EventDestinationCollection.EventDestinationCollection",
    "@odata.id":"/redfish/v1/EventService/Subscriptions",
    "Name":"Event Subscription Collection",
    "Members":[{"@odata.id":"/redfish/v1/EventService/Subscriptions/1"}]
}"##;

/// `GET /redfish/v1/EventService/Subscriptions/1` -- the single webhook
/// subscription member with every optional contract field populated; the
/// delivery and filtering fields are decoded but stay outside the strictly
/// projectable field set, exactly like the `rutilus-infra-redfish` fixture
/// the product's decoder accepts.
pub(crate) const EVENT_SUBSCRIPTION_1: &str = r##"{
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

/// `GET /redfish/v1/TelemetryService` -- the root telemetry service,
/// advertising the `MetricDefinitions` and `MetricReports` collections
/// behind the 0.2 `metric-definition` and `metric-report` families. The
/// `ServiceEnabled` and capacity fields are decoded by the schema but stay
/// outside the strictly projectable field set: the product defers the
/// service-enabled posture and the service-capacity fields to the 0.4.0
/// telemetry iteration.
pub(crate) const TELEMETRY_SERVICE: &str = r##"{
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

/// `GET /redfish/v1/TelemetryService/MetricDefinitions` -- the metric
/// definition collection with the single power-consumption member.
pub(crate) const METRIC_DEFINITIONS_COLLECTION: &str = r##"{
    "@odata.type":"#MetricDefinitionCollection.MetricDefinitionCollection",
    "@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions",
    "Name":"Metric Definition Collection",
    "Members":[{"@odata.id":"/redfish/v1/TelemetryService/MetricDefinitions/1"}]
}"##;

/// `GET /redfish/v1/TelemetryService/MetricDefinitions/1` -- the power
/// consumption definition member with every optional contract field
/// populated; the measurement-semantics fields are decoded but stay outside
/// the strictly projectable field set, exactly like the
/// `rutilus-infra-redfish` fixture the product's decoder accepts.
pub(crate) const METRIC_DEFINITION_1: &str = r##"{
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

/// `GET /redfish/v1/TelemetryService/MetricReports` -- the metric report
/// collection with the single power-report member.
pub(crate) const METRIC_REPORTS_COLLECTION: &str = r##"{
    "@odata.type":"#MetricReportCollection.MetricReportCollection",
    "@odata.id":"/redfish/v1/TelemetryService/MetricReports",
    "Name":"Metric Report Collection",
    "Members":[{"@odata.id":"/redfish/v1/TelemetryService/MetricReports/1"}]
}"##;

/// `GET /redfish/v1/TelemetryService/MetricReports/1` -- the power report
/// member: the `MetricValues` array and the `Timestamp`/`Context` metadata
/// are decoded by the schema, but the projection carries only the derived
/// `MetricValuesCount`, exactly like the `rutilus-infra-redfish` fixture the
/// product's decoder accepts (`Status` is not a `MetricReport_v1` property
/// and stays out).
pub(crate) const METRIC_REPORT_1: &str = r##"{
    "@odata.type":"#MetricReport.v1_4_0.MetricReport",
    "@odata.id":"/redfish/v1/TelemetryService/MetricReports/1",
    "@odata.etag":"W/\"metric-report-1\"",
    "Id":"1",
    "Name":"Power Report",
    "Description":"Average platform power usage",
    "ReportSequence":"1",
    "Timestamp":"2026-08-01T09:30:00Z",
    "Context":"power-context",
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

/// `GET /redfish/v1/TaskService` -- the root task service, advertising its
/// `Tasks` collection behind the 0.2 `task` family; the service-plumbing
/// fields are decoded by the schema but stay outside the strictly
/// projectable field set.
pub(crate) const TASK_SERVICE: &str = r##"{
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

/// `GET /redfish/v1/TaskService/Tasks` -- the task collection with the
/// single firmware-update member.
pub(crate) const TASKS_COLLECTION: &str = r##"{
    "@odata.type":"#TaskCollection.TaskCollection",
    "@odata.id":"/redfish/v1/TaskService/Tasks",
    "Name":"Task Collection",
    "Members":[{"@odata.id":"/redfish/v1/TaskService/Tasks/1"}]
}"##;

/// `GET /redfish/v1/TaskService/Tasks/1` -- the running firmware-update task
/// member with every optional contract field populated; the task plumbing
/// fields are decoded but stay outside the strictly projectable field set,
/// exactly like the `rutilus-infra-redfish` fixture the product's decoder
/// accepts.
pub(crate) const TASK_1: &str = r##"{
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

/// The Redfish-shaped error body for unregistered paths.
///
/// A `404` with this body lets the product classify the miss as an endpoint
/// state instead of a transport failure, so one unknown URI cannot take down
/// the demo tree.
pub(crate) const NOT_FOUND: &str = r#"{
    "error":{
        "code":"Base.1.0.ResourceMissingAtURI",
        "message":"The resource identified by the request URI was not found."
    }
}"#;

/// The Service Root document of one vendor profile.
///
/// The default profile keeps the byte-identical [`SERVICE_ROOT`]; only the
/// profile-specific identity strings are swapped in for another vendor.
pub(crate) fn service_root(profile: MockProfile) -> &'static str {
    match profile {
        MockProfile::Rutilus => SERVICE_ROOT,
        MockProfile::Dell => SERVICE_ROOT_DELL,
        MockProfile::Nvidia => SERVICE_ROOT_NVIDIA,
    }
}

/// `GET /redfish/v1` -- the Service Root of the NVIDIA vendor profile.
///
/// Only the identity strings differ from the default profile: a real NVIDIA
/// `BlueField` identifies itself as Vendor "NVIDIA" with the `BlueField` product
/// name. The navigation surface is byte-identical to [`SERVICE_ROOT`], and
/// no `Oem` segment is served here because the NVIDIA namespace lives on the
/// System document, exactly where the gateway's probe and read look for it.
pub(crate) const SERVICE_ROOT_NVIDIA: &str = r##"{
    "@odata.id":"/redfish/v1/",
    "@odata.type":"#ServiceRoot.v1_16_0.ServiceRoot",
    "@odata.etag":"W/\"root-1\"",
    "Id":"RootService",
    "Name":"Root Service",
    "RedfishVersion":"1.20.0",
    "Vendor":"NVIDIA",
    "Product":"BlueField-3",
    "Links":{"Sessions":{"@odata.id":"/redfish/v1/SessionService/Sessions"}},
    "SessionService":{"@odata.id":"/redfish/v1/SessionService"},
    "Systems":{"@odata.id":"/redfish/v1/Systems"},
    "Chassis":{"@odata.id":"/redfish/v1/Chassis"},
    "Managers":{"@odata.id":"/redfish/v1/Managers"},
    "AccountService":{"@odata.id":"/redfish/v1/AccountService"},
    "UpdateService":{"@odata.id":"/redfish/v1/UpdateService"},
    "EventService":{"@odata.id":"/redfish/v1/EventService"},
    "TelemetryService":{"@odata.id":"/redfish/v1/TelemetryService"},
    "Tasks":{"@odata.id":"/redfish/v1/TaskService"}
}"##;

/// The `Managers/1` document of one vendor profile.
///
/// The default profile keeps the byte-identical [`MANAGER`]; the Dell
/// profile adds the `Oem.Dell` segment that advertises its OEM namespace,
/// and the NVIDIA profile adds the `Oem.Nvidia` segment that advertises its
/// OEM namespace and navigates the power-compliance and managed-entity
/// chains.
pub(crate) fn manager(profile: MockProfile) -> &'static str {
    match profile {
        MockProfile::Rutilus => MANAGER,
        MockProfile::Dell => MANAGER_DELL,
        // The NVIDIA profile carries the `Oem.Nvidia` segment on both the
        // System member (the system-config-profile chain) and the Manager
        // member (the power-compliance and managed-entity chains).
        MockProfile::Nvidia => MANAGER_NVIDIA,
    }
}

/// The `Systems/1` document of one vendor profile.
///
/// The default profile keeps the byte-identical [`SYSTEM`]; the NVIDIA
/// profile adds the `Oem.Nvidia` segment that advertises its OEM namespace
/// and navigates the system-config-profile chain.
pub(crate) fn system(profile: MockProfile) -> &'static str {
    match profile {
        // The Dell profile shares the default system document: the Dell
        // OEM surface lives on the manager member, not the system.
        MockProfile::Rutilus | MockProfile::Dell => SYSTEM,
        MockProfile::Nvidia => SYSTEM_NVIDIA,
    }
}
