//! Static Redfish JSON documents of the Mock BMC fixture tree.
//!
//! Every document mirrors the shapes `rutilus-infra-redfish`'s own tests
//! already decode with `nv-redfish` 0.13 (same `@odata.type` versions, same
//! field sets, same enum spellings), so the mock cannot drift from what the
//! product actually parses. The tree is deliberately small: one System with
//! two Processors, one Memory module, one Bios singleton, one Boot Option,
//! and one Secure Boot singleton, one Chassis with one Power and one Thermal
//! singleton plus one Sensor and one Control member, one Manager, the
//! `SessionService`, and one `AccountService` with a single account. Links
//! the tree does not serve are omitted entirely, so the capability probe
//! reports `NotAdvertised` for them instead of guessing paths.

/// `GET /redfish/v1` -- the Service Root.
///
/// The core navigation links plus the 0.2 `AccountService` root service are
/// advertised; the remaining root services (`EventService`, `TaskService`,
/// and friends) stay absent so the probe reports them as `NotAdvertised`.
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
    "AccountService":{"@odata.id":"/redfish/v1/AccountService"}
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
/// Bios, `BootOptions`, `SecureBoot`, `Processors`, and `Memory` families
/// through typed navigation links.
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
    "Memory":{"@odata.id":"/redfish/v1/Systems/1/Memory"}
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
/// telemetry families through typed navigation links. The `Power` and
/// `Thermal` singletons plus the `Sensors` and `Controls` collections are
/// served so the capability probe reports them `Supported` and the typed
/// resource read carries their readings; links the tree does not serve
/// (`NetworkAdapters`, `Assembly`, `PowerSubsystem`, ...) stay absent so the
/// probe reports those features as `NotAdvertised`.
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
    "Controls":{"@odata.id":"/redfish/v1/Chassis/1/Controls"}
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
/// Optional links (`EthernetInterfaces`, `HostInterfaces`,
/// `NetworkProtocol`, `LogServices`) stay absent on purpose: the probe must
/// observe them as `NotAdvertised` rather than following guessed paths.
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
}"#;

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
