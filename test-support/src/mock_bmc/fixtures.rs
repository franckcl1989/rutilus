//! Static Redfish JSON documents of the Mock BMC fixture tree.
//!
//! Every document mirrors the shapes `rutilus-infra-redfish`'s own tests
//! already decode with `nv-redfish` 0.13 (same `@odata.type` versions, same
//! field sets, same enum spellings), so the mock cannot drift from what the
//! product actually parses. The tree is deliberately small: one System with
//! two Processors and one Memory module, one Chassis, one Manager, and the
//! `SessionService`. Links the tree does not serve are omitted entirely, so
//! the capability probe reports `NotAdvertised` for them instead of guessing
//! paths.

/// `GET /redfish/v1` -- the Service Root.
///
/// Only the core navigation links are advertised (`SessionService`, Systems,
/// Chassis, Managers); the root services (`AccountService`, `EventService`,
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
    "Managers":{"@odata.id":"/redfish/v1/Managers"}
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

/// `GET /redfish/v1/Systems` -- the computer system collection.
pub(crate) const SYSTEMS_COLLECTION: &str = r##"{
    "@odata.type":"#ComputerSystemCollection.ComputerSystemCollection",
    "@odata.id":"/redfish/v1/Systems",
    "Name":"Computer System Collection",
    "Members":[{"@odata.id":"/redfish/v1/Systems/1"}]
}"##;

/// `GET /redfish/v1/Systems/1` -- the compute system, advertising the 0.2
/// Processors and Memory families through typed navigation links.
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

/// `GET /redfish/v1/Chassis/1` -- the rack chassis.
///
/// No member-scoped links (Power, Thermal, and friends) are advertised, so
/// the capability probe reports those features as `NotAdvertised`.
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
    "Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}
}"#;

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
