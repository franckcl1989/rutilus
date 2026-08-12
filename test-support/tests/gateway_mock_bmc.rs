#![forbid(unsafe_code)]

//! Integration tests driving the product `RedfishGateway` against the shared
//! Mock BMC, proving the §19.1 Mock-BMC test layer through public APIs only:
//! trust-first onboarding of the mock's self-signed identity, the Service
//! Root read, the complete 47-capability probe (33 standard §2.1 features and
//! 14 OEM features), the typed core resource read, the Session create/delete
//! lifecycle, and the 0.5.0 vendor profiles (the Dell profile's `oem-dell`
//! probe states and its §11.5 `DellAttributes` snapshot, the NVIDIA
//! profile's `oem-nvidia*` probe states and its §11.5 chains, the Lenovo
//! profile's `oem-lenovo` probe states and its §11.5 `SecurityService`
//! snapshot, the AMI profile's `oem-ami` probe state and its §11.5
//! `AmiServiceRoot`/`ConfigBmc` snapshots, the HPE profile's `oem-hpe`
//! probe state and its §11.5 `HpeiLoServiceExt`/`HpeiLo` segments, and the
//! xFusion/Inspur no-OEM profiles proving every OEM capability stays
//! `NotAdvertised` and the read tree stays OEM-free).
//!
//! Every test starts its own `MockBmc` on an ephemeral port, so the suite is
//! self-contained: it needs no manual setup, no fixture files, and no
//! separately started `mock-bmc` binary (`cargo test -p rutilus-test-support`).

use std::{error::Error, io};

use rutilus_domain::{
    AccountCommand, AccountId, AccountPassword, AccountUserName, CAPABILITY_LEDGER_ORDER,
    CapabilityState, CreateAccount, CredentialUsername, DeleteAccount, EndpointAddress,
    EndpointCapability, EndpointCapabilityObservation, EraseToken, EraseType,
    NvidiaDebugTokenCommand, NvidiaPowerSmoothingCommand, NvidiaSystemConfigProfileCommand,
    OEM_CAPABILITY_LEDGER_ORDER, OemCommand, ProfileFile, ProfileId, RedfishCommand,
    ResourceFeature, RoleId, TlsTrust, TokenData, TokenType, UpdateAccount, UpdateAccountPassword,
    UpdateAccountUserName,
};
use rutilus_infra_redfish::{
    CommandExecutionError, CommandExecutionOutcome, CommandRejection, CommandVerificationOutcome,
    CoreResourceProjection, RedfishGateway, SystemCaStatus,
};
use rutilus_test_support::{MockBmc, MockProfile, RequestRecord};
use secrecy::SecretString;
use time::OffsetDateTime;

/// The Mock BMC account the mock fixture accepts; `SecretString` keeps the
/// value out of Debug output the same way the product boundary does.
const MOCK_USERNAME: &str = "admin";
const MOCK_PASSWORD: &str = "password";

/// The capability states the Mock BMC must achieve for the core §2.1 surface.
///
/// Member-scoped features (Power, Thermal, ...) stay fixture-dependent, so
/// only the inventory count and the core capability states are pinned here;
/// a fixture change cannot silently shrink the inventory, but a richer mock
/// does not force this test to know every member-scoped link.
const CORE_CAPABILITIES_SUPPORTED: [EndpointCapability; 24] = [
    EndpointCapability::SessionService,
    EndpointCapability::Systems,
    EndpointCapability::Chassis,
    EndpointCapability::Managers,
    EndpointCapability::Processors,
    EndpointCapability::Memory,
    EndpointCapability::Accounts,
    EndpointCapability::Bios,
    EndpointCapability::BootOptions,
    EndpointCapability::SecureBoot,
    EndpointCapability::Power,
    EndpointCapability::Thermal,
    EndpointCapability::Sensors,
    EndpointCapability::Controls,
    EndpointCapability::HostInterfaces,
    EndpointCapability::LogServices,
    EndpointCapability::ManagerNetworkProtocol,
    // The 0.2 device-family read surface: the System advertises
    // `pcie-devices` as a link array, the Chassis advertises its `Assembly`
    // document, and the Service Root advertises `update-service`.
    EndpointCapability::PcieDevices,
    EndpointCapability::Assembly,
    EndpointCapability::UpdateService,
    // The 0.2 service-family read surface: the Service Root advertises the
    // `event-service`, `telemetry-service`, and `task-service` root services.
    EndpointCapability::EventService,
    EndpointCapability::TelemetryService,
    EndpointCapability::TaskService,
    // The `bmc-http` transport capability: every probe request runs through
    // the compiled HTTP transport, so a completed probe observes it
    // `Supported` without any resource-level probe (§3.1 服务与连接).
    EndpointCapability::BmcHttp,
];

/// Establishes the trust-first onboarding decision for the Mock BMC's
/// self-signed leaf exactly the way §17 prescribes: observe the leaf without
/// credentials, verify its SHA-256 identity against the mock's advertised
/// fingerprint, and record an explicit Pin decision (a self-signed leaf is
/// never accepted through system roots, so the mock always exercises the Pin
/// branch of the onboarding flow).
async fn pin_mock_identity(
    gateway: &RedfishGateway,
    mock: &MockBmc,
) -> Result<(EndpointAddress, TlsTrust), Box<dyn Error>> {
    let address = mock.endpoint_address();
    let observation = gateway.observe_tls(&address).await?;
    assert_eq!(
        observation.certificate().fingerprint(),
        mock.fingerprint(),
        "the observed leaf must match the SHA-256 identity the mock advertises"
    );
    assert_eq!(
        observation.system_ca_status(),
        SystemCaStatus::Rejected,
        "a fresh self-signed mock leaf can never validate through system roots"
    );
    Ok((
        address,
        TlsTrust::PinnedCertificate {
            certificate: observation.certificate().clone(),
            trusted_at: OffsetDateTime::now_utc(),
        },
    ))
}

fn credentials() -> Result<(CredentialUsername, SecretString), Box<dyn Error>> {
    Ok((
        CredentialUsername::parse(MOCK_USERNAME)?,
        SecretString::from(MOCK_PASSWORD),
    ))
}

/// Asserts the observed state of one capability, explaining which capability
/// disappeared when the probe drops an entry from the §2.1 inventory.
fn assert_capability_state(
    observations: &[EndpointCapabilityObservation],
    capability: EndpointCapability,
    expected: CapabilityState,
) -> Result<(), Box<dyn Error>> {
    let observed = observations
        .iter()
        .find(|observation| observation.capability() == capability)
        .ok_or_else(|| io::Error::other(format!("{capability} is missing from the probe")))?;
    assert_eq!(observed.state(), expected);
    Ok(())
}

#[tokio::test]
async fn service_root_read_establishes_pinned_trust_and_reads_summary() -> Result<(), Box<dyn Error>>
{
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let summary = gateway
        .read_service_root(&address, &trust, &username, &password)
        .await?;

    // The fixture metadata flows through the product boundary unchanged, so a
    // mismatch here means either the mock or the gateway projection broke.
    assert_eq!(summary.vendor(), Some("Rutilus Test"));
    assert_eq!(summary.product(), Some("Mock BMC"));
    assert_eq!(summary.redfish_version(), Some("1.20.0"));
    Ok(())
}

#[tokio::test]
async fn probes_all_forty_seven_capabilities_with_core_surface_supported()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // The gateway must return exactly the §2.1 inventory in design-document
    // order; the domain ledger is the canonical order, so a new capability or
    // a dropped observation fails this assertion instead of drifting silently.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The mock serves no vendor `Oem` namespace and no LiteOn chassis, so the
    // probe must report every compiled OEM capability `NotAdvertised`: the
    // §11.3 advertised layer is decided by the decoded documents, never
    // guessed from the vendor name.
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::NotAdvertised,
        )?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("Rutilus Test"),
        "the probe must carry the same Service Root the read returns"
    );
    Ok(())
}

#[tokio::test]
async fn reads_core_resource_snapshots_across_all_families() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The mock serves one System with its configuration surface (Bios,
    // BootOptions, SecureBoot), two Processors, one Memory module, and one
    // PCIe device; one Chassis with its Power and Thermal singletons plus one
    // Sensor, one Control member, and one Assembly member; one Manager with
    // its LogServices, NetworkProtocol, and HostInterfaces surface; one
    // Account; one SoftwareInventory member under the UpdateService; and the
    // event, telemetry, and task service families (one subscription, one
    // metric definition, one metric report, and one task); typed navigation
    // must visit every family exactly in the documented read order.
    assert_eq!(resources.len(), 28);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    assert_family_payloads(resources)?;
    assert_resource_identifiers(resources);
    Ok(())
}

/// Asserts the typed field projections of every family, naming the resource
/// when a projected value does not match the mock fixture.
fn assert_family_payloads(resources: &[CoreResourceProjection]) -> Result<(), Box<dyn Error>> {
    assert_projection_payload(&resources[0], "Id", "RootService")?;
    assert_projection_payload(&resources[0], "RedfishVersion", "1.20.0")?;
    assert_projection_payload(&resources[1], "SystemType", "Physical")?;
    assert_projection_payload(
        &resources[2],
        "AttributeRegistry",
        "BiosAttributeRegistryP11.v1_2_0",
    )?;
    assert_projection_payload(&resources[3], "DisplayName", "PXE Network Boot")?;
    assert_projection_payload(&resources[4], "SecureBootMode", "UserMode")?;
    assert_projection_payload(&resources[5], "ProcessorType", "CPU")?;
    assert_projection_payload(&resources[6], "ProcessorType", "CPU")?;
    assert_projection_payload(&resources[7], "MemoryDeviceType", "DDR4")?;
    // The device-family projections carry the direct properties exactly as
    // published: the PCIe device its type and hardware identifiers.
    assert_projection_payload(&resources[8], "DeviceType", "SingleFunction")?;
    assert_projection_payload(&resources[8], "Manufacturer", "Rutilus Test")?;
    assert_projection_payload(&resources[8], "Model", "PCIE-GEN4-X16")?;
    assert_projection_payload(&resources[9], "ChassisType", "RackMount")?;
    // The telemetry projections carry exactly the published surface: the
    // `Power` singleton has no projectable details, `Thermal` carries only
    // status, and the sensor and control members their direct readings.
    assert_projection_payload(&resources[10], "Name", "Power")?;
    assert!(
        !resources[10]
            .payload()
            .as_str()
            .contains("PowerConsumedWatts")
    );
    assert!(
        resources[11]
            .payload()
            .as_str()
            .contains("\"Health\":\"OK\"")
    );
    assert_projection_payload(&resources[12], "ReadingType", "Temperature")?;
    assert_projection_payload(&resources[12], "ReadingUnits", "Cel")?;
    assert!(
        resources[12]
            .payload()
            .as_str()
            .contains("\"Reading\":27.5")
    );
    assert_projection_payload(&resources[13], "ControlType", "DutyCycle")?;
    assert!(
        resources[13]
            .payload()
            .as_str()
            .contains("\"SetPoint\":30.0")
    );
    // The `AssemblyData` member carries its `MemberId` as the common Id and
    // its producer exactly as published.
    assert_projection_payload(&resources[14], "Id", "0")?;
    assert_projection_payload(&resources[14], "Producer", "Rutilus Test")?;
    assert_projection_payload(&resources[15], "ManagerType", "BMC")?;
    // The manager surface projections carry the direct properties exactly as
    // published: the log service its enable flag and record capacity, the
    // network protocol singleton its host metadata, and the host interface
    // its interface state and type.
    let log_service_payload: serde_json::Value =
        serde_json::from_str(resources[16].payload().as_str())?;
    assert_eq!(log_service_payload["ServiceEnabled"], true);
    assert_eq!(log_service_payload["MaxNumberOfRecords"], 1000);
    let protocol_payload: serde_json::Value =
        serde_json::from_str(resources[17].payload().as_str())?;
    assert_eq!(protocol_payload["HostName"], "bmc-1");
    assert_eq!(protocol_payload["FQDN"], "bmc-1.example.com");
    let host_interface_payload: serde_json::Value =
        serde_json::from_str(resources[18].payload().as_str())?;
    assert_eq!(host_interface_payload["InterfaceEnabled"], true);
    assert_eq!(
        host_interface_payload["HostInterfaceType"],
        "NetworkHostInterface"
    );
    assert_projection_payload(&resources[19], "RoleId", "Administrator")?;
    // The software inventory member carries its identity, version, and typed
    // release date exactly as published.
    assert_projection_payload(&resources[20], "SoftwareId", "BIOS-2026-1")?;
    assert_projection_payload(&resources[20], "Version", "2.7.0")?;
    assert_projection_payload(&resources[20], "ReleaseDate", "2026-05-01T00:00:00Z")?;
    assert_service_family_payloads(resources)
}

/// Asserts the typed field projections of the event, telemetry, and task
/// service families, keeping `assert_family_payloads` short by moving the
/// service-family assertions behind one call.
fn assert_service_family_payloads(
    resources: &[CoreResourceProjection],
) -> Result<(), Box<dyn Error>> {
    // The service-family projections carry the direct properties exactly as
    // published: the event service its enable flag and status, the
    // subscription its destination, protocol, context, and event types, the
    // telemetry service only status, the metric definition its units and
    // type, the metric report its derived value count, the task service its
    // enable flag and overwrite policy, and the task its state, progress,
    // and timeline.
    let event_service_payload: serde_json::Value =
        serde_json::from_str(resources[21].payload().as_str())?;
    assert_eq!(event_service_payload["ServiceEnabled"], true);
    assert_eq!(event_service_payload["Status"]["Health"], "OK");
    let subscription_payload: serde_json::Value =
        serde_json::from_str(resources[22].payload().as_str())?;
    assert_eq!(
        subscription_payload["Destination"],
        "https://events.example.com/hook-1"
    );
    assert_eq!(subscription_payload["Protocol"], "Redfish");
    assert_eq!(subscription_payload["Context"], "hook-one");
    assert_eq!(
        subscription_payload["EventTypes"],
        serde_json::json!(["StatusChange", "Alert"])
    );
    let telemetry_payload: serde_json::Value =
        serde_json::from_str(resources[23].payload().as_str())?;
    assert_eq!(telemetry_payload["Status"]["State"], "Enabled");
    let definition_payload: serde_json::Value =
        serde_json::from_str(resources[24].payload().as_str())?;
    assert_eq!(definition_payload["MetricType"], "Numeric");
    assert_eq!(definition_payload["Units"], "W");
    let report_payload: serde_json::Value = serde_json::from_str(resources[25].payload().as_str())?;
    assert_eq!(report_payload["MetricValuesCount"], 2);
    let task_service_payload: serde_json::Value =
        serde_json::from_str(resources[26].payload().as_str())?;
    assert_eq!(task_service_payload["ServiceEnabled"], true);
    assert_eq!(
        task_service_payload["CompletedTaskOverWritePolicy"],
        "Oldest"
    );
    let task_payload: serde_json::Value = serde_json::from_str(resources[27].payload().as_str())?;
    assert_eq!(task_payload["TaskState"], "Running");
    assert_eq!(task_payload["TaskStatus"], "OK");
    assert_eq!(task_payload["PercentComplete"], 42);
    assert_eq!(task_payload["StartTime"], "2026-08-01T09:30:00Z");
    Ok(())
}

/// Asserts the exact `@odata.id` of every projection and that the mock's
/// `ETag` survived the read; presence plus exact URI is the shape assertion
/// for the typed identifiers.
fn assert_resource_identifiers(resources: &[CoreResourceProjection]) {
    let odata_ids = [
        "/redfish/v1/",
        "/redfish/v1/Systems/1",
        "/redfish/v1/Systems/1/Bios",
        "/redfish/v1/Systems/1/BootOptions/PXE-1",
        "/redfish/v1/Systems/1/SecureBoot",
        "/redfish/v1/Systems/1/Processors/CPU1",
        "/redfish/v1/Systems/1/Processors/CPU2",
        "/redfish/v1/Systems/1/Memory/DIMM1",
        "/redfish/v1/Systems/1/PCIeDevices/GPU1",
        "/redfish/v1/Chassis/1",
        "/redfish/v1/Chassis/1/Power",
        "/redfish/v1/Chassis/1/Thermal",
        "/redfish/v1/Chassis/1/Sensors/InletTemp",
        "/redfish/v1/Chassis/1/Controls/FanDuty",
        // The `AssemblyData` member keeps its fragment-style `@odata.id`,
        // exactly as the fixture publishes it.
        "/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
        "/redfish/v1/Managers/1",
        "/redfish/v1/Managers/1/LogServices/1",
        "/redfish/v1/Managers/1/NetworkProtocol",
        "/redfish/v1/Managers/1/HostInterfaces/1",
        "/redfish/v1/AccountService/Accounts/admin",
        "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
        "/redfish/v1/EventService",
        "/redfish/v1/EventService/Subscriptions/1",
        "/redfish/v1/TelemetryService",
        "/redfish/v1/TelemetryService/MetricDefinitions/1",
        "/redfish/v1/TelemetryService/MetricReports/1",
        "/redfish/v1/TaskService",
        "/redfish/v1/TaskService/Tasks/1",
    ];
    for (resource, expected) in resources.iter().zip(odata_ids) {
        assert_eq!(resource.odata_id().as_str(), expected);
        assert!(
            resource.etag().is_some(),
            "{} must carry its upstream ETag",
            resource.odata_id()
        );
    }
}

#[tokio::test]
async fn session_lifecycle_posts_create_and_deletes_through_the_gateway()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;

    // The gateway must prefer the Session transport: POST the Session
    // collection, authenticate every subsequent read with the in-memory
    // token, and DELETE the created Session before returning (§19.1 Session
    // creation). Asserting the exact wire sequence on the mock side proves
    // the lifecycle happens through the product path, not through test
    // plumbing; the empty Session ledger proves the DELETE actually removed
    // the created Session instead of just answering 204.
    assert_request_sequence(
        &mock.requests(),
        &[
            ("GET", "/redfish/v1"),
            ("GET", "/redfish/v1/SessionService"),
            ("GET", "/redfish/v1/SessionService/Sessions"),
            ("POST", "/redfish/v1/SessionService/Sessions"),
            ("GET", "/redfish/v1/Systems"),
            ("GET", "/redfish/v1/Systems/1"),
            ("GET", "/redfish/v1/Systems/1/Bios"),
            ("GET", "/redfish/v1/Systems/1/BootOptions"),
            ("GET", "/redfish/v1/Systems/1/BootOptions/PXE-1"),
            ("GET", "/redfish/v1/Systems/1/SecureBoot"),
            ("GET", "/redfish/v1/Systems/1/Processors"),
            ("GET", "/redfish/v1/Systems/1/Processors/CPU1"),
            ("GET", "/redfish/v1/Systems/1/Processors/CPU2"),
            ("GET", "/redfish/v1/Systems/1/Memory"),
            ("GET", "/redfish/v1/Systems/1/Memory/DIMM1"),
            ("GET", "/redfish/v1/Systems/1/PCIeDevices/GPU1"),
            ("GET", "/redfish/v1/Chassis"),
            ("GET", "/redfish/v1/Chassis/1"),
            ("GET", "/redfish/v1/Chassis/1/Power"),
            ("GET", "/redfish/v1/Chassis/1/Thermal"),
            ("GET", "/redfish/v1/Chassis/1/Sensors"),
            ("GET", "/redfish/v1/Chassis/1/Sensors/InletTemp"),
            ("GET", "/redfish/v1/Chassis/1/Controls"),
            ("GET", "/redfish/v1/Chassis/1/Controls/FanDuty"),
            ("GET", "/redfish/v1/Chassis/1/Assembly"),
            // The `AssemblyData` member is fetched through its fragment-style
            // `@odata.id`, which the HTTP client percent-encodes on the wire
            // (`%23`), exactly as the fixture publishes it.
            ("GET", "/redfish/v1/Chassis/1/Assembly%23/Assemblies/0"),
            ("GET", "/redfish/v1/Managers"),
            ("GET", "/redfish/v1/Managers/1"),
            ("GET", "/redfish/v1/Managers/1/LogServices"),
            ("GET", "/redfish/v1/Managers/1/LogServices/1"),
            ("GET", "/redfish/v1/Managers/1/NetworkProtocol"),
            ("GET", "/redfish/v1/Managers/1/HostInterfaces"),
            ("GET", "/redfish/v1/Managers/1/HostInterfaces/1"),
            ("GET", "/redfish/v1/AccountService"),
            ("GET", "/redfish/v1/AccountService/Accounts"),
            ("GET", "/redfish/v1/AccountService/Accounts/admin"),
            ("GET", "/redfish/v1/UpdateService"),
            ("GET", "/redfish/v1/UpdateService/SoftwareInventory"),
            ("GET", "/redfish/v1/UpdateService/SoftwareInventory/BIOS"),
            ("GET", "/redfish/v1/EventService"),
            ("GET", "/redfish/v1/EventService/Subscriptions"),
            ("GET", "/redfish/v1/EventService/Subscriptions/1"),
            ("GET", "/redfish/v1/TelemetryService"),
            ("GET", "/redfish/v1/TelemetryService/MetricDefinitions"),
            ("GET", "/redfish/v1/TelemetryService/MetricDefinitions/1"),
            ("GET", "/redfish/v1/TelemetryService/MetricReports"),
            ("GET", "/redfish/v1/TelemetryService/MetricReports/1"),
            ("GET", "/redfish/v1/TaskService"),
            ("GET", "/redfish/v1/TaskService/Tasks"),
            ("GET", "/redfish/v1/TaskService/Tasks/1"),
            ("DELETE", "/redfish/v1/SessionService/Sessions/1"),
        ],
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the gateway must delete its transient Session before returning"
    );
    Ok(())
}

/// Asserts one Mock-BMC request sequence, mirroring the typed navigation
/// order the gateway documents: Basic on the pre-Session reads and on the
/// final Session DELETE (the upstream Session wrapper keeps the initial
/// transport), no credentials on the Session POST, and X-Auth-Token on every
/// read that runs through the token transport.
fn assert_request_sequence(requests: &[RequestRecord], expected: &[(&str, &str)]) {
    assert_eq!(
        requests.len(),
        expected.len(),
        "the mock must receive exactly the documented request count"
    );
    let last = expected.len().saturating_sub(1);
    for (index, (record, (method, path))) in requests.iter().zip(expected).enumerate() {
        assert_eq!(record.method(), *method, "request {index} method");
        assert_eq!(record.path(), *path, "request {index} path");
        if index == 3 {
            // The Session POST must not carry credentials: the product only
            // sends Basic through the initial transport, never on the POST.
            assert!(
                record.header("authorization").is_none() && record.header("x-auth-token").is_none(),
                "the Session POST must not carry credentials"
            );
        } else if index == last {
            // The upstream Session wrapper keeps the initial Basic transport,
            // so the cleanup DELETE authenticates with Basic like the
            // pre-Session reads; `rutilus-infra-redfish`'s own session tests
            // document this exact wire behavior.
            assert!(
                record
                    .header("authorization")
                    .is_some_and(|value| value.starts_with("Basic ")),
                "request {index} must authenticate the Session DELETE with Basic"
            );
            assert!(
                record.header("x-auth-token").is_none(),
                "request {index} must not mix a token into the Session DELETE"
            );
        } else if index < 3 {
            // Before the Session exists, the initial transport authenticates
            // with Basic and must not yet use a token.
            assert!(
                record
                    .header("authorization")
                    .is_some_and(|value| value.starts_with("Basic ")),
                "request {index} must authenticate with Basic before the Session exists"
            );
            assert!(
                record.header("x-auth-token").is_none(),
                "request {index} must not use a token before the Session POST"
            );
        } else {
            // Every token-transport read authenticates with the in-memory
            // Session token only; Basic never appears on that transport.
            assert_eq!(
                record.header("x-auth-token"),
                Some("test-session-token"),
                "request {index} must authenticate with the Session token"
            );
            assert!(
                record.header("authorization").is_none(),
                "request {index} must not leak Basic credentials"
            );
        }
    }
}

/// Asserts one typed field inside a core resource projection, decoding the
/// canonical JSON the gateway produced from typed upstream fields.
fn assert_projection_payload(
    projection: &CoreResourceProjection,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
    assert_eq!(
        payload[field],
        expected,
        "{} payload field {field}",
        projection.odata_id()
    );
    Ok(())
}

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the Dell profile: exactly the 34 requests of the default
/// profile, because the §11.3 namespace probe decides `oem-dell` from the
/// already-decoded manager member and never probes a vendor URL.
const DELL_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the Dell profile: the 51 requests of the default profile plus the
/// single §11.5 `DellAttributes` fetch.
const DELL_RESOURCE_READ_REQUEST_COUNT: u64 = 52;

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the NVIDIA profile: exactly the 34 requests of the default
/// profile, because the §11.3 namespace probe decides the `oem-nvidia*`
/// capabilities from the already-decoded system member and never probes a
/// vendor URL.
const NVIDIA_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the NVIDIA profile: the 51 requests of the default profile plus the
/// five §11.5 system-config-profile chain fetches (the profile service
/// document, its status singleton, the profile collection, the profile
/// member, and its profile file) plus the fifteen power-compliance and
/// managed-entity chain fetches (the compliance document, the `PowerDomains`
/// collection with its member, the `ACLossPolicy` / `PSUCompliancePolicy`
/// singletons, the `ManagedEntityGroups` collection with its member and the
/// member's `ManagedEntities` collection with its entity member, the
/// `PowerStateGroup` document with its `PowerShelfControllers` and
/// `PowerSupplies` collections with their members, and the `PSURedundancy`
/// singleton).
const NVIDIA_RESOURCE_READ_REQUEST_COUNT: u64 = 71;

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the Lenovo profile: exactly the 34 requests of the default
/// profile, because the §11.3 namespace probe decides `oem-lenovo` from the
/// already-decoded manager member and never probes a vendor URL.
const LENOVO_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the Lenovo profile: the 51 requests of the default profile plus the
/// single §11.5 `SecurityService` fetch.
const LENOVO_RESOURCE_READ_REQUEST_COUNT: u64 = 52;

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with a no-OEM profile (xFusion / Inspur): exactly the 34 requests
/// of the default profile, because the §11.3 namespace probe decides the OEM
/// capabilities from already-decoded documents and never probes a vendor
/// URL.
const NO_OEM_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with a no-OEM profile (xFusion / Inspur): exactly the 51 requests of the
/// default profile, because the tree serves no OEM chain to fetch.
const NO_OEM_RESOURCE_READ_REQUEST_COUNT: u64 = 51;

/// The no-OEM vendor profiles and their Service Root identities, the §21
/// 0.5.0 standard-pattern verification basis: the identity strings swap and
/// no vendor `Oem` namespace is served anywhere.
const NO_OEM_PROFILES: [(MockProfile, &str, &str); 2] = [
    (MockProfile::XFusion, "xFusion", "2288H V7"),
    (MockProfile::Inspur, "Inspur", "NF5280M6"),
];

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the Supermicro profile: exactly the 34 requests of the default
/// profile, because the §11.3 namespace probe decides `oem-supermicro` from
/// the already-decoded manager member and never probes a vendor URL.
const SUPERMICRO_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the Supermicro profile: the 51 requests of the default profile plus
/// the two §11.5 `SysLockdown` and `KcsInterface` fetches.
const SUPERMICRO_RESOURCE_READ_REQUEST_COUNT: u64 = 53;

#[tokio::test]
async fn dell_profile_probes_oem_dell_supported_with_standard_surface_unchanged()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Dell).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // Same §2.1 inventory, same order, and the same served standard surface
    // as the default profile: a vendor profile only swaps the identity
    // strings and the OEM surface, never the standard tree.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The Dell profile advertises exactly the Dell namespace: the decoded
    // manager member carries `Oem.Dell`, so `oem-dell` and its
    // `oem-dell-attributes` sub-feature probe `Supported`; no other vendor
    // namespace is served, so every remaining OEM capability stays
    // `NotAdvertised` (§11.3 advertised layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemDell | EndpointCapability::OemDellAttributes => {
                CapabilityState::Supported
            }
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("Dell Inc."),
        "the probe must carry the Dell Service Root identity"
    );
    assert_eq!(
        mock.requests_served(),
        DELL_PROBE_REQUEST_COUNT,
        "the Dell namespace probe must fetch no document beyond the default flow"
    );
    Ok(())
}

// The complete Dell read surface is asserted in one test so the request
// position and the 29-resource order stay one contract; splitting it would
// duplicate the pin/credentials flow. The infra crate allows the same lint
// on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn dell_profile_reads_oem_dell_attributes_snapshot() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Dell).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The Dell read surface adds exactly the §11.5 `DellAttributes` snapshot
    // to the default 28-resource tree, in the documented read order: it is
    // one manager surface, projected right after the manager's
    // `HostInterfaces` member and before the root-level `Accounts` family.
    assert_eq!(resources.len(), 29);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::OemDell,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    // The `DellAttributes` snapshot carries the manager's `Oem.Dell` surface:
    // the crafted `{manager}/Oem/Dell/DellAttributes/{id}` identity, its
    // upstream ETag, and the five pinned identity attributes exactly as
    // published; the unpinned `BiosVersion` bag entry stays out of the
    // strictly projectable field set.
    let dell = &resources[19];
    assert_eq!(dell.feature(), ResourceFeature::OemDell);
    assert_eq!(
        dell.odata_id().as_str(),
        "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1"
    );
    assert!(
        dell.etag().is_some(),
        "{} must carry its upstream ETag",
        dell.odata_id()
    );
    let payload: serde_json::Value = serde_json::from_str(dell.payload().as_str())?;
    assert_eq!(payload["Id"], "1");
    assert_eq!(payload["Name"], "Dell Attributes");
    assert_eq!(payload["Description"], "Dell iDRAC attributes");
    assert_eq!(payload["ServerModel"], "PowerEdge R750");
    assert_eq!(payload["ServerServiceTag"], "ABC1234");
    assert_eq!(payload["ServerGeneration"], "16G");
    assert_eq!(payload["ServerBmcMacAddress"], "14:18:77:aa:bb:cc");
    assert_eq!(payload["ServerName"], "rack-1-server-2");
    assert!(
        payload.get("BiosVersion").is_none(),
        "the unpinned attribute bag entry must not leak into the snapshot"
    );

    // The gateway fetches the `DellAttributes` document exactly once, as one
    // manager surface right after the `HostInterfaces/1` member, and through
    // the Session token transport like every other read.
    let requests = mock.requests();
    assert_eq!(
        mock.requests_served(),
        DELL_RESOURCE_READ_REQUEST_COUNT,
        "the Dell read must issue exactly one request beyond the default flow"
    );
    let host_interface_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/HostInterfaces/1")
        .ok_or_else(|| io::Error::other("HostInterfaces/1 is missing from the request log"))?;
    let dell_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1")
        .ok_or_else(|| {
            io::Error::other("the Dell Attributes fetch is missing from the request log")
        })?;
    assert_eq!(
        dell_index,
        host_interface_index + 1,
        "the Dell Attributes fetch must follow the manager's HostInterfaces member"
    );
    assert_eq!(
        requests[dell_index].header("x-auth-token"),
        Some("test-session-token"),
        "the Dell Attributes fetch must authenticate with the Session token"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn supermicro_profile_probes_oem_supermicro_supported_with_standard_surface_unchanged()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Supermicro).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // Same §2.1 inventory, same order, and the same served standard surface
    // as the default profile: a vendor profile only swaps the identity
    // strings and the OEM surface, never the standard tree.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The Supermicro profile advertises exactly the Supermicro namespace: the
    // decoded manager member carries `Oem.Supermicro`, so `oem-supermicro`
    // probes `Supported`; no other vendor namespace is served, so every
    // remaining OEM capability stays `NotAdvertised` (§11.3 advertised
    // layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemSupermicro => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("Supermicro"),
        "the probe must carry the Supermicro Service Root identity"
    );
    assert_eq!(
        mock.requests_served(),
        SUPERMICRO_PROBE_REQUEST_COUNT,
        "the Supermicro namespace probe must fetch no document beyond the default flow"
    );
    Ok(())
}

// The complete Supermicro read surface is asserted in one test so the request
// position and the 30-resource order stay one contract; splitting it would
// duplicate the pin/credentials flow. The infra crate allows the same lint on
// its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn supermicro_profile_reads_oem_supermicro_documents_snapshot() -> Result<(), Box<dyn Error>>
{
    let mock = MockBmc::start_with_profile(MockProfile::Supermicro).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The Supermicro read surface adds exactly the §11.5 `SysLockdown` and
    // `KcsInterface` snapshots to the default 28-resource tree, in the
    // documented read order: two manager surfaces projected right after the
    // manager's `HostInterfaces` member and before the root-level `Accounts`
    // family.
    assert_eq!(resources.len(), 30);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::OemSmcSysLockdown,
            ResourceFeature::OemSmcKcsInterface,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    // The `SysLockdown` snapshot carries the embedded reference identity and
    // the enabled state; the `KcsInterface` snapshot carries the vendor's
    // enum spelling verbatim.
    let sys_lockdown = &resources[19];
    assert_eq!(sys_lockdown.feature(), ResourceFeature::OemSmcSysLockdown);
    assert_eq!(
        sys_lockdown.odata_id().as_str(),
        "/redfish/v1/Managers/1/SysLockdown"
    );
    assert!(
        sys_lockdown.etag().is_some(),
        "{} must carry its upstream ETag",
        sys_lockdown.odata_id()
    );
    let sys_lockdown_payload: serde_json::Value =
        serde_json::from_str(sys_lockdown.payload().as_str())?;
    assert_eq!(sys_lockdown_payload["SysLockdownEnabled"], true);
    let kcs_interface = &resources[20];
    assert_eq!(kcs_interface.feature(), ResourceFeature::OemSmcKcsInterface);
    assert_eq!(
        kcs_interface.odata_id().as_str(),
        "/redfish/v1/Managers/1/KCSInterface"
    );
    assert!(
        kcs_interface.etag().is_some(),
        "{} must carry its upstream ETag",
        kcs_interface.odata_id()
    );
    let kcs_interface_payload: serde_json::Value =
        serde_json::from_str(kcs_interface.payload().as_str())?;
    assert_eq!(kcs_interface_payload["Privilege"], "Administrator");

    // The gateway fetches the two documents exactly once each, as manager
    // surfaces right after the `HostInterfaces/1` member, and through the
    // Session token transport like every other read.
    let requests = mock.requests();
    assert_eq!(
        mock.requests_served(),
        SUPERMICRO_RESOURCE_READ_REQUEST_COUNT,
        "the Supermicro read must issue exactly two requests beyond the default flow"
    );
    let host_interface_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/HostInterfaces/1")
        .ok_or_else(|| io::Error::other("HostInterfaces/1 is missing from the request log"))?;
    let sys_lockdown_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/SysLockdown")
        .ok_or_else(|| io::Error::other("the SysLockdown fetch is missing from the request log"))?;
    let kcs_interface_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/KCSInterface")
        .ok_or_else(|| {
            io::Error::other("the KcsInterface fetch is missing from the request log")
        })?;
    assert_eq!(
        sys_lockdown_index,
        host_interface_index + 1,
        "the SysLockdown fetch must follow the manager's HostInterfaces member"
    );
    assert_eq!(
        kcs_interface_index,
        sys_lockdown_index + 1,
        "the KcsInterface fetch must follow the SysLockdown fetch"
    );
    for index in [sys_lockdown_index, kcs_interface_index] {
        assert_eq!(
            requests[index].header("x-auth-token"),
            Some("test-session-token"),
            "the Supermicro fetch at {index} must authenticate with the Session token"
        );
    }
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn nvidia_profile_probes_oem_nvidia_supported_with_standard_surface_unchanged()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // Same §2.1 inventory, same order, and the same served standard surface
    // as the default profile.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The NVIDIA profile advertises exactly the NVIDIA namespace: the decoded
    // system member carries `Oem.Nvidia`, so `oem-nvidia` and all five
    // `oem-nvidia-*` sub-features probe `Supported` (§11.3 advertised layer);
    // no other vendor namespace is served, so every remaining OEM capability
    // stays `NotAdvertised`.
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemNvidia
            | EndpointCapability::OemNvidiaCper
            | EndpointCapability::OemNvidiaFabrics
            | EndpointCapability::OemNvidiaPowerManagement
            | EndpointCapability::OemNvidiaProfiles
            | EndpointCapability::OemNvidiaSecurity => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("NVIDIA"),
        "the probe must carry the NVIDIA Service Root identity"
    );
    assert_eq!(
        mock.requests_served(),
        NVIDIA_PROBE_REQUEST_COUNT,
        "the NVIDIA namespace probe must fetch no document beyond the default flow"
    );
    Ok(())
}

// The complete NVIDIA read surface is asserted in one test so the request
// position and the 32-resource order stay one contract; splitting it would
// duplicate the pin/credentials flow. The infra crate allows the same lint
// on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn nvidia_profile_reads_system_config_profile_chain_snapshots() -> Result<(), Box<dyn Error>>
{
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The NVIDIA read surface adds exactly the four §11.5
    // system-config-profile snapshots to the default 28-resource tree (the
    // chain root, its status singleton, the profile member, and its profile
    // file), in the documented read order: they follow the System member and
    // precede the system's `Bios` singleton. The manager's `Oem.Nvidia`
    // segment adds the ten power-chain snapshots (nine power-compliance
    // documents and one managed-entity document), which follow the manager's
    // standard surface and precede the `Accounts` family.
    assert_eq!(resources.len(), 42);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::OemNvidiaSystemConfigProfile,
            ResourceFeature::OemNvidiaSystemConfigProfile,
            ResourceFeature::OemNvidiaSystemConfigProfile,
            ResourceFeature::OemNvidiaSystemConfigProfile,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            // The power-compliance chain: the compliance manager, the power
            // domain member, the two policies, the managed entity group
            // member, the power state group, the PSC and PSU state members,
            // and the PSU redundancy. The managed entity member follows its
            // group (the shared traversal reads each group member's
            // `ManagedEntities` collection right after the group document).
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaManagedEntity,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::OemNvidiaPowerCompliance,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    // The chain root snapshot carries the `Truststore` link-presence
    // metadata; the certificate documents behind the links stay unfetched.
    let chain_root = &resources[2];
    assert_eq!(
        chain_root.odata_id().as_str(),
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
    );
    assert!(chain_root.etag().is_some());
    let payload: serde_json::Value = serde_json::from_str(chain_root.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "system_config_profile");
    assert_eq!(payload["Truststore"]["NvidiaCertificates"], true);
    assert_eq!(payload["Truststore"]["OemCertificates"], true);

    let status = &resources[3];
    assert_eq!(
        status.odata_id().as_str(),
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"
    );
    let payload: serde_json::Value = serde_json::from_str(status.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "system_config_profile_status");
    assert_eq!(payload["PendingList"]["Activation"], "profile-1");
    assert_eq!(payload["ActiveProfileIndex"], 1);
    assert_eq!(payload["BmcProfileVersion"], 2);
    assert_eq!(payload["FactoryResetStatus"], "Idle");
    assert_eq!(payload["DefaultProfileIndex"], 1);

    let profile = &resources[4];
    assert_eq!(
        profile.odata_id().as_str(),
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"
    );
    let payload: serde_json::Value = serde_json::from_str(profile.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "system_profile");
    assert_eq!(payload["Default"], true);
    assert_eq!(payload["Owner"], "Nvidia");
    assert_eq!(payload["UUID"], "11111111-2222-3333-4444-555555555555");
    assert_eq!(payload["Version"], 1);
    assert_eq!(payload["ProfileName"], "default-profile");

    let profile_file = &resources[5];
    assert_eq!(
        profile_file.odata_id().as_str(),
        "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
    );
    let payload: serde_json::Value = serde_json::from_str(profile_file.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "system_profile_file");
    assert_eq!(payload["ProfileFile"]["Metadata"]["Activate"], true);
    assert_eq!(payload["ProfileFile"]["Metadata"]["Delete"], false);
    assert_eq!(
        payload["ProfileFile"]["Metadata"]["OriginProfileUUID"],
        "11111111-2222-3333-4444-555555555555"
    );
    assert_eq!(payload["ProfileFile"]["Metadata"]["More_Profiles"], false);
    assert_eq!(
        payload["ProfileFile"]["Metadata"]["ProjectName"],
        "BlueField"
    );
    assert_eq!(
        payload["ProfileFile"]["Profile"],
        "eyJwcm9maWxlIjogInRlc3QifQ=="
    );

    // The power-compliance chain root follows the manager's standard surface
    // and carries the compiled `ManagerType` enumeration spelling verbatim.
    let power_compliance = &resources[23];
    assert_eq!(
        power_compliance.odata_id().as_str(),
        "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"
    );
    let payload: serde_json::Value = serde_json::from_str(power_compliance.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "power_compliance_manager");
    assert_eq!(payload["ManagerType"], "PowerManager");
    assert!(payload.get("PowerDomains").is_none());
    let power_domain = &resources[24];
    let payload: serde_json::Value = serde_json::from_str(power_domain.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "power_domain");
    assert_eq!(payload["Value"], 800);
    assert_eq!(payload["Type"], "Above");
    assert_eq!(payload["Unit"], "Watts");
    assert_eq!(payload["SensorReadingType"], "Power");
    assert_eq!(payload["SensorImpl"], "PhysicalSensor");
    let ac_loss = &resources[25];
    let payload: serde_json::Value = serde_json::from_str(ac_loss.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "power_policy");
    assert_eq!(payload["PolicyActions"], "AssertPowerBrake");
    assert_eq!(payload["Type"], "Inclusive");
    assert!(payload.get("DwellTime").is_none());
    let psu_policy = &resources[26];
    let payload: serde_json::Value = serde_json::from_str(psu_policy.payload().as_str())?;
    assert_eq!(payload["PolicyActions"], "DoNothing");
    let group = &resources[27];
    let payload: serde_json::Value = serde_json::from_str(group.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "managed_entity_group");
    assert_eq!(payload["CurrentManagedEntityId"], "BF1");
    // The managed-entity family: the entity member follows its group (the
    // shared traversal reads each group member's `ManagedEntities`
    // collection right after the group document).
    let entity = &resources[28];
    assert_eq!(entity.feature(), ResourceFeature::OemNvidiaManagedEntity);
    let payload: serde_json::Value = serde_json::from_str(entity.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "managed_entity");
    assert_eq!(payload["TransportProtocol"], "HTTPS");
    assert_eq!(payload["IPv4Address"], "192.0.2.10");
    assert_eq!(payload["IPv6Address"], "2001:db8::10");
    assert_eq!(payload["Port"], 443);
    let state_group = &resources[29];
    let payload: serde_json::Value = serde_json::from_str(state_group.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "power_state_group");
    assert_eq!(payload["GeneratedWatts"], 2400);
    assert_eq!(payload["NumberOfPscs"], 1);
    assert_eq!(payload["NumberOfLocalPsus"], 2);
    let psc = &resources[30];
    let payload: serde_json::Value = serde_json::from_str(psc.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "psc_state");
    assert_eq!(payload["NumOfOperationalPsus"], 4);
    assert_eq!(payload["PowerBrakeAssert"], false);
    assert_eq!(payload["MillisecondsSinceLastHeartbeat"], 12);
    assert_eq!(payload["Status"], "Operational");
    let psu = &resources[31];
    let payload: serde_json::Value = serde_json::from_str(psu.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "psu_state");
    assert_eq!(payload["PsuId"], "PSU1");
    assert_eq!(payload["Presence"], true);
    assert_eq!(payload["Input1Active"], true);
    assert_eq!(payload["Input2Active"], false);
    let redundancy = &resources[32];
    let payload: serde_json::Value = serde_json::from_str(redundancy.payload().as_str())?;
    assert_eq!(payload["DocumentType"], "psu_redundancy");
    assert_eq!(payload["MaxNumSupported"], "4");
    assert_eq!(payload["MinNumNeeded"], "2");
    assert_eq!(payload["RedundancySetting"], "NPlusOne");

    // The gateway fetches the chain documents exactly once each, right after
    // the System member and before the `Bios` singleton, and through the
    // Session token transport like every other read.
    let requests = mock.requests();
    assert_eq!(
        mock.requests_served(),
        NVIDIA_RESOURCE_READ_REQUEST_COUNT,
        "the NVIDIA read must issue exactly twenty requests beyond the default flow"
    );
    let system_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Systems/1")
        .ok_or_else(|| io::Error::other("Systems/1 is missing from the request log"))?;
    let chain_root_index = requests
        .iter()
        .position(|request| {
            request.path() == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
        })
        .ok_or_else(|| {
            io::Error::other("the SystemConfigProfile fetch is missing from the request log")
        })?;
    assert_eq!(
        chain_root_index,
        system_index + 1,
        "the chain must be read right after the System member"
    );
    let profile_file_index = requests
        .iter()
        .position(|request| {
            request.path()
                == "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
        })
        .ok_or_else(|| io::Error::other("the ProfileFile fetch is missing from the request log"))?;
    assert_eq!(
        requests[profile_file_index].header("x-auth-token"),
        Some("test-session-token"),
        "the chain fetches must authenticate with the Session token"
    );
    // The manager power chain is fetched right after the manager member and
    // its standard surface, through the same Session token transport.
    let manager_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1")
        .ok_or_else(|| io::Error::other("Managers/1 is missing from the request log"))?;
    let power_compliance_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance")
        .ok_or_else(|| {
            io::Error::other("the PowerCompliance fetch is missing from the request log")
        })?;
    assert_eq!(
        power_compliance_index,
        manager_index + 6,
        "the power chain must be read right after the manager's standard surface"
    );
    assert_eq!(
        requests[power_compliance_index].header("x-auth-token"),
        Some("test-session-token"),
        "the power chain fetches must authenticate with the Session token"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn nvidia_profile_executes_oem_actions_through_the_typed_mock_actions()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    // The synchronous profile-service and device-token actions are accepted
    // through the decoded action targets.
    for command in [
        RedfishCommand::Oem(OemCommand::SystemConfigProfile(
            NvidiaSystemConfigProfileCommand::FactoryReset,
        )),
        RedfishCommand::Oem(OemCommand::SystemConfigProfile(
            NvidiaSystemConfigProfileCommand::ActivateProfile,
        )),
        RedfishCommand::Oem(OemCommand::DebugToken(
            NvidiaDebugTokenCommand::GenerateToken(TokenType::Frc),
        )),
        RedfishCommand::Oem(OemCommand::DebugToken(
            NvidiaDebugTokenCommand::InstallToken(TokenData::new("dG9rZW4tZGF0YQ==".to_owned())),
        )),
        RedfishCommand::Oem(OemCommand::DebugToken(
            NvidiaDebugTokenCommand::DisableToken,
        )),
    ] {
        let outcome = gateway
            .execute_command(&address, &trust, &username, &password, &command)
            .await?;
        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
    }
    assert_eq!(
        mock.active_sessions(),
        0,
        "every command must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn nvidia_profile_update_accepts_a_task_and_surfaces_its_location()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    // The mock answers the Update action with `202 Accepted` and the Task
    // location, so the gateway surfaces the §13.6 acceptance for the Task
    // monitor instead of a synchronous outcome.
    let result = gateway
        .execute_command(
            &address,
            &trust,
            &username,
            &password,
            &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                NvidiaSystemConfigProfileCommand::Update(ProfileFile::new("{}".to_owned())),
            )),
        )
        .await;

    assert!(matches!(
        result,
        Err(CommandExecutionError::AsyncTaskAccepted { task_location })
            if task_location.to_string() == "/redfish/v1/TaskService/Tasks/1"
    ));
    assert_eq!(
        mock.active_sessions(),
        0,
        "a Task acceptance must still delete its transient Session"
    );
    Ok(())
}

#[tokio::test]
async fn nvidia_profile_executes_erase_token_through_the_manager_chain()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .execute_command(
            &address,
            &trust,
            &username,
            &password,
            &RedfishCommand::Oem(OemCommand::DebugToken(NvidiaDebugTokenCommand::EraseToken(
                EraseToken::new(EraseType::EraseAll, TokenType::Frc),
            ))),
        )
        .await?;

    assert_eq!(outcome, CommandExecutionOutcome::Accepted);
    Ok(())
}

#[tokio::test]
async fn nvidia_profile_executes_power_smoothing_actions_through_the_chassis_chain()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    for command in [
        RedfishCommand::Oem(OemCommand::PowerSmoothing(
            NvidiaPowerSmoothingCommand::ActivatePresetProfile(ProfileId::new(3)),
        )),
        RedfishCommand::Oem(OemCommand::PowerSmoothing(
            NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
        )),
    ] {
        let outcome = gateway
            .execute_command(&address, &trust, &username, &password, &command)
            .await?;
        assert_eq!(outcome, CommandExecutionOutcome::Accepted);
    }
    Ok(())
}

#[tokio::test]
async fn nvidia_profile_verifies_oem_commands_by_re_reading_the_chain() -> Result<(), Box<dyn Error>>
{
    let mock = MockBmc::start_with_profile(MockProfile::Nvidia).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    for command in [
        RedfishCommand::Oem(OemCommand::SystemConfigProfile(
            NvidiaSystemConfigProfileCommand::FactoryReset,
        )),
        RedfishCommand::Oem(OemCommand::DebugToken(
            NvidiaDebugTokenCommand::GenerateToken(TokenType::Frc),
        )),
    ] {
        let verdict = gateway
            .verify_command(&address, &trust, &username, &password, &command)
            .await?;
        assert_eq!(verdict, CommandVerificationOutcome::Confirmed);
    }
    assert_eq!(
        mock.active_sessions(),
        0,
        "every verification must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn lenovo_profile_probes_oem_lenovo_supported_with_standard_surface_unchanged()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Lenovo).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // Same §2.1 inventory, same order, and the same served standard surface
    // as the default profile: a vendor profile only swaps the identity
    // strings and the OEM surface, never the standard tree.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The Lenovo profile advertises exactly the Lenovo namespace: the decoded
    // manager member carries `Oem.Lenovo`, so `oem-lenovo` probes
    // `Supported`; no other vendor namespace is served, so every remaining
    // OEM capability stays `NotAdvertised` (§11.3 advertised layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemLenovo => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("Lenovo"),
        "the probe must carry the Lenovo Service Root identity"
    );
    assert_eq!(
        discovery.service_root().product(),
        Some("ThinkSystem SR650"),
        "the probe must carry the Lenovo Service Root product"
    );
    assert_eq!(
        mock.requests_served(),
        LENOVO_PROBE_REQUEST_COUNT,
        "the Lenovo namespace probe must fetch no document beyond the default flow"
    );
    Ok(())
}

// The complete Lenovo read surface is asserted in one test so the request
// position and the 29-resource order stay one contract; splitting it would
// duplicate the pin/credentials flow. The infra crate allows the same lint
// on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn lenovo_profile_reads_lenovo_security_service_snapshot() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Lenovo).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The Lenovo read surface adds exactly the §11.5 `SecurityService`
    // snapshot to the default 28-resource tree, in the documented read order:
    // it is one manager surface, projected right after the manager's
    // `HostInterfaces` member and before the root-level `Accounts` family.
    assert_eq!(resources.len(), 29);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::OemLenovoSecurityService,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    // The `SecurityService` snapshot carries the manager's `Oem.Lenovo`
    // surface: the embedded navigation identity, its upstream ETag, and the
    // `FWRollback` state exactly as published (the `Configurator` nesting of
    // the compiled schema collapses onto the wrapper's flattened accessor).
    let security = &resources[19];
    assert_eq!(
        security.feature(),
        ResourceFeature::OemLenovoSecurityService
    );
    assert_eq!(
        security.odata_id().as_str(),
        "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService"
    );
    assert!(
        security.etag().is_some(),
        "{} must carry its upstream ETag",
        security.odata_id()
    );
    let payload: serde_json::Value = serde_json::from_str(security.payload().as_str())?;
    assert_eq!(payload["Id"], "SecurityService");
    assert_eq!(payload["Name"], "Lenovo Security Service");
    assert_eq!(payload["Description"], "Lenovo security service");
    assert_eq!(payload["FWRollback"], "Enabled");

    // The gateway fetches the `SecurityService` document exactly once, as one
    // manager surface right after the `HostInterfaces/1` member, and through
    // the Session token transport like every other read.
    let requests = mock.requests();
    assert_eq!(
        mock.requests_served(),
        LENOVO_RESOURCE_READ_REQUEST_COUNT,
        "the Lenovo read must issue exactly one request beyond the default flow"
    );
    let host_interface_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/HostInterfaces/1")
        .ok_or_else(|| io::Error::other("HostInterfaces/1 is missing from the request log"))?;
    let security_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService")
        .ok_or_else(|| {
            io::Error::other("the SecurityService fetch is missing from the request log")
        })?;
    assert_eq!(
        security_index,
        host_interface_index + 1,
        "the SecurityService fetch must follow the manager's HostInterfaces member"
    );
    assert_eq!(
        requests[security_index].header("x-auth-token"),
        Some("test-session-token"),
        "the SecurityService fetch must authenticate with the Session token"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the AMI profile: exactly the 34 requests of the default
/// profile, because the §11.3 namespace probe decides `oem-ami` from the
/// already-decoded Service Root and manager member and never probes a
/// vendor URL.
const AMI_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the AMI profile: the 51 requests of the default profile plus the
/// single §11.5 `ConfigBmc` fetch through the manager's `ConfigBMC`
/// reference.
const AMI_RESOURCE_READ_REQUEST_COUNT: u64 = 52;

#[tokio::test]
async fn ami_profile_probes_oem_ami_supported_with_standard_surface_unchanged()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Ami).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // Same §2.1 inventory, same order, and the same served standard surface
    // as the default profile: a vendor profile only swaps the identity
    // strings and the OEM surface, never the standard tree.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The AMI profile advertises exactly the AMI namespace: the decoded
    // Service Root and manager member both carry `Oem.Ami`, so `oem-ami`
    // probes `Supported`; no other vendor namespace is served, so every
    // remaining OEM capability stays `NotAdvertised` (§11.3 advertised
    // layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemAmi => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("AMI"),
        "the probe must carry the AMI Service Root identity"
    );
    assert_eq!(
        discovery.service_root().product(),
        Some("MegaRAC SP-X"),
        "the probe must carry the AMI Service Root product"
    );
    assert_eq!(
        mock.requests_served(),
        AMI_PROBE_REQUEST_COUNT,
        "the AMI namespace probe must fetch no document beyond the default flow"
    );
    Ok(())
}

// The complete AMI read surface is asserted in one test so the request
// position and the 30-resource order stay one contract; splitting it would
// duplicate the pin/credentials flow. The infra crate allows the same lint
// on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn ami_profile_reads_oem_ami_snapshots() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Ami).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The AMI read surface adds exactly the two §11.5 snapshots to the
    // default 28-resource tree, in the documented read order: the embedded
    // `AmiServiceRoot` segment right after the Service Root projection, and
    // the fetched `ConfigBmc` document right after the manager's
    // `HostInterfaces` member and before the root-level `Accounts` family.
    assert_eq!(resources.len(), 30);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::OemAmiServiceRoot,
            ResourceFeature::Systems,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::OemAmiConfigBmc,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    // The `AmiServiceRoot` snapshot carries the segment's location inside
    // the Service Root document (`/redfish/v1/Oem/Ami`), the root's own
    // ETag, and the Redfish Technology Pack version exactly as published.
    let ami = &resources[1];
    assert_eq!(ami.feature(), ResourceFeature::OemAmiServiceRoot);
    assert_eq!(ami.odata_id().as_str(), "/redfish/v1/Oem/Ami");
    assert!(
        ami.etag().is_some(),
        "{} must carry its upstream ETag",
        ami.odata_id()
    );
    let payload: serde_json::Value = serde_json::from_str(ami.payload().as_str())?;
    assert_eq!(payload["Id"], "RootService");
    assert_eq!(payload["Name"], "Root Service");
    assert_eq!(payload["RtpVersion"], "1.2.3");

    // The `ConfigBmc` snapshot carries the vendor-published document: the
    // `ConfigBMC` reference identity, its upstream ETag, and the four BIOS
    // lockout/lockdown states in their vendor enum spellings.
    let config_bmc = &resources[20];
    assert_eq!(config_bmc.feature(), ResourceFeature::OemAmiConfigBmc);
    assert_eq!(
        config_bmc.odata_id().as_str(),
        "/redfish/v1/Managers/1/Oem/ConfigBMC"
    );
    assert!(
        config_bmc.etag().is_some(),
        "{} must carry its upstream ETag",
        config_bmc.odata_id()
    );
    let payload: serde_json::Value = serde_json::from_str(config_bmc.payload().as_str())?;
    assert_eq!(payload["LockoutHostControl"], "Enable");
    assert_eq!(payload["LockoutBiosVariableWriteMode"], "Disable");
    assert_eq!(payload["LockdownBiosSettingsChange"], "Enable");
    assert_eq!(payload["LockdownBiosUpgradeDowngrade"], "Disable");

    // The gateway fetches the `ConfigBmc` document exactly once, as one
    // manager surface right after the `HostInterfaces/1` member, and through
    // the Session token transport like every other read.
    let requests = mock.requests();
    assert_eq!(
        mock.requests_served(),
        AMI_RESOURCE_READ_REQUEST_COUNT,
        "the AMI read must issue exactly one request beyond the default flow"
    );
    let host_interface_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/HostInterfaces/1")
        .ok_or_else(|| io::Error::other("HostInterfaces/1 is missing from the request log"))?;
    let config_bmc_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1/Oem/ConfigBMC")
        .ok_or_else(|| io::Error::other("the ConfigBmc fetch is missing from the request log"))?;
    assert_eq!(
        config_bmc_index,
        host_interface_index + 1,
        "the ConfigBmc fetch must follow the manager's HostInterfaces member"
    );
    assert_eq!(
        requests[config_bmc_index].header("x-auth-token"),
        Some("test-session-token"),
        "the ConfigBmc fetch must authenticate with the Session token"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the HPE profile: exactly the 34 requests of the default
/// profile, because the §11.3 namespace probe decides `oem-hpe` from the
/// already-decoded Service Root and manager member and never probes a
/// vendor URL.
const HPE_PROBE_REQUEST_COUNT: u64 = 34;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the HPE profile: exactly the 51 requests of the default profile,
/// because both HPE segments are embedded in documents the default flow
/// already fetches, so the read issues no request beyond the standard tree.
const HPE_RESOURCE_READ_REQUEST_COUNT: u64 = 51;

#[tokio::test]
async fn hpe_profile_probes_oem_hpe_supported_with_standard_surface_unchanged()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Hpe).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // Same §2.1 inventory, same order, and the same served standard surface
    // as the default profile: a vendor profile only swaps the identity
    // strings and the OEM surface, never the standard tree.
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the §2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    // The HPE profile advertises exactly the HPE namespace: the decoded
    // Service Root and manager member both carry `Oem.Hpe`, so `oem-hpe`
    // probes `Supported`; no other vendor namespace is served, so every
    // remaining OEM capability stays `NotAdvertised` (§11.3 advertised
    // layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemHpe => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("HPE"),
        "the probe must carry the HPE Service Root identity"
    );
    assert_eq!(
        discovery.service_root().product(),
        Some("ProLiant DL380 Gen11"),
        "the probe must carry the HPE Service Root product"
    );
    assert_eq!(
        mock.requests_served(),
        HPE_PROBE_REQUEST_COUNT,
        "the HPE namespace probe must fetch no document beyond the default flow"
    );
    Ok(())
}

// The complete HPE read surface is asserted in one test so the 30-resource
// order stays one contract; splitting it would duplicate the pin/credentials
// flow. The infra crate allows the same lint on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn hpe_profile_reads_oem_hpe_segments_snapshot() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Hpe).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The HPE read surface adds exactly the two §11.5 segments to the
    // default 28-resource tree, in the documented read order: the embedded
    // `HpeiLoServiceExt` segment right after the Service Root projection,
    // and the embedded `HpeiLo` segment right after the manager's
    // `HostInterfaces` member and before the root-level `Accounts` family.
    assert_eq!(resources.len(), 30);
    let features: Vec<ResourceFeature> = resources
        .iter()
        .map(CoreResourceProjection::feature)
        .collect();
    assert_eq!(
        features,
        [
            ResourceFeature::ServiceRoot,
            ResourceFeature::OemHpeILoServiceExt,
            ResourceFeature::Systems,
            ResourceFeature::Bios,
            ResourceFeature::BootOptions,
            ResourceFeature::SecureBoot,
            ResourceFeature::Processors,
            ResourceFeature::Processors,
            ResourceFeature::Memory,
            ResourceFeature::PcieDevices,
            ResourceFeature::Chassis,
            ResourceFeature::Power,
            ResourceFeature::Thermal,
            ResourceFeature::Sensors,
            ResourceFeature::Controls,
            ResourceFeature::Assembly,
            ResourceFeature::Managers,
            ResourceFeature::LogServices,
            ResourceFeature::ManagerNetworkProtocol,
            ResourceFeature::HostInterfaces,
            ResourceFeature::OemHpeManager,
            ResourceFeature::Accounts,
            ResourceFeature::SoftwareInventory,
            ResourceFeature::EventService,
            ResourceFeature::EventSubscription,
            ResourceFeature::TelemetryService,
            ResourceFeature::MetricDefinition,
            ResourceFeature::MetricReport,
            ResourceFeature::TaskService,
            ResourceFeature::Task,
        ]
    );

    // The `HpeiLoServiceExt` snapshot carries the segment's location inside
    // the Service Root document (`/redfish/v1/Oem/Hpe`), the root's own
    // ETag, and the iLO manager identity of the first `Manager` entry
    // exactly as published.
    let hpe_root = &resources[1];
    assert_eq!(hpe_root.feature(), ResourceFeature::OemHpeILoServiceExt);
    assert_eq!(hpe_root.odata_id().as_str(), "/redfish/v1/Oem/Hpe");
    assert!(
        hpe_root.etag().is_some(),
        "{} must carry its upstream ETag",
        hpe_root.odata_id()
    );
    let payload: serde_json::Value = serde_json::from_str(hpe_root.payload().as_str())?;
    assert_eq!(payload["Id"], "RootService");
    assert_eq!(payload["ManagerType"], "iLO 5");
    assert_eq!(payload["ManagerFirmwareVersion"], "2.44");

    // The `HpeiLo` snapshot carries the segment's location inside the
    // Manager document (`/redfish/v1/Managers/1/Oem/Hpe`), the manager's
    // own ETag, and the `VirtualNICEnabled` value exactly as published.
    let hpe_manager = &resources[20];
    assert_eq!(hpe_manager.feature(), ResourceFeature::OemHpeManager);
    assert_eq!(
        hpe_manager.odata_id().as_str(),
        "/redfish/v1/Managers/1/Oem/Hpe"
    );
    assert!(
        hpe_manager.etag().is_some(),
        "{} must carry its upstream ETag",
        hpe_manager.odata_id()
    );
    let payload: serde_json::Value = serde_json::from_str(hpe_manager.payload().as_str())?;
    assert_eq!(payload["Id"], "1");
    assert_eq!(payload["Name"], "Manager One");
    assert_eq!(payload["VirtualNICEnabled"], true);

    // The gateway fetches no document beyond the default flow: both HPE
    // segments are embedded in the Service Root and Manager documents the
    // default flow already fetches, so no vendor URL is fabricated and no
    // request path carries an `Oem` segment (§11.5).
    let requests = mock.requests();
    assert_eq!(
        mock.requests_served(),
        HPE_RESOURCE_READ_REQUEST_COUNT,
        "the HPE read must issue exactly the default request count"
    );
    assert!(
        requests
            .iter()
            .all(|request| !request.path().contains("/Oem/")),
        "the embedded HPE segments must not be fetched through a vendor URL"
    );
    let manager_index = requests
        .iter()
        .position(|request| request.path() == "/redfish/v1/Managers/1")
        .ok_or_else(|| io::Error::other("Managers/1 is missing from the request log"))?;
    assert_eq!(
        requests[manager_index].header("x-auth-token"),
        Some("test-session-token"),
        "the HPE read must authenticate with the Session token"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

/// An endpoint that serves no vendor namespace — the default profile — must
/// leave both the AMI and HPE read families absent: the §11.3 advertised
/// layer reports `oem-ami` and `oem-hpe` `NotAdvertised`, the read tree
/// carries no AMI or HPE snapshot, and no AMI/HPE request is fabricated
/// (the failure guard of §11.5's no-fabricated-URL rule).
#[tokio::test]
async fn namespace_free_endpoint_leaves_ami_and_hpe_families_absent() -> Result<(), Box<dyn Error>>
{
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;
    // The default tree serves no `Oem.Ami` / `Oem.Hpe` namespace anywhere,
    // so the probe must report both OEM capabilities `NotAdvertised`.
    assert_capability_state(
        discovery.capabilities(),
        EndpointCapability::OemAmi,
        CapabilityState::NotAdvertised,
    )?;
    assert_capability_state(
        discovery.capabilities(),
        EndpointCapability::OemHpe,
        CapabilityState::NotAdvertised,
    )?;

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();
    // The read tree stays the default 28-resource tree: none of the four
    // AMI/HPE resource features may appear.
    assert_eq!(resources.len(), 28);
    assert!(
        resources.iter().all(|resource| !matches!(
            resource.feature(),
            ResourceFeature::OemAmiServiceRoot
                | ResourceFeature::OemAmiConfigBmc
                | ResourceFeature::OemHpeILoServiceExt
                | ResourceFeature::OemHpeManager
        )),
        "a namespace-free endpoint must carry no AMI or HPE snapshot"
    );
    // The combined flow stays at the default request counts (the default
    // tree shares the no-OEM request counts): no AMI/HPE fetch is
    // fabricated.
    assert_eq!(
        mock.requests_served(),
        NO_OEM_PROBE_REQUEST_COUNT + NO_OEM_RESOURCE_READ_REQUEST_COUNT,
        "an AMI/HPE-free endpoint must issue exactly the default request count"
    );
    Ok(())
}

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with the `LiteOn` or Delta profile: the 34 requests of the default
/// profile plus three for the modern `PowerSubsystem` power-supplies probe
/// (the subsystem document, the `PowerSupplies` collection, and the one
/// supply member — the §11.3 probe follows the typed link the profile's
/// chassis advertises).
const POWER_SUPPLY_PROFILE_PROBE_REQUEST_COUNT: u64 = 37;

/// The gateway's request count for one complete `read_core_resources` flow
/// with the `LiteOn` or Delta profile: the 51 requests of the default
/// profile plus six for the `PowerSubsystem` power-supply chain (the
/// subsystem document, the `PowerSupplies` collection, and the one supply
/// member, fetched once for the standard `power-supplies` family and once
/// for the OEM family).
const POWER_SUPPLY_PROFILE_RESOURCE_READ_REQUEST_COUNT: u64 = 57;

// The complete `LiteOn` read surface is asserted in one test so the request
// count and the family coexistence stay one contract; splitting it would
// duplicate the pin/credentials flow. The infra crate allows the same lint
// on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn liteon_profile_reads_both_power_supply_families_with_distinct_identities()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::LiteOn).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // The `LiteOn` profile advertises exactly the `LiteOn` surface: the
    // chassis `Manufacturer` gate value flips `oem-liteon` to `Supported`;
    // no other vendor namespace is served, so every remaining OEM capability
    // stays `NotAdvertised` (§11.3 advertised layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemLiteOn => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("LiteOn"),
        "the probe must carry the LiteOn Service Root identity"
    );
    assert_eq!(
        mock.requests_served(),
        POWER_SUPPLY_PROFILE_PROBE_REQUEST_COUNT,
        "the power-supplies probe must fetch the subsystem chain exactly once"
    );

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The read surface adds exactly the two supply snapshots to the default
    // 28-resource tree: the standard `power-supplies` family and the §11.5
    // `LiteOn` family project the same supply document, and the `LiteOn`
    // snapshot carries its synthetic storage key, so both families land in
    // one inventory without a duplicate `@odata.id` (the failure the A16
    // audit found on real `LiteOn` shelves).
    assert_eq!(resources.len(), 30);
    let standard: Vec<&CoreResourceProjection> = resources
        .iter()
        .filter(|resource| resource.feature() == ResourceFeature::PowerSupplies)
        .collect();
    assert_eq!(standard.len(), 1);
    assert_eq!(
        standard[0].odata_id().as_str(),
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1"
    );
    let liteon: Vec<&CoreResourceProjection> = resources
        .iter()
        .filter(|resource| resource.feature() == ResourceFeature::OemLiteOnPowerSupply)
        .collect();
    assert_eq!(liteon.len(), 1);
    assert_eq!(
        liteon[0].odata_id().as_str(),
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1/Oem/LiteOn"
    );
    assert_ne!(standard[0].odata_id(), liteon[0].odata_id());
    let payload: serde_json::Value = serde_json::from_str(liteon[0].payload().as_str())?;
    assert_eq!(payload["Manufacturer"], "LITE-ON TECHNOLOGY CORP.");

    // The chain is fetched exactly once per family (three requests each),
    // and the transient Session is deleted before returning.
    assert_eq!(
        mock.requests_served(),
        POWER_SUPPLY_PROFILE_PROBE_REQUEST_COUNT + POWER_SUPPLY_PROFILE_RESOURCE_READ_REQUEST_COUNT,
        "the LiteOn read must issue exactly six requests beyond the default flow"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn delta_profile_reads_both_power_supply_families_with_distinct_identities()
-> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start_with_profile(MockProfile::Delta).await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;

    // The Delta profile advertises exactly the Delta surface: the chassis
    // `Oem.deltaenergysystems` namespace key flips `oem-delta` to
    // `Supported`; no other vendor namespace is served, so every remaining
    // OEM capability stays `NotAdvertised` (§11.3 advertised layer).
    for capability in OEM_CAPABILITY_LEDGER_ORDER {
        let expected = match capability {
            EndpointCapability::OemDelta => CapabilityState::Supported,
            _ => CapabilityState::NotAdvertised,
        };
        assert_capability_state(discovery.capabilities(), capability, expected)?;
    }
    assert_eq!(
        discovery.service_root().vendor(),
        Some("DELTA"),
        "the probe must carry the Delta Service Root identity"
    );
    assert_eq!(
        mock.requests_served(),
        POWER_SUPPLY_PROFILE_PROBE_REQUEST_COUNT,
        "the power-supplies probe must fetch the subsystem chain exactly once"
    );

    let outcome = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    let resources = outcome.projections();

    // The read surface adds exactly the two supply snapshots to the default
    // 28-resource tree: the standard `power-supplies` family and the §11.5
    // Delta family project the same supply document, and the Delta snapshot
    // carries its synthetic storage key, so both families land in one
    // inventory without a duplicate `@odata.id` (the failure the A16 audit
    // found on real Delta power shelves).
    assert_eq!(resources.len(), 30);
    let standard: Vec<&CoreResourceProjection> = resources
        .iter()
        .filter(|resource| resource.feature() == ResourceFeature::PowerSupplies)
        .collect();
    assert_eq!(standard.len(), 1);
    assert_eq!(
        standard[0].odata_id().as_str(),
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1"
    );
    let delta: Vec<&CoreResourceProjection> = resources
        .iter()
        .filter(|resource| resource.feature() == ResourceFeature::OemDeltaPowerSupply)
        .collect();
    assert_eq!(delta.len(), 1);
    assert_eq!(
        delta[0].odata_id().as_str(),
        "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1/Oem/deltaenergysystems"
    );
    assert_ne!(standard[0].odata_id(), delta[0].odata_id());
    let payload: serde_json::Value = serde_json::from_str(delta[0].payload().as_str())?;
    assert_eq!(payload["Power"], true);
    assert_eq!(payload["FanSpeedTarget"], 50);

    // The chain is fetched exactly once per family (three requests each),
    // and the transient Session is deleted before returning.
    assert_eq!(
        mock.requests_served(),
        POWER_SUPPLY_PROFILE_PROBE_REQUEST_COUNT + POWER_SUPPLY_PROFILE_RESOURCE_READ_REQUEST_COUNT,
        "the Delta read must issue exactly six requests beyond the default flow"
    );
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );
    Ok(())
}

#[tokio::test]
async fn no_oem_profiles_probe_every_oem_capability_not_advertised() -> Result<(), Box<dyn Error>> {
    for (profile, vendor, product) in NO_OEM_PROFILES {
        let mock = MockBmc::start_with_profile(profile).await?;
        let gateway = RedfishGateway::from_system_roots().await?;
        let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
        let (username, password) = credentials()?;

        let discovery = gateway
            .probe_core_capabilities(&address, &trust, &username, &password)
            .await?;

        // Same §2.1 inventory, same order, and the same served standard
        // surface as the default profile: a no-OEM profile swaps only the
        // identity strings, never the standard tree.
        assert_eq!(
            discovery.capabilities().len(),
            CAPABILITY_LEDGER_ORDER.len()
        );
        for (index, observation) in discovery.capabilities().iter().enumerate() {
            assert_eq!(
                observation.capability(),
                CAPABILITY_LEDGER_ORDER[index],
                "capability {index} must follow the §2.1 inventory order"
            );
        }
        for capability in CORE_CAPABILITIES_SUPPORTED {
            assert_capability_state(
                discovery.capabilities(),
                capability,
                CapabilityState::Supported,
            )?;
        }
        // The §21 0.5.0 standard-pattern verification: a vendor that serves
        // no `Oem` namespace must never mis-advertise another vendor's
        // surface, so every one of the 14 §2.1 OEM capabilities probes
        // `NotAdvertised` exactly like the default tree.
        for capability in OEM_CAPABILITY_LEDGER_ORDER {
            assert_capability_state(
                discovery.capabilities(),
                capability,
                CapabilityState::NotAdvertised,
            )?;
        }
        assert_eq!(
            discovery.service_root().vendor(),
            Some(vendor),
            "the probe must carry the {vendor} Service Root identity"
        );
        assert_eq!(
            discovery.service_root().product(),
            Some(product),
            "the probe must carry the {vendor} Service Root product"
        );
        assert_eq!(
            mock.requests_served(),
            NO_OEM_PROBE_REQUEST_COUNT,
            "a no-OEM namespace probe must fetch no document beyond the default flow"
        );
    }
    Ok(())
}

// The complete no-OEM read surface is asserted in one test so the
// 28-resource order stays one contract with the default profile; splitting
// it would duplicate the pin/credentials flow for both profiles. The infra
// crate allows the same lint on its fixture-sequence tests.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn no_oem_profiles_read_the_default_core_tree_without_oem_snapshots()
-> Result<(), Box<dyn Error>> {
    for (profile, vendor, _) in NO_OEM_PROFILES {
        let mock = MockBmc::start_with_profile(profile).await?;
        let gateway = RedfishGateway::from_system_roots().await?;
        let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
        let (username, password) = credentials()?;

        let outcome = gateway
            .read_core_resources(&address, &trust, &username, &password)
            .await?;
        let resources = outcome.projections();

        // The read surface is the default 28-resource tree with zero OEM
        // snapshots: the exact feature order of the default profile, so any
        // leaked vendor snapshot would break this list instead of drifting.
        assert_eq!(
            resources.len(),
            28,
            "a no-OEM profile must add no snapshot to the default tree"
        );
        let features: Vec<ResourceFeature> = resources
            .iter()
            .map(CoreResourceProjection::feature)
            .collect();
        assert_eq!(
            features,
            [
                ResourceFeature::ServiceRoot,
                ResourceFeature::Systems,
                ResourceFeature::Bios,
                ResourceFeature::BootOptions,
                ResourceFeature::SecureBoot,
                ResourceFeature::Processors,
                ResourceFeature::Processors,
                ResourceFeature::Memory,
                ResourceFeature::PcieDevices,
                ResourceFeature::Chassis,
                ResourceFeature::Power,
                ResourceFeature::Thermal,
                ResourceFeature::Sensors,
                ResourceFeature::Controls,
                ResourceFeature::Assembly,
                ResourceFeature::Managers,
                ResourceFeature::LogServices,
                ResourceFeature::ManagerNetworkProtocol,
                ResourceFeature::HostInterfaces,
                ResourceFeature::Accounts,
                ResourceFeature::SoftwareInventory,
                ResourceFeature::EventService,
                ResourceFeature::EventSubscription,
                ResourceFeature::TelemetryService,
                ResourceFeature::MetricDefinition,
                ResourceFeature::MetricReport,
                ResourceFeature::TaskService,
                ResourceFeature::Task,
            ]
        );
        assert_resource_identifiers(resources);

        // The gateway fetches no document beyond the default flow, through
        // the Session token transport like every other read, and deletes its
        // transient Session before returning.
        assert_eq!(
            mock.requests_served(),
            NO_OEM_RESOURCE_READ_REQUEST_COUNT,
            "a no-OEM read must issue exactly the default request count"
        );
        let requests = mock.requests();
        let system_index = requests
            .iter()
            .position(|request| request.path() == "/redfish/v1/Systems/1")
            .ok_or_else(|| io::Error::other("Systems/1 is missing from the request log"))?;
        assert_eq!(
            requests[system_index].header("x-auth-token"),
            Some("test-session-token"),
            "the {vendor} read must authenticate with the Session token"
        );
        assert_eq!(
            mock.active_sessions(),
            0,
            "the resource read must delete its transient Session before returning"
        );
    }
    Ok(())
}

/// The §0.3.0 account write surface: every one of the five typed operations
/// executes against the mock's account ledger and verifies through a
/// post-write re-read, exactly like the §13.3 flow drives them.
//
// The five operations each assert execution, ledger state, and verification
// in one flow, so the shared pin/credentials sequence runs once; the line
// count is the coverage.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn executes_and_verifies_all_five_account_write_operations() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    // Create: the ledger gains the account and the verification re-read
    // confirms the user name.
    let create = RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
        AccountUserName::parse("jane")?,
        AccountPassword::parse("initial-secret".to_owned())?,
        RoleId::parse("Operator")?,
    )));
    assert_eq!(
        gateway
            .execute_command(&address, &trust, &username, &password, &create)
            .await?,
        CommandExecutionOutcome::Accepted
    );
    assert_eq!(mock.account_ids(), ["admin", "user-1"]);
    assert_eq!(
        mock.account("user-1").ok_or("created account")?.user_name(),
        "jane"
    );
    assert_eq!(
        gateway
            .verify_command(&address, &trust, &username, &password, &create)
            .await?,
        CommandVerificationOutcome::Confirmed
    );

    // Role update: the ledger reflects the new role and the verification
    // re-read confirms it.
    let role = RedfishCommand::Account(AccountCommand::UpdateAccount(UpdateAccount::new(
        AccountId::parse("admin")?,
        RoleId::parse("Operator")?,
    )));
    assert_eq!(
        gateway
            .execute_command(&address, &trust, &username, &password, &role)
            .await?,
        CommandExecutionOutcome::Accepted
    );
    assert_eq!(
        mock.account("admin").ok_or("admin account")?.role_id(),
        "Operator"
    );
    assert_eq!(
        gateway
            .verify_command(&address, &trust, &username, &password, &role)
            .await?,
        CommandVerificationOutcome::Confirmed
    );

    // Password change: accepted, and the verification re-read confirms the
    // member stays readable (the CSDL password property is write-only).
    let password_change = RedfishCommand::Account(AccountCommand::UpdateAccountPassword(
        UpdateAccountPassword::new(
            AccountId::parse("admin")?,
            AccountPassword::parse("new-secret".to_owned())?,
        ),
    ));
    assert_eq!(
        gateway
            .execute_command(&address, &trust, &username, &password, &password_change)
            .await?,
        CommandExecutionOutcome::Accepted
    );
    assert_eq!(
        gateway
            .verify_command(&address, &trust, &username, &password, &password_change)
            .await?,
        CommandVerificationOutcome::Confirmed
    );

    // Rename: the ledger reflects the new user name and the verification
    // re-read confirms it.
    let rename = RedfishCommand::Account(AccountCommand::UpdateAccountUserName(
        UpdateAccountUserName::new(
            AccountId::parse("admin")?,
            AccountUserName::parse("admin.renamed")?,
        ),
    ));
    assert_eq!(
        gateway
            .execute_command(&address, &trust, &username, &password, &rename)
            .await?,
        CommandExecutionOutcome::Accepted
    );
    assert_eq!(
        mock.account("admin").ok_or("admin account")?.user_name(),
        "admin.renamed"
    );
    assert_eq!(
        gateway
            .verify_command(&address, &trust, &username, &password, &rename)
            .await?,
        CommandVerificationOutcome::Confirmed
    );

    // Delete: the ledger drops the account and the verification re-read
    // confirms the absence.
    let delete = RedfishCommand::Account(AccountCommand::DeleteAccount(DeleteAccount::new(
        AccountId::parse("admin")?,
    )));
    assert_eq!(
        gateway
            .execute_command(&address, &trust, &username, &password, &delete)
            .await?,
        CommandExecutionOutcome::Accepted
    );
    assert_eq!(mock.account_ids(), ["user-1"]);
    assert_eq!(
        gateway
            .verify_command(&address, &trust, &username, &password, &delete)
            .await?,
        CommandVerificationOutcome::Confirmed
    );

    assert_eq!(
        mock.active_sessions(),
        0,
        "every command must delete its transient Session before returning"
    );
    Ok(())
}

/// A member write targeting an account the endpoint does not hold is refused
/// provably, before any write request is sent.
#[tokio::test]
async fn refuses_account_member_writes_for_an_unknown_account() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let (address, trust) = pin_mock_identity(&gateway, &mock).await?;
    let (username, password) = credentials()?;

    let outcome = gateway
        .execute_command(
            &address,
            &trust,
            &username,
            &password,
            &RedfishCommand::Account(AccountCommand::DeleteAccount(DeleteAccount::new(
                AccountId::parse("ghost")?,
            ))),
        )
        .await;

    assert!(matches!(
        outcome,
        Err(CommandExecutionError::Rejected(
            CommandRejection::RefusedByBmc
        ))
    ));
    assert_eq!(mock.account_ids(), ["admin"]);
    assert_eq!(
        mock.active_sessions(),
        0,
        "the refused write must still delete its transient Session"
    );
    Ok(())
}
