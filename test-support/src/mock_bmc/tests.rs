//! Tests for the Mock BMC: deterministic identity, routing unit tests, and
//! the complete product flow driven through the real `RedfishGateway`.
//!
//! The gateway-level test is the crate's acceptance proof: it runs the exact
//! product request sequence (TLS observation, pinned trust, Session
//! lifecycle, 44-capability probe, typed core resource read, refresh)
//! against a live Mock BMC and asserts shapes, counts, and cleanup.

use std::{error::Error, io};

use rutilus_domain::{
    CAPABILITY_LEDGER_ORDER, CapabilityState, CertificateFingerprint, CredentialUsername,
    EndpointCapability, EndpointCapabilityObservation, OEM_CAPABILITY_LEDGER_ORDER,
    ResourceFeature, TlsTrust,
};
use rutilus_infra_redfish::{CoreResourceProjection, RedfishGateway, SystemCaStatus};
use secrecy::SecretString;
use time::OffsetDateTime;

use super::http::HttpMethod;
use super::route;
use super::{MockBmc, MockState};

/// The Mock BMC account; the fixture records any user name, so this is the
/// value the demo credentials should use.
const MOCK_USERNAME: &str = "admin";
const MOCK_PASSWORD: &str = "password";

/// The core 2.1 capabilities the fixture tree must serve as `Supported`.
const CORE_CAPABILITIES_SUPPORTED: [EndpointCapability; 23] = [
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
    // The 0.2 device-family read surface: `pcie-devices` is presence-only in
    // the probe (the System advertises its link array), while `assembly` and
    // `update-service` are probed through their documents.
    EndpointCapability::PcieDevices,
    EndpointCapability::Assembly,
    EndpointCapability::UpdateService,
    // The 0.2 service-family read surface: `event-service`,
    // `telemetry-service`, and `task-service` are probed through their
    // root-level service documents advertised by the Service Root.
    EndpointCapability::EventService,
    EndpointCapability::TelemetryService,
    EndpointCapability::TaskService,
];

/// Capabilities the fixture deliberately does not serve, which the probe
/// must report as `NotAdvertised` instead of guessing paths.
const CAPABILITIES_NOT_ADVERTISED: [EndpointCapability; 1] =
    [EndpointCapability::EthernetInterfaces];

/// The gateway's request count for one complete `read_core_resources` flow:
/// root, `SessionService`, Sessions collection, Session create, Systems
/// collection with member, `Bios` singleton, `BootOptions` collection with
/// member, `SecureBoot` singleton, Processors collection with CPU1 and CPU2,
/// Memory collection with DIMM1, the `PCIeDevices` member link fetch, Chassis
/// collection with member, `Power` singleton, `Thermal` singleton, `Sensors`
/// collection with member, `Controls` collection with member, `Assembly`
/// document plus its `AssemblyData` member fetch, Managers collection with
/// member, `LogServices` collection with member, `NetworkProtocol`
/// singleton, `HostInterfaces` collection with member, `AccountService` with
/// Accounts collection and member, `UpdateService` document with
/// `SoftwareInventory` collection and member, the `EventService` document
/// with its `Subscriptions` collection and member, the `TelemetryService`
/// document with its `MetricDefinitions` and `MetricReports` collections and
/// members, the `TaskService` document with its `Tasks` collection and
/// member, and the Session delete.
const RESOURCE_READ_REQUEST_COUNT: u64 = 51;

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with this fixture: root, `SessionService`, Sessions collection,
/// Session create, the three core collections with their members, the
/// Processors and Memory member fetches, the `Bios`, `BootOptions`, and
/// `SecureBoot` navigation (the `BootOptions` probe fetches only the
/// collection document, matching the `nv-redfish` wrapper), the `Power` and
/// `Thermal` singletons plus the `Sensors` collection document (the wrapper
/// keeps sensor members as lazy links), the `Controls` collection document
/// and its member (the wrapper's `controls()` accessor eagerly fetches
/// members), the `LogServices` collection document and its member (the
/// wrapper's `log_services()` accessor eagerly fetches members, unlike the
/// lazy `host_interfaces()` collection wrapper), the `NetworkProtocol`
/// document, the `HostInterfaces` collection document, the `AccountService`
/// document, the `EventService`, `TaskService`, and `TelemetryService`
/// documents (each advertised root service is probed through its document),
/// the `Assembly` document and the `UpdateService` document (the probe
/// fetches each advertised document; `pcie-devices` is presence-only and
/// adds no request), and the Session delete. Unadvertised features add no
/// requests.
const CAPABILITY_PROBE_REQUEST_COUNT: u64 = 34;

#[test]
fn deterministic_identity_reproduces_fingerprint_and_text() -> Result<(), Box<dyn Error>> {
    let first = super::tls::MockTlsIdentity::generate()?;
    let second = super::tls::MockTlsIdentity::generate()?;

    assert_eq!(first.certificate_der(), second.certificate_der());
    assert_eq!(first.fingerprint(), second.fingerprint());
    assert_eq!(
        first.fingerprint(),
        CertificateFingerprint::from_certificate_der(first.certificate_der())
    );

    let text = first.fingerprint_text();
    assert_eq!(text, first.fingerprint().to_string());
    assert_eq!(text.parse::<CertificateFingerprint>()?, first.fingerprint());
    assert_eq!(text.len(), 95);
    assert_eq!(
        text.chars().filter(|character| *character == ':').count(),
        31
    );
    Ok(())
}

#[test]
fn unregistered_paths_return_redfish_shaped_404() -> Result<(), Box<dyn Error>> {
    let state = MockState::new();

    let response = route::dispatch(HttpMethod::Get, "/redfish/v1/NotServed", &[], &state);

    assert_eq!(response.status, "404 Not Found");
    let body: serde_json::Value = serde_json::from_str(&response.body)?;
    assert_eq!(body["error"]["code"], "Base.1.0.ResourceMissingAtURI");
    assert!(body["error"]["message"].is_string());

    // A trailing slash is the same resource, not a separate path.
    let root = route::dispatch(HttpMethod::Get, "/redfish/v1/", &[], &state);
    assert_eq!(root.status, "200 OK");
    Ok(())
}

#[test]
fn session_create_returns_token_location_and_echoes_user() -> Result<(), Box<dyn Error>> {
    let state = MockState::new();

    let response = route::dispatch(
        HttpMethod::Post,
        "/redfish/v1/SessionService/Sessions",
        br#"{"UserName":"ops","Password":"secret"}"#,
        &state,
    );

    assert_eq!(response.status, "201 Created");
    assert_eq!(
        header_value(&response, "X-Auth-Token"),
        Some("test-session-token")
    );
    assert_eq!(
        header_value(&response, "Location"),
        Some("/redfish/v1/SessionService/Sessions/1")
    );
    let body: serde_json::Value = serde_json::from_str(&response.body)?;
    assert_eq!(body["Id"], "1");
    assert_eq!(body["UserName"], "ops");
    assert_eq!(state.active_sessions(), 1);
    Ok(())
}

#[test]
fn session_delete_removes_only_the_named_session() {
    let state = MockState::new();
    let create = |user: &str| {
        route::dispatch(
            HttpMethod::Post,
            "/redfish/v1/SessionService/Sessions",
            user.as_bytes(),
            &state,
        )
    };
    create("one");
    create("two");
    assert_eq!(state.active_sessions(), 2);

    let deleted = route::dispatch(
        HttpMethod::Delete,
        "/redfish/v1/SessionService/Sessions/1",
        &[],
        &state,
    );
    assert_eq!(deleted.status, "204 No Content");
    assert_eq!(state.active_sessions(), 1);

    // Deleting the same Session again is a 404, not a silent success.
    let again = route::dispatch(
        HttpMethod::Delete,
        "/redfish/v1/SessionService/Sessions/1",
        &[],
        &state,
    );
    assert_eq!(again.status, "404 Not Found");

    let second = route::dispatch(
        HttpMethod::Delete,
        "/redfish/v1/SessionService/Sessions/2",
        &[],
        &state,
    );
    assert_eq!(second.status, "204 No Content");
    assert_eq!(state.active_sessions(), 0);
}

#[tokio::test]
async fn mock_serves_the_complete_demo_flow_and_cleans_up() -> Result<(), Box<dyn Error>> {
    let mock = MockBmc::start().await?;
    let gateway = RedfishGateway::from_system_roots().await?;
    let address = mock.endpoint_address();

    // Trust-first observation: a fresh self-signed leaf can never validate
    // through system roots, and its identity must match the fingerprint the
    // mock advertises for the Pin dialog.
    let observation = gateway.observe_tls(&address).await?;
    assert_eq!(observation.system_ca_status(), SystemCaStatus::Rejected);
    assert_eq!(observation.certificate().fingerprint(), mock.fingerprint());
    let trust = TlsTrust::PinnedCertificate {
        certificate: observation.certificate().clone(),
        trusted_at: OffsetDateTime::now_utc(),
    };
    let username = CredentialUsername::parse(MOCK_USERNAME)?;
    let password = SecretString::from(MOCK_PASSWORD);

    // The 44-capability probe: exactly the §2.1 inventory in order (30
    // standard features followed by the 14 OEM features), with the served
    // surface `Supported`, the unserved standard surface `NotAdvertised`, and
    // every OEM capability `NotAdvertised` (the mock serves no vendor
    // namespace).
    let discovery = gateway
        .probe_core_capabilities(&address, &trust, &username, &password)
        .await?;
    assert_eq!(
        discovery.capabilities().len(),
        CAPABILITY_LEDGER_ORDER.len()
    );
    for (index, observation) in discovery.capabilities().iter().enumerate() {
        assert_eq!(
            observation.capability(),
            CAPABILITY_LEDGER_ORDER[index],
            "capability {index} must follow the 2.1 inventory order"
        );
    }
    for capability in CORE_CAPABILITIES_SUPPORTED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::Supported,
        )?;
    }
    for capability in CAPABILITIES_NOT_ADVERTISED {
        assert_capability_state(
            discovery.capabilities(),
            capability,
            CapabilityState::NotAdvertised,
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
        mock.active_sessions(),
        0,
        "the probe must delete its transient Session before returning"
    );

    // The typed core resource read: every family in the documented order.
    let resources = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    assert_resource_order(&resources);
    assert_surface_payloads(&resources)?;
    for resource in &resources {
        assert!(
            resource.etag().is_some(),
            "{} must carry its upstream ETag",
            resource.odata_id()
        );
    }
    assert_eq!(
        mock.active_sessions(),
        0,
        "the resource read must delete its transient Session before returning"
    );

    // A refresh repeats the same flow against the same fixture tree.
    let refreshed = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;
    assert_eq!(refreshed.len(), resources.len());
    assert_eq!(mock.active_sessions(), 0);

    // The whole demo flow is deterministic: probe + read + refresh.
    assert_eq!(
        mock.requests_served(),
        CAPABILITY_PROBE_REQUEST_COUNT + 2 * RESOURCE_READ_REQUEST_COUNT
    );
    mock.stop().await?;
    Ok(())
}

/// Asserts the typed resource projections arrive in the documented read
/// order with the fixture's exact identifiers.
fn assert_resource_order(resources: &[CoreResourceProjection]) {
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
    let odata_ids: Vec<&str> = resources
        .iter()
        .map(|resource| resource.odata_id().as_str())
        .collect();
    assert_eq!(
        odata_ids,
        [
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
        ]
    );
}

/// Asserts the typed field projections of every family, keeping the
/// demo-flow test short by moving every payload assertion behind one call.
fn assert_surface_payloads(resources: &[CoreResourceProjection]) -> Result<(), Box<dyn Error>> {
    assert_payload(
        &resources[2],
        "AttributeRegistry",
        "BiosAttributeRegistryP11.v1_2_0",
    )?;
    assert_payload(&resources[3], "DisplayName", "PXE Network Boot")?;
    assert_payload(&resources[4], "SecureBootMode", "UserMode")?;
    assert_payload(&resources[5], "TotalCores", "64")?;
    assert_payload(&resources[7], "CapacityMiB", "32768")?;
    assert_payload(&resources[15], "FirmwareVersion", "1.2.3")?;
    assert_payload(&resources[19], "RoleId", "Administrator")?;
    // The telemetry projections carry the readings and status exactly as
    // published: `Power_v1` has no projectable details, `Thermal_v1` only
    // status, and the sensor and control members their direct readings.
    let power_payload: serde_json::Value = serde_json::from_str(resources[10].payload().as_str())?;
    assert_eq!(power_payload["Name"], "Power");
    assert!(power_payload.get("PowerConsumedWatts").is_none());
    let thermal_payload: serde_json::Value =
        serde_json::from_str(resources[11].payload().as_str())?;
    assert_eq!(thermal_payload["Status"]["Health"], "OK");
    let sensor_payload: serde_json::Value = serde_json::from_str(resources[12].payload().as_str())?;
    assert_eq!(sensor_payload["Reading"], 27.5);
    assert_eq!(sensor_payload["ReadingUnits"], "Cel");
    assert_eq!(sensor_payload["ReadingType"], "Temperature");
    let control_payload: serde_json::Value =
        serde_json::from_str(resources[13].payload().as_str())?;
    assert_eq!(control_payload["SetPoint"], 30.0);
    assert_eq!(control_payload["ControlType"], "DutyCycle");
    // The manager surface projections carry the direct properties exactly as
    // published: the log service its enable flag and record capacity, the
    // network protocol singleton its host metadata, and the host interface
    // its interface state.
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
    // The device-family projections carry the direct properties exactly as
    // published: the PCIe device its type and hardware identifiers, the
    // assembly member its producer, and the software inventory its identity,
    // version, and typed release date.
    let pcie_payload: serde_json::Value = serde_json::from_str(resources[8].payload().as_str())?;
    assert_eq!(pcie_payload["DeviceType"], "SingleFunction");
    assert_eq!(pcie_payload["Manufacturer"], "Rutilus Test");
    assert_eq!(pcie_payload["Model"], "PCIE-GEN4-X16");
    let assembly_payload: serde_json::Value =
        serde_json::from_str(resources[14].payload().as_str())?;
    assert_eq!(assembly_payload["Id"], "0");
    assert_eq!(assembly_payload["Producer"], "Rutilus Test");
    let software_payload: serde_json::Value =
        serde_json::from_str(resources[20].payload().as_str())?;
    assert_eq!(software_payload["SoftwareId"], "BIOS-2026-1");
    assert_eq!(software_payload["Version"], "2.7.0");
    assert_eq!(software_payload["ReleaseDate"], "2026-05-01T00:00:00Z");
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

/// Asserts one typed field of a core resource projection.
fn assert_payload(
    projection: &CoreResourceProjection,
    field: &str,
    expected: &str,
) -> Result<(), Box<dyn Error>> {
    let payload: serde_json::Value = serde_json::from_str(projection.payload().as_str())?;
    let actual = match &payload[field] {
        serde_json::Value::String(value) => value.clone(),
        other => other.to_string(),
    };
    assert_eq!(
        actual,
        expected,
        "{} payload field {field}",
        projection.odata_id()
    );
    Ok(())
}

/// Asserts the observed state of one capability, naming the capability when
/// the probe drops an inventory entry.
fn assert_capability_state(
    observations: &[EndpointCapabilityObservation],
    capability: EndpointCapability,
    expected: CapabilityState,
) -> Result<(), Box<dyn Error>> {
    let observed = observations
        .iter()
        .find(|observation| observation.capability() == capability)
        .ok_or_else(|| io::Error::other(format!("{capability} is missing from the probe")))?;
    assert_eq!(observed.state(), expected, "{capability}");
    Ok(())
}

/// Looks up one response header by exact name.
fn header_value<'a>(response: &'a super::http::HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(header_name, _)| header_name == name)
        .map(|(_, value)| value.as_str())
}
