#![forbid(unsafe_code)]

//! Integration tests driving the product `RedfishGateway` against the shared
//! Mock BMC, proving the §19.1 Mock-BMC test layer through public APIs only:
//! trust-first onboarding of the mock's self-signed identity, the Service
//! Root read, the complete 30-capability probe, the typed core resource read,
//! and the Session create/delete lifecycle.
//!
//! Every test starts its own `MockBmc` on an ephemeral port, so the suite is
//! self-contained: it needs no manual setup, no fixture files, and no
//! separately started `mock-bmc` binary (`cargo test -p rutilus-test-support`).

use std::{error::Error, io};

use rutilus_domain::{
    CAPABILITY_LEDGER_ORDER, CapabilityState, CredentialUsername, EndpointAddress,
    EndpointCapability, EndpointCapabilityObservation, ResourceFeature, TlsTrust,
};
use rutilus_infra_redfish::{CoreResourceProjection, RedfishGateway, SystemCaStatus};
use rutilus_test_support::{MockBmc, RequestRecord};
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
const CORE_CAPABILITIES_SUPPORTED: [EndpointCapability; 20] = [
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
async fn probes_all_thirty_capabilities_with_core_surface_supported() -> Result<(), Box<dyn Error>>
{
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

    let resources = gateway
        .read_core_resources(&address, &trust, &username, &password)
        .await?;

    // The mock serves one System with its configuration surface (Bios,
    // BootOptions, SecureBoot), two Processors, one Memory module, and one
    // PCIe device; one Chassis with its Power and Thermal singletons plus one
    // Sensor, one Control member, and one Assembly member; one Manager with
    // its LogServices, NetworkProtocol, and HostInterfaces surface; one
    // Account; and one SoftwareInventory member under the UpdateService;
    // typed navigation must visit every family exactly in the documented
    // read order.
    assert_eq!(resources.len(), 21);
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
        ]
    );

    assert_family_payloads(&resources)?;
    assert_resource_identifiers(&resources);
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
