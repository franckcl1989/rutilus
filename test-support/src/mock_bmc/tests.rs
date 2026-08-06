//! Tests for the Mock BMC: deterministic identity, routing unit tests, and
//! the complete product flow driven through the real `RedfishGateway`.
//!
//! The gateway-level test is the crate's acceptance proof: it runs the exact
//! product request sequence (TLS observation, pinned trust, Session
//! lifecycle, 30-capability probe, typed core resource read, refresh)
//! against a live Mock BMC and asserts shapes, counts, and cleanup.

use std::{error::Error, io};

use rutilus_domain::{
    CAPABILITY_LEDGER_ORDER, CapabilityState, CertificateFingerprint, CredentialUsername,
    EndpointCapability, EndpointCapabilityObservation, ResourceFeature, TlsTrust,
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
const CORE_CAPABILITIES_SUPPORTED: [EndpointCapability; 10] = [
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
];

/// Capabilities the fixture deliberately does not serve, which the probe
/// must report as `NotAdvertised` instead of guessing paths.
const CAPABILITIES_NOT_ADVERTISED: [EndpointCapability; 4] = [
    EndpointCapability::EthernetInterfaces,
    EndpointCapability::Power,
    EndpointCapability::Thermal,
    EndpointCapability::UpdateService,
];

/// The gateway's request count for one complete `read_core_resources` flow:
/// root, `SessionService`, Sessions collection, Session create, Systems
/// collection + member, `Bios` singleton, `BootOptions` collection + member,
/// `SecureBoot` singleton, Processors collection + CPU1 + CPU2, Memory
/// collection + DIMM1, Chassis collection + member, Managers collection +
/// member, `AccountService` + Accounts collection + member, Session delete.
const RESOURCE_READ_REQUEST_COUNT: u64 = 23;

/// The gateway's request count for one complete `probe_core_capabilities`
/// flow with this fixture: root, `SessionService`, Sessions collection,
/// Session create, the three core collections with their members, the
/// Processors and Memory member fetches, the `Bios`, `BootOptions`, and
/// `SecureBoot` navigation (the `BootOptions` probe fetches only the
/// collection document, matching the `nv-redfish` wrapper), the
/// `AccountService` document, and the Session delete. Unadvertised features
/// add no requests.
const CAPABILITY_PROBE_REQUEST_COUNT: u64 = 20;

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

    // The 30-capability probe: exactly the 2.1 inventory in order, with the
    // served surface `Supported` and the unserved surface `NotAdvertised`.
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
    assert_payload(
        &resources[2],
        "AttributeRegistry",
        "BiosAttributeRegistryP11.v1_2_0",
    )?;
    assert_payload(&resources[3], "DisplayName", "PXE Network Boot")?;
    assert_payload(&resources[4], "SecureBootMode", "UserMode")?;
    assert_payload(&resources[5], "TotalCores", "64")?;
    assert_payload(&resources[7], "CapacityMiB", "32768")?;
    assert_payload(&resources[9], "FirmwareVersion", "1.2.3")?;
    assert_payload(&resources[10], "RoleId", "Administrator")?;
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
            ResourceFeature::Chassis,
            ResourceFeature::Managers,
            ResourceFeature::Accounts,
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
            "/redfish/v1/Chassis/1",
            "/redfish/v1/Managers/1",
            "/redfish/v1/AccountService/Accounts/admin",
        ]
    );
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
