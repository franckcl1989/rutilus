//! Method/path dispatch over the fixture tree, plus the Session ledger.
//!
//! The dispatch table is a pure function of (method, path, body, state) so
//! unit tests can exercise the 404 path and the Session lifecycle without
//! any network. The Session ledger is the only mutable resource state: the
//! product creates one transient Session per operation and deletes it before
//! returning, which the ledger records and the [`MockBmc::active_sessions`]
//! accessor exposes. The vendor profile (0.5.0) selects the profile-specific
//! fixture documents, and the vendor `Oem` routes are gated on it: the Dell
//! Attributes surface exists only under the Dell profile, so no vendor
//! namespace can leak into another profile's tree.

use serde_json::Value;

use super::MockState;
use super::fixtures;
use super::http::{HttpMethod, HttpResponse};
use super::profile::MockProfile;

/// The path prefix of one Session resource inside the Session collection.
const SESSIONS_PREFIX: &str = "/redfish/v1/SessionService/Sessions/";

/// The path prefix of one account resource inside the `Accounts` collection.
const ACCOUNTS_PREFIX: &str = "/redfish/v1/AccountService/Accounts/";

/// The fixed Session token issued on every successful creation.
///
/// The product treats the token as opaque, so a fixed value keeps
/// wire-sequence assertions deterministic; the same convention is already
/// proven in `rutilus-infra-redfish`'s own fixture responses.
const SESSION_TOKEN: &str = "test-session-token";

/// The user name recorded when a Session is created without a parseable
/// body, mirroring the fixture's well-known account.
const DEFAULT_USER_NAME: &str = "admin";

/// Routes one request to its fixture document or a Redfish-shaped 404.
///
/// The target is normalized by trimming a trailing slash so hand-typed URLs
/// behave like the links the product decodes. Paths the fixture tree does
/// not serve fall through to the 404 arm instead of failing the connection.
// The dispatch table is a pure (method, path) match whose arm count grows
// with the fixture tree, and the arms must stay in one place so the served
// surface reads as a single table; splitting the service-family routes into
// a helper would scatter the routing logic. The infra crate allows the same
// lint on its fixture-sequence tests, and the `204` action acceptances
// share one body by design.
#[allow(clippy::too_many_lines, clippy::match_same_arms)]
pub(crate) fn dispatch(
    method: HttpMethod,
    target: &str,
    body: &[u8],
    state: &MockState,
) -> HttpResponse {
    // The path is normalized by trimming a trailing slash and dropping the
    // query string, so hand-typed URLs and typed-client requests with
    // `$expand` behave like the links the product decodes — a real BMC
    // serves the same resource regardless of query parameters.
    let path = target
        .split('?')
        .next()
        .unwrap_or(target)
        .trim_end_matches('/');
    match (method, path) {
        (HttpMethod::Get, "/redfish/v1") => json_ok(fixtures::service_root(state.profile())),
        (HttpMethod::Get, "/redfish/v1/SessionService") => json_ok(fixtures::SESSION_SERVICE),
        (HttpMethod::Get, "/redfish/v1/SessionService/Sessions") => sessions_collection(state),
        (HttpMethod::Post, "/redfish/v1/SessionService/Sessions") => create_session(body, state),
        (HttpMethod::Delete, path) if path.starts_with(SESSIONS_PREFIX) => {
            delete_session(path, state)
        }
        (HttpMethod::Get, "/redfish/v1/AccountService") => json_ok(fixtures::ACCOUNT_SERVICE),
        // The §0.3.0 account write surface is served from the account
        // ledger, so a created, updated, renamed, or deleted account is
        // visible to the next read — exactly what the gateway's
        // post-write verification re-reads (§13.3 steps 9-10).
        (HttpMethod::Get, "/redfish/v1/AccountService/Accounts") => accounts_collection(state),
        (HttpMethod::Post, "/redfish/v1/AccountService/Accounts") => create_account(body, state),
        (HttpMethod::Get, path) if path.starts_with(ACCOUNTS_PREFIX) => account_member(path, state),
        (HttpMethod::Patch, path) if path.starts_with(ACCOUNTS_PREFIX) => {
            update_account(path, body, state)
        }
        (HttpMethod::Delete, path) if path.starts_with(ACCOUNTS_PREFIX) => {
            delete_account(path, state)
        }
        (HttpMethod::Get, "/redfish/v1/Systems") => json_ok(fixtures::SYSTEMS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Systems/1") => json_ok(fixtures::system(state.profile())),
        // The §11.5 NVIDIA system-config-profile chain is a vendor fixture:
        // it exists only under the NVIDIA profile, and any other profile
        // must 404 it like any unserved path instead of leaking a vendor
        // namespace. The chain root is reached through the `Oem.Nvidia`
        // segment's `SystemConfigProfile` navigation, so the routes mirror
        // the exact `@odata.id` values the fixture serves.
        (HttpMethod::Get, "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_SYSTEM_CONFIG_PROFILE)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_SYSTEM_CONFIG_PROFILE_STATUS)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_PROFILES_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_SYSTEM_PROFILE_1)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_SYSTEM_PROFILE_FILE_1)
        }
        // The §0.5.0 OEM write slice targets the debug-token and
        // power-smoothing chain documents through the same §11.5 navigation;
        // like the read chains, they exist only under the NVIDIA profile.
        (HttpMethod::Get, "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_DEBUG_TOKEN)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_DEBUG_TOKEN_MANAGEMENT)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_POWER_SMOOTHING)
        }
        // The §0.5.0 OEM write slice runs the typed actions the fixtures
        // advertise. The Update action answers `202 Accepted` with the
        // Task location (the async path of §13.6), the GenerateToken action
        // answers with the `BinaryTokenURI` entity, and every other action
        // answers `204`, exactly like the write responses the gateway's own
        // fixture sequences serve.
        (
            HttpMethod::Post,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Actions/NvidiaSystemConfigProfile.Update",
        ) if state.profile() == MockProfile::Nvidia => nvidia_update_task(),
        (
            HttpMethod::Post,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Actions/NvidiaSystemConfigProfile.FactoryReset",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (
            HttpMethod::Post,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/Actions/NvidiaSystemProfile.Activate",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (
            HttpMethod::Post,
            "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.GenerateToken",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(r#"{"BinaryTokenURI":"/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Token"}"#)
        }
        (
            HttpMethod::Post,
            "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.InstallToken",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (
            HttpMethod::Post,
            "/redfish/v1/Systems/1/Oem/Nvidia/CPUDebugToken/Actions/NvidiaDebugToken.DisableToken",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (
            HttpMethod::Post,
            "/redfish/v1/Managers/1/Oem/Nvidia/DebugTokenManagement/Actions/NvidiaDebugTokenManagement.EraseToken",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (
            HttpMethod::Post,
            "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing/Actions/NvidiaPowerSmoothing.ActivatePresetProfile",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (
            HttpMethod::Post,
            "/redfish/v1/Chassis/1/Oem/Nvidia/PowerSmoothing/Actions/NvidiaPowerSmoothing.ApplyAdminOverrides",
        ) if state.profile() == MockProfile::Nvidia => no_content(),
        (HttpMethod::Get, "/redfish/v1/Systems/1/Bios") => json_ok(fixtures::BIOS),
        (HttpMethod::Get, "/redfish/v1/Systems/1/BootOptions") => {
            json_ok(fixtures::BOOT_OPTIONS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/BootOptions/PXE-1") => {
            json_ok(fixtures::BOOT_OPTION_PXE1)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/SecureBoot") => json_ok(fixtures::SECURE_BOOT),
        (HttpMethod::Get, "/redfish/v1/Systems/1/Processors") => {
            json_ok(fixtures::PROCESSORS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/Processors/CPU1") => {
            json_ok(fixtures::PROCESSOR_CPU1)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/Processors/CPU2") => {
            json_ok(fixtures::PROCESSOR_CPU2)
        }
        (HttpMethod::Get, "/redfish/v1/Systems/1/Memory") => json_ok(fixtures::MEMORY_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Systems/1/Memory/DIMM1") => json_ok(fixtures::MEMORY_DIMM1),
        (HttpMethod::Get, "/redfish/v1/Systems/1/PCIeDevices/GPU1") => {
            json_ok(fixtures::PCIE_DEVICE_GPU1)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis") => json_ok(fixtures::CHASSIS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Chassis/1") => json_ok(fixtures::chassis(state.profile())),
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Power") => json_ok(fixtures::POWER),
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Thermal") => json_ok(fixtures::THERMAL),
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Sensors") => json_ok(fixtures::SENSORS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Sensors/InletTemp") => {
            json_ok(fixtures::SENSOR_INLET_TEMP)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Controls") => {
            json_ok(fixtures::CONTROLS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Controls/FanDuty") => {
            json_ok(fixtures::CONTROL_FAN_DUTY)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Assembly") => json_ok(fixtures::ASSEMBLY),
        // The `AssemblyData` member keeps its fragment-style `@odata.id` in
        // the payload, but the HTTP client percent-encodes the JSON-pointer
        // `#` when it builds the request URL, so the fixture is served under
        // the encoded path instead of letting the request fall through to
        // the 404 arm.
        (HttpMethod::Get, "/redfish/v1/Chassis/1/Assembly%23/Assemblies/0") => {
            json_ok(fixtures::ASSEMBLY_FAN)
        }
        (HttpMethod::Get, "/redfish/v1/Managers") => json_ok(fixtures::MANAGERS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Managers/1") => json_ok(fixtures::manager(state.profile())),
        // The §11.5 NVIDIA power-compliance and managed-entity chains are
        // vendor fixtures: they exist only under the NVIDIA profile, and any
        // other profile must 404 them like any unserved path instead of
        // leaking a vendor namespace. The chains are reached through the
        // `Oem.Nvidia` segment's `PowerCompliance` navigation and its
        // sub-navigations, so the routes mirror the exact `@odata.id` values
        // the fixture serves.
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_POWER_COMPLIANCE)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_POWER_DOMAINS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_POWER_DOMAIN_1)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_POWER_AC_LOSS_POLICY)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSUCompliancePolicy",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_POWER_PSU_COMPLIANCE_POLICY)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_MANAGED_ENTITY_GROUPS_COLLECTION)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_MANAGED_ENTITY_GROUP_1)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_MANAGED_ENTITIES_COLLECTION)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
        ) if state.profile() == MockProfile::Nvidia => json_ok(fixtures::NVIDIA_MANAGED_ENTITY_1),
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_POWER_STATE_GROUP)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_PSC_STATES_COLLECTION)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
        ) if state.profile() == MockProfile::Nvidia => json_ok(fixtures::NVIDIA_PSC_STATE_1),
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies",
        ) if state.profile() == MockProfile::Nvidia => {
            json_ok(fixtures::NVIDIA_PSU_STATES_COLLECTION)
        }
        (
            HttpMethod::Get,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
        ) if state.profile() == MockProfile::Nvidia => json_ok(fixtures::NVIDIA_PSU_STATE_1),
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy")
            if state.profile() == MockProfile::Nvidia =>
        {
            json_ok(fixtures::NVIDIA_PSU_REDUNDANCY)
        }
        // The §11.5 `DellAttributes` leaf is a vendor fixture: it exists only
        // under the Dell profile, and any other profile must 404 it like any
        // unserved path instead of leaking a vendor namespace.
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1")
            if state.profile() == MockProfile::Dell =>
        {
            json_ok(fixtures::DELL_ATTRIBUTES)
        }
        // The §11.5 Lenovo `SecurityService` document is a vendor fixture: it
        // exists only under the Lenovo profile, and any other profile must
        // 404 it like any unserved path instead of leaking a vendor
        // namespace. The document is reached through the `Oem.Lenovo`
        // segment's `Security` navigation, so the route mirrors the exact
        // `@odata.id` value the fixture serves.
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService")
            if state.profile() == MockProfile::Lenovo =>
        {
            json_ok(fixtures::LENOVO_SECURITY_SERVICE)
        }
        // The §11.5 AMI `ConfigBmc` document is a vendor fixture: it exists
        // only under the AMI profile, and any other profile must 404 it like
        // any unserved path instead of leaking a vendor namespace. The
        // document is reached through the `ConfigBMC` reference of the
        // manager's `Oem.Ami` segment, so the route mirrors the exact
        // `@odata.id` value the fixture serves.
        (HttpMethod::Get, "/redfish/v1/Managers/1/Oem/ConfigBMC")
            if state.profile() == MockProfile::Ami =>
        {
            json_ok(fixtures::AMI_CONFIG_BMC)
        }
        // The §11.5 LiteOn and Delta power-supply chains are vendor
        // fixtures: they exist only under their profiles, and any other
        // profile must 404 them like any unserved path instead of leaking a
        // vendor namespace. The chains are reached through the chassis's
        // `PowerSubsystem` navigation and its `PowerSupplies` collection, so
        // the routes mirror the exact `@odata.id` values the fixtures serve.
        (HttpMethod::Get, "/redfish/v1/Chassis/1/PowerSubsystem")
            if matches!(state.profile(), MockProfile::LiteOn | MockProfile::Delta) =>
        {
            json_ok(fixtures::POWER_SUBSYSTEM)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies")
            if matches!(state.profile(), MockProfile::LiteOn | MockProfile::Delta) =>
        {
            json_ok(fixtures::POWER_SUPPLIES_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1")
            if state.profile() == MockProfile::LiteOn =>
        {
            json_ok(fixtures::LITEON_POWER_SUPPLY_1)
        }
        (HttpMethod::Get, "/redfish/v1/Chassis/1/PowerSubsystem/PowerSupplies/1")
            if state.profile() == MockProfile::Delta =>
        {
            json_ok(fixtures::DELTA_POWER_SUPPLY_1)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/LogServices") => {
            json_ok(fixtures::LOG_SERVICES_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/LogServices/1") => json_ok(fixtures::LOG_SERVICE),
        (HttpMethod::Get, "/redfish/v1/Managers/1/NetworkProtocol") => {
            json_ok(fixtures::MANAGER_NETWORK_PROTOCOL)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/HostInterfaces") => {
            json_ok(fixtures::HOST_INTERFACES_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/Managers/1/HostInterfaces/1") => {
            json_ok(fixtures::HOST_INTERFACE)
        }
        (HttpMethod::Get, "/redfish/v1/UpdateService") => json_ok(fixtures::UPDATE_SERVICE),
        (HttpMethod::Get, "/redfish/v1/UpdateService/SoftwareInventory") => {
            json_ok(fixtures::SOFTWARE_INVENTORIES_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/UpdateService/SoftwareInventory/BIOS") => {
            json_ok(fixtures::SOFTWARE_INVENTORY_BIOS)
        }
        (HttpMethod::Get, "/redfish/v1/EventService") => json_ok(fixtures::EVENT_SERVICE),
        (HttpMethod::Get, "/redfish/v1/EventService/Subscriptions") => {
            json_ok(fixtures::EVENT_SUBSCRIPTIONS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/EventService/Subscriptions/1") => {
            json_ok(fixtures::EVENT_SUBSCRIPTION_1)
        }
        (HttpMethod::Get, "/redfish/v1/TelemetryService") => json_ok(fixtures::TELEMETRY_SERVICE),
        (HttpMethod::Get, "/redfish/v1/TelemetryService/MetricDefinitions") => {
            json_ok(fixtures::METRIC_DEFINITIONS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/TelemetryService/MetricDefinitions/1") => {
            json_ok(fixtures::METRIC_DEFINITION_1)
        }
        (HttpMethod::Get, "/redfish/v1/TelemetryService/MetricReports") => {
            json_ok(fixtures::METRIC_REPORTS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/TelemetryService/MetricReports/1") => {
            json_ok(fixtures::METRIC_REPORT_1)
        }
        (HttpMethod::Get, "/redfish/v1/TaskService") => json_ok(fixtures::TASK_SERVICE),
        (HttpMethod::Get, "/redfish/v1/TaskService/Tasks") => json_ok(fixtures::TASKS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/TaskService/Tasks/1") => json_ok(fixtures::TASK_1),
        _ => not_found(),
    }
}

fn json_ok(body: impl Into<String>) -> HttpResponse {
    HttpResponse::json("200 OK", body.into())
}

/// The `204` answer of one synchronously accepted action.
fn no_content() -> HttpResponse {
    HttpResponse::json("204 No Content", String::new())
}

/// The `202` Task acceptance of the profile Update action.
///
/// The `Location` names the Task the `TaskService` routes serve, and the body
/// is the Task document itself, mirroring a real BMC's async acceptance
/// (§13.6).
fn nvidia_update_task() -> HttpResponse {
    HttpResponse::json_with_headers(
        "202 Accepted",
        vec![(
            "Location".to_owned(),
            "/redfish/v1/TaskService/Tasks/1".to_owned(),
        )],
        fixtures::TASK_1.to_owned(),
    )
}

fn not_found() -> HttpResponse {
    HttpResponse::json("404 Not Found", fixtures::NOT_FOUND.to_owned())
}

/// Builds the Session collection document from the active ledger.
fn sessions_collection(state: &MockState) -> HttpResponse {
    let ids = state.lock_ledger().session_ids();
    let members = ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "@odata.id": format!("/redfish/v1/SessionService/Sessions/{id}")
            })
        })
        .collect::<Vec<_>>();
    let body = serde_json::json!({
        "@odata.type": "#SessionCollection.SessionCollection",
        "@odata.id": "/redfish/v1/SessionService/Sessions",
        "Name": "Session Collection",
        "Members": members,
    })
    .to_string();
    json_ok(body)
}

/// Creates one Session and answers with the token, Location, and document
/// the product's Session transport expects.
fn create_session(body: &[u8], state: &MockState) -> HttpResponse {
    let user_name = request_user_name(body);
    let session = state.lock_ledger().create(user_name);
    let id = session.id();
    HttpResponse::json_with_headers(
        "201 Created",
        vec![
            ("X-Auth-Token".to_owned(), SESSION_TOKEN.to_owned()),
            (
                "Location".to_owned(),
                format!("/redfish/v1/SessionService/Sessions/{id}"),
            ),
        ],
        session_body(id, &session.user_name),
    )
}

/// Deletes the named Session, answering 204 only when it existed.
fn delete_session(path: &str, state: &MockState) -> HttpResponse {
    let removed = path
        .strip_prefix(SESSIONS_PREFIX)
        .and_then(|id| id.parse::<u64>().ok())
        .is_some_and(|id| state.lock_ledger().delete(id));
    if removed {
        HttpResponse::json("204 No Content", String::new())
    } else {
        not_found()
    }
}

/// Extracts the requested user name from the Session creation payload,
/// falling back to the well-known fixture account when the body is not a
/// decodable Redfish Session request.
fn request_user_name(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| {
            value
                .get("UserName")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .unwrap_or_else(|| String::from(DEFAULT_USER_NAME))
}

/// Renders the created Session document.
fn session_body(id: u64, user_name: &str) -> String {
    serde_json::json!({
        "@odata.id": format!("/redfish/v1/SessionService/Sessions/{id}"),
        "@odata.type": "#Session.v1_4_0.Session",
        "Id": id.to_string(),
        "Name": "Rutilus Mock Session",
        "UserName": user_name,
    })
    .to_string()
}

/// Builds the `Accounts` collection document from the account ledger.
fn accounts_collection(state: &MockState) -> HttpResponse {
    let accounts = state.lock_accounts();
    let members = accounts
        .ids()
        .iter()
        .map(|id| {
            serde_json::json!({
                "@odata.id": format!("/redfish/v1/AccountService/Accounts/{id}")
            })
        })
        .collect::<Vec<_>>();
    let body = serde_json::json!({
        "@odata.type": "#ManagerAccountCollection.ManagerAccountCollection",
        "@odata.id": "/redfish/v1/AccountService/Accounts",
        "Name": "Account Collection",
        "Members": members,
    })
    .to_string();
    json_ok(body)
}

/// Serves one account member document from the ledger, or a Redfish-shaped
/// 404 when the account does not exist.
fn account_member(path: &str, state: &MockState) -> HttpResponse {
    let Some(id) = path.strip_prefix(ACCOUNTS_PREFIX) else {
        return not_found();
    };
    match state.lock_accounts().find(id) {
        Some(account) => json_ok(account_document(&account)),
        None => not_found(),
    }
}

/// Creates one account from the typed `ManagerAccountCreate` wire shape and
/// answers `201` with the created member document.
///
/// The id is assigned from a monotonic counter (`user-1`, `user-2`, ...);
/// the product never guesses or depends on the value — the gateway
/// verification re-reads the collection and matches by user name (§13.3).
fn create_account(body: &[u8], state: &MockState) -> HttpResponse {
    let Some(create) = serde_json::from_slice::<Value>(body).ok() else {
        return not_found();
    };
    let Some(user_name) = create.get("UserName").and_then(Value::as_str) else {
        return not_found();
    };
    let Some(role_id) = create.get("RoleId").and_then(Value::as_str) else {
        return not_found();
    };
    let account = state.lock_accounts().create(user_name, role_id);
    HttpResponse::json("201 Created", account_document(&account))
}

/// Applies one typed `ManagerAccountUpdate` shape to the named account and
/// answers `200` with the updated member document.
///
/// The `Password` property is accepted but never stored (the CSDL marks it
/// `null` in responses); `UserName` and `RoleId` updates are applied so a
/// rename or role change is visible to the next read.
fn update_account(path: &str, body: &[u8], state: &MockState) -> HttpResponse {
    let Some(id) = path.strip_prefix(ACCOUNTS_PREFIX) else {
        return not_found();
    };
    let Some(update) = serde_json::from_slice::<Value>(body).ok() else {
        return not_found();
    };
    let user_name = update.get("UserName").and_then(Value::as_str);
    let role_id = update.get("RoleId").and_then(Value::as_str);
    match state.lock_accounts().update(id, user_name, role_id) {
        Some(account) => json_ok(account_document(&account)),
        None => not_found(),
    }
}

/// Deletes the named account, answering `204` only when it existed.
fn delete_account(path: &str, state: &MockState) -> HttpResponse {
    let Some(id) = path.strip_prefix(ACCOUNTS_PREFIX) else {
        return not_found();
    };
    if state.lock_accounts().delete(id) {
        no_content()
    } else {
        not_found()
    }
}

/// Renders one ledger account as its `ManagerAccount` member document.
fn account_document(account: &MockAccount) -> String {
    serde_json::json!({
        "@odata.type": "#ManagerAccount.v1_12_0.ManagerAccount",
        "@odata.id": format!("/redfish/v1/AccountService/Accounts/{}", account.id),
        "@odata.etag": format!("W/\"account-{}\"", account.etag),
        "Id": account.id,
        "Name": format!("{} Account", account.user_name),
        "UserName": account.user_name,
        "RoleId": account.role_id,
        "Enabled": account.enabled,
        "Locked": account.locked,
        "AccountTypes": ["Redfish"],
    })
    .to_string()
}

/// The mock's account bookkeeping: the built-in `admin` account plus every
/// created account, so creation, update, deletion, and listing stay
/// consistent across the gateway's write-then-verify flows.
pub(crate) struct AccountLedger {
    next_id: u64,
    next_etag: u64,
    accounts: Vec<MockAccount>,
}

/// One account held by the mock, projected from the wire shapes it serves.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MockAccount {
    pub(crate) id: String,
    pub(crate) user_name: String,
    pub(crate) role_id: String,
    pub(crate) enabled: bool,
    pub(crate) locked: bool,
    etag: u64,
}

impl MockAccount {
    /// Returns the Redfish `Id` of the account.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the `UserName` of the account.
    #[must_use]
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    /// Returns the `RoleId` of the account.
    #[must_use]
    pub fn role_id(&self) -> &str {
        &self.role_id
    }

    /// Returns whether the account is enabled.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Returns whether the account is locked.
    #[must_use]
    pub const fn locked(&self) -> bool {
        self.locked
    }
}

impl AccountLedger {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            next_etag: 2,
            accounts: vec![MockAccount {
                id: "admin".to_owned(),
                user_name: "admin".to_owned(),
                role_id: "Administrator".to_owned(),
                enabled: true,
                locked: false,
                etag: 1,
            }],
        }
    }

    /// Returns the account ids in ledger order.
    pub(crate) fn ids(&self) -> Vec<String> {
        self.accounts
            .iter()
            .map(|account| account.id.clone())
            .collect()
    }

    /// Returns one account by id.
    pub(crate) fn find(&self, id: &str) -> Option<MockAccount> {
        self.accounts
            .iter()
            .find(|account| account.id == id)
            .cloned()
    }

    /// Creates one account with an assigned id.
    fn create(&mut self, user_name: &str, role_id: &str) -> MockAccount {
        let account = MockAccount {
            id: format!("user-{}", self.next_id),
            user_name: user_name.to_owned(),
            role_id: role_id.to_owned(),
            enabled: true,
            locked: false,
            etag: self.next_etag,
        };
        self.next_id += 1;
        self.next_etag += 1;
        self.accounts.push(account.clone());
        account
    }

    /// Applies one update to the named account; returns the updated account
    /// or `None` when the account does not exist.
    fn update(
        &mut self,
        id: &str,
        user_name: Option<&str>,
        role_id: Option<&str>,
    ) -> Option<MockAccount> {
        let account = self.accounts.iter_mut().find(|account| account.id == id)?;
        if let Some(user_name) = user_name {
            user_name.clone_into(&mut account.user_name);
        }
        if let Some(role_id) = role_id {
            role_id.clone_into(&mut account.role_id);
        }
        account.etag = self.next_etag;
        self.next_etag += 1;
        Some(account.clone())
    }

    /// Removes the named account; returns whether it existed.
    fn delete(&mut self, id: &str) -> bool {
        let before = self.accounts.len();
        self.accounts.retain(|account| account.id != id);
        self.accounts.len() != before
    }
}

impl Default for AccountLedger {
    fn default() -> Self {
        Self::new()
    }
}

/// The mock's Session bookkeeping: one monotonic id counter plus the active
/// Sessions, so creation, deletion, and listing stay consistent.
pub(crate) struct SessionLedger {
    next_id: u64,
    sessions: Vec<ActiveSession>,
}

/// One active Session held by the mock.
#[derive(Clone)]
struct ActiveSession {
    id: u64,
    user_name: String,
}

impl ActiveSession {
    fn id(&self) -> u64 {
        self.id
    }
}

impl SessionLedger {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            sessions: Vec::new(),
        }
    }

    /// Records a new Session and returns its id, starting at 1 per run.
    fn create(&mut self, user_name: String) -> ActiveSession {
        let session = ActiveSession {
            id: self.next_id,
            user_name,
        };
        self.next_id += 1;
        self.sessions.push(session.clone());
        session
    }

    /// Removes the named Session; returns whether it existed.
    fn delete(&mut self, id: u64) -> bool {
        let before = self.sessions.len();
        self.sessions.retain(|session| session.id != id);
        self.sessions.len() != before
    }

    pub(crate) fn count(&self) -> usize {
        self.sessions.len()
    }

    fn session_ids(&self) -> Vec<u64> {
        self.sessions.iter().map(|session| session.id).collect()
    }
}

impl Default for SessionLedger {
    fn default() -> Self {
        Self::new()
    }
}
