//! Method/path dispatch over the fixture tree, plus the Session ledger.
//!
//! The dispatch table is a pure function of (method, path, body, state) so
//! unit tests can exercise the 404 path and the Session lifecycle without
//! any network. The Session ledger is the only mutable resource state: the
//! product creates one transient Session per operation and deletes it before
//! returning, which the ledger records and the [`MockBmc::active_sessions`]
//! accessor exposes.

use serde_json::Value;

use super::MockState;
use super::fixtures;
use super::http::{HttpMethod, HttpResponse};

/// The path prefix of one Session resource inside the Session collection.
const SESSIONS_PREFIX: &str = "/redfish/v1/SessionService/Sessions/";

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
pub(crate) fn dispatch(
    method: HttpMethod,
    target: &str,
    body: &[u8],
    state: &MockState,
) -> HttpResponse {
    let path = target.trim_end_matches('/');
    match (method, path) {
        (HttpMethod::Get, "/redfish/v1") => json_ok(fixtures::SERVICE_ROOT),
        (HttpMethod::Get, "/redfish/v1/SessionService") => json_ok(fixtures::SESSION_SERVICE),
        (HttpMethod::Get, "/redfish/v1/SessionService/Sessions") => sessions_collection(state),
        (HttpMethod::Post, "/redfish/v1/SessionService/Sessions") => create_session(body, state),
        (HttpMethod::Delete, path) if path.starts_with(SESSIONS_PREFIX) => {
            delete_session(path, state)
        }
        (HttpMethod::Get, "/redfish/v1/AccountService") => json_ok(fixtures::ACCOUNT_SERVICE),
        (HttpMethod::Get, "/redfish/v1/AccountService/Accounts") => {
            json_ok(fixtures::ACCOUNTS_COLLECTION)
        }
        (HttpMethod::Get, "/redfish/v1/AccountService/Accounts/admin") => {
            json_ok(fixtures::ACCOUNT_ADMIN)
        }
        (HttpMethod::Get, "/redfish/v1/Systems") => json_ok(fixtures::SYSTEMS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Systems/1") => json_ok(fixtures::SYSTEM),
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
        (HttpMethod::Get, "/redfish/v1/Chassis") => json_ok(fixtures::CHASSIS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Chassis/1") => json_ok(fixtures::CHASSIS),
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
        (HttpMethod::Get, "/redfish/v1/Managers") => json_ok(fixtures::MANAGERS_COLLECTION),
        (HttpMethod::Get, "/redfish/v1/Managers/1") => json_ok(fixtures::MANAGER),
        _ => not_found(),
    }
}

fn json_ok(body: impl Into<String>) -> HttpResponse {
    HttpResponse::json("200 OK", body.into())
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
