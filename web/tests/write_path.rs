#![forbid(unsafe_code)]

//! End-to-end Axum tests for the 0.1 write paths: credential creation, the
//! trust-first onboarding flow, CSV import, and the audit query.
//!
//! Every application boundary is served by an in-memory fake so the Web
//! Router is exercised without persistence or network access.

use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    sync::{Arc, Mutex},
};

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt as _;
use rutilus_application::{
    AuditEventWriter, BoundaryFuture, Clock, CoreResourceReader, CredentialCreationRepository,
    CredentialInventoryRepository, CredentialResolver, CredentialSecretProtector,
    DiscoveredEndpointRepository, EndpointInventoryItem, EndpointInventoryRepository,
    EndpointRefreshRepository, ProtectedCredentialCreation, RedfishDiscovery, ResolvedCredential,
    ResourceObservation, SystemCaEvaluation, TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    AuditActor, AuditEvent, CapabilityState, Credential, CredentialId, CredentialName,
    CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapability, EndpointCapabilityObservation, EndpointDisplayName, EndpointId,
    RefreshGeneration, ResourceFeature, ResourceId, ResourceODataId, ResourceSnapshot,
    ResourceSnapshotPayload, TlsCertificate, TlsTrust,
};
use rutilus_web::{AuditEventQuery, WebProductInfo, router};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const CREDENTIAL_ID: &str = "0198e29f-7800-7000-8000-000000000001";

#[derive(Default)]
struct MockState {
    audit_events: Vec<AuditEvent>,
    credentials: Vec<Credential>,
    endpoints: Vec<Endpoint>,
    commits: usize,
}

/// Implements every application boundary behind the injected services bundle.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
    inventory: Result<Vec<EndpointInventoryItem>, MockError>,
    accept_protection: bool,
    credentials_available: bool,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>) -> Self {
        Self {
            state,
            inventory: Ok(Vec::new()),
            accept_protection: true,
            credentials_available: true,
        }
    }
}

/// Implements every Redfish boundary exercised by the trust and enrollment
/// flows without opening a socket.
#[derive(Clone)]
struct MockGateway {
    certificate: TlsCertificate,
    evaluation: SystemCaEvaluation,
}

impl MockGateway {
    fn verified(certificate: TlsCertificate) -> Self {
        Self {
            certificate,
            evaluation: SystemCaEvaluation::Verified,
        }
    }

    fn rejected(certificate: TlsCertificate) -> Self {
        Self {
            certificate,
            evaluation: SystemCaEvaluation::Rejected,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockError {
    Lock,
    Protection,
    Probe,
    Persistence,
}

impl fmt::Display for MockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lock => "mock state is unavailable",
            Self::Protection => "mock protection failed",
            Self::Probe => "mock TLS probe failed",
            Self::Persistence => "mock persistence failed",
        })
    }
}

impl Error for MockError {}

#[derive(Clone, Copy)]
struct MockProtected {
    credential_id: CredentialId,
    version_id: CredentialVersionId,
}

impl CredentialSecretProtector for MockServices {
    type Protected = MockProtected;
    type Error = MockError;

    fn protect(
        &self,
        credential_id: CredentialId,
        version_id: CredentialVersionId,
        _password: SecretString,
    ) -> Result<Self::Protected, Self::Error> {
        if !self.accept_protection {
            return Err(MockError::Protection);
        }
        Ok(MockProtected {
            credential_id,
            version_id,
        })
    }
}

impl CredentialCreationRepository<MockProtected> for MockServices {
    type Error = MockError;

    fn create_credential(
        &self,
        creation: ProtectedCredentialCreation<MockProtected>,
    ) -> BoundaryFuture<'_, Result<Credential, Self::Error>> {
        Box::pin(async move {
            let (credential_id, version_id, name, username, protected, created_at) =
                creation.into_parts();
            if protected.credential_id != credential_id || protected.version_id != version_id {
                return Err(MockError::Protection);
            }
            let credential = Credential::try_new(
                credential_id,
                name,
                username,
                version_id,
                created_at,
                created_at,
            )
            .map_err(|_| MockError::Persistence)?;
            self.state
                .lock()
                .map_err(|_| MockError::Lock)?
                .credentials
                .push(credential.clone());
            Ok(credential)
        })
    }
}

impl CredentialInventoryRepository for MockServices {
    type Error = MockError;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .credentials
                .clone())
        })
    }
}

impl CredentialResolver for MockServices {
    type Error = MockError;

    fn resolve(
        &self,
        _credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        Box::pin(async move {
            if !self.credentials_available {
                return Ok(None);
            }
            let username =
                CredentialUsername::parse("administrator").map_err(|_| MockError::Lock)?;
            Ok(Some(ResolvedCredential::new(
                username,
                String::from("in-memory secret").into(),
            )))
        })
    }
}

impl EndpointInventoryRepository for MockServices {
    type Error = MockError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        Box::pin(async { self.inventory.clone() })
    }
}

impl DiscoveredEndpointRepository for MockServices {
    type Error = MockError;

    fn create_discovered_endpoint<'a>(
        &'a self,
        endpoint: Endpoint,
        _observations: &'a [EndpointCapabilityObservation],
    ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
        Box::pin(async move {
            self.state
                .lock()
                .map_err(|_| MockError::Lock)?
                .endpoints
                .push(endpoint.clone());
            Ok(endpoint)
        })
    }
}

impl EndpointRefreshRepository for MockServices {
    type Error = MockError;

    fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|_| MockError::Lock)?;
            Ok(state
                .endpoints
                .iter()
                .find(|endpoint| endpoint.id() == endpoint_id)
                .cloned())
        })
    }

    fn commit_resource_generation<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [ResourceObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| MockError::Lock)?;
            state.commits += 1;
            let generation = RefreshGeneration::new(1).map_err(|_| MockError::Persistence)?;
            Ok(observations
                .iter()
                .map(|observation| {
                    ResourceSnapshot::new(
                        ResourceId::generate(),
                        endpoint_id,
                        observation.feature(),
                        observation.odata_id().clone(),
                        observation.payload().clone(),
                        observed_at,
                        generation,
                    )
                })
                .collect())
        })
    }
}

impl AuditEventWriter for MockServices {
    type Error = MockError;

    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.state
                .lock()
                .map_err(|_| MockError::Lock)?
                .audit_events
                .push(event.clone());
            Ok(())
        })
    }
}

impl AuditEventQuery for MockServices {
    type Error = MockError;

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<AuditEvent>, Self::Error>> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|_| MockError::Lock)?;
            let take = usize::try_from(limit.get()).map_err(|_| MockError::Lock)?;
            Ok(state
                .audit_events
                .iter()
                .rev()
                .take(take)
                .cloned()
                .collect())
        })
    }
}

impl TlsIdentityProbe for MockGateway {
    type Error = MockError;

    fn observe<'a>(
        &'a self,
        address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
        Box::pin(async move {
            match address.as_url().host_str() {
                Some("probe-fail.example.test") => Err(MockError::Probe),
                Some("pin.example.test") => Ok(TlsIdentityObservation::new(
                    self.certificate.clone(),
                    SystemCaEvaluation::Rejected,
                )),
                _ => Ok(TlsIdentityObservation::new(
                    self.certificate.clone(),
                    self.evaluation,
                )),
            }
        })
    }
}

impl RedfishDiscovery for MockGateway {
    type Error = MockError;

    fn probe_core_capabilities<'a>(
        &'a self,
        _address: &'a EndpointAddress,
        _trust: &'a TlsTrust,
        _username: &'a CredentialUsername,
        _password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<rutilus_application::EndpointDiscovery, Self::Error>> {
        Box::pin(async {
            Ok(rutilus_application::EndpointDiscovery::new(vec![
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::Supported,
                ),
            ]))
        })
    }
}

impl CoreResourceReader for MockGateway {
    type Error = MockError;

    fn read_core_resources<'a>(
        &'a self,
        _address: &'a EndpointAddress,
        _trust: &'a TlsTrust,
        _username: &'a CredentialUsername,
        _password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
        Box::pin(async {
            Ok(vec![
                ResourceObservation::new(
                    ResourceFeature::Systems,
                    ResourceODataId::parse("/redfish/v1/Systems/1")
                        .map_err(|_| MockError::Probe)?,
                    ResourceSnapshotPayload::parse(r#"{"Name":"System"}"#)
                        .map_err(|_| MockError::Probe)?,
                ),
                ResourceObservation::new(
                    ResourceFeature::Managers,
                    ResourceODataId::parse("/redfish/v1/Managers/1")
                        .map_err(|_| MockError::Probe)?,
                    ResourceSnapshotPayload::parse(r#"{"Name":"Manager"}"#)
                        .map_err(|_| MockError::Probe)?,
                ),
            ])
        })
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }
}

fn test_router(services: MockServices, gateway: MockGateway) -> Router {
    router(
        WebProductInfo::new("0.1.0-test", "0.13.0-test"),
        AuditActor::LocalOperator,
        DeploymentPosture::Standalone,
        Arc::new(services),
        Arc::new(gateway),
        FixedClock,
    )
}

async fn post_json(
    router: &Router,
    path: &str,
    body: Value,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?)
}

async fn get(router: &Router, path: &str) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(Request::get(path).body(Body::empty())?)
        .await?)
}

async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

#[tokio::test]
async fn creates_credentials_without_echoing_secrets() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"credential test certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    let response = post_json(
        &router,
        "/api/v1/credentials",
        json!({
            "name": "Rack administrators",
            "username": "administrator",
            "password": "never render this secret"
        }),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let body = json_body(response).await?;
    assert!(body["credential_id"].as_str().is_some());
    assert_eq!(body["name"], "Rack administrators");
    assert_eq!(body["username"], "administrator");
    assert_eq!(body["created_at"], "1970-01-01T00:00:00Z");
    let encoded = serde_json::to_string(&body)?;
    assert!(!encoded.contains("password"));
    assert!(!encoded.contains("never render this secret"));
    Ok(())
}

#[tokio::test]
async fn lists_credentials_with_secret_free_metadata() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"credential inventory certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    let empty = get(&router, "/api/v1/credentials").await?;
    assert_eq!(empty.status(), axum::http::StatusCode::OK);
    assert_eq!(json_body(empty).await?, json!({ "credentials": [] }));

    let created = post_json(
        &router,
        "/api/v1/credentials",
        json!({
            "name": "Rack administrators",
            "username": "administrator",
            "password": "in-memory secret"
        }),
    )
    .await?;
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);

    let listed = get(&router, "/api/v1/credentials").await?;
    assert_eq!(listed.status(), axum::http::StatusCode::OK);
    let body = json_body(listed).await?;
    let credentials = body["credentials"]
        .as_array()
        .ok_or("credentials must be an array")?;
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0]["name"], "Rack administrators");
    assert_eq!(credentials[0]["username"], "administrator");
    assert_eq!(credentials[0]["created_at"], "1970-01-01T00:00:00Z");
    assert!(credentials[0]["credential_id"].as_str().is_some());
    let encoded = serde_json::to_string(&body)?;
    assert!(!encoded.contains("password"));
    assert!(!encoded.contains("in-memory secret"));
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_credential_requests() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"credential validation certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    let empty_password = post_json(
        &router,
        "/api/v1/credentials",
        json!({
            "name": "Empty password",
            "username": "administrator",
            "password": ""
        }),
    )
    .await?;
    assert_eq!(empty_password.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = json_body(empty_password).await?;
    assert_eq!(body["message"], "credential password is invalid");

    let invalid_name = post_json(
        &router,
        "/api/v1/credentials",
        json!({
            "name": "bad\u{0000}name",
            "username": "administrator",
            "password": "valid secret"
        }),
    )
    .await?;
    assert_eq!(invalid_name.status(), axum::http::StatusCode::BAD_REQUEST);

    let unknown_field = post_json(
        &router,
        "/api/v1/credentials",
        json!({
            "name": "Rack administrators",
            "username": "administrator",
            "password": "valid secret",
            "remember": true
        }),
    )
    .await?;
    assert_eq!(
        unknown_field.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );
    assert!(
        state
            .lock()
            .map_err(|_| MockError::Lock)?
            .endpoints
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn begins_trust_with_a_secret_free_challenge() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"trust test certificate".to_vec())?;
    let expected_fingerprint = certificate.fingerprint().to_string();

    let trusted = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate.clone()),
    );
    let response = post_json(
        &trusted,
        "/api/v1/endpoints/trust",
        json!({ "address": "https://192.0.2.10" }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["address"], "https://192.0.2.10/");
    assert_eq!(body["fingerprint_sha256"], expected_fingerprint);
    assert_eq!(body["observed_at"], "1970-01-01T00:00:00Z");
    assert_eq!(body["state"], "system_ca_trusted");

    let pin = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::rejected(certificate),
    );
    let response = post_json(
        &pin,
        "/api/v1/endpoints/trust",
        json!({ "address": "https://192.0.2.11" }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["state"], "explicit_pin_required");
    assert_eq!(body["fingerprint_sha256"], expected_fingerprint);

    let bad_address = post_json(
        &trusted,
        "/api/v1/endpoints/trust",
        json!({ "address": "not-an-address" }),
    )
    .await?;
    assert_eq!(bad_address.status(), axum::http::StatusCode::BAD_REQUEST);

    let unreachable = post_json(
        &trusted,
        "/api/v1/endpoints/trust",
        json!({ "address": "https://probe-fail.example.test" }),
    )
    .await?;
    assert_eq!(unreachable.status(), axum::http::StatusCode::BAD_GATEWAY);
    Ok(())
}

#[tokio::test]
async fn confirms_declared_trust_expectations() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"expectation test certificate".to_vec())?;
    let different = TlsCertificate::from_der(b"different expectation certificate".to_vec())?;

    let trusted = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate.clone()),
    );
    let response = post_json(
        &trusted,
        "/api/v1/endpoints/trust/expect",
        json!({
            "address": "https://192.0.2.20",
            "trust": { "mode": "system_ca" }
        }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["address"], "https://192.0.2.20/");
    assert_eq!(body["tls_trust_mode"], "system_ca");
    assert_eq!(body["trusted_at"], "1970-01-01T00:00:00Z");

    let pinned = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::rejected(certificate.clone()),
    );
    let response = post_json(
        &pinned,
        "/api/v1/endpoints/trust/expect",
        json!({
            "address": "https://192.0.2.21",
            "trust": {
                "mode": "pinned_certificate",
                "fingerprint_sha256": certificate.fingerprint().to_string()
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["tls_trust_mode"], "pinned_certificate");

    let rejected = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::rejected(certificate.clone()),
    );
    let response = post_json(
        &rejected,
        "/api/v1/endpoints/trust/expect",
        json!({
            "address": "https://192.0.2.22",
            "trust": { "mode": "system_ca" }
        }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    let body = json_body(response).await?;
    assert_eq!(body["expected_fingerprint_sha256"], Value::Null);
    assert_eq!(
        body["observed_fingerprint_sha256"],
        certificate.fingerprint().to_string()
    );

    let mismatch = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::rejected(certificate.clone()),
    );
    let response = post_json(
        &mismatch,
        "/api/v1/endpoints/trust/expect",
        json!({
            "address": "https://192.0.2.23",
            "trust": {
                "mode": "pinned_certificate",
                "fingerprint_sha256": different.fingerprint().to_string()
            }
        }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    let body = json_body(response).await?;
    assert_eq!(
        body["expected_fingerprint_sha256"],
        different.fingerprint().to_string()
    );
    assert_eq!(
        body["observed_fingerprint_sha256"],
        certificate.fingerprint().to_string()
    );
    Ok(())
}

#[tokio::test]
async fn enrolls_a_trusted_endpoint_and_records_its_audit_trail() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"enrollment test certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    let response = post_json(
        &router,
        "/api/v1/endpoints",
        json!({
            "display_name": "Rack A BMC",
            "address": "https://192.0.2.30",
            "trust": { "mode": "system_ca" },
            "credential_id": CREDENTIAL_ID
        }),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    let endpoint_id = body["endpoint_id"]
        .as_str()
        .ok_or("enrollment must return an endpoint_id")?;
    assert_eq!(body["initial_generation"], 1);
    assert_eq!(body["resource_counts"]["systems"], 1);
    assert_eq!(body["resource_counts"]["chassis"], 0);
    assert_eq!(body["resource_counts"]["managers"], 1);

    {
        let state = state.lock().map_err(|_| MockError::Lock)?;
        assert_eq!(state.audit_events.len(), 5);
        assert_eq!(state.endpoints.len(), 1);
        assert_eq!(state.commits, 1);
        assert_eq!(
            state.endpoints[0].id().to_string(),
            endpoint_id,
            "the persisted endpoint must match the enrollment response"
        );
    }

    let audit = get(&router, "/api/v1/audit?limit=10").await?;
    assert_eq!(audit.status(), axum::http::StatusCode::OK);
    let audit_body = json_body(audit).await?;
    let events = audit_body["events"]
        .as_array()
        .ok_or("audit must return an events array")?;
    assert_eq!(events.len(), 5);
    assert_eq!(events[0]["outcome"]["kind"], "succeeded");
    assert_eq!(events[0]["action"], "refresh-endpoint");
    assert_eq!(events[0]["target"]["kind"], "endpoint");
    assert_eq!(events[0]["target"]["identifier"], endpoint_id);
    assert_eq!(events[0]["actor"], "local-operator");
    assert_eq!(
        events[0]["message"],
        format!(
            "local-operator refresh-endpoint succeeded for endpoint {endpoint_id} (sequence 2)"
        )
    );
    assert_eq!(events[4]["outcome"]["kind"], "started");
    assert!(
        events[4]["message"]
            .as_str()
            .ok_or("audit message must exist")?
            .contains("enroll-endpoint started")
    );
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_or_unknown_enrollment_state() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"enrollment rejection certificate".to_vec())?;
    let different = TlsCertificate::from_der(b"different enrollment certificate".to_vec())?;

    let bad_name = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate.clone()),
    );
    let response = post_json(
        &bad_name,
        "/api/v1/endpoints",
        json!({
            "display_name": "bad\u{0000}name",
            "address": "https://192.0.2.31",
            "trust": { "mode": "system_ca" },
            "credential_id": CREDENTIAL_ID
        }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);

    let missing_credential = MockServices {
        credentials_available: false,
        ..MockServices::new(Arc::clone(&state))
    };
    let router = test_router(
        missing_credential,
        MockGateway::verified(certificate.clone()),
    );
    let response = post_json(
        &router,
        "/api/v1/endpoints",
        json!({
            "display_name": "Rack A BMC",
            "address": "https://192.0.2.31",
            "trust": { "mode": "system_ca" },
            "credential_id": CREDENTIAL_ID
        }),
    )
    .await?;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );
    let body = json_body(response).await?;
    assert!(
        body["message"]
            .as_str()
            .ok_or("error response must carry a message")?
            .contains("was not found")
    );

    let wrong_pin = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::rejected(certificate.clone()),
    );
    let response = post_json(
        &wrong_pin,
        "/api/v1/endpoints",
        json!({
            "display_name": "Rack A BMC",
            "address": "https://192.0.2.32",
            "trust": {
                "mode": "pinned_certificate",
                "fingerprint_sha256": different.fingerprint().to_string()
            },
            "credential_id": CREDENTIAL_ID
        }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::CONFLICT);
    let body = json_body(response).await?;
    assert_eq!(
        body["observed_fingerprint_sha256"],
        certificate.fingerprint().to_string()
    );
    assert_eq!(
        state.lock().map_err(|_| MockError::Lock)?.endpoints.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn imports_csv_rows_with_independent_results() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"import test certificate".to_vec())?;
    let different = TlsCertificate::from_der(b"different import certificate".to_vec())?;
    let csv = format!(
        "display_name,address,credential_id,tls_sha256\n\
         Good,https://good.example.test,{CREDENTIAL_ID},\n\
         Wrong Pin,https://pin.example.test,{CREDENTIAL_ID},{}\n",
        different.fingerprint()
    );
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate.clone()),
    );

    let response = post_json(&router, "/api/v1/endpoints/import", json!({ "csv": csv })).await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["total_rows"], 2);
    assert_eq!(body["succeeded_count"], 1);
    assert_eq!(body["failed_count"], 1);
    let rows = body["rows"].as_array().ok_or("import must return rows")?;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["record_number"], 2);
    assert_eq!(rows[0]["address"], "https://good.example.test/");
    assert_eq!(rows[0]["status"], "enrolled");
    assert!(rows[0]["endpoint_id"].as_str().is_some());
    assert_eq!(rows[1]["status"], "trust_rejected");
    assert_eq!(rows[1]["endpoint_id"], Value::Null);
    assert!(
        rows[1]["message"]
            .as_str()
            .ok_or("rejected rows must carry a reason")?
            .contains("does not match expected Pin")
    );

    let state = state.lock().map_err(|_| MockError::Lock)?;
    assert_eq!(state.audit_events.len(), 9);
    assert_eq!(state.audit_events[0].outcome().kind().as_str(), "started");
    assert_eq!(
        state.audit_events[2].context().action().as_str(),
        "enroll-endpoint",
        "the enrolled row must carry its own audited enrollment operation"
    );
    assert_eq!(
        state.audit_events[8].outcome().kind().as_str(),
        "failed",
        "a partially failed batch must terminate as failed"
    );
    assert_eq!(state.endpoints.len(), 1);
    assert_eq!(state.commits, 1);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_csv_documents() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"csv validation certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    let response = post_json(
        &router,
        "/api/v1/endpoints/import",
        json!({ "csv": "address,display_name,credential_id,tls_sha256\n" }),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    let body = json_body(response).await?;
    assert_eq!(body["message"], "endpoint CSV is invalid");

    let response = post_json(
        &router,
        "/api/v1/endpoints/import",
        json!({ "csv": "", "file": "unexpected" }),
    )
    .await?;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );
    assert_eq!(
        state.lock().map_err(|_| MockError::Lock)?.endpoints.len(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn bounds_the_audit_query_limit() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"audit limit certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    for query in ["?limit=0", "?limit=1001", "?limit=abc", "?page=2"] {
        let response = get(&router, &format!("/api/v1/audit{query}")).await?;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "query {query} must be rejected"
        );
    }

    let response = get(&router, "/api/v1/audit?limit=1").await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(
        body["events"].as_array().ok_or("events must exist")?.len(),
        0
    );

    let response = get(&router, "/api/v1/audit").await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(
        body["events"].as_array().ok_or("events must exist")?.len(),
        0,
        "a missing limit must default to a bounded query"
    );
    Ok(())
}

#[test]
fn credential_identifiers_are_validated_domain_values() -> Result<(), Box<dyn Error>> {
    let name = CredentialName::parse("Rack administrators")?;
    let username = CredentialUsername::parse("administrator")?;

    assert_eq!(name.as_str(), "Rack administrators");
    assert_eq!(username.as_str(), "administrator");
    assert!(CredentialName::parse("").is_err());
    assert!(EndpointDisplayName::parse("").is_err());
    assert!(EndpointAddress::parse("https://admin:password@bmc.example.test").is_err());
    Ok(())
}
