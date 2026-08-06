#![forbid(unsafe_code)]

//! End-to-end Axum tests for the endpoint capability ledger read path.
//!
//! Every application boundary is served by an in-memory fake so the Web
//! Router is exercised without persistence or network access.

use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt as _;
use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository,
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialCreationRepository,
    CredentialInventoryRepository, CredentialResolver, CredentialSecretProtector,
    DiscoveredEndpointRepository, EndpointInventoryItem, EndpointInventoryRepository,
    EndpointRefreshRepository, EventRepository, OperationStore, ProtectedCredentialCreation,
    RedfishDiscovery, ResolvedCredential, ResourceObservation, StoredCapability,
    SystemCaEvaluation, TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, CAPABILITY_LEDGER_ORDER,
    CapabilityState, Credential, CredentialId, CredentialUsername, CredentialVersionId,
    DeploymentPosture, Endpoint, EndpointAddress, EndpointCapability,
    EndpointCapabilityObservation, EndpointDisplayName, EndpointId, Event, Operation, OperationId,
    OperationState, RefreshGeneration, ResourceFeature, ResourceId, ResourceODataId,
    ResourceSnapshot, ResourceSnapshotPayload, TlsCertificate, TlsTrust,
};
use rutilus_web::{AuditEventQuery, WebProductInfo, router};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

const CREDENTIAL_ID: &str = "0198e29f-7800-7000-8000-000000000002";

#[derive(Default)]
struct MockState {
    audit_events: Vec<AuditEvent>,
    credentials: Vec<Credential>,
    endpoints: Vec<Endpoint>,
    capabilities: Vec<StoredCapability>,
    commits: usize,
}

/// Implements every application boundary behind the injected services bundle.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
    inventory: Result<Vec<EndpointInventoryItem>, MockError>,
    accept_protection: bool,
    credentials_available: bool,
    capability_failure: bool,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>) -> Self {
        Self {
            state,
            inventory: Ok(Vec::new()),
            accept_protection: true,
            credentials_available: true,
            capability_failure: false,
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

impl EventRepository for MockServices {
    type Error = MockError;

    fn append_event<'a>(
        &'a self,
        _event: &'a Event,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_recent_events(
        &self,
        _limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// Serves one endpoint's stored capability observations exactly like the
/// store query: `None` for an unknown endpoint, the stored rows for a known
/// one, and a controlled failure when injected.
impl CapabilityQueryRepository for MockServices {
    type Error = MockError;

    fn find_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
        Box::pin(async move {
            if self.capability_failure {
                return Err(MockError::Persistence);
            }
            let state = self.state.lock().map_err(|_| MockError::Lock)?;
            let known = state
                .endpoints
                .iter()
                .any(|endpoint| endpoint.id() == endpoint_id);
            if !known {
                return Ok(None);
            }
            Ok(Some(state.capabilities.clone()))
        })
    }
}

/// Replaces the whole stored capability page exactly like the atomic store
/// write, so an enrolled endpoint's refresh re-probe is visible to the
/// capability read path.
impl CapabilitySnapshotRepository for MockServices {
    type Error = MockError;

    fn replace_endpoint_capabilities<'a>(
        &'a self,
        _endpoint_id: EndpointId,
        observations: &'a [EndpointCapabilityObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| MockError::Lock)?;
            state.capabilities = observations
                .iter()
                .map(|observation| StoredCapability::new(*observation, observed_at))
                .collect();
            Ok(())
        })
    }
}

impl TlsIdentityProbe for MockGateway {
    type Error = MockError;

    fn observe<'a>(
        &'a self,
        _address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
        Box::pin(async move {
            Ok(TlsIdentityObservation::new(
                self.certificate.clone(),
                self.evaluation,
            ))
        })
    }
}

/// The operation lifecycle boundary, required by the product-services bundle.
///
/// The capability read-path tests never submit operations, so every operation
/// call reports the controlled failure instead of mutating the mock state.
impl ArtifactRepository for MockServices {
    type Error = MockError;

    fn create_artifact<'a>(
        &'a self,
        _artifact: &'a Artifact,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn find_artifact(
        &self,
        _artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
        Box::pin(async { Ok(None) })
    }

    fn list_artifacts_by_state(
        &self,
        _state: ArtifactState,
    ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn update_artifact(
        &self,
        _artifact_id: ArtifactId,
        _uploaded_bytes: u64,
        _state: ArtifactState,
        _occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn artifact_file_path(&self, _artifact_id: ArtifactId) -> PathBuf {
        // The artifact paths are never exercised by this suite; the path
        // contract is covered by the artifact_path e2e tests.
        PathBuf::from("unused-artifact-path")
    }
}

impl OperationStore for MockServices {
    type Error = MockError;

    fn create_operation<'a>(
        &'a self,
        _operation: &'a Operation,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn find_operation(
        &self,
        _operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn apply_transition(
        &self,
        _operation_id: OperationId,
        _new_state: OperationState,
        _occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_operations(
        &self,
        _state: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
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
            Ok(vec![ResourceObservation::new(
                ResourceFeature::Systems,
                ResourceODataId::parse("/redfish/v1/Systems/1").map_err(|_| MockError::Probe)?,
                ResourceSnapshotPayload::parse(r#"{"Name":"System"}"#)
                    .map_err(|_| MockError::Probe)?,
            )])
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

fn known_endpoint() -> Result<Endpoint, Box<dyn Error>> {
    Ok(Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse("Capability BMC")?,
        EndpointAddress::parse("https://192.0.2.40")?,
        TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(b"capability test certificate".to_vec())?,
            trusted_at: OffsetDateTime::UNIX_EPOCH,
        },
        CredentialId::generate(),
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH,
    )?)
}

/// Builds one stored capability observation with the deterministic state and
/// second offset that the wire assertions expect.
fn stored_entry(
    capability: EndpointCapability,
    index: usize,
) -> Result<StoredCapability, MockError> {
    let observed_at = OffsetDateTime::UNIX_EPOCH
        + time::Duration::seconds(i64::try_from(index).map_err(|_| MockError::Persistence)?);
    Ok(StoredCapability::new(
        EndpointCapabilityObservation::new(capability, CapabilityState::Supported),
        observed_at,
    ))
}

#[tokio::test]
async fn lists_the_complete_capability_ledger_in_design_order() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    // The stored rows arrive reversed so the response order must come from
    // the ledger, not from the repository insertion order.
    let mut stored = Vec::new();
    for (index, capability) in CAPABILITY_LEDGER_ORDER.iter().enumerate() {
        stored.push(stored_entry(*capability, index)?);
    }
    stored.reverse();
    {
        let mut state = state.lock().map_err(|_| MockError::Lock)?;
        state.endpoints.push(endpoint);
        state.capabilities = stored;
    }
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(TlsCertificate::from_der(
            b"capability ledger certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/capabilities"),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    let body = json_body(response).await?;
    assert_eq!(body["endpoint_id"], endpoint_id.to_string());
    let entries = body["entries"]
        .as_array()
        .ok_or("entries must be an array")?;
    assert_eq!(
        entries.len(),
        CAPABILITY_LEDGER_ORDER.len(),
        "the complete §2.1 ledger must be served"
    );
    for (index, capability) in CAPABILITY_LEDGER_ORDER.iter().enumerate() {
        assert_eq!(
            entries[index]["capability"],
            capability.as_str(),
            "entry {index} must carry the stable product code"
        );
        assert_eq!(
            entries[index]["upstream_feature"],
            capability.upstream_feature()
        );
        let classification = if matches!(
            capability,
            EndpointCapability::SessionService | EndpointCapability::TaskService
        ) {
            "infrastructure"
        } else {
            "user_facing"
        };
        assert_eq!(entries[index]["classification"], classification);
        // The API serializes UI locations in snake_case ("secure_boot") while
        // the domain product code is kebab-case ("secure-boot").
        assert_eq!(
            entries[index]["ui_location"],
            capability.ui_location().as_str().replace('-', "_")
        );
        assert_eq!(entries[index]["state"], "supported");
        assert_eq!(
            entries[index]["observed_at"],
            format!("1970-01-01T00:00:{index:02}Z")
        );
    }
    Ok(())
}

#[tokio::test]
async fn distinguishes_capability_route_states() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    {
        let mut state = state.lock().map_err(|_| MockError::Lock)?;
        state.endpoints.push(endpoint);
    }
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(TlsCertificate::from_der(
            b"capability states certificate".to_vec(),
        )?),
    );

    let bad_id = get(&router, "/api/v1/endpoints/not-a-uuid/capabilities").await?;
    assert_eq!(bad_id.status(), axum::http::StatusCode::BAD_REQUEST);
    let missing = get(
        &router,
        &format!("/api/v1/endpoints/{}/capabilities", EndpointId::generate()),
    )
    .await?;
    assert_eq!(missing.status(), axum::http::StatusCode::NOT_FOUND);
    let wrong_method = router
        .clone()
        .oneshot(
            Request::post(format!("/api/v1/endpoints/{endpoint_id}/capabilities"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        wrong_method.status(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED
    );

    // A known endpoint without any completed probe must still serve the full
    // ledger, with every observed field absent.
    let waiting = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/capabilities"),
    )
    .await?;
    assert_eq!(waiting.status(), axum::http::StatusCode::OK);
    let body = json_body(waiting).await?;
    let entries = body["entries"]
        .as_array()
        .ok_or("entries must be an array")?;
    assert_eq!(entries.len(), CAPABILITY_LEDGER_ORDER.len());
    for entry in entries {
        assert_eq!(entry["state"], Value::Null);
        assert_eq!(entry["observed_at"], Value::Null);
    }
    Ok(())
}

#[tokio::test]
async fn reports_storage_failures_as_service_unavailable() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    {
        let mut state = state.lock().map_err(|_| MockError::Lock)?;
        state.endpoints.push(endpoint);
    }
    let failing = MockServices {
        capability_failure: true,
        ..MockServices::new(Arc::clone(&state))
    };
    let router = test_router(
        failing,
        MockGateway::verified(TlsCertificate::from_der(
            b"capability failure certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/capabilities"),
    )
    .await?;

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    Ok(())
}

#[tokio::test]
async fn reports_duplicate_observations_as_internal_error() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    {
        let mut state = state.lock().map_err(|_| MockError::Lock)?;
        state.endpoints.push(endpoint);
        // A corrupted store can repeat one capability across two rows; the
        // query boundary must surface the inconsistency as an internal fault
        // rather than guessing which observation wins.
        state.capabilities = vec![
            stored_entry(EndpointCapability::Systems, 0)?,
            stored_entry(EndpointCapability::Systems, 1)?,
        ];
    }
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(TlsCertificate::from_der(
            b"duplicate capability certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/capabilities"),
    )
    .await?;

    assert_eq!(
        response.status(),
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    Ok(())
}

#[tokio::test]
async fn serves_capabilities_for_a_newly_created_endpoint() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let certificate = TlsCertificate::from_der(b"enrollment capability certificate".to_vec())?;
    let router = test_router(
        MockServices::new(Arc::clone(&state)),
        MockGateway::verified(certificate),
    );

    let response = post_json(
        &router,
        "/api/v1/endpoints",
        json!({
            "display_name": "Rack A BMC",
            "address": "https://192.0.2.50",
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

    let capabilities = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/capabilities"),
    )
    .await?;
    assert_eq!(capabilities.status(), axum::http::StatusCode::OK);
    let body = json_body(capabilities).await?;
    assert_eq!(body["endpoint_id"], endpoint_id);
    let entries = body["entries"]
        .as_array()
        .ok_or("entries must be an array")?;
    assert_eq!(entries.len(), CAPABILITY_LEDGER_ORDER.len());
    assert_eq!(entries[0]["capability"], "accounts");
    assert_eq!(entries[29]["capability"], "update-service");
    assert_eq!(entries[0]["state"], Value::Null);
    Ok(())
}
