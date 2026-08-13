#![forbid(unsafe_code)]

//! End-to-end Axum tests for the 0.3 operation submission and query paths:
//! `POST /api/v1/operations`, `GET /api/v1/operations`, and
//! `GET /api/v1/operations/{operation_id}`.
//!
//! Every application boundary is served by an in-memory fake, with a real
//! in-memory operation store and endpoint list, so the Web Router is
//! exercised without persistence or network access.

use std::{
    collections::HashMap,
    error::Error,
    fmt, io,
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt as _;
use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository,
    CapabilitySnapshotRepository, ClassifiedBatchChild, Clock, CoreResourceReadOutcome,
    CoreResourceReader, CredentialCreationRepository, CredentialInventoryRepository,
    CredentialResolver, CredentialSecretProtector, DiscoveredEndpointRepository,
    EndpointInventoryItem, EndpointInventoryRepository, EndpointRefreshRepository, EventRepository,
    OperationStore, ProtectedCredentialCreation, RedfishDiscovery, ResolvedCredential,
    ResourceDecodeFailure, ResourceObservation, StoredCapability, TelemetryRepository,
    TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    AccountCommand, AccountPassword, AccountUserName, Artifact, ArtifactId, ArtifactState,
    AuditActor, AuditEvent, BatchOperation, BatchOperationId, CreateAccount, Credential,
    CredentialId, CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint,
    EndpointAddress, EndpointCapabilityObservation, EndpointDisplayName, EndpointId, Event,
    InstanceId, Operation, OperationId, OperationSource, OperationState, OperationTarget,
    PrincipalId, RedfishCommand, ResetType, ResourceODataId, ResourceSnapshot, RoleId, SeriesKey,
    SystemCommand, TargetId, TelemetrySample, TelemetrySeries, TelemetrySeriesId, TlsCertificate,
    TlsTrust,
};
use rutilus_web::{
    AuditEventQuery, CenterEndpointView, CenterOperationRefusal, CenterOperationView,
    CenterServices, CenterSiteView, DispatchedCenterOperation, RegisteredCenterSite,
    WebProductInfo, router,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

#[derive(Default)]
struct MockState {
    endpoints: Vec<Endpoint>,
    operations: HashMap<OperationId, Operation>,
    batches: HashMap<BatchOperationId, BatchOperation>,
    batch_children: HashMap<BatchOperationId, Vec<Operation>>,
}

/// Implements every application boundary behind the injected services bundle,
/// with a functioning in-memory operation store and endpoint list.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>) -> Self {
        Self { state }
    }
}

/// Implements the Redfish boundaries without opening a socket; the operation
/// paths never exercise them.
#[derive(Clone, Copy)]
struct MockGateway;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockError {
    Lock,
    Persistence,
}

impl fmt::Display for MockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lock => "mock state is unavailable",
            Self::Persistence => "mock persistence failed",
        })
    }
}

impl Error for MockError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MockProtected;

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

impl TelemetryRepository for MockServices {
    type Error = MockError;

    fn upsert_series<'a>(
        &'a self,
        _endpoint_id: EndpointId,
        _series_key: &'a SeriesKey,
    ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn append_sample<'a>(
        &'a self,
        _sample: &'a TelemetrySample,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_samples(
        &self,
        _series_id: TelemetrySeriesId,
        _limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn prune_before(&self, _cutoff: OffsetDateTime) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl OperationStore for MockServices {
    type Error = MockError;

    fn create_operation<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.state
                .lock()
                .map_err(|_| MockError::Lock)?
                .operations
                .entry(operation.id())
                .or_insert_with(|| operation.clone());
            Ok(())
        })
    }

    fn find_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .operations
                .get(&operation_id)
                .cloned())
        })
    }

    fn apply_transition(
        &self,
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| MockError::Lock)?;
            let row = state
                .operations
                .get(&operation_id)
                .ok_or(MockError::Persistence)?
                .clone();
            if row.is_terminal() {
                return Err(MockError::Persistence);
            }
            let updated = Operation::try_from_parts(
                row.id(),
                row.source(),
                row.targets().to_vec(),
                row.command(),
                new_state,
                row.created_at(),
                occurred_at,
            )
            .map_err(|_| MockError::Persistence)?;
            state.operations.insert(operation_id, updated);
            Ok(())
        })
    }

    fn apply_transition_if_current(
        &self,
        operation_id: OperationId,
        expected_state: OperationState,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| MockError::Lock)?;
            let row = state
                .operations
                .get(&operation_id)
                .ok_or(MockError::Persistence)?
                .clone();
            // The conditional transition writes only when the persisted state
            // is exactly the driver's expected in-flight state; a conflict
            // never writes anything (the driver's racing-state contract).
            if row.state() != expected_state {
                return Err(MockError::Persistence);
            }
            let updated = Operation::try_from_parts(
                row.id(),
                row.source(),
                row.targets().to_vec(),
                row.command(),
                new_state,
                row.created_at(),
                occurred_at,
            )
            .map_err(|_| MockError::Persistence)?;
            state.operations.insert(operation_id, updated);
            Ok(())
        })
    }

    fn list_operations(
        &self,
        state_filter: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .operations
                .values()
                .filter(|operation| state_filter.is_none_or(|state| operation.state() == state))
                .cloned()
                .collect())
        })
    }

    fn create_batch<'a>(
        &'a self,
        batch: &'a BatchOperation,
        children: &'a [Operation],
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.state.lock().map_err(|_| MockError::Lock)?;
            // At-least-once delivery (§15.4): a re-delivered batch id is a
            // no-op that never re-inserts the children.
            if state.batches.contains_key(&batch.id()) {
                return Ok(());
            }
            state.batches.insert(batch.id(), batch.clone());
            for child in children {
                state
                    .operations
                    .entry(child.id())
                    .or_insert_with(|| child.clone());
            }
            state.batch_children.insert(batch.id(), children.to_vec());
            Ok(())
        })
    }

    fn find_batch(
        &self,
        batch_id: BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .batches
                .get(&batch_id)
                .cloned())
        })
    }

    fn list_batches(&self) -> BoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
        Box::pin(async move {
            let mut batches = self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .batches
                .values()
                .cloned()
                .collect::<Vec<_>>();
            batches.sort_by_key(|batch| (batch.created_at(), batch.id()));
            Ok(batches)
        })
    }

    fn record_failure_kind(
        &self,
        _operation_id: OperationId,
        _kind: rutilus_domain::FailureKind,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        // The submission paths never classify failures; the executor's
        // refusal path owns that write, so this stub is unreachable here.
        Box::pin(async { Ok(()) })
    }

    fn list_batch_children(
        &self,
        batch_id: BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
        Box::pin(async move {
            let mut children = self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .batch_children
                .get(&batch_id)
                .cloned()
                .unwrap_or_default();
            // Target order (§13.7): each child carries exactly one target, so
            // ordering by that target's identity is a total order. The
            // submission paths never classify failures, so every child reads
            // back unclassified.
            children.sort_by_key(|child| child.targets().first().map(|target| target.target_id()));
            Ok(children.into_iter().map(|child| (child, None)).collect())
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
            Ok(self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .endpoints
                .iter()
                .find(|endpoint| endpoint.id() == endpoint_id)
                .cloned())
        })
    }

    fn commit_resource_generation<'a>(
        &'a self,
        _endpoint_id: EndpointId,
        _observations: &'a [ResourceObservation],
        _decode_failures: &'a [ResourceDecodeFailure],
        _observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl EndpointInventoryRepository for MockServices {
    type Error = MockError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl CredentialInventoryRepository for MockServices {
    type Error = MockError;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl CredentialSecretProtector for MockServices {
    type Protected = MockProtected;
    type Error = MockError;

    fn protect(
        &self,
        _credential_id: CredentialId,
        _version_id: CredentialVersionId,
        _password: SecretString,
    ) -> Result<Self::Protected, Self::Error> {
        Err(MockError::Persistence)
    }
}

impl CredentialCreationRepository<MockProtected> for MockServices {
    type Error = MockError;

    fn create_credential(
        &self,
        _creation: ProtectedCredentialCreation<MockProtected>,
    ) -> BoundaryFuture<'_, Result<Credential, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl CredentialResolver for MockServices {
    type Error = MockError;

    fn resolve(
        &self,
        _credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        Box::pin(async { Ok(None) })
    }
}

impl DiscoveredEndpointRepository for MockServices {
    type Error = MockError;

    fn create_discovered_endpoint<'a>(
        &'a self,
        _endpoint: Endpoint,
        _observations: &'a [EndpointCapabilityObservation],
    ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl AuditEventWriter for MockServices {
    type Error = MockError;

    fn append_audit_event<'a>(
        &'a self,
        _event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl AuditEventQuery for MockServices {
    type Error = MockError;

    fn list_recent_events(
        &self,
        _limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<AuditEvent>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
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

impl CapabilityQueryRepository for MockServices {
    type Error = MockError;

    fn find_endpoint_capabilities(
        &self,
        _endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl CapabilitySnapshotRepository for MockServices {
    type Error = MockError;

    fn replace_endpoint_capabilities<'a>(
        &'a self,
        _endpoint_id: EndpointId,
        _observations: &'a [EndpointCapabilityObservation],
        _observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl rutilus_application::GroupRepository for MockServices {
    type Error = MockError;

    fn create<'a>(
        &'a self,
        _group: &'a rutilus_domain::Group,
    ) -> rutilus_application::BoundaryFuture<'a, Result<rutilus_domain::Group, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn find(
        &self,
        _group_id: rutilus_domain::GroupId,
    ) -> rutilus_application::BoundaryFuture<'_, Result<Option<rutilus_domain::Group>, Self::Error>>
    {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list(
        &self,
    ) -> rutilus_application::BoundaryFuture<'_, Result<Vec<rutilus_domain::Group>, Self::Error>>
    {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn add_member(
        &self,
        _group_id: rutilus_domain::GroupId,
        _endpoint_id: rutilus_domain::EndpointId,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn remove_member(
        &self,
        _group_id: rutilus_domain::GroupId,
        _endpoint_id: rutilus_domain::EndpointId,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn delete(
        &self,
        _group_id: rutilus_domain::GroupId,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl rutilus_application::TagRepository for MockServices {
    type Error = MockError;

    fn assign<'a>(
        &'a self,
        _tag: &'a rutilus_domain::Tag,
    ) -> rutilus_application::BoundaryFuture<'a, Result<rutilus_domain::Tag, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn remove<'a>(
        &'a self,
        _endpoint_id: rutilus_domain::EndpointId,
        _tag_name: &'a rutilus_domain::TagName,
    ) -> rutilus_application::BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_for_endpoint(
        &self,
        _endpoint_id: rutilus_domain::EndpointId,
    ) -> rutilus_application::BoundaryFuture<'_, Result<Vec<rutilus_domain::Tag>, Self::Error>>
    {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_by_tag<'a>(
        &'a self,
        _tag_name: &'a rutilus_domain::TagName,
    ) -> rutilus_application::BoundaryFuture<'a, Result<Vec<rutilus_domain::Tag>, Self::Error>>
    {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl TlsIdentityProbe for MockGateway {
    type Error = MockError;

    fn observe<'a>(
        &'a self,
        _address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
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
        Box::pin(async { Err(MockError::Persistence) })
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
    ) -> BoundaryFuture<'a, Result<CoreResourceReadOutcome, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }
}

fn test_router(services: MockServices) -> Router {
    router(
        WebProductInfo::new("0.1.0-test", "0.13.0-test"),
        AuditActor::LocalOperator,
        DeploymentPosture::Standalone,
        Arc::new(services),
        Arc::new(MockGateway),
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

/// Builds the one managed endpoint the operation tests target.
fn managed_endpoint() -> Result<Endpoint, Box<dyn Error>> {
    let now = OffsetDateTime::UNIX_EPOCH;
    Ok(Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse("Rack A BMC")?,
        EndpointAddress::parse("https://192.0.2.10")?,
        TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(b"operation test certificate".to_vec())?,
            trusted_at: now,
        },
        CredentialId::generate(),
        now,
        now,
    )?)
}

#[tokio::test]
async fn submits_an_operation_and_echoes_the_queued_projection() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let response = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "targets": [endpoint.id().to_string()],
            "command": { "System": { "Reset": "PowerCycle" } }
        }),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    let body = json_body(response).await?;
    let operation_id = body["operation_id"]
        .as_str()
        .ok_or("submission must return an operation_id")?;
    assert_eq!(body["source"], "standalone");
    let targets = body["targets"]
        .as_array()
        .ok_or("submission must return targets")?;
    assert_eq!(targets.len(), 1);
    assert!(targets[0]["target_id"].as_str().is_some());
    assert_eq!(targets[0]["endpoint_id"], endpoint.id().to_string());
    assert_eq!(
        body["command"],
        json!({ "System": { "Reset": "PowerCycle" } })
    );
    assert_eq!(body["state"], "queued");
    assert_eq!(body["created_at"], "1970-01-01T00:00:00Z");
    assert_eq!(body["updated_at"], "1970-01-01T00:00:00Z");

    {
        let state = state.lock().map_err(|_| MockError::Lock)?;
        let stored = state
            .operations
            .get(&operation_id.parse::<OperationId>()?)
            .ok_or("the submitted operation must be persisted")?;
        assert_eq!(stored.state(), OperationState::Queued);
        assert_eq!(stored.source(), OperationSource::Standalone);
        assert_eq!(stored.targets().len(), 1);
        assert_eq!(
            stored.targets()[0].endpoint_id(),
            endpoint.id(),
            "the persisted target must bind the submitted endpoint"
        );
    }
    Ok(())
}

#[tokio::test]
async fn submits_an_account_operation_and_echoes_a_redacted_command() -> Result<(), Box<dyn Error>>
{
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let router = test_router(MockServices::new(Arc::clone(&state)));

    // An account creation rides the same typed command boundary as every
    // other §7.5 family: the route persists the payload verbatim, but the
    // echoed projection replaces the §10 password with the fixed redaction
    // marker (S3-1) — the secret never returns on the response wire.
    let response = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "targets": [endpoint.id().to_string()],
            "command": { "Account": { "CreateAccount": {
                "user_name": "jane",
                "password": "initial-secret",
                "role_id": "Operator"
            } } }
        }),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let body = json_body(response).await?;
    assert_eq!(
        body["command"],
        json!({ "Account": { "CreateAccount": {
            "user_name": "jane",
            "password": "[REDACTED]",
            "role_id": "Operator"
        } } })
    );
    assert_eq!(body["state"], "queued");
    assert!(
        !serde_json::to_string(&body)?.contains("initial-secret"),
        "the response wire must never carry the submitted password"
    );

    {
        let state = state.lock().map_err(|_| MockError::Lock)?;
        let operation_id = body["operation_id"]
            .as_str()
            .ok_or("submission must return an operation_id")?
            .parse::<OperationId>()?;
        let stored = state
            .operations
            .get(&operation_id)
            .ok_or("the submitted operation must be persisted")?;
        let RedfishCommand::Account(AccountCommand::CreateAccount(create)) = stored.command()
        else {
            return Err(io::Error::other(
                "the persisted command must be the submitted account creation",
            )
            .into());
        };
        assert_eq!(create.user_name().as_str(), "jane");
        assert_eq!(create.password().expose_secret(), "initial-secret");
        assert_eq!(create.role_id().as_str(), "Operator");
    }
    Ok(())
}

/// S3-1 regression: the Viewer-readable history routes — the operation
/// listing, the operation detail, and the batch report — project the command
/// structure but never the §10 account password, while the persisted
/// operations keep the full secret for execution.
// The walk covers the listing, the detail, and the batch report (parent and
// children), so the line count is the coverage.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn operation_history_routes_never_expose_account_passwords() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let services = MockServices::new(Arc::clone(&state));
    let router = test_router(services.clone());

    let now = OffsetDateTime::UNIX_EPOCH;
    let secret = "history-must-never-echo-this";
    let create = RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
        AccountUserName::parse("jane")?,
        AccountPassword::parse(secret.to_owned())?,
        RoleId::parse("Operator")?,
    )));
    let operation = Operation::try_from_parts(
        OperationId::generate(),
        OperationSource::Standalone,
        vec![OperationTarget::new(TargetId::generate(), endpoint.id())],
        create.clone(),
        OperationState::Succeeded,
        now,
        now,
    )?;
    services.create_operation(&operation).await?;
    let batch = BatchOperation::new(
        BatchOperationId::generate(),
        OperationSource::Site,
        create,
        now,
    );
    let child = Operation::try_from_parts(
        OperationId::generate(),
        OperationSource::Site,
        vec![OperationTarget::new(TargetId::generate(), endpoint.id())],
        batch.command(),
        OperationState::Succeeded,
        now,
        now,
    )?;
    services.create_batch(&batch, &[child]).await?;

    // The listing (RoleMask::ANY) keeps the command shape, redacts the secret.
    let listed = get(&router, "/api/v1/operations").await?;
    assert_eq!(listed.status(), axum::http::StatusCode::OK);
    let body = json_body(listed).await?;
    let listed_operations = body["operations"]
        .as_array()
        .ok_or("operations must be a list")?;
    assert_eq!(listed_operations.len(), 2);
    for operation in listed_operations {
        let text = serde_json::to_string(operation)?;
        assert!(
            !text.contains(secret),
            "the listing must never carry the password plaintext"
        );
        assert!(
            text.contains("[REDACTED]"),
            "the redaction marker must stand in for the password"
        );
        assert_eq!(
            operation["command"]["Account"]["CreateAccount"]["user_name"], "jane",
            "the non-secret command structure stays visible"
        );
    }

    // The detail pins the exact redacted command shape.
    let detail = get(&router, &format!("/api/v1/operations/{}", operation.id())).await?;
    assert_eq!(detail.status(), axum::http::StatusCode::OK);
    let body = json_body(detail).await?;
    assert_eq!(
        body["command"],
        json!({ "Account": { "CreateAccount": {
            "user_name": "jane",
            "password": "[REDACTED]",
            "role_id": "Operator"
        } } })
    );
    assert!(
        !serde_json::to_string(&body)?.contains(secret),
        "the operation detail must never carry the password plaintext"
    );

    // The batch report redacts the parent command and every child projection.
    let report = get(&router, &format!("/api/v1/batches/{}", batch.id())).await?;
    assert_eq!(report.status(), axum::http::StatusCode::OK);
    let body = json_body(report).await?;
    assert!(
        !serde_json::to_string(&body)?.contains(secret),
        "the batch report must never carry the password plaintext"
    );
    assert_eq!(
        body["command"]["Account"]["CreateAccount"]["password"],
        "[REDACTED]"
    );
    assert_eq!(
        body["children"][0]["command"]["Account"]["CreateAccount"]["password"], "[REDACTED]",
        "the batch children are ordinary operation projections and redact too"
    );
    assert_eq!(
        body["children"][0]["command"]["Account"]["CreateAccount"]["user_name"],
        "jane"
    );

    // The persisted commands keep the full secret for execution recovery.
    {
        let state = state.lock().map_err(|_| MockError::Lock)?;
        let stored = state
            .operations
            .get(&operation.id())
            .ok_or("the submitted operation must be persisted")?;
        let RedfishCommand::Account(AccountCommand::CreateAccount(create)) = stored.command()
        else {
            return Err(io::Error::other(
                "the persisted command must be the submitted account creation",
            )
            .into());
        };
        assert_eq!(
            create.password().expose_secret(),
            secret,
            "the persisted command must keep the password for execution"
        );
    }
    Ok(())
}

#[tokio::test]
async fn submits_a_batch_and_echoes_one_child_per_target() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let first = managed_endpoint()?;
    let second = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(first.clone());
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(second.clone());
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let response = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "source": "site",
            "targets": [first.id().to_string(), second.id().to_string()],
            "command": { "System": { "Reset": "PowerCycle" } }
        }),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    let body = json_body(response).await?;
    let batch_id = body["batch_id"]
        .as_str()
        .ok_or("batch submission must return a batch_id")?;
    assert_eq!(body["source"], "site");
    assert_eq!(
        body["command"],
        json!({ "System": { "Reset": "PowerCycle" } })
    );
    assert_eq!(body["created_at"], "1970-01-01T00:00:00Z");

    // The acknowledgement pairs every submitted endpoint with one child
    // operation id in the same order (§13.7), so the console can track each
    // write through an ordinary operation record.
    let targets = body["targets"]
        .as_array()
        .ok_or("batch submission must return targets")?;
    assert_eq!(targets.len(), 2);
    assert_eq!(targets[0], first.id().to_string());
    assert_eq!(targets[1], second.id().to_string());
    let children = body["child_operation_ids"]
        .as_array()
        .ok_or("batch submission must return child operation ids")?;
    assert_eq!(children.len(), 2);

    let state = state.lock().map_err(|_| MockError::Lock)?;
    let stored_batch = state
        .batches
        .get(&batch_id.parse::<BatchOperationId>()?)
        .ok_or("the submitted batch must be persisted")?;
    assert_eq!(stored_batch.source(), OperationSource::Site);
    // Every child is an ordinary single-target queued operation bound to its
    // own endpoint — never one multi-target operation wearing both.
    for (child_id, endpoint) in children.iter().zip([&first, &second]) {
        let child_id = child_id
            .as_str()
            .ok_or("child operation id must be a string")?
            .parse::<OperationId>()?;
        let child = state
            .operations
            .get(&child_id)
            .ok_or("the batch child must be persisted as an ordinary operation")?;
        assert_eq!(child.state(), OperationState::Queued);
        assert_eq!(child.targets().len(), 1);
        assert_eq!(child.targets()[0].endpoint_id(), endpoint.id());
    }
    Ok(())
}

#[tokio::test]
async fn rejects_an_over_limit_batch_without_persisting() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state)));
    let targets = (0..=128)
        .map(|_| {
            // Managed endpoints are not required to reach the limit check: it
            // fires before any endpoint lookup, exactly like the empty and
            // duplicate checks.
            EndpointId::generate().to_string()
        })
        .collect::<Vec<_>>();

    let response = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "targets": targets,
            "command": { "System": { "Reset": "PowerCycle" } }
        }),
    )
    .await?;

    assert_eq!(
        response.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "an over-limit batch must be rejected"
    );
    let body = json_body(response).await?;
    assert_eq!(
        body["message"],
        json!("a batch may target at most 128 endpoints")
    );
    assert_eq!(
        state.lock().map_err(|_| MockError::Lock)?.operations.len(),
        0,
        "every rejected submission must leave the store untouched"
    );
    assert_eq!(
        state.lock().map_err(|_| MockError::Lock)?.batches.len(),
        0,
        "every rejected submission must leave the store untouched"
    );
    Ok(())
}

#[tokio::test]
async fn accepts_an_explicit_operation_source() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let response = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "source": "center",
            "targets": [endpoint.id().to_string()],
            "command": { "Manager": { "Reset": "GracefulRestart" } }
        }),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    let body = json_body(response).await?;
    assert_eq!(body["source"], "center");
    assert_eq!(
        body["command"],
        json!({ "Manager": { "Reset": "GracefulRestart" } })
    );
    let stored = state
        .lock()
        .map_err(|_| MockError::Lock)?
        .operations
        .values()
        .next()
        .ok_or("the operation must be persisted")?
        .clone();
    assert_eq!(stored.source(), OperationSource::Center);
    Ok(())
}

#[tokio::test]
async fn rejects_malformed_operation_requests_without_persisting() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let router = test_router(MockServices::new(Arc::clone(&state)));
    let command = json!({ "System": { "Reset": "PowerCycle" } });

    let invalid_source = post_json(
        &router,
        "/api/v1/operations",
        json!({ "source": "cluster", "targets": [endpoint.id().to_string()], "command": command }),
    )
    .await?;
    assert_eq!(
        invalid_source.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "an unknown source must be rejected"
    );

    let empty_targets = post_json(
        &router,
        "/api/v1/operations",
        json!({ "targets": [], "command": command }),
    )
    .await?;
    assert_eq!(
        empty_targets.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "an empty target list must be rejected"
    );

    let duplicate_targets = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "targets": [endpoint.id().to_string(), endpoint.id().to_string()],
            "command": command
        }),
    )
    .await?;
    assert_eq!(
        duplicate_targets.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "a repeated endpoint must be rejected"
    );

    let unknown_endpoint = post_json(
        &router,
        "/api/v1/operations",
        json!({ "targets": [EndpointId::generate().to_string()], "command": command }),
    )
    .await?;
    assert_eq!(
        unknown_endpoint.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "a body-referenced unmanaged endpoint must be unprocessable"
    );
    let body = json_body(unknown_endpoint).await?;
    assert!(
        body["message"]
            .as_str()
            .ok_or("error response must carry a message")?
            .contains("is not a managed endpoint")
    );

    let invalid_target = post_json(
        &router,
        "/api/v1/operations",
        json!({ "targets": ["not-a-uuid"], "command": command }),
    )
    .await?;
    assert_eq!(
        invalid_target.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "a malformed target uuid must fail at deserialization"
    );

    let unknown_field = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "targets": [endpoint.id().to_string()],
            "command": command,
            "remember": true
        }),
    )
    .await?;
    assert_eq!(
        unknown_field.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY,
        "unknown request fields must be rejected"
    );

    assert_eq!(
        state.lock().map_err(|_| MockError::Lock)?.operations.len(),
        0,
        "every rejected submission must leave the store untouched"
    );
    Ok(())
}

#[tokio::test]
async fn lists_operations_with_an_optional_state_filter() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let services = MockServices::new(Arc::clone(&state));
    let router = test_router(services.clone());

    let empty = get(&router, "/api/v1/operations").await?;
    assert_eq!(empty.status(), axum::http::StatusCode::OK);
    assert_eq!(json_body(empty).await?, json!({ "operations": [] }));

    for source in ["standalone", "site"] {
        let response = post_json(
            &router,
            "/api/v1/operations",
            json!({
                "source": source,
                "targets": [endpoint.id().to_string()],
                "command": { "System": { "Reset": "PowerCycle" } }
            }),
        )
        .await?;
        assert_eq!(response.status(), axum::http::StatusCode::CREATED);
    }

    // One operation is parked in the asynchronous-acceptance phase directly in
    // the store, so the listing exercises the full state vocabulary.
    let now = OffsetDateTime::UNIX_EPOCH;
    let waiting = Operation::try_from_parts(
        OperationId::generate(),
        OperationSource::Standalone,
        vec![OperationTarget::new(TargetId::generate(), endpoint.id())],
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
        OperationState::WaitingRemote,
        now,
        now + Duration::SECOND,
    )?;
    services.create_operation(&waiting).await?;

    let all = get(&router, "/api/v1/operations").await?;
    assert_eq!(all.status(), axum::http::StatusCode::OK);
    let body = json_body(all).await?;
    let operations = body["operations"]
        .as_array()
        .ok_or("operations must be an array")?;
    assert_eq!(operations.len(), 3);
    for operation in operations {
        assert_eq!(
            operation["command"],
            json!({ "System": { "Reset": "PowerCycle" } })
        );
    }

    let queued = get(&router, "/api/v1/operations?state=queued").await?;
    let body = json_body(queued).await?;
    assert_eq!(
        body["operations"]
            .as_array()
            .ok_or("operations must be an array")?
            .len(),
        2
    );

    let waiting_remote = get(&router, "/api/v1/operations?state=waiting_remote").await?;
    let body = json_body(waiting_remote).await?;
    let operations = body["operations"]
        .as_array()
        .ok_or("operations must be an array")?;
    assert_eq!(operations.len(), 1);
    assert_eq!(operations[0]["state"], "waiting_remote");
    assert_eq!(operations[0]["operation_id"], waiting.id().to_string());

    let succeeded = get(&router, "/api/v1/operations?state=succeeded").await?;
    assert_eq!(succeeded.status(), axum::http::StatusCode::OK);
    assert_eq!(
        json_body(succeeded).await?,
        json!({ "operations": [] }),
        "a filter without matching operations must return an empty list"
    );

    for query in ["?state=bogus", "?state=", "?page=2", "?state=queued&page=1"] {
        let response = get(&router, &format!("/api/v1/operations{query}")).await?;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "query {query} must be rejected"
        );
    }
    Ok(())
}

#[tokio::test]
async fn reads_one_operation_detail() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = managed_endpoint()?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .push(endpoint.clone());
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let created = post_json(
        &router,
        "/api/v1/operations",
        json!({
            "targets": [endpoint.id().to_string()],
            "command": { "System": { "Reset": "PowerCycle" } }
        }),
    )
    .await?;
    assert_eq!(created.status(), axum::http::StatusCode::CREATED);
    let created_body = json_body(created).await?;
    let operation_id = created_body["operation_id"]
        .as_str()
        .ok_or("submission must return an operation_id")?
        .to_owned();

    let detail = get(&router, &format!("/api/v1/operations/{operation_id}")).await?;
    assert_eq!(detail.status(), axum::http::StatusCode::OK);
    assert_eq!(json_body(detail).await?, created_body);

    let missing = get(
        &router,
        &format!("/api/v1/operations/{}", OperationId::generate()),
    )
    .await?;
    assert_eq!(
        missing.status(),
        axum::http::StatusCode::NOT_FOUND,
        "an unknown operation id must be not-found"
    );

    let invalid = get(&router, "/api/v1/operations/not-a-uuid").await?;
    assert_eq!(
        invalid.status(),
        axum::http::StatusCode::BAD_REQUEST,
        "a malformed operation id must be rejected"
    );
    Ok(())
}

/// The auth boundaries of the test bundle: every store read answers
/// "nothing found" and every write fails, so the Open test routers never
/// touch a session.
impl rutilus_web::AuthServices for MockServices {
    type Error = MockError;

    fn find_session_by_token_hash<'a>(
        &'a self,
        _token_hash: &'a [u8; 32],
    ) -> rutilus_application::BoundaryFuture<'a, Result<Option<rutilus_domain::Session>, Self::Error>>
    {
        Box::pin(async move { Ok(None) })
    }
    fn create_session<'a>(
        &'a self,
        _session: &'a rutilus_domain::Session,
    ) -> rutilus_application::BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn touch_session(
        &self,
        _session_id: rutilus_domain::SessionId,
        _at: time::OffsetDateTime,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn revoke_session(
        &self,
        _session_id: rutilus_domain::SessionId,
        _at: time::OffsetDateTime,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn revoke_sessions_for_principal(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
        _at: time::OffsetDateTime,
    ) -> rutilus_application::BoundaryFuture<'_, Result<u64, Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn list_sessions(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
    ) -> rutilus_application::BoundaryFuture<'_, Result<Vec<rutilus_domain::Session>, Self::Error>>
    {
        Box::pin(async move { Ok(Vec::new()) })
    }
    fn find_principal(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
    ) -> rutilus_application::BoundaryFuture<
        '_,
        Result<Option<rutilus_domain::Principal>, Self::Error>,
    > {
        Box::pin(async move { Ok(None) })
    }
    fn find_principal_by_name<'a>(
        &'a self,
        _name: &'a rutilus_domain::PrincipalName,
    ) -> rutilus_application::BoundaryFuture<
        'a,
        Result<Option<rutilus_domain::Principal>, Self::Error>,
    > {
        Box::pin(async move { Ok(None) })
    }
    fn list_principals(
        &self,
    ) -> rutilus_application::BoundaryFuture<'_, Result<Vec<rutilus_domain::Principal>, Self::Error>>
    {
        Box::pin(async move { Ok(Vec::new()) })
    }
    fn create_principal<'a>(
        &'a self,
        _principal: &'a rutilus_domain::Principal,
    ) -> rutilus_application::BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn set_principal_state(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
        _state: rutilus_domain::PrincipalState,
        _at: time::OffsetDateTime,
    ) -> rutilus_application::BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn assign_role<'a>(
        &'a self,
        _assignment: &'a rutilus_domain::RoleAssignment,
    ) -> rutilus_application::BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn find_role_assignment(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
    ) -> rutilus_application::BoundaryFuture<
        '_,
        Result<Option<rutilus_domain::RoleAssignment>, Self::Error>,
    > {
        Box::pin(async move { Ok(None) })
    }
    fn list_role_assignments(
        &self,
    ) -> rutilus_application::BoundaryFuture<
        '_,
        Result<Vec<rutilus_domain::RoleAssignment>, Self::Error>,
    > {
        Box::pin(async move { Ok(Vec::new()) })
    }
    fn find_password_credential(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
    ) -> rutilus_application::BoundaryFuture<
        '_,
        Result<Option<rutilus_domain::PasswordCredential>, Self::Error>,
    > {
        Box::pin(async move { Ok(None) })
    }
    fn save_password_credential<'a>(
        &'a self,
        _credential: &'a rutilus_domain::PasswordCredential,
    ) -> rutilus_application::BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn list_totp_authenticators(
        &self,
        _principal_id: rutilus_domain::PrincipalId,
    ) -> rutilus_application::BoundaryFuture<
        '_,
        Result<Vec<rutilus_domain::TotpAuthenticator>, Self::Error>,
    > {
        Box::pin(async move { Ok(Vec::new()) })
    }
    fn record_totp_step(
        &self,
        _authenticator_id: rutilus_domain::TotpAuthenticatorId,
        _step: u64,
    ) -> rutilus_application::BoundaryFuture<'_, Result<bool, Self::Error>> {
        Box::pin(async move { Ok(false) })
    }
    fn find_bootstrap_code_by_hash<'a>(
        &'a self,
        _code_hash: &'a [u8; 32],
    ) -> rutilus_application::BoundaryFuture<
        'a,
        Result<Option<rutilus_domain::BootstrapCode>, Self::Error>,
    > {
        Box::pin(async move { Ok(None) })
    }
    fn has_unconsumed_bootstrap_code(
        &self,
    ) -> rutilus_application::BoundaryFuture<'_, Result<bool, Self::Error>> {
        Box::pin(async move { Ok(false) })
    }
    fn consume_bootstrap_code<'a>(
        &'a self,
        _code_id: rutilus_domain::BootstrapCodeId,
        _used_by: rutilus_domain::PrincipalId,
        _password: &'a rutilus_domain::PasswordCredential,
        _authenticator: Option<&'a rutilus_domain::TotpAuthenticator>,
        _session: &'a rutilus_domain::Session,
        _consumed_at: time::OffsetDateTime,
    ) -> rutilus_application::BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { Err(MockError::Persistence) })
    }
    fn verify_password(
        &self,
        _hash: &rutilus_domain::Argon2IdHash,
        _password: &secrecy::SecretString,
    ) -> bool {
        false
    }
    fn verify_totp(
        &self,
        _secret: &secrecy::SecretBox<[u8; rutilus_domain::TOTP_SECRET_LENGTH]>,
        _code: &str,
        _now: time::OffsetDateTime,
        _last_used_step: Option<u64>,
    ) -> Result<u64, rutilus_domain::TotpAuthenticatorError> {
        Err(rutilus_domain::TotpAuthenticatorError::InvalidCode)
    }
    fn hash_password(
        &self,
        _password: &secrecy::SecretString,
    ) -> Result<rutilus_domain::Argon2IdHash, Self::Error> {
        Err(MockError::Persistence)
    }
    fn hash_bootstrap_code(&self, code: &str) -> [u8; 32] {
        let mut hash = [0_u8; 32];
        hash[..code.len().min(32)].copy_from_slice(code.as_bytes());
        hash
    }
    fn issue_tokens(&self) -> Result<rutilus_web::IssuedSessionTokens, Self::Error> {
        Err(MockError::Persistence)
    }
    fn token_hash(&self, wire: &str) -> [u8; 32] {
        let mut hash = [0_u8; 32];
        hash[..wire.len().min(32)].copy_from_slice(wire.as_bytes());
        hash
    }
}

/// The unavailable center-view boundary: every center route of this test
/// bench answers the store verdict, exactly like the unconfigured product
/// boundaries.
impl CenterServices for MockServices {
    type Error = MockError;

    fn list_center_sites(&self) -> BoundaryFuture<'_, Result<Vec<CenterSiteView>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_center_endpoints(
        &self,
        _site: Option<InstanceId>,
    ) -> BoundaryFuture<'_, Result<Vec<CenterEndpointView>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_center_operations(
        &self,
        _site: Option<InstanceId>,
    ) -> BoundaryFuture<'_, Result<Vec<CenterOperationView>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn register_center_site(
        &self,
        _display_name: &str,
        _center_url: &str,
        _now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<RegisteredCenterSite, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn revoke_center_binding(
        &self,
        _site: InstanceId,
        _now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn dispatch_center_operation(
        &self,
        _site: InstanceId,
        _endpoint: EndpointId,
        _target: &ResourceODataId,
        _command: &RedfishCommand,
        _actor: PrincipalId,
        _now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<DispatchedCenterOperation, CenterOperationRefusal>> {
        Box::pin(async { Err(CenterOperationRefusal::Store) })
    }
}
