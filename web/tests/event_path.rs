#![forbid(unsafe_code)]

//! End-to-end Axum tests for the 0.4 §14.4 event history path:
//! `GET /api/v1/events`.
//!
//! Every application boundary is served by an in-memory fake, with a real
//! in-memory event store, so the Web Router is exercised without persistence
//! or network access. The dedup contract of §14.4 去除明显重复 is the
//! persistence implementation's — the application ingestion tests cover it —
//! so this fake appends every event and only mirrors the newest-first
//! bounded listing the console relies on.

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
    TelemetryRepository, TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, Credential, CredentialId,
    CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapabilityObservation, EndpointId, Event, EventId, EventSeverity, MessageId, Operation,
    OperationId, OperationState, ResourceSnapshot, SeriesKey, TelemetrySample, TelemetrySeries,
    TelemetrySeriesId, TlsTrust,
};
use rutilus_web::{AuditEventQuery, WebProductInfo, router};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

#[derive(Default)]
struct MockState {
    events: Vec<Event>,
    fail_event_listing: bool,
}

/// Implements every application boundary behind the injected services bundle,
/// with a functioning in-memory event store.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>) -> Self {
        Self { state }
    }
}

/// Implements the Redfish boundaries without opening a socket; the event
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
        _operation: &'a Operation,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn find_operation(
        &self,
        _operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
        Box::pin(async { Ok(None) })
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
        _state_filter: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn create_batch<'a>(
        &'a self,
        _batch: &'a rutilus_domain::BatchOperation,
        _children: &'a [Operation],
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        // The suites in this file never create batches; the operation
        // submission path owns that boundary, so this stub is unreachable
        // here.
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn find_batch(
        &self,
        _batch_id: rutilus_domain::BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Option<rutilus_domain::BatchOperation>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_batches(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<rutilus_domain::BatchOperation>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_batch_children(
        &self,
        _batch_id: rutilus_domain::BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

impl EndpointRefreshRepository for MockServices {
    type Error = MockError;

    fn find_endpoint(
        &self,
        _endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        Box::pin(async { Ok(None) })
    }

    fn commit_resource_generation<'a>(
        &'a self,
        _endpoint_id: EndpointId,
        _observations: &'a [ResourceObservation],
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

impl EventRepository for MockServices {
    type Error = MockError;

    /// Appends one event to the in-memory store.
    ///
    /// The §14.4 去除明显重复 dedup is the persistence implementation's
    /// contract, exercised by the application ingestion tests; this fake
    /// keeps every row so the listing assertions stay about the web path.
    fn append_event<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.state
                .lock()
                .map_err(|_| MockError::Lock)?
                .events
                .push(event.clone());
            Ok(())
        })
    }

    /// Lists the newest events first: the fake stores in append order, so
    /// the reversed tail is the console's newest-first view.
    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|_| MockError::Lock)?;
            if state.fail_event_listing {
                return Err(MockError::Persistence);
            }
            let take = usize::try_from(limit.get()).map_err(|_| MockError::Persistence)?;
            Ok(state.events.iter().rev().take(take).cloned().collect())
        })
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
    ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
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

/// Builds one event recorded from the given endpoint at the given times.
///
/// The receive time is always one second after the BMC's event timestamp, so
/// the domain timeline constraint holds; the observed times are what the
/// listing order and the assertions pin.
fn recorded_event(
    endpoint_id: EndpointId,
    message_id: &str,
    severity: EventSeverity,
    event_timestamp: OffsetDateTime,
) -> Result<Event, Box<dyn Error>> {
    Ok(Event::new(
        EventId::generate(),
        endpoint_id,
        MessageId::parse(message_id)?,
        severity,
        Some(format!("message text of {message_id}")),
        event_timestamp,
        event_timestamp + Duration::SECOND,
    )?)
}

#[tokio::test]
async fn events_route_lists_newest_first_with_all_fields() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = EndpointId::generate();
    let oldest = recorded_event(
        endpoint,
        "Alert.1.0.PowerSupplyFailure",
        EventSeverity::Critical,
        OffsetDateTime::UNIX_EPOCH + Duration::SECOND * 10,
    )?;
    let middle = recorded_event(
        endpoint,
        "ResourceEvent.1.0.LanResetType",
        EventSeverity::Warning,
        OffsetDateTime::UNIX_EPOCH + Duration::SECOND * 20,
    )?;
    let newest = recorded_event(
        EndpointId::generate(),
        "Alert.1.0.FanRedundancyLost",
        EventSeverity::Ok,
        OffsetDateTime::UNIX_EPOCH + Duration::SECOND * 30,
    )?;
    {
        let mut state = state.lock().map_err(|_| MockError::Lock)?;
        state.events.push(oldest.clone());
        state.events.push(middle.clone());
        state.events.push(newest.clone());
    }
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let response = get(&router, "/api/v1/events").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    let body = json_body(response).await?;
    let events = body["events"]
        .as_array()
        .ok_or("the response must carry events")?;
    assert_eq!(events.len(), 3);
    // Newest first, with the BMC-reported MessageId, the stable severity
    // code, the original message text, and both clocks.
    assert_eq!(events[0]["id"], newest.id().to_string());
    assert_eq!(events[0]["endpoint_id"], newest.endpoint_id().to_string());
    assert_eq!(events[0]["message_id"], "Alert.1.0.FanRedundancyLost");
    assert_eq!(events[0]["severity"], "ok");
    assert_eq!(
        events[0]["message"],
        "message text of Alert.1.0.FanRedundancyLost"
    );
    assert_eq!(events[0]["event_timestamp"], "1970-01-01T00:00:30Z");
    assert_eq!(events[0]["observed_at"], "1970-01-01T00:00:31Z");
    assert_eq!(events[1]["id"], middle.id().to_string());
    assert_eq!(events[1]["message_id"], "ResourceEvent.1.0.LanResetType");
    assert_eq!(events[1]["severity"], "warning");
    assert_eq!(events[2]["id"], oldest.id().to_string());
    assert_eq!(events[2]["severity"], "critical");
    Ok(())
}

#[tokio::test]
async fn events_route_respects_the_limit_and_never_exceeds_it() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = EndpointId::generate();
    for seconds in 0..5 {
        let event = recorded_event(
            endpoint,
            "Alert.1.0.PowerSupplyFailure",
            EventSeverity::Critical,
            OffsetDateTime::UNIX_EPOCH + Duration::SECOND * seconds,
        )?;
        state
            .lock()
            .map_err(|_| MockError::Lock)?
            .events
            .push(event);
    }
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let response = get(&router, "/api/v1/events?limit=2").await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    let events = body["events"]
        .as_array()
        .ok_or("the response must carry events")?;
    assert_eq!(events.len(), 2);
    // The bounded window is the newest tail.
    assert_eq!(events[0]["event_timestamp"], "1970-01-01T00:00:04Z");
    assert_eq!(events[1]["event_timestamp"], "1970-01-01T00:00:03Z");

    // A limit beyond the recorded count returns what exists, not an error.
    let response = get(&router, "/api/v1/events?limit=7").await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(
        body["events"]
            .as_array()
            .ok_or("the response must carry events")?
            .len(),
        5
    );
    Ok(())
}

#[tokio::test]
async fn events_route_rejects_invalid_limits() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(state));

    for path in [
        "/api/v1/events?limit=0",
        "/api/v1/events?limit=1001",
        "/api/v1/events?limit=abc",
        "/api/v1/events?limit=",
        "/api/v1/events?limit=-1",
    ] {
        let response = get(&router, path).await?;
        assert_eq!(
            response.status(),
            axum::http::StatusCode::BAD_REQUEST,
            "path {path} must be refused"
        );
        let body = json_body(response).await?;
        assert!(body["message"].as_str().is_some());
    }
    Ok(())
}

#[tokio::test]
async fn events_route_returns_an_empty_list_before_any_event_was_recorded()
-> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/events").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body, json!({ "events": [] }));
    Ok(())
}

#[tokio::test]
async fn events_route_reports_a_failed_listing_as_unavailable() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .fail_event_listing = true;
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/events").await?;

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}
