#![forbid(unsafe_code)]

//! End-to-end Axum tests for the §14.2 static-group and tag paths: group
//! create/list/detail/member-mutation/delete (§12.1 分组), tag assignment,
//! removal, and the cross-endpoint §14.2 tag-filter union.
//!
//! Every application boundary is served by an in-memory fake with a pair of
//! managed endpoints, so the Router is exercised without persistence or
//! network access.

use std::{
    collections::BTreeMap,
    error::Error,
    fmt,
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt as _;
use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository,
    CapabilitySnapshotRepository, ClassifiedBatchChild, Clock, CoreResourceReadOutcome,
    CoreResourceReader, CredentialCreationRepository, CredentialInventoryRepository,
    CredentialResolver, CredentialSecretProtector, DiscoveredEndpointRepository,
    EndpointInventoryItem, EndpointInventoryRepository, EndpointRefreshRepository, EventRepository,
    GroupRepository, OperationStore, ProtectedCredentialCreation, RedfishDiscovery,
    ResolvedCredential, ResourceDecodeFailure, ResourceObservation, StoredCapability,
    TagRepository, TelemetryRepository, TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, Credential, CredentialId,
    CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapabilityObservation, EndpointDisplayName, EndpointId, Event, Group, GroupId,
    InstanceId, Operation, OperationId, OperationState, PrincipalId, RedfishCommand,
    ResourceODataId, ResourceSnapshot, SeriesKey, Tag, TagName, TelemetrySample, TelemetrySeries,
    TelemetrySeriesId, TlsTrust,
};
use rutilus_web::{
    AuditEventQuery, CenterEndpointView, CenterOperationRefusal, CenterOperationView,
    CenterServices, CenterSiteView, DispatchedCenterOperation, RegisteredCenterSite,
    SessionRevocation, WebProductInfo, router,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

/// A well-formed but never-created identity for 404 checks.
const UNKNOWN_ID: &str = "00000000-0000-7000-8000-000000000000";

#[derive(Default)]
struct MockState {
    groups: BTreeMap<GroupId, Group>,
    tags: BTreeMap<(EndpointId, String), Tag>,
    endpoints: Vec<Endpoint>,
    fail_groups: bool,
    fail_tags: bool,
    fail_inventory: bool,
}

impl MockState {
    fn with_endpoints(endpoints: Vec<Endpoint>) -> Self {
        Self {
            endpoints,
            ..Self::default()
        }
    }
}

/// Implements every application boundary behind the injected services bundle,
/// with in-memory group/tag repositories mirroring the §9.3 tables.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
    artifact_directory: PathBuf,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>, data_directory: &std::path::Path) -> Self {
        Self {
            state,
            artifact_directory: data_directory.join("artifacts"),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MockState>, MockError> {
        self.state.lock().map_err(|_| MockError::Lock)
    }
}

/// Implements the Redfish boundaries without opening a socket; the group and
/// tag paths never exercise them.
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

impl GroupRepository for MockServices {
    type Error = MockError;

    fn create<'a>(&'a self, group: &'a Group) -> BoundaryFuture<'a, Result<Group, Self::Error>> {
        Box::pin(async move {
            let mut state = self.lock()?;
            if state.fail_groups {
                return Err(MockError::Persistence);
            }
            state.groups.insert(group.id(), group.clone());
            Ok(group.clone())
        })
    }

    fn find(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<Option<Group>, Self::Error>> {
        Box::pin(async move {
            let state = self.lock()?;
            if state.fail_groups {
                return Err(MockError::Persistence);
            }
            Ok(state.groups.get(&group_id).cloned())
        })
    }

    fn list(&self) -> BoundaryFuture<'_, Result<Vec<Group>, Self::Error>> {
        Box::pin(async move {
            let state = self.lock()?;
            if state.fail_groups {
                return Err(MockError::Persistence);
            }
            Ok(state.groups.values().cloned().collect())
        })
    }

    fn add_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.lock()?;
            if state.fail_groups {
                return Err(MockError::Persistence);
            }
            let mut group = state
                .groups
                .get_mut(&group_id)
                .ok_or(MockError::Persistence)?
                .clone();
            let _changed = group.add_member(endpoint_id);
            state.groups.insert(group_id, group);
            Ok(())
        })
    }

    fn remove_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.lock()?;
            if state.fail_groups {
                return Err(MockError::Persistence);
            }
            let mut group = state
                .groups
                .get_mut(&group_id)
                .ok_or(MockError::Persistence)?
                .clone();
            let _changed = group.remove_member(endpoint_id);
            state.groups.insert(group_id, group);
            Ok(())
        })
    }

    fn delete(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut state = self.lock()?;
            if state.fail_groups {
                return Err(MockError::Persistence);
            }
            state
                .groups
                .remove(&group_id)
                .ok_or(MockError::Persistence)?;
            Ok(())
        })
    }
}

impl TagRepository for MockServices {
    type Error = MockError;

    fn assign<'a>(&'a self, tag: &'a Tag) -> BoundaryFuture<'a, Result<Tag, Self::Error>> {
        let key = (tag.endpoint_id(), tag.name().as_str().to_owned());
        Box::pin(async move {
            let mut state = self.lock()?;
            if state.fail_tags {
                return Err(MockError::Persistence);
            }
            Ok(state.tags.entry(key).or_insert_with(|| tag.clone()).clone())
        })
    }

    fn remove<'a>(
        &'a self,
        endpoint_id: EndpointId,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        let key = (endpoint_id, tag_name.as_str().to_owned());
        Box::pin(async move {
            let mut state = self.lock()?;
            if state.fail_tags {
                return Err(MockError::Persistence);
            }
            state.tags.remove(&key);
            Ok(())
        })
    }

    fn list_for_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<Tag>, Self::Error>> {
        Box::pin(async move {
            let state = self.lock()?;
            if state.fail_tags {
                return Err(MockError::Persistence);
            }
            Ok(state
                .tags
                .iter()
                .filter(|((bound_endpoint, _), _)| *bound_endpoint == endpoint_id)
                .map(|(_, tag)| tag.clone())
                .collect())
        })
    }

    fn list_by_tag<'a>(
        &'a self,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<Vec<Tag>, Self::Error>> {
        let key = tag_name.as_str().to_owned();
        Box::pin(async move {
            let state = self.lock()?;
            if state.fail_tags {
                return Err(MockError::Persistence);
            }
            Ok(state
                .tags
                .iter()
                .filter(|((_, name), _)| name.as_str() == key)
                .map(|(_, tag)| tag.clone())
                .collect())
        })
    }
}

impl EndpointInventoryRepository for MockServices {
    type Error = MockError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        Box::pin(async move {
            let state = self.lock()?;
            if state.fail_inventory {
                return Err(MockError::Persistence);
            }
            state
                .endpoints
                .iter()
                .cloned()
                .map(|endpoint| EndpointInventoryItem::try_new(endpoint, Vec::new()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| MockError::Persistence)
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
            let state = self.lock()?;
            Ok(state
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

    fn list_recent_events_with_offset(
        &self,
        _limit: NonZeroU64,
        _offset: u64,
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
        Box::pin(async { Ok(()) })
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

    fn apply_transition_if_current(
        &self,
        _operation_id: OperationId,
        _expected_state: OperationState,
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

    fn record_failure_kind(
        &self,
        _operation_id: OperationId,
        _kind: rutilus_domain::FailureKind,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_batch_children(
        &self,
        _batch_id: rutilus_domain::BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

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
        Box::pin(async { Err(MockError::Persistence) })
    }

    fn list_artifacts_by_state(
        &self,
        _state: ArtifactState,
    ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
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

    fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
        self.artifact_directory.join(format!("{artifact_id}.bin"))
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

fn test_router_with(state: MockState) -> Result<Router, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let services = MockServices::new(Arc::new(Mutex::new(state)), directory.path());
    Ok(test_router(services))
}

async fn get(router: &Router, path: &str) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(Request::get(path).body(Body::empty())?)
        .await?)
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

async fn put_json(
    router: &Router,
    path: &str,
    body: Value,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(
            Request::put(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body)?))?,
        )
        .await?)
}

async fn delete(router: &Router, path: &str) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(Request::delete(path).body(Body::empty())?)
        .await?)
}

async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

fn endpoint(name: &str, address_suffix: u8) -> Result<Endpoint, Box<dyn Error>> {
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    Ok(Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse(name)?,
        EndpointAddress::parse(&format!("https://192.0.2.{address_suffix}"))?,
        TlsTrust::PinnedCertificate {
            certificate: rutilus_domain::TlsCertificate::from_der(vec![address_suffix])?,
            trusted_at: now,
        },
        CredentialId::generate(),
        now,
        now,
    )?)
}

fn two_endpoint_state() -> Result<MockState, Box<dyn Error>> {
    Ok(MockState::with_endpoints(vec![
        endpoint("Rack A", 1)?,
        endpoint("Rack B", 2)?,
    ]))
}

#[tokio::test]
async fn group_lifecycle_creates_lists_mutates_members_and_deletes() -> Result<(), Box<dyn Error>> {
    let state = two_endpoint_state()?;
    let first_id = state.endpoints[0].id();
    let second_id = state.endpoints[1].id();
    let router = test_router_with(state)?;

    // Create, then refuse the duplicate name with 409 (§12.1 unique names).
    let created = post_json(&router, "/api/v1/groups", json!({ "name": "Rack A" })).await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = json_body(created).await?;
    let group_id = body["group_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing group id"))?
        .to_owned();
    assert_eq!(body["name"], json!("Rack A"));
    assert_eq!(body["member_endpoint_ids"], json!([]));
    assert!(body["created_at"].is_string());
    assert!(body["updated_at"].is_string());

    let conflict = post_json(&router, "/api/v1/groups", json!({ "name": "Rack A" })).await?;
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
    assert_eq!(
        json_body(conflict).await?["message"],
        json!("a group with this name already exists")
    );

    // A second group appears in the deterministic §12.1 inventory.
    let second = post_json(&router, "/api/v1/groups", json!({ "name": "Lab" })).await?;
    assert_eq!(second.status(), StatusCode::CREATED);
    let inventory = get(&router, "/api/v1/groups").await?;
    assert_eq!(inventory.status(), StatusCode::OK);
    let inventory_body = json_body(inventory).await?;
    assert_eq!(inventory_body["groups"].as_array().map(Vec::len), Some(2));
    assert_eq!(inventory_body["groups"][0]["name"], json!("Lab"));
    assert_eq!(inventory_body["groups"][1]["name"], json!("Rack A"));

    // Member add is an idempotent PUT; unknown endpoints are refused.
    let add = put_json(
        &router,
        &format!("/api/v1/groups/{group_id}/members/{first_id}"),
        json!({}),
    )
    .await?;
    assert_eq!(add.status(), StatusCode::NO_CONTENT);
    let add_again = put_json(
        &router,
        &format!("/api/v1/groups/{group_id}/members/{first_id}"),
        json!({}),
    )
    .await?;
    assert_eq!(add_again.status(), StatusCode::NO_CONTENT);
    let unknown_endpoint = put_json(
        &router,
        &format!("/api/v1/groups/{group_id}/members/{UNKNOWN_ID}"),
        json!({}),
    )
    .await?;
    assert_eq!(unknown_endpoint.status(), StatusCode::NOT_FOUND);
    let unknown_group = put_json(
        &router,
        &format!("/api/v1/groups/{UNKNOWN_ID}/members/{first_id}"),
        json!({}),
    )
    .await?;
    assert_eq!(unknown_group.status(), StatusCode::NOT_FOUND);

    // Detail shows the member once; removal is an idempotent DELETE.
    let detail = get(&router, &format!("/api/v1/groups/{group_id}")).await?;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = json_body(detail).await?;
    assert_eq!(
        detail_body["member_endpoint_ids"],
        json!([first_id.to_string()])
    );

    let remove = delete(
        &router,
        &format!("/api/v1/groups/{group_id}/members/{first_id}"),
    )
    .await?;
    assert_eq!(remove.status(), StatusCode::NO_CONTENT);
    let remove_again = delete(
        &router,
        &format!("/api/v1/groups/{group_id}/members/{first_id}"),
    )
    .await?;
    assert_eq!(remove_again.status(), StatusCode::NO_CONTENT);

    // Add the second endpoint, then delete the group and confirm the 404s.
    let add_second = put_json(
        &router,
        &format!("/api/v1/groups/{group_id}/members/{second_id}"),
        json!({}),
    )
    .await?;
    assert_eq!(add_second.status(), StatusCode::NO_CONTENT);
    let deleted = delete(&router, &format!("/api/v1/groups/{group_id}")).await?;
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
    let gone = get(&router, &format!("/api/v1/groups/{group_id}")).await?;
    assert_eq!(gone.status(), StatusCode::NOT_FOUND);
    let unknown_delete = delete(&router, &format!("/api/v1/groups/{UNKNOWN_ID}")).await?;
    assert_eq!(unknown_delete.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn tag_lifecycle_assigns_lists_unions_and_removes() -> Result<(), Box<dyn Error>> {
    let state = two_endpoint_state()?;
    let first_id = state.endpoints[0].id();
    let second_id = state.endpoints[1].id();
    let router = test_router_with(state)?;

    // Assignment is an idempotent PUT; unknown endpoints are refused.
    let assigned = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": first_id.to_string(), "tag_name": "production" }),
    )
    .await?;
    assert_eq!(assigned.status(), StatusCode::NO_CONTENT);
    let reassigned = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": first_id.to_string(), "tag_name": "production" }),
    )
    .await?;
    assert_eq!(reassigned.status(), StatusCode::NO_CONTENT);
    let unknown = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": UNKNOWN_ID, "tag_name": "production" }),
    )
    .await?;
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);

    // The same name on a second endpoint is a separate binding, and the
    // §14.2 union lists all three in deterministic order.
    let second = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": second_id.to_string(), "tag_name": "production" }),
    )
    .await?;
    assert_eq!(second.status(), StatusCode::NO_CONTENT);
    let lab = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": second_id.to_string(), "tag_name": "lab" }),
    )
    .await?;
    assert_eq!(lab.status(), StatusCode::NO_CONTENT);

    let inventory = get(&router, "/api/v1/tags").await?;
    assert_eq!(inventory.status(), StatusCode::OK);
    let inventory_body = json_body(inventory).await?;
    assert_eq!(inventory_body["tags"].as_array().map(Vec::len), Some(3));
    assert_eq!(inventory_body["tags"][0]["name"], json!("lab"));
    assert_eq!(
        inventory_body["tags"][0]["endpoint_id"],
        json!(second_id.to_string())
    );
    assert_eq!(inventory_body["tags"][1]["name"], json!("production"));
    assert_eq!(
        inventory_body["tags"][1]["endpoint_id"],
        json!(first_id.to_string())
    );
    assert_eq!(inventory_body["tags"][2]["name"], json!("production"));
    assert_eq!(
        inventory_body["tags"][2]["endpoint_id"],
        json!(second_id.to_string())
    );
    for tag in inventory_body["tags"]
        .as_array()
        .ok_or("tags must be an array")?
    {
        assert!(tag["tag_id"].is_string());
    }

    // Removal is an idempotent DELETE; an endpoint outside the managed set
    // (a deleted endpoint with residual bindings) still converges on 204.
    let removed = delete(
        &router,
        &format!("/api/v1/endpoints/{first_id}/tags/production"),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    let removed_again = delete(
        &router,
        &format!("/api/v1/endpoints/{first_id}/tags/production"),
    )
    .await?;
    assert_eq!(removed_again.status(), StatusCode::NO_CONTENT);
    let deleted_endpoint =
        delete(&router, &format!("/api/v1/endpoints/{UNKNOWN_ID}/tags/lab")).await?;
    assert_eq!(deleted_endpoint.status(), StatusCode::NO_CONTENT);

    let remaining = json_body(get(&router, "/api/v1/tags").await?).await?;
    assert_eq!(remaining["tags"].as_array().map(Vec::len), Some(2));
    Ok(())
}

#[tokio::test]
async fn deleted_endpoint_tag_residue_is_cleanable() -> Result<(), Box<dyn Error>> {
    // A tag assigned while the endpoint was managed must stay removable after
    // the endpoint leaves the managed set: the binding disappears from the
    // union (which enumerates managed endpoints) but the cleanup path still
    // converges over the same store.
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(two_endpoint_state()?));
    let managed = state.lock().map_err(|_| MockError::Lock)?.endpoints[0].id();
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));

    let assigned = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": managed.to_string(), "tag_name": "production" }),
    )
    .await?;
    assert_eq!(assigned.status(), StatusCode::NO_CONTENT);

    // The endpoint is deleted: it drops out of the managed set, so its tag no
    // longer appears in the §14.2 union, and the residue is removed through
    // the same endpoint-addressed path with 204.
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .endpoints
        .retain(|endpoint| endpoint.id() != managed);
    let union = json_body(get(&router, "/api/v1/tags").await?).await?;
    assert_eq!(union["tags"].as_array().map(Vec::len), Some(0));
    let cleaned = delete(
        &router,
        &format!("/api/v1/endpoints/{managed}/tags/production"),
    )
    .await?;
    assert_eq!(cleaned.status(), StatusCode::NO_CONTENT);
    let cleaned_again = delete(
        &router,
        &format!("/api/v1/endpoints/{managed}/tags/production"),
    )
    .await?;
    assert_eq!(cleaned_again.status(), StatusCode::NO_CONTENT);
    Ok(())
}

#[tokio::test]
async fn tag_names_with_spaces_round_trip_through_path_encoding() -> Result<(), Box<dyn Error>> {
    let state = two_endpoint_state()?;
    let first_id = state.endpoints[0].id();
    let router = test_router_with(state)?;

    let assigned = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": first_id.to_string(), "tag_name": "Rack A" }),
    )
    .await?;
    assert_eq!(assigned.status(), StatusCode::NO_CONTENT);
    let inventory = json_body(get(&router, "/api/v1/tags").await?).await?;
    assert_eq!(inventory["tags"][0]["name"], json!("Rack A"));

    // The path extractor percent-decodes the name before validation.
    let removed = delete(
        &router,
        &format!("/api/v1/endpoints/{first_id}/tags/Rack%20A"),
    )
    .await?;
    assert_eq!(removed.status(), StatusCode::NO_CONTENT);
    let empty = json_body(get(&router, "/api/v1/tags").await?).await?;
    assert_eq!(empty["tags"].as_array().map(Vec::len), Some(0));
    Ok(())
}

#[tokio::test]
async fn group_and_tag_validation_errors_are_typed() -> Result<(), Box<dyn Error>> {
    let state = two_endpoint_state()?;
    let first_id = state.endpoints[0].id();
    let router = test_router_with(state)?;

    // 400: invalid names and identities.
    let empty_name = post_json(&router, "/api/v1/groups", json!({ "name": "" })).await?;
    assert_eq!(empty_name.status(), StatusCode::BAD_REQUEST);
    let bad_group_id = get(&router, "/api/v1/groups/not-a-uuid").await?;
    assert_eq!(bad_group_id.status(), StatusCode::BAD_REQUEST);
    let bad_member_path = put_json(
        &router,
        "/api/v1/groups/not-a-uuid/members/also-not-a-uuid",
        json!({}),
    )
    .await?;
    assert_eq!(bad_member_path.status(), StatusCode::BAD_REQUEST);
    let bad_tag_path = delete(&router, "/api/v1/endpoints/not-a-uuid/tags/lab").await?;
    assert_eq!(bad_tag_path.status(), StatusCode::BAD_REQUEST);
    let bad_tag_name = delete(&router, &format!("/api/v1/endpoints/{first_id}/tags/%0A")).await?;
    assert_eq!(bad_tag_name.status(), StatusCode::BAD_REQUEST);

    // 422: unknown or malformed request fields.
    let unknown_field = post_json(
        &router,
        "/api/v1/groups",
        json!({ "name": "Rack A", "color": "#f00" }),
    )
    .await?;
    assert_eq!(unknown_field.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let missing_field = post_json(&router, "/api/v1/groups", json!({})).await?;
    assert_eq!(missing_field.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let bad_endpoint_uuid = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": "not-a-uuid", "tag_name": "lab" }),
    )
    .await?;
    assert_eq!(bad_endpoint_uuid.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let unknown_tag_field = put_json(
        &router,
        "/api/v1/tags",
        json!({ "endpoint_id": first_id.to_string(), "tag_name": "lab", "color": "#0f0" }),
    )
    .await?;
    assert_eq!(unknown_tag_field.status(), StatusCode::UNPROCESSABLE_ENTITY);
    Ok(())
}

#[tokio::test]
async fn group_and_tag_repository_failures_return_503() -> Result<(), Box<dyn Error>> {
    let mut state = two_endpoint_state()?;
    state.fail_groups = true;
    let router = test_router_with(state)?;

    assert_eq!(
        get(&router, "/api/v1/groups").await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        post_json(&router, "/api/v1/groups", json!({ "name": "Rack A" }))
            .await?
            .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let mut state = two_endpoint_state()?;
    let tagged_endpoint = state.endpoints[0].id();
    state.fail_tags = true;
    let router = test_router_with(state)?;
    assert_eq!(
        get(&router, "/api/v1/tags").await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        put_json(
            &router,
            "/api/v1/tags",
            json!({ "endpoint_id": tagged_endpoint.to_string(), "tag_name": "lab" }),
        )
        .await?
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );

    let mut state = two_endpoint_state()?;
    state.fail_inventory = true;
    let router = test_router_with(state)?;
    assert_eq!(
        get(&router, "/api/v1/tags").await?.status(),
        StatusCode::SERVICE_UNAVAILABLE
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
    ) -> rutilus_application::BoundaryFuture<'_, Result<SessionRevocation, Self::Error>> {
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
