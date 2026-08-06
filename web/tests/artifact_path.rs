#![forbid(unsafe_code)]

//! End-to-end Axum tests for the §14.3 artifact upload paths: declaration,
//! strict sequential chunk upload with at-least-once retransmission, digest
//! finalize, and the artifact inventory.
//!
//! Every application boundary is served by an in-memory fake with real file
//! I/O under a temporary directory, so the Router is exercised without
//! persistence or network access. The declared digest of the test content
//! `hello!` is `ce06092fb948d9ffac7d1a376e404b26b7575bcc11ee05a4615fef4fec3a308b`
//! (verified against `sha256sum`).

use std::{
    collections::HashMap,
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
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialCreationRepository,
    CredentialInventoryRepository, CredentialResolver, CredentialSecretProtector,
    DiscoveredEndpointRepository, EndpointInventoryItem, EndpointInventoryRepository,
    EndpointRefreshRepository, OperationStore, ProtectedCredentialCreation, RedfishDiscovery,
    ResolvedCredential, ResourceObservation, StoredCapability, TlsIdentityObservation,
    TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, Credential, CredentialId,
    CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapabilityObservation, EndpointId, Operation, OperationId, OperationState,
    ResourceSnapshot, TlsTrust,
};
use rutilus_web::{AuditEventQuery, WebProductInfo, router};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt as _;

/// The SHA-256 digest of the `hello!` test content.
const CONTENT_DIGEST: &str = "ce06092fb948d9ffac7d1a376e404b26b7575bcc11ee05a4615fef4fec3a308b";
/// A well-formed but never-created artifact identity.
const UNKNOWN_ID: &str = "00000000-0000-7000-8000-000000000000";

#[derive(Default)]
struct MockState {
    artifacts: HashMap<ArtifactId, Artifact>,
}

/// Implements every application boundary behind the injected services bundle,
/// with a functioning in-memory artifact store and real file I/O under a
/// temporary directory mirroring the production `artifacts/` layout.
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
}

/// Implements the Redfish boundaries without opening a socket; the artifact
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
        artifact: &'a Artifact,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.state
                .lock()
                .map_err(|_| MockError::Lock)?
                .artifacts
                .entry(artifact.id())
                .or_insert_with(|| artifact.clone());
            Ok(())
        })
    }

    fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
        Box::pin(async move {
            Ok(self
                .state
                .lock()
                .map_err(|_| MockError::Lock)?
                .artifacts
                .get(&artifact_id)
                .cloned())
        })
    }

    fn list_artifacts_by_state(
        &self,
        state: ArtifactState,
    ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
        Box::pin(async move {
            let state_rows = self.state.lock().map_err(|_| MockError::Lock)?;
            let mut artifacts: Vec<_> = state_rows
                .artifacts
                .values()
                .filter(|artifact| artifact.state() == state)
                .cloned()
                .collect();
            artifacts.sort_by_key(|artifact| (artifact.created_at(), artifact.id()));
            Ok(artifacts)
        })
    }

    fn update_artifact(
        &self,
        artifact_id: ArtifactId,
        uploaded_bytes: u64,
        state: ArtifactState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let mut rows = self.state.lock().map_err(|_| MockError::Lock)?;
            let current = rows
                .artifacts
                .get(&artifact_id)
                .ok_or(MockError::Persistence)?
                .clone();
            if current.state().is_terminal() {
                return Err(MockError::Persistence);
            }
            if uploaded_bytes < current.uploaded_bytes()
                || uploaded_bytes > current.size_bytes()
                || (state == ArtifactState::Ready && uploaded_bytes != current.size_bytes())
            {
                return Err(MockError::Persistence);
            }
            let updated = Artifact::try_from_parts(
                current.id(),
                current.name().clone(),
                current.size_bytes(),
                current.sha256(),
                state,
                uploaded_bytes,
                current.created_at(),
                occurred_at,
            )
            .map_err(|_| MockError::Persistence)?;
            rows.artifacts.insert(artifact_id, updated);
            Ok(())
        })
    }

    fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
        self.artifact_directory.join(format!("{artifact_id}.bin"))
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

impl EndpointRefreshRepository for MockServices {
    type Error = MockError;

    fn find_endpoint(
        &self,
        _endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
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
        Box::pin(async { Ok(()) })
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
async fn complete_upload_flow_creates_chunks_finalizes_and_lists() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));

    let created = post_json(
        &router,
        "/api/v1/artifacts",
        json!({
            "name": "firmware.bin",
            "size_bytes": 6,
            "sha256": CONTENT_DIGEST
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let body = json_body(created).await?;
    let artifact_id = body["artifact_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing artifact id"))?
        .to_owned();
    assert_eq!(body["state"], json!("uploading"));
    assert_eq!(body["uploaded_bytes"], json!(0));
    assert_eq!(body["size_bytes"], json!(6));
    assert_eq!(body["name"], json!("firmware.bin"));
    assert_eq!(body["sha256"], json!(CONTENT_DIGEST));

    let first = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": "aGVs" }),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);
    let first_progress = json_body(first).await?;
    assert_eq!(first_progress["artifact_id"], json!(artifact_id));
    assert_eq!(first_progress["uploaded_bytes"], json!(3));
    assert_eq!(first_progress["size_bytes"], json!(6));

    let second = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 3, "data": "bG8h" }),
    )
    .await?;
    assert_eq!(second.status(), StatusCode::OK);
    let second_progress = json_body(second).await?;
    assert_eq!(second_progress["uploaded_bytes"], json!(6));

    // The decoded bytes land in the file at the declared path, exactly in
    // order: the artifact file and the row link deterministically.
    let stored = std::fs::read(
        directory
            .path()
            .join("artifacts")
            .join(format!("{artifact_id}.bin")),
    )?;
    assert_eq!(stored, b"hello!");

    let finalized = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/finalize"),
        json!({}),
    )
    .await?;
    assert_eq!(finalized.status(), StatusCode::OK);
    let verdict = json_body(finalized).await?;
    assert_eq!(verdict["state"], json!("ready"));
    assert_eq!(verdict["uploaded_bytes"], json!(6));

    // A finished artifact absorbs no further chunks (409 state conflict).
    let late_chunk = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 6, "data": "" }),
    )
    .await?;
    assert_eq!(late_chunk.status(), StatusCode::CONFLICT);

    let listed = get(&router, "/api/v1/artifacts").await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let list_body = json_body(listed).await?;
    assert_eq!(list_body["artifacts"][0]["artifact_id"], json!(artifact_id));
    assert_eq!(list_body["artifacts"][0]["state"], json!("ready"));

    let detail = get(&router, &format!("/api/v1/artifacts/{artifact_id}")).await?;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail_body = json_body(detail).await?;
    assert_eq!(detail_body["state"], json!("ready"));
    assert_eq!(detail_body["name"], json!("firmware.bin"));

    let empty_state = get(&router, "/api/v1/artifacts").await?;
    assert_eq!(empty_state.status(), StatusCode::OK);
    assert_eq!(
        json_body(empty_state).await?["artifacts"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );
    Ok(())
}

#[tokio::test]
async fn interrupted_uploads_resume_with_idempotent_retransmission() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));
    let created = post_json(
        &router,
        "/api/v1/artifacts",
        json!({
            "name": "firmware.bin",
            "size_bytes": 6,
            "sha256": CONTENT_DIGEST
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let artifact_id = json_body(created).await?["artifact_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing artifact id"))?
        .to_owned();

    // The first range lands; its acknowledgement is then lost, so the client
    // restarts mid-upload by retransmitting it.
    let first = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": "aGVs" }),
    )
    .await?;
    assert_eq!(first.status(), StatusCode::OK);

    // The retransmission must be acknowledged with the unchanged progress —
    // the §15.4 at-least-once discipline, never a duplicate write.
    let retried = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": "aGVs" }),
    )
    .await?;
    assert_eq!(retried.status(), StatusCode::OK);
    let progress = json_body(retried).await?;
    assert_eq!(progress["uploaded_bytes"], json!(3));

    // A range beyond the acknowledged progress is refused: holes are never
    // opened, so a resumed upload continues from the exact offset.
    let out_of_order = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 4, "data": "bG8h" }),
    )
    .await?;
    assert_eq!(out_of_order.status(), StatusCode::BAD_REQUEST);

    // The resumed continuation lands the file and finalizes cleanly.
    let resumed = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 3, "data": "bG8h" }),
    )
    .await?;
    assert_eq!(resumed.status(), StatusCode::OK);
    let finalized = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/finalize"),
        json!({}),
    )
    .await?;
    assert_eq!(finalized.status(), StatusCode::OK);
    assert_eq!(json_body(finalized).await?["state"], json!("ready"));
    Ok(())
}

#[tokio::test]
async fn unknown_artifact_ids_return_404() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));

    let chunk = post_json(
        &router,
        &format!("/api/v1/artifacts/{UNKNOWN_ID}/chunks"),
        json!({ "offset": 0, "data": "aGVs" }),
    )
    .await?;
    assert_eq!(chunk.status(), StatusCode::NOT_FOUND);

    let finalized = post_json(
        &router,
        &format!("/api/v1/artifacts/{UNKNOWN_ID}/finalize"),
        json!({}),
    )
    .await?;
    assert_eq!(finalized.status(), StatusCode::NOT_FOUND);

    let detail = get(&router, &format!("/api/v1/artifacts/{UNKNOWN_ID}")).await?;
    assert_eq!(detail.status(), StatusCode::NOT_FOUND);
    Ok(())
}

#[tokio::test]
async fn invalid_chunk_requests_return_400() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));
    let created = post_json(
        &router,
        "/api/v1/artifacts",
        json!({
            "name": "firmware.bin",
            "size_bytes": 6,
            "sha256": CONTENT_DIGEST
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let artifact_id = json_body(created).await?["artifact_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing artifact id"))?
        .to_owned();

    // Malformed base64.
    let malformed = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": "!!!not-base64!!!" }),
    )
    .await?;
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

    // A range beyond the declared size (7 decoded bytes into a 6-byte file).
    let oversized = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": "aGVsbG8hIQ==" }),
    )
    .await?;
    assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);

    // A chunk over the 4 MiB base64 wire limit.
    let huge = "A".repeat(4 * 1024 * 1024 + 1);
    let over_limit = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": huge }),
    )
    .await?;
    assert_eq!(over_limit.status(), StatusCode::BAD_REQUEST);

    // A chunk whose JSON body exceeds the transport limit (4 MiB base64 plus
    // framing headroom) is rejected by the body-limit layer with 413 before
    // any decoding work — the handler's own 4 MiB check stays reachable for
    // payloads just past the protocol limit.
    let beyond_transport = "A".repeat(4 * 1024 * 1024 + 2048);
    let transport_rejected = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 0, "data": beyond_transport }),
    )
    .await?;
    assert_eq!(transport_rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);

    // A path id that is not a UUID.
    let bad_id = post_json(
        &router,
        "/api/v1/artifacts/not-a-uuid/chunks",
        json!({ "offset": 0, "data": "aGVs" }),
    )
    .await?;
    assert_eq!(bad_id.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn invalid_declarations_return_400() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));

    let empty_name = post_json(
        &router,
        "/api/v1/artifacts",
        json!({ "name": "", "size_bytes": 6, "sha256": CONTENT_DIGEST }),
    )
    .await?;
    assert_eq!(empty_name.status(), StatusCode::BAD_REQUEST);

    let bad_digest = post_json(
        &router,
        "/api/v1/artifacts",
        json!({ "name": "firmware.bin", "size_bytes": 6, "sha256": "not-a-digest" }),
    )
    .await?;
    assert_eq!(bad_digest.status(), StatusCode::BAD_REQUEST);

    let zero_size = post_json(
        &router,
        "/api/v1/artifacts",
        json!({ "name": "firmware.bin", "size_bytes": 0, "sha256": CONTENT_DIGEST }),
    )
    .await?;
    assert_eq!(zero_size.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn digest_mismatch_finalizes_as_422_failed_and_never_reopens() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));

    // Declared digest of a different file than the uploaded `hello!`.
    let wrong_digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let created = post_json(
        &router,
        "/api/v1/artifacts",
        json!({
            "name": "firmware.bin",
            "size_bytes": 6,
            "sha256": wrong_digest
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let artifact_id = json_body(created).await?["artifact_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing artifact id"))?
        .to_owned();
    for (data, offset) in [("aGVs", 0), ("bG8h", 3)] {
        let chunk = post_json(
            &router,
            &format!("/api/v1/artifacts/{artifact_id}/chunks"),
            json!({ "offset": offset, "data": data }),
        )
        .await?;
        assert_eq!(chunk.status(), StatusCode::OK);
    }

    // The finalize verdict: 422 (unprocessable — the request is well formed
    // but its subject content cannot be validated) with the terminal failed
    // projection and the exact reason.
    let finalized = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/finalize"),
        json!({}),
    )
    .await?;
    assert_eq!(finalized.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let failure = json_body(finalized).await?;
    assert_eq!(failure["artifact"]["state"], json!("failed"));
    assert_eq!(failure["artifact"]["artifact_id"], json!(artifact_id));
    let reason = failure["reason"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing failure reason"))?;
    assert!(reason.contains("SHA-256 verification failed"));

    // A failed verdict is terminal: finalizing again is a conflict and the
    // artifact is no longer chunkable — the §0.4.0 "明确失败" guarantee.
    let again = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/finalize"),
        json!({}),
    )
    .await?;
    assert_eq!(again.status(), StatusCode::CONFLICT);
    let late_chunk = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/chunks"),
        json!({ "offset": 6, "data": "" }),
    )
    .await?;
    assert_eq!(late_chunk.status(), StatusCode::CONFLICT);
    Ok(())
}

#[tokio::test]
async fn missing_artifact_file_fails_finalize_with_500_without_burning_the_artifact()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));
    let created = post_json(
        &router,
        "/api/v1/artifacts",
        json!({
            "name": "firmware.bin",
            "size_bytes": 6,
            "sha256": CONTENT_DIGEST
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let artifact_id = json_body(created).await?["artifact_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing artifact id"))?
        .to_owned();
    for (data, offset) in [("aGVs", 0), ("bG8h", 3)] {
        let chunk = post_json(
            &router,
            &format!("/api/v1/artifacts/{artifact_id}/chunks"),
            json!({ "offset": offset, "data": data }),
        )
        .await?;
        assert_eq!(chunk.status(), StatusCode::OK);
    }

    // The row claims a complete upload but the bytes are gone (for example,
    // the data directory was tampered with): finalize cannot hash the file,
    // which is an environmental failure, not a content verdict — the server
    // reports 500 and leaves the artifact uploadable instead of failing it.
    std::fs::remove_file(
        directory
            .path()
            .join("artifacts")
            .join(format!("{artifact_id}.bin")),
    )?;
    let finalized = post_json(
        &router,
        &format!("/api/v1/artifacts/{artifact_id}/finalize"),
        json!({}),
    )
    .await?;
    assert_eq!(finalized.status(), StatusCode::INTERNAL_SERVER_ERROR);

    let detail = get(&router, &format!("/api/v1/artifacts/{artifact_id}")).await?;
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(
        json_body(detail).await?["state"],
        json!("uploading"),
        "an unreadable file must not burn the artifact; the client can repair and retry"
    );
    Ok(())
}

#[tokio::test]
async fn inventory_starts_empty_and_lists_across_states() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(Arc::clone(&state), directory.path()));

    let empty = get(&router, "/api/v1/artifacts").await?;
    assert_eq!(empty.status(), StatusCode::OK);
    assert_eq!(
        json_body(empty).await?["artifacts"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );

    // One uploading artifact appears in the inventory before finalize.
    let created = post_json(
        &router,
        "/api/v1/artifacts",
        json!({
            "name": "pending.bin",
            "size_bytes": 6,
            "sha256": CONTENT_DIGEST
        }),
    )
    .await?;
    assert_eq!(created.status(), StatusCode::CREATED);
    let artifact_id = json_body(created).await?["artifact_id"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("missing artifact id"))?
        .to_owned();
    let listed = get(&router, "/api/v1/artifacts").await?;
    assert_eq!(listed.status(), StatusCode::OK);
    let list_body = json_body(listed).await?;
    assert_eq!(list_body["artifacts"][0]["artifact_id"], json!(artifact_id));
    assert_eq!(list_body["artifacts"][0]["state"], json!("uploading"));
    Ok(())
}
