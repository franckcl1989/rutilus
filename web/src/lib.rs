#![forbid(unsafe_code)]

use std::{error::Error, num::NonZeroU64, path::Path, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{
        HeaderValue, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName},
    },
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
};
use rust_embed::RustEmbed;
use rutilus_api::{
    AboutResponse, AppendArtifactChunkRequest, ArtifactFinalizeFailureResponse,
    ArtifactListResponse, ArtifactProgressResponse, ArtifactResponse, ArtifactStateResponse,
    AssignTagRequest, AuditEventResponse, AuditOutcomeResponse, AuditQueryResponse,
    AuditTargetResponse, BeginEndpointTrustRequest, CapabilityClassificationResponse,
    CapabilityEntryResponse, CapabilityStateResponse, ConfirmEndpointTrustRequest,
    CoreResourceCommonResponse, CoreResourceCountsResponse, CoreResourceDetailsResponse,
    CoreResourceResponse, CoreResourceSourceResponse, CreateArtifactRequest,
    CreateCredentialRequest, CreateGroupRequest, CreateOperationRequest,
    CredentialInventoryResponse, CredentialSummaryResponse, EndpointCapabilityInventoryResponse,
    EndpointCsvImportRequest, EndpointCsvImportResponse, EndpointCsvImportRowResponse,
    EndpointCsvImportRowStatusResponse, EndpointEnrollmentResponse, EndpointIdentityResponse,
    EndpointInventoryResponse, EndpointResourceInventoryResponse, EndpointResourceSnapshotResponse,
    EndpointSnapshotSummaryResponse, EndpointSummaryResponse, EndpointTrustChallengeResponse,
    EndpointTrustChallengeStateResponse, EndpointTrustExpectationRequest, EnrollEndpointRequest,
    ErrorResponse, EventListResponse, EventResponse, GroupListResponse, GroupResponse,
    HealthResponse, MetricValueResponse, OperationListResponse, OperationResponse,
    OperationSourceResponse, OperationStateResponse, OperationTargetResponse,
    ResourceDiagnosticsResponse, ResourceStatusResponse, TagListResponse, TagResponse,
    TelemetrySampleListResponse, TelemetrySampleResponse, TelemetrySeriesListResponse,
    TelemetrySeriesResponse, TlsTrustModeResponse, TrustRejectedResponse, TrustedEndpointResponse,
    UiLocationResponse,
};
use rutilus_application::{
    ARTIFACT_CHUNK_BASE64_MAX_BYTES, ArtifactProgress, ArtifactRepository, ArtifactStore,
    ArtifactStoreError, AuditEventWriter, AuditedOnboardEndpointError, BoundaryFuture,
    CapabilityLedgerEntry, CapabilityQueryRepository, CapabilitySnapshotRepository, Clock,
    CoreResourceDetails, CoreResourceReader, CoreResourceSummary, CredentialCreation,
    CredentialCreationError, CredentialCreationRepository, CredentialInventoryQuery,
    CredentialInventoryQueryError, CredentialInventoryRepository, CredentialResolver,
    CredentialSecretProtector, DiscoveredEndpointRepository, EndpointCapabilityQuery,
    EndpointCapabilityQueryError, EndpointCsvImportExecutor, EndpointCsvImportReport,
    EndpointCsvRowOutcome, EndpointCsvRowResult, EndpointEnrollment, EndpointEnrollmentError,
    EndpointInventoryItem, EndpointInventoryQuery, EndpointInventoryQueryError,
    EndpointInventoryRepository, EndpointRefreshRepository, EndpointResourceInventory,
    EndpointResourceInventoryQuery, EndpointResourceInventoryQueryError, EndpointTrustChallenge,
    EndpointTrustEstablishment, EndpointTrustExpectation, EndpointTrustExpectationError,
    EnrolledEndpoint, EventRepository, GroupManagement, GroupManagementError, GroupRepository,
    NewCredentialRequest, OnboardEndpointError, OnboardEndpointRequest, OperationStore,
    OperationSubmission, RedfishDiscovery, ResourceDiagnostics, ResourceDiagnosticsQuery,
    ResourceDiagnosticsQueryError, ResourceStatusSummary, SubmissionError, TagManagement,
    TagManagementError, TagRepository, TelemetryRepository, TlsIdentityProbe, TrustedEndpoint,
    parse_endpoint_csv,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, CapabilityClassification,
    CapabilityState, CertificateFingerprintParseError, Credential, CredentialId, CredentialName,
    CredentialUsername, DeploymentPosture, Endpoint, EndpointAddress, EndpointDisplayName,
    EndpointId, Event, Group, GroupId, GroupName, Operation, OperationId, OperationSource,
    OperationState, OperationTarget, ResourceFeature, ResourceId, ResourceSnapshot, Tag, TagName,
    TargetId, TelemetrySample, TelemetrySeries, TelemetrySeriesId, TlsTrust, UiLocation,
};
use tower_http::set_header::SetResponseHeaderLayer;

/// The HTTP body limit of one chunk request: the 4 MiB base64 protocol limit
/// plus JSON framing headroom, so the handler's own
/// [`ARTIFACT_CHUNK_BASE64_MAX_BYTES`] validation stays reachable. Bodies far
/// beyond the protocol limit are rejected by the transport layer with 413
/// before any decoding work.
///
/// The cast cannot truncate on any supported pointer width: 4 MiB fits even
/// a 32-bit `usize`, so the protocol limit and the transport limit never
/// drift.
#[allow(clippy::cast_possible_truncation)]
const ARTIFACT_CHUNK_BODY_LIMIT_BYTES: usize = ARTIFACT_CHUNK_BASE64_MAX_BYTES as usize + 1024;
const CONTENT_SECURITY_POLICY: HeaderName = HeaderName::from_static("content-security-policy");
const CROSS_ORIGIN_OPENER_POLICY: HeaderName =
    HeaderName::from_static("cross-origin-opener-policy");
const PERMISSIONS_POLICY: HeaderName = HeaderName::from_static("permissions-policy");
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const CSP: &str = "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; img-src 'self' data:; object-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; form-action 'self'";

#[derive(RustEmbed)]
#[folder = "assets/"]
struct EmbeddedAssets;

/// Immutable build metadata displayed by the local management console.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebProductInfo {
    product_version: &'static str,
    nv_redfish_baseline: &'static str,
}

impl WebProductInfo {
    #[must_use]
    pub const fn new(product_version: &'static str, nv_redfish_baseline: &'static str) -> Self {
        Self {
            product_version,
            nv_redfish_baseline,
        }
    }

    #[must_use]
    pub const fn product_version(self) -> &'static str {
        self.product_version
    }

    #[must_use]
    pub const fn nv_redfish_baseline(self) -> &'static str {
        self.nv_redfish_baseline
    }
}

/// Appends immutable audit facts through an application-owned boundary.
///
/// The boundary intentionally exposes no update or delete operation. The
/// returned events are newest-first and never contain secret material.
pub trait AuditEventQuery: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<AuditEvent>, Self::Error>>;
}

impl<Query> AuditEventQuery for &Query
where
    Query: AuditEventQuery + ?Sized,
{
    type Error = Query::Error;

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<AuditEvent>, Self::Error>> {
        Query::list_recent_events(*self, limit)
    }
}

/// One injected bundle of application boundaries for every product path.
///
/// The Web crate never touches persistence; the embedding runtime composes
/// concrete repository, security, and gateway implementations behind these
/// boundaries and assembles the application use cases per request. The
/// blanket implementation keeps the bundle open to any runtime composition.
///
/// The operation boundaries (§13) are `OperationStore` — the persistence
/// boundary of the operation lifecycle, re-exported through the application
/// facade — together with `EndpointRefreshRepository`, whose `find_endpoint`
/// read is the endpoint-existence check of the operation submission use case.
/// The embedding runtime supplies the `OperationStore` implementation (the
/// Standalone posture delegates to its `SqliteStore`, which already
/// implements the boundary) and the application composes it per request.
///
/// The artifact boundary (§14.3) is [`ArtifactRepository`]: the five-method
/// contract that drives the upload store (create, find, per-state listing,
/// progress/state update, and the deterministic `artifact_file_path`). The
/// contract mirrors the `SqliteStore` artifact surface exactly — the
/// embedding runtime delegates its five methods to the store, which persists
/// the manifest and the upload progress while the application use case owns
/// the file bytes (`spawn_blocking`, §7.8).
///
/// The grouping boundaries (§12.1, §14.2) are [`GroupRepository`] and
/// [`TagRepository`]: the six-method static-group contract (`create`, `find`,
/// `list`, `add_member`, `remove_member`, `delete`) and the four-method
/// tag-binding contract (`assign`, `remove`, `list_for_endpoint`,
/// `list_by_tag`), both composed by the application use cases per request.
/// The embedding runtime delegates them to the `groups`, `group_members`,
/// `tags`, and `endpoint_tags` tables (§9.3).
pub trait ProductServices:
    EndpointInventoryRepository
    + CredentialInventoryRepository
    + CredentialSecretProtector
    + CredentialCreationRepository<Self::Protected>
    + CredentialResolver
    + DiscoveredEndpointRepository
    + EndpointRefreshRepository
    + CapabilitySnapshotRepository
    + AuditEventWriter
    + AuditEventQuery
    + CapabilityQueryRepository
    + OperationStore
    + ArtifactRepository
    + EventRepository
    + TelemetryRepository
    + GroupRepository
    + TagRepository
{
}

impl<T> ProductServices for T where
    T: EndpointInventoryRepository
        + CredentialInventoryRepository
        + CredentialSecretProtector
        + CredentialCreationRepository<T::Protected>
        + CredentialResolver
        + DiscoveredEndpointRepository
        + EndpointRefreshRepository
        + CapabilitySnapshotRepository
        + AuditEventWriter
        + AuditEventQuery
        + CapabilityQueryRepository
        + OperationStore
        + ArtifactRepository
        + EventRepository
        + TelemetryRepository
        + GroupRepository
        + TagRepository
{
}

struct WebState<Services, Gateway, Time> {
    product: WebProductInfo,
    actor: AuditActor,
    origin: DeploymentPosture,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
}

impl<Services, Gateway, Time> Clone for WebState<Services, Gateway, Time>
where
    Time: Clone,
{
    fn clone(&self) -> Self {
        Self {
            product: self.product,
            actor: self.actor,
            origin: self.origin,
            services: Arc::clone(&self.services),
            gateway: Arc::clone(&self.gateway),
            clock: self.clock.clone(),
        }
    }
}

/// Builds the local Web application without binding a socket.
///
/// Socket policy remains an app/platform responsibility, so the same Router
/// can serve Standalone loopback and a future HTTPS Site listener. All write
/// paths are composed from the injected application boundaries at request
/// time, keeping the Web crate free of persistence and security internals.
///
/// The function is a declarative route table; the line count grows with the
/// product surface, so the lint is not a signal here.
#[allow(clippy::too_many_lines)]
pub fn router<Services, Gateway, Time>(
    product: WebProductInfo,
    actor: AuditActor,
    origin: DeploymentPosture,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
) -> Router
where
    Services: ProductServices + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/about", get(about::<Services, Gateway, Time>))
        .route(
            "/api/v1/endpoints",
            get(endpoint_inventory::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints/{endpoint_id}/resources",
            get(endpoint_resources::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics",
            get(resource_diagnostics::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints/{endpoint_id}/capabilities",
            get(endpoint_capabilities::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/credentials",
            get(credential_inventory::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/credentials",
            post(create_credential::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints/trust",
            post(begin_endpoint_trust::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints/trust/expect",
            post(confirm_endpoint_trust::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints",
            post(enroll_endpoint::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/endpoints/import",
            post(import_endpoints_csv::<Services, Gateway, Time>),
        )
        .route("/api/v1/audit", get(audit_query::<Services, Gateway, Time>))
        .route(
            "/api/v1/events",
            get(event_query::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/telemetry",
            get(telemetry_series::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/telemetry/{series_id}/samples",
            get(telemetry_samples::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/operations",
            post(create_operation::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/operations",
            get(list_operations::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/operations/{operation_id}",
            get(operation_detail::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/artifacts",
            post(create_artifact::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/artifacts",
            get(list_artifacts::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/artifacts/{artifact_id}/chunks",
            post(append_artifact_chunk::<Services, Gateway, Time>)
                .layer(DefaultBodyLimit::max(ARTIFACT_CHUNK_BODY_LIMIT_BYTES)),
        )
        .route(
            "/api/v1/artifacts/{artifact_id}/finalize",
            post(finalize_artifact::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/artifacts/{artifact_id}",
            get(artifact_detail::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/groups",
            get(group_inventory::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/groups",
            post(create_group::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/groups/{group_id}",
            get(group_detail::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/groups/{group_id}",
            delete(delete_group::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/groups/{group_id}/members/{endpoint_id}",
            put(add_group_member::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/groups/{group_id}/members/{endpoint_id}",
            delete(remove_group_member::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/tags",
            get(tag_inventory::<Services, Gateway, Time>),
        )
        .route("/api/v1/tags", put(assign_tag::<Services, Gateway, Time>))
        .route(
            "/api/v1/endpoints/{endpoint_id}/tags/{tag_name}",
            delete(remove_tag::<Services, Gateway, Time>),
        )
        .fallback(static_asset)
        .with_state(WebState {
            product,
            actor,
            origin,
            services,
            gateway,
            clock,
        })
        .layer(SetResponseHeaderLayer::overriding(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            CROSS_ORIGIN_OPENER_POLICY,
            HeaderValue::from_static("same-origin"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            PERMISSIONS_POLICY,
            HeaderValue::from_static("camera=(), geolocation=(), microphone=()"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            REFERRER_POLICY,
            HeaderValue::from_static("no-referrer"),
        ))
        .layer(SetResponseHeaderLayer::overriding(
            X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse::healthy())
}

async fn about<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Json<AboutResponse> {
    Json(AboutResponse::new(
        "rutilus".to_owned(),
        state.product.product_version().to_owned(),
        state.product.nv_redfish_baseline().to_owned(),
    ))
}

async fn endpoint_inventory<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: EndpointInventoryRepository,
{
    let Ok(items) = EndpointInventoryQuery::new(state.services.as_ref())
        .execute()
        .await
    else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(endpoints) = items
        .iter()
        .map(project_endpoint_summary)
        .collect::<Result<Vec<_>, _>>()
    else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = Json(EndpointInventoryResponse::new(endpoints)).into_response();
    no_store(&mut response);
    response
}

async fn endpoint_resources<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(endpoint_id): AxumPath<String>,
) -> Response
where
    Services: EndpointInventoryRepository,
{
    let Ok(endpoint_id) = endpoint_id.parse::<EndpointId>() else {
        return uncached_status(StatusCode::BAD_REQUEST);
    };
    let inventory = match EndpointResourceInventoryQuery::new(state.services.as_ref(), endpoint_id)
        .execute()
        .await
    {
        Ok(Some(inventory)) => inventory,
        Ok(None) => return uncached_status(StatusCode::NOT_FOUND),
        Err(EndpointResourceInventoryQueryError::Inventory(
            EndpointInventoryQueryError::Repository(_),
        )) => return uncached_status(StatusCode::SERVICE_UNAVAILABLE),
        Err(
            EndpointResourceInventoryQueryError::Inventory(
                EndpointInventoryQueryError::DuplicateEndpoint { .. },
            )
            | EndpointResourceInventoryQueryError::Projection { .. },
        ) => return uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let Ok(response) = project_endpoint_resources(&inventory) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = Json(response).into_response();
    no_store(&mut response);
    response
}

/// Serves the §12.4 Advanced Diagnostics view of one stored resource snapshot.
///
/// The resource is addressed by its stable local `ResourceId` (the same UUID
/// identity the resource-inventory API exposes), not by the vendor-controlled
/// `@odata.id` URI: the URI contains path and fragment characters that would
/// need URL encoding and is not a product identity, while the response body
/// carries the URI verbatim for display.
///
/// The view is read-only by construction — §12.4 forbids changing Method,
/// submitting arbitrary JSON, and bypassing the permission and task model —
/// so this path only ever reads the current Generation and never triggers a
/// refresh or a write.
async fn resource_diagnostics<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath((endpoint_id, resource_id)): AxumPath<(String, String)>,
) -> Response
where
    Services: EndpointInventoryRepository,
{
    let (Ok(endpoint_id), Ok(resource_id)) = (
        endpoint_id.parse::<EndpointId>(),
        resource_id.parse::<ResourceId>(),
    ) else {
        return uncached_status(StatusCode::BAD_REQUEST);
    };
    let diagnostics =
        match ResourceDiagnosticsQuery::new(state.services.as_ref(), endpoint_id, resource_id)
            .execute()
            .await
        {
            Ok(Some(diagnostics)) => diagnostics,
            Ok(None) => return uncached_status(StatusCode::NOT_FOUND),
            Err(ResourceDiagnosticsQueryError::Inventory(
                EndpointInventoryQueryError::Repository(_),
            )) => return uncached_status(StatusCode::SERVICE_UNAVAILABLE),
            Err(ResourceDiagnosticsQueryError::Inventory(
                EndpointInventoryQueryError::DuplicateEndpoint { .. },
            )) => return uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
        };
    let Ok(response) = project_resource_diagnostics(&diagnostics) else {
        return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let mut response = Json(response).into_response();
    no_store(&mut response);
    response
}

/// Returns one endpoint's complete capability ledger in design-document
/// order, with the observed state where a probe has already run.
async fn endpoint_capabilities<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(endpoint_id): AxumPath<String>,
) -> Response
where
    Services: CapabilityQueryRepository,
{
    let Ok(endpoint_id) = endpoint_id.parse::<EndpointId>() else {
        return uncached_status(StatusCode::BAD_REQUEST);
    };
    let entries = match EndpointCapabilityQuery::new(state.services.as_ref(), endpoint_id)
        .execute()
        .await
    {
        Ok(Some(entries)) => entries,
        Ok(None) => return uncached_status(StatusCode::NOT_FOUND),
        Err(EndpointCapabilityQueryError::Repository(_)) => {
            return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(EndpointCapabilityQueryError::DuplicateObservation { .. }) => {
            return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    let mut response = Json(EndpointCapabilityInventoryResponse::new(
        endpoint_id.into_uuid(),
        entries
            .iter()
            .copied()
            .map(project_capability_entry)
            .collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Maximum accepted `limit` for one bounded audit query.
const AUDIT_QUERY_MAX_LIMIT: u64 = 1000;
/// Default `limit` for one bounded audit query without an explicit value.
const AUDIT_QUERY_DEFAULT_LIMIT: u64 = 100;

/// Lists secret-free reusable credential metadata in deterministic product
/// order.
async fn credential_inventory<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: CredentialInventoryRepository,
{
    let credentials = match CredentialInventoryQuery::new(state.services.as_ref())
        .execute()
        .await
    {
        Ok(credentials) => credentials,
        Err(CredentialInventoryQueryError::Repository(_)) => {
            return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(
            CredentialInventoryQueryError::DuplicateCredential { .. }
            | CredentialInventoryQueryError::DuplicateActiveVersion { .. },
        ) => return uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let mut response = Json(CredentialInventoryResponse::new(
        credentials.iter().map(project_credential_summary).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Protects, persists, and returns one new credential without echoing its
/// plaintext.
async fn create_credential<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<CreateCredentialRequest>,
) -> Response
where
    Services: ProductServices,
    Time: Clock,
{
    let (name, username, password) = request.into_parts();
    let Ok(name) = CredentialName::parse(&name) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "credential name is invalid".to_owned(),
        );
    };
    let Ok(username) = CredentialUsername::parse(&username) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "credential username is invalid".to_owned(),
        );
    };
    let Ok(request) = NewCredentialRequest::try_new(name, username, password) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "credential password is invalid".to_owned(),
        );
    };
    let creation = CredentialCreation::new(
        state.services.as_ref(),
        state.services.as_ref(),
        &state.clock,
    );
    match creation.execute(request).await {
        Ok(credential) => json_created(Json(project_credential_summary(&credential))),
        Err(CredentialCreationError::Protection(_)) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential protection failed".to_owned(),
        ),
        Err(CredentialCreationError::Repository(_)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "credential persistence failed".to_owned(),
        ),
        Err(CredentialCreationError::IncoherentPersistence { .. }) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "credential persistence returned incoherent state".to_owned(),
        ),
    }
}

/// Observes one endpoint's TLS identity without credentials and returns the
/// safe next trust state.
async fn begin_endpoint_trust<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<BeginEndpointTrustRequest>,
) -> Response
where
    Gateway: TlsIdentityProbe,
    Time: Clock,
{
    let Ok(address) = EndpointAddress::parse(request.address()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "endpoint address is invalid".to_owned(),
        );
    };
    let establishment = EndpointTrustEstablishment::new(state.gateway.as_ref(), &state.clock);
    match establishment.begin(address).await {
        Ok(challenge) => json_ok(Json(project_trust_challenge(challenge))),
        Err(source) => json_error(
            StatusCode::BAD_GATEWAY,
            format!("TLS identity observation failed: {source}"),
        ),
    }
}

/// Verifies a predeclared trust expectation against the credential-free
/// re-observation of the same address.
async fn confirm_endpoint_trust<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<ConfirmEndpointTrustRequest>,
) -> Response
where
    Gateway: TlsIdentityProbe,
    Time: Clock,
{
    let Ok(address) = EndpointAddress::parse(request.address()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "endpoint address is invalid".to_owned(),
        );
    };
    let Ok(expectation) = project_trust_expectation(request.trust()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "trust expectation is invalid".to_owned(),
        );
    };
    let establishment = EndpointTrustEstablishment::new(state.gateway.as_ref(), &state.clock);
    let Ok(challenge) = establishment.begin(address).await else {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "TLS identity re-observation failed".to_owned(),
        );
    };
    match establishment.complete_with_expectation(challenge, expectation) {
        Ok(target) => json_ok(Json(project_trusted_endpoint(&target))),
        Err(source) => trust_rejected_response(source),
    }
}

/// Re-observes the declared trust policy, then enrolls and initially
/// refreshes one endpoint under mandatory audit.
async fn enroll_endpoint<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<EnrollEndpointRequest>,
) -> Response
where
    Services: ProductServices,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader,
    Time: Clock,
{
    let Ok(display_name) = EndpointDisplayName::parse(request.display_name()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "endpoint display name is invalid".to_owned(),
        );
    };
    let Ok(address) = EndpointAddress::parse(request.address()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "endpoint address is invalid".to_owned(),
        );
    };
    let Ok(expectation) = project_trust_expectation(request.trust()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "trust expectation is invalid".to_owned(),
        );
    };
    let establishment = EndpointTrustEstablishment::new(state.gateway.as_ref(), &state.clock);
    let Ok(challenge) = establishment.begin(address).await else {
        return json_error(
            StatusCode::BAD_GATEWAY,
            "TLS identity observation failed".to_owned(),
        );
    };
    let target = match establishment.complete_with_expectation(challenge, expectation) {
        Ok(target) => target,
        Err(source) => return trust_rejected_response(source),
    };
    let enrollment = EndpointEnrollment::new(
        state.services.as_ref(),
        state.services.as_ref(),
        state.gateway.as_ref(),
        &state.clock,
        state.actor,
        state.origin,
    );
    let request = OnboardEndpointRequest::new(
        display_name,
        target,
        CredentialId::from_uuid(request.credential_id()),
    );
    match enrollment.execute(request).await {
        Ok(enrolled) => match project_enrollment(&enrolled) {
            Ok(response) => json_ok(Json(response)),
            Err(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "enrollment result could not be projected".to_owned(),
            ),
        },
        Err(source) => enrollment_error_response(source),
    }
}

/// Imports validated CSV rows sequentially, retaining every independent row
/// result under one mandatory batch audit.
async fn import_endpoints_csv<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<EndpointCsvImportRequest>,
) -> Response
where
    Services: ProductServices,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader,
    Time: Clock,
{
    let Ok(import) = parse_endpoint_csv(request.csv().as_bytes()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "endpoint CSV is invalid".to_owned(),
        );
    };
    let enrollment = EndpointEnrollment::new(
        state.services.as_ref(),
        state.services.as_ref(),
        state.gateway.as_ref(),
        &state.clock,
        state.actor,
        state.origin,
    );
    let importer = EndpointCsvImportExecutor::new(
        state.gateway.as_ref(),
        &enrollment,
        state.services.as_ref(),
        &state.clock,
        state.actor,
        state.origin,
    );
    match importer.execute(import).await {
        Ok(report) => json_ok(Json(project_import_report(&report))),
        Err(source) => {
            let mut response = Json(project_import_report(source.report())).into_response();
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            no_store(&mut response);
            response
        }
    }
}

/// Returns recent immutable audit events, newest first, bounded by `limit`.
async fn audit_query<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    uri: Uri,
) -> Response
where
    Services: AuditEventQuery,
{
    let Ok(limit) = parse_audit_limit(uri.query()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            format!("audit limit must be between 1 and {AUDIT_QUERY_MAX_LIMIT}"),
        );
    };
    let Ok(events) = state.services.list_recent_events(limit).await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut response = Json(AuditQueryResponse::new(
        events.iter().map(project_audit_event).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Maximum accepted `limit` for one bounded event query.
const EVENT_QUERY_MAX_LIMIT: u64 = 1000;
/// Default `limit` for one bounded event query without an explicit value.
const EVENT_QUERY_DEFAULT_LIMIT: u64 = 100;

/// Maximum accepted `limit` for one bounded sample query (§14.4 有界历史).
const TELEMETRY_QUERY_MAX_LIMIT: u64 = 1000;
/// Default `limit` for one bounded sample query without an explicit value.
const TELEMETRY_QUERY_DEFAULT_LIMIT: u64 = 100;

/// Returns every telemetry series with its §14.4 current-value aggregates.
///
/// The current value of a series is its newest retained sample, fetched
/// through the repository's bounded newest-first listing with limit one —
/// the product's "current value and bounded history" is deliberately served
/// by one primitive, not a separate time-series surface (§14.4 不把产品变成
/// 通用时序数据库). A series whose upsert preceded its first successful
/// append reports `None` for both latest fields.
async fn telemetry_series<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: TelemetryRepository,
{
    let Ok(series) = state.services.list_series().await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut projected = Vec::with_capacity(series.len());
    for series_item in &series {
        let Ok(samples) = state
            .services
            .list_samples(series_item.id(), NonZeroU64::MIN)
            .await
        else {
            return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
        };
        projected.push(project_series(series_item, samples.first().copied()));
    }
    let mut response = Json(TelemetrySeriesListResponse::new(projected)).into_response();
    no_store(&mut response);
    response
}

/// Returns one series' bounded history, newest first (§14.4).
///
/// An unknown series id lists no samples — the store's bounded listing has
/// no existence check, and an empty bounded history is indistinguishable
/// from (and as valid as) a series whose samples were all pruned.
async fn telemetry_samples<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(series_id): AxumPath<String>,
    uri: Uri,
) -> Response
where
    Services: TelemetryRepository,
{
    let Ok(series_id) = series_id.parse::<TelemetrySeriesId>() else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "series id must be a valid uuid".to_owned(),
        );
    };
    let Ok(limit) = parse_telemetry_limit(uri.query()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            format!("sample limit must be between 1 and {TELEMETRY_QUERY_MAX_LIMIT}"),
        );
    };
    let Ok(samples) = state.services.list_samples(series_id, limit).await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut response = Json(TelemetrySampleListResponse::new(
        samples.iter().map(project_sample).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Returns recent persisted BMC events, newest first, bounded by `limit`
/// (§14.4 Event History).
///
/// The response carries the BMC-reported `MessageId` and the stable severity
/// code verbatim, so the console renders exactly what the endpoint reported.
async fn event_query<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    uri: Uri,
) -> Response
where
    Services: EventRepository,
{
    let Ok(limit) = parse_event_limit(uri.query()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            format!("event limit must be between 1 and {EVENT_QUERY_MAX_LIMIT}"),
        );
    };
    let Ok(events) = state.services.list_recent_events(limit).await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut response = Json(EventListResponse::new(
        events.iter().map(project_event).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Converts one typed Redfish write into a persisted operation (§13.1) and
/// returns its `Queued` projection.
///
/// The request names target endpoints only; the application submission use
/// case binds a fresh target identity to each endpoint, verifies that every
/// endpoint is managed, and persists the operation with the submitted source
/// (defaulting to `standalone`).
async fn create_operation<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<CreateOperationRequest>,
) -> Response
where
    Services: ProductServices,
    Time: Clock,
{
    let source = match request.source() {
        None => OperationSource::Standalone,
        Some(raw) => match raw.parse() {
            Ok(source) => source,
            Err(_) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "operation source is invalid".to_owned(),
                );
            }
        },
    };
    let targets = request
        .targets()
        .iter()
        .map(|endpoint_id| {
            OperationTarget::new(TargetId::generate(), EndpointId::from_uuid(*endpoint_id))
        })
        .collect();
    let submission = OperationSubmission::new(state.services.as_ref(), state.services.as_ref());
    let now = state.clock.now();
    match submission
        .submit(source, targets, request.command().clone(), now)
        .await
    {
        Ok(operation) => json_created(Json(project_operation(&operation))),
        Err(SubmissionError::EmptyTargets) => json_error(
            StatusCode::BAD_REQUEST,
            "an operation must target at least one endpoint".to_owned(),
        ),
        Err(SubmissionError::DuplicateEndpoint { endpoint_id }) => json_error(
            StatusCode::BAD_REQUEST,
            format!("operation targets endpoint {endpoint_id} more than once"),
        ),
        // A body-referenced endpoint that does not exist is unprocessable,
        // exactly like the enrollment path's missing-credential verdict.
        Err(SubmissionError::UnknownEndpoint { endpoint_id }) => json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("target endpoint {endpoint_id} is not a managed endpoint"),
        ),
        Err(SubmissionError::Inventory(_)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the target endpoints could not be checked".to_owned(),
        ),
        Err(SubmissionError::Store(_)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "operation persistence failed".to_owned(),
        ),
    }
}

/// Lists persisted operations, optionally filtered by exact §13.2 state.
async fn list_operations<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    uri: Uri,
) -> Response
where
    Services: ProductServices,
{
    let Ok(state_filter) = parse_operation_state_filter(uri.query()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "operation state filter is invalid".to_owned(),
        );
    };
    let submission = OperationSubmission::new(state.services.as_ref(), state.services.as_ref());
    let operations = match submission.list(state_filter).await {
        Ok(operations) => operations,
        // The submission verdicts cannot occur from a listing; only the store
        // boundary is reachable here.
        Err(SubmissionError::Store(_) | SubmissionError::Inventory(_)) => {
            return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
        }
        Err(
            SubmissionError::EmptyTargets
            | SubmissionError::DuplicateEndpoint { .. }
            | SubmissionError::UnknownEndpoint { .. },
        ) => return uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let mut response = Json(OperationListResponse::new(
        operations.iter().map(project_operation).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Returns one persisted operation projection by id.
async fn operation_detail<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(operation_id): AxumPath<String>,
) -> Response
where
    Services: ProductServices,
{
    let Ok(operation_id) = operation_id.parse::<OperationId>() else {
        return uncached_status(StatusCode::BAD_REQUEST);
    };
    let submission = OperationSubmission::new(state.services.as_ref(), state.services.as_ref());
    match submission.find(operation_id).await {
        Ok(Some(operation)) => json_ok(Json(project_operation(&operation))),
        Ok(None) => uncached_status(StatusCode::NOT_FOUND),
        Err(SubmissionError::Store(_)) => uncached_status(StatusCode::SERVICE_UNAVAILABLE),
        // The submission verdicts cannot occur from a single-record read; only
        // the store boundary is reachable here.
        Err(
            SubmissionError::EmptyTargets
            | SubmissionError::DuplicateEndpoint { .. }
            | SubmissionError::UnknownEndpoint { .. }
            | SubmissionError::Inventory(_),
        ) => uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Declares one firmware artifact manifest before any byte is transferred
/// (§14.3) and returns its `Uploading` projection.
///
/// The name and digest are validated by their domain types and `size_bytes`
/// must be positive; every declaration failure is a client error (400). The
/// artifact starts with zero bytes received, so the client immediately knows
/// the offset the first chunk must carry.
async fn create_artifact<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<CreateArtifactRequest>,
) -> Response
where
    Services: ProductServices,
    Time: Clock,
{
    let store = ArtifactStore::new(state.services.as_ref());
    let now = state.clock.now();
    match store
        .create(request.name(), request.size_bytes(), request.sha256(), now)
        .await
    {
        Ok(artifact) => json_created(Json(project_artifact(&artifact))),
        Err(ArtifactStoreError::InvalidName(_)) => json_error(
            StatusCode::BAD_REQUEST,
            "artifact name is invalid".to_owned(),
        ),
        Err(ArtifactStoreError::InvalidSha256(_)) => json_error(
            StatusCode::BAD_REQUEST,
            "artifact SHA-256 digest is invalid".to_owned(),
        ),
        Err(ArtifactStoreError::ZeroSize) => json_error(
            StatusCode::BAD_REQUEST,
            "artifact size must be at least one byte".to_owned(),
        ),
        Err(ArtifactStoreError::Repository(_)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact persistence failed".to_owned(),
        ),
        // The remaining verdicts cannot be produced by a declaration.
        Err(
            ArtifactStoreError::NotFound { .. }
            | ArtifactStoreError::InvalidBase64(_)
            | ArtifactStoreError::ChunkTooLarge { .. }
            | ArtifactStoreError::ChunkExceedsSize { .. }
            | ArtifactStoreError::OutOfOrder { .. }
            | ArtifactStoreError::NotUploading { .. }
            | ArtifactStoreError::AlreadyFailed { .. }
            | ArtifactStoreError::FinalizeFailed { .. }
            | ArtifactStoreError::Domain(_)
            | ArtifactStoreError::Restore(_)
            | ArtifactStoreError::File(_),
        ) => uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Lists every artifact across all three lifecycle phases in declaration
/// order (§9.3 artifact inventory).
async fn list_artifacts<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: ProductServices,
{
    let store = ArtifactStore::new(state.services.as_ref());
    let artifacts = match store.list().await {
        Ok(artifacts) => artifacts,
        Err(ArtifactStoreError::Repository(_)) => {
            return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
        }
        // The remaining verdicts cannot be produced by a listing.
        Err(_) => return uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    };
    let mut response = Json(ArtifactListResponse::new(
        artifacts.iter().map(project_artifact).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Returns one artifact's secret-free projection by id.
async fn artifact_detail<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(artifact_id): AxumPath<String>,
) -> Response
where
    Services: ProductServices,
{
    let Ok(artifact_id) = artifact_id.parse::<ArtifactId>() else {
        return json_error(StatusCode::BAD_REQUEST, "artifact id is invalid".to_owned());
    };
    let store = ArtifactStore::new(state.services.as_ref());
    match store.find(artifact_id).await {
        Ok(Some(artifact)) => json_ok(Json(project_artifact(&artifact))),
        Ok(None) => uncached_status(StatusCode::NOT_FOUND),
        Err(ArtifactStoreError::Repository(_)) => uncached_status(StatusCode::SERVICE_UNAVAILABLE),
        // The remaining verdicts cannot be produced by a single-record read.
        Err(_) => uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Receives one base64-encoded byte range of an artifact upload (§14.3) and
/// returns the current progress as the resume point.
///
/// A chunk whose offset lies in the already-received range is acknowledged
/// with the unchanged progress — the §15.4 at-least-once retransmission
/// discipline — while a chunk whose offset lies beyond it is refused (400):
/// the protocol never opens a hole. State conflicts (chunking an artifact
/// that already finished) are a 409: the client's assumption about the
/// artifact state is wrong, and a read settles it.
async fn append_artifact_chunk<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(artifact_id): AxumPath<String>,
    Json(request): Json<AppendArtifactChunkRequest>,
) -> Response
where
    Services: ProductServices,
    Time: Clock,
{
    let Ok(artifact_id) = artifact_id.parse::<ArtifactId>() else {
        return json_error(StatusCode::BAD_REQUEST, "artifact id is invalid".to_owned());
    };
    let store = ArtifactStore::new(state.services.as_ref());
    let now = state.clock.now();
    match store
        .append_chunk(artifact_id, request.offset(), request.data(), now)
        .await
    {
        Ok(progress) => json_ok(Json(project_artifact_progress(&progress))),
        Err(ArtifactStoreError::NotFound { .. }) => uncached_status(StatusCode::NOT_FOUND),
        Err(ArtifactStoreError::InvalidBase64(_)) => json_error(
            StatusCode::BAD_REQUEST,
            "artifact chunk is not valid base64".to_owned(),
        ),
        Err(ArtifactStoreError::ChunkTooLarge { .. }) => json_error(
            StatusCode::BAD_REQUEST,
            format!(
                "artifact chunk exceeds the {ARTIFACT_CHUNK_BASE64_MAX_BYTES} character base64 limit"
            ),
        ),
        Err(ArtifactStoreError::ChunkExceedsSize { .. }) => json_error(
            StatusCode::BAD_REQUEST,
            "artifact chunk exceeds the declared size".to_owned(),
        ),
        Err(ArtifactStoreError::OutOfOrder { .. }) => json_error(
            StatusCode::BAD_REQUEST,
            "artifact chunk is out of order; resume from the last acknowledged offset".to_owned(),
        ),
        Err(ArtifactStoreError::NotUploading { .. }) => json_error(
            StatusCode::CONFLICT,
            "artifact no longer accepts chunks".to_owned(),
        ),
        Err(ArtifactStoreError::Repository(_)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact persistence failed".to_owned(),
        ),
        // The remaining verdicts cannot be produced by a chunk append.
        Err(
            ArtifactStoreError::InvalidName(_)
            | ArtifactStoreError::InvalidSha256(_)
            | ArtifactStoreError::ZeroSize
            | ArtifactStoreError::AlreadyFailed { .. }
            | ArtifactStoreError::FinalizeFailed { .. }
            | ArtifactStoreError::Domain(_)
            | ArtifactStoreError::Restore(_)
            | ArtifactStoreError::File(_),
        ) => uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Verifies one complete upload against its declared SHA-256 digest (§14.3)
/// and returns the terminal verdict.
///
/// The verdict statuses: a verified digest returns the `Ready` projection
/// (200); a digest mismatch or an incomplete upload returns 422
/// [`ArtifactFinalizeFailureResponse`] carrying the now-terminal `Failed`
/// projection and the exact reason — the request itself is well formed, but
/// its subject content cannot be validated, mirroring the unprocessable
/// verdict of a body-referenced unknown endpoint. An already `Failed`
/// artifact is a state conflict (409), and an already `Ready` artifact
/// finalizes again as an idempotent success (the §15.4 duplicate-acceptance
/// discipline).
async fn finalize_artifact<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(artifact_id): AxumPath<String>,
) -> Response
where
    Services: ProductServices,
    Time: Clock,
{
    let Ok(artifact_id) = artifact_id.parse::<ArtifactId>() else {
        return json_error(StatusCode::BAD_REQUEST, "artifact id is invalid".to_owned());
    };
    let store = ArtifactStore::new(state.services.as_ref());
    let now = state.clock.now();
    match store.finalize(artifact_id, now).await {
        Ok(artifact) => json_ok(Json(project_artifact(&artifact))),
        Err(ArtifactStoreError::NotFound { .. }) => uncached_status(StatusCode::NOT_FOUND),
        Err(ArtifactStoreError::AlreadyFailed { .. }) => json_error(
            StatusCode::CONFLICT,
            "artifact already failed; declare a new artifact".to_owned(),
        ),
        Err(ArtifactStoreError::FinalizeFailed {
            artifact, reason, ..
        }) => json_error_with_status(
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ArtifactFinalizeFailureResponse::new(
                project_artifact(&artifact),
                reason,
            )),
        ),
        Err(ArtifactStoreError::File(_)) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the stored artifact file could not be read".to_owned(),
        ),
        Err(ArtifactStoreError::Repository(_)) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "artifact persistence failed".to_owned(),
        ),
        // The remaining verdicts cannot be produced by a finalize.
        Err(
            ArtifactStoreError::InvalidName(_)
            | ArtifactStoreError::InvalidSha256(_)
            | ArtifactStoreError::ZeroSize
            | ArtifactStoreError::InvalidBase64(_)
            | ArtifactStoreError::ChunkTooLarge { .. }
            | ArtifactStoreError::ChunkExceedsSize { .. }
            | ArtifactStoreError::OutOfOrder { .. }
            | ArtifactStoreError::NotUploading { .. }
            | ArtifactStoreError::Domain(_)
            | ArtifactStoreError::Restore(_),
        ) => uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

fn project_artifact(artifact: &Artifact) -> ArtifactResponse {
    ArtifactResponse::new(
        artifact.id().into_uuid(),
        artifact.name().to_string(),
        artifact.size_bytes(),
        artifact.sha256().to_string(),
        project_artifact_state(artifact.state()),
        artifact.uploaded_bytes(),
        artifact.created_at(),
        artifact.updated_at(),
    )
}

fn project_artifact_state(state: ArtifactState) -> ArtifactStateResponse {
    match state {
        ArtifactState::Uploading => ArtifactStateResponse::Uploading,
        ArtifactState::Ready => ArtifactStateResponse::Ready,
        ArtifactState::Failed => ArtifactStateResponse::Failed,
    }
}

fn project_artifact_progress(progress: &ArtifactProgress) -> ArtifactProgressResponse {
    ArtifactProgressResponse::new(
        progress.artifact_id().into_uuid(),
        progress.uploaded_bytes(),
        progress.size_bytes(),
    )
}

fn project_operation(operation: &Operation) -> OperationResponse {
    OperationResponse::new(
        operation.id().into_uuid(),
        project_operation_source(operation.source()),
        operation
            .targets()
            .iter()
            .map(project_operation_target)
            .collect(),
        operation.command(),
        project_operation_state(operation.state()),
        operation.created_at(),
        operation.updated_at(),
    )
}

fn project_operation_target(target: &OperationTarget) -> OperationTargetResponse {
    OperationTargetResponse::new(
        target.target_id().into_uuid(),
        target.endpoint_id().into_uuid(),
    )
}

fn project_operation_source(source: OperationSource) -> OperationSourceResponse {
    match source {
        OperationSource::Standalone => OperationSourceResponse::Standalone,
        OperationSource::Site => OperationSourceResponse::Site,
        OperationSource::Center => OperationSourceResponse::Center,
    }
}

fn project_operation_state(state: OperationState) -> OperationStateResponse {
    match state {
        OperationState::Queued => OperationStateResponse::Queued,
        OperationState::Validating => OperationStateResponse::Validating,
        OperationState::Running => OperationStateResponse::Running,
        OperationState::WaitingRemote => OperationStateResponse::WaitingRemote,
        OperationState::Verifying => OperationStateResponse::Verifying,
        OperationState::Succeeded => OperationStateResponse::Succeeded,
        OperationState::Failed => OperationStateResponse::Failed,
        OperationState::Unknown => OperationStateResponse::Unknown,
        OperationState::Cancelled => OperationStateResponse::Cancelled,
    }
}

/// Parses the optional `state` query filter against the nine console wire
/// values pinned by the api contract tests.
///
/// The filter deliberately accepts the same `snake_case` vocabulary the
/// response emits (`waiting_remote`), not the domain's persistence code
/// (`waiting-remote`), so the console needs exactly one state vocabulary.
fn parse_operation_state_filter(
    query: Option<&str>,
) -> Result<Option<OperationState>, ParseOperationStateFilterError> {
    let Some(query) = query else {
        return Ok(None);
    };
    let Some(value) = query.strip_prefix("state=") else {
        return Err(ParseOperationStateFilterError);
    };
    match value {
        "queued" => Ok(Some(OperationState::Queued)),
        "validating" => Ok(Some(OperationState::Validating)),
        "running" => Ok(Some(OperationState::Running)),
        "waiting_remote" => Ok(Some(OperationState::WaitingRemote)),
        "verifying" => Ok(Some(OperationState::Verifying)),
        "succeeded" => Ok(Some(OperationState::Succeeded)),
        "failed" => Ok(Some(OperationState::Failed)),
        "unknown" => Ok(Some(OperationState::Unknown)),
        "cancelled" => Ok(Some(OperationState::Cancelled)),
        _ => Err(ParseOperationStateFilterError),
    }
}

/// A `state` filter value that is not one of the nine console wire values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParseOperationStateFilterError;

fn project_credential_summary(credential: &Credential) -> CredentialSummaryResponse {
    CredentialSummaryResponse::new(
        credential.id().into_uuid(),
        credential.name().to_string(),
        credential.username().to_string(),
        credential.created_at(),
        credential.updated_at(),
    )
}

fn project_trust_challenge(challenge: EndpointTrustChallenge) -> EndpointTrustChallengeResponse {
    match challenge {
        EndpointTrustChallenge::SystemCaTrusted(target) => {
            let trust = target.trust();
            EndpointTrustChallengeResponse::new(
                target.address().to_string(),
                trust.certificate().fingerprint().to_string(),
                trust.established_at(),
                EndpointTrustChallengeStateResponse::SystemCaTrusted,
            )
        }
        EndpointTrustChallenge::ExplicitPinRequired(pending) => {
            EndpointTrustChallengeResponse::new(
                pending.address().to_string(),
                pending.fingerprint().to_string(),
                pending.observed_at(),
                EndpointTrustChallengeStateResponse::ExplicitPinRequired,
            )
        }
    }
}

fn project_trusted_endpoint(target: &TrustedEndpoint) -> TrustedEndpointResponse {
    TrustedEndpointResponse::new(
        target.address().to_string(),
        project_trust_mode(target.trust()),
        target.trust().established_at(),
    )
}

fn project_trust_mode(trust: &TlsTrust) -> TlsTrustModeResponse {
    match trust {
        TlsTrust::SystemCa { .. } => TlsTrustModeResponse::SystemCa,
        TlsTrust::PinnedCertificate { .. } => TlsTrustModeResponse::PinnedCertificate,
    }
}

fn project_trust_expectation(
    expectation: &EndpointTrustExpectationRequest,
) -> Result<EndpointTrustExpectation, CertificateFingerprintParseError> {
    match expectation {
        EndpointTrustExpectationRequest::SystemCa => Ok(EndpointTrustExpectation::SystemCaOnly),
        EndpointTrustExpectationRequest::PinnedCertificate { fingerprint_sha256 } => Ok(
            EndpointTrustExpectation::ExplicitPin(fingerprint_sha256.parse()?),
        ),
    }
}

fn project_enrollment(
    enrolled: &EnrolledEndpoint,
) -> Result<EndpointEnrollmentResponse, EnrollmentProjectionError> {
    let snapshots = enrolled.snapshots();
    let generation = snapshots
        .first()
        .map(ResourceSnapshot::generation)
        .ok_or(EnrollmentProjectionError::EmptyGeneration)?;
    let mut systems = 0_u64;
    let mut chassis = 0_u64;
    let mut managers = 0_u64;
    for snapshot in snapshots {
        match snapshot.feature() {
            ResourceFeature::Systems => systems += 1,
            ResourceFeature::Chassis => chassis += 1,
            ResourceFeature::Managers => managers += 1,
            // The 0.2 resource families (Processors, Memory, Storage,
            // Network, Accounts, Bios, BootOptions, SecureBoot, the
            // Power/Thermal/Sensors/Controls telemetry families, the
            // LogServices/ManagerNetworkProtocol/HostInterfaces manager
            // surface, the PcieDevices/Assembly/SoftwareInventory read
            // families, and the EventService/EventSubscription/
            // TelemetryService/MetricDefinition/MetricReport/TaskService/Task
            // service families) intentionally stay out of the three-field
            // enrollment counts; the typed resource-inventory route carries
            // their full snapshots instead.
            ResourceFeature::ServiceRoot
            | ResourceFeature::Processors
            | ResourceFeature::Memory
            | ResourceFeature::Storages
            | ResourceFeature::NetworkAdapters
            | ResourceFeature::EthernetInterfaces
            | ResourceFeature::Accounts
            | ResourceFeature::Bios
            | ResourceFeature::BootOptions
            | ResourceFeature::SecureBoot
            | ResourceFeature::Power
            | ResourceFeature::Thermal
            | ResourceFeature::Sensors
            | ResourceFeature::Controls
            | ResourceFeature::LogServices
            | ResourceFeature::ManagerNetworkProtocol
            | ResourceFeature::HostInterfaces
            | ResourceFeature::PcieDevices
            | ResourceFeature::Assembly
            | ResourceFeature::SoftwareInventory
            | ResourceFeature::EventService
            | ResourceFeature::EventSubscription
            | ResourceFeature::TelemetryService
            | ResourceFeature::MetricDefinition
            | ResourceFeature::MetricReport
            | ResourceFeature::TaskService
            | ResourceFeature::Task => {}
        }
    }
    Ok(EndpointEnrollmentResponse::new(
        enrolled.onboarded().endpoint().id().into_uuid(),
        NonZeroU64::new(generation.get()).ok_or(EnrollmentProjectionError::ZeroGeneration)?,
        CoreResourceCountsResponse::new(systems, chassis, managers),
    ))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnrollmentProjectionError {
    EmptyGeneration,
    ZeroGeneration,
}

fn project_import_report<ProbeError, EnrollmentError>(
    report: &EndpointCsvImportReport<ProbeError, EnrollmentError>,
) -> EndpointCsvImportResponse
where
    ProbeError: Error,
    EnrollmentError: Error,
{
    let rows = report
        .rows()
        .iter()
        .map(project_import_row)
        .collect::<Vec<_>>();
    EndpointCsvImportResponse::new(
        u64::try_from(report.total_rows()).unwrap_or(u64::MAX),
        u64::try_from(report.succeeded_count()).unwrap_or(u64::MAX),
        u64::try_from(report.failed_count()).unwrap_or(u64::MAX),
        rows,
    )
}

fn project_import_row<ProbeError, EnrollmentError>(
    result: &EndpointCsvRowResult<ProbeError, EnrollmentError>,
) -> EndpointCsvImportRowResponse
where
    ProbeError: Error,
    EnrollmentError: Error,
{
    let record_number = u64::try_from(result.record_number()).unwrap_or(u64::MAX);
    let address = result.address().to_string();
    match result.outcome() {
        EndpointCsvRowOutcome::Enrolled(endpoint_id) => EndpointCsvImportRowResponse::new(
            record_number,
            address,
            EndpointCsvImportRowStatusResponse::Enrolled,
            Some(endpoint_id.into_uuid()),
            None,
        ),
        EndpointCsvRowOutcome::TlsProbeFailed(source) => EndpointCsvImportRowResponse::new(
            record_number,
            address,
            EndpointCsvImportRowStatusResponse::TlsProbeFailed,
            None,
            Some(source.to_string()),
        ),
        EndpointCsvRowOutcome::TrustRejected(source) => EndpointCsvImportRowResponse::new(
            record_number,
            address,
            EndpointCsvImportRowStatusResponse::TrustRejected,
            None,
            Some(source.to_string()),
        ),
        EndpointCsvRowOutcome::EnrollmentFailed(source) => EndpointCsvImportRowResponse::new(
            record_number,
            address,
            EndpointCsvImportRowStatusResponse::EnrollmentFailed,
            None,
            Some(source.to_string()),
        ),
    }
}

fn project_audit_event(event: &AuditEvent) -> AuditEventResponse {
    let context = event.context();
    let outcome = event.outcome();
    let target = context.target();
    AuditEventResponse::new(
        event.occurred_at(),
        context.actor().as_str().to_owned(),
        context.action().as_str().to_owned(),
        AuditTargetResponse::new(target.kind().to_owned(), target.identifier()),
        AuditOutcomeResponse::new(
            outcome.kind().as_str().to_owned(),
            outcome
                .progress()
                .map(|progress| progress.as_str().to_owned()),
            outcome.failure().map(|failure| failure.as_str().to_owned()),
            outcome
                .verification()
                .map(|verification| verification.as_str().to_owned()),
        ),
        event.sequence().get(),
        context.operation_id().into_uuid(),
        audit_message(event),
    )
}

fn audit_message(event: &AuditEvent) -> String {
    let context = event.context();
    let base = format!(
        "{} {} {} for {}",
        context.actor().as_str(),
        context.action().as_str(),
        event.outcome().kind().as_str(),
        context.target().kind()
    );
    match context.target().identifier() {
        Some(identifier) => format!("{base} {identifier} (sequence {})", event.sequence().get()),
        None => format!("{base} (sequence {})", event.sequence().get()),
    }
}

fn project_event(event: &Event) -> EventResponse {
    EventResponse::new(
        event.id().into_uuid(),
        event.endpoint_id().into_uuid(),
        event.message_id().as_str().to_owned(),
        event.severity().as_str().to_owned(),
        event.message().map(str::to_owned),
        event.event_timestamp(),
        event.observed_at(),
    )
}

fn project_series(
    series: &TelemetrySeries,
    latest: Option<TelemetrySample>,
) -> TelemetrySeriesResponse {
    TelemetrySeriesResponse::new(
        series.id().into_uuid(),
        series.endpoint_id().into_uuid(),
        series.series_key().as_str().to_owned(),
        series.sample_count(),
        latest.as_ref().map(TelemetrySample::value),
        latest.as_ref().map(TelemetrySample::observed_at),
    )
}

fn project_sample(sample: &TelemetrySample) -> TelemetrySampleResponse {
    TelemetrySampleResponse::new(
        sample.series_id().into_uuid(),
        sample.observed_at(),
        sample.bmc_timestamp(),
        sample.value(),
    )
}

fn parse_telemetry_limit(query: Option<&str>) -> Result<NonZeroU64, ParseTelemetryLimitError> {
    let Some(query) = query else {
        return default_telemetry_limit();
    };
    let Some(value) = query.strip_prefix("limit=") else {
        return Err(ParseTelemetryLimitError);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseTelemetryLimitError);
    }
    let Ok(limit) = value.parse::<u64>() else {
        return Err(ParseTelemetryLimitError);
    };
    if limit == 0 || limit > TELEMETRY_QUERY_MAX_LIMIT {
        return Err(ParseTelemetryLimitError);
    }
    NonZeroU64::new(limit).ok_or(ParseTelemetryLimitError)
}

fn default_telemetry_limit() -> Result<NonZeroU64, ParseTelemetryLimitError> {
    NonZeroU64::new(TELEMETRY_QUERY_DEFAULT_LIMIT).ok_or(ParseTelemetryLimitError)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParseTelemetryLimitError;

fn parse_event_limit(query: Option<&str>) -> Result<NonZeroU64, ParseEventLimitError> {
    let Some(query) = query else {
        return default_event_limit();
    };
    let Some(value) = query.strip_prefix("limit=") else {
        return Err(ParseEventLimitError);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseEventLimitError);
    }
    let Ok(limit) = value.parse::<u64>() else {
        return Err(ParseEventLimitError);
    };
    if limit == 0 || limit > EVENT_QUERY_MAX_LIMIT {
        return Err(ParseEventLimitError);
    }
    NonZeroU64::new(limit).ok_or(ParseEventLimitError)
}

fn default_event_limit() -> Result<NonZeroU64, ParseEventLimitError> {
    NonZeroU64::new(EVENT_QUERY_DEFAULT_LIMIT).ok_or(ParseEventLimitError)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParseEventLimitError;

fn parse_audit_limit(query: Option<&str>) -> Result<NonZeroU64, ParseAuditLimitError> {
    let Some(query) = query else {
        return default_audit_limit();
    };
    let Some(value) = query.strip_prefix("limit=") else {
        return Err(ParseAuditLimitError);
    };
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(ParseAuditLimitError);
    }
    let Ok(limit) = value.parse::<u64>() else {
        return Err(ParseAuditLimitError);
    };
    if limit == 0 || limit > AUDIT_QUERY_MAX_LIMIT {
        return Err(ParseAuditLimitError);
    }
    NonZeroU64::new(limit).ok_or(ParseAuditLimitError)
}

fn default_audit_limit() -> Result<NonZeroU64, ParseAuditLimitError> {
    NonZeroU64::new(AUDIT_QUERY_DEFAULT_LIMIT).ok_or(ParseAuditLimitError)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParseAuditLimitError;

fn trust_rejected_response(source: EndpointTrustExpectationError) -> Response {
    json_error_with_status(
        StatusCode::CONFLICT,
        Json(TrustRejectedResponse::new(
            source.expected().map(|fingerprint| fingerprint.to_string()),
            source.observed().to_string(),
        )),
    )
}

fn enrollment_error_response<
    CredentialError,
    DiscoveryError,
    OnboardingRepositoryError,
    RefreshRepositoryError,
    CapabilityError,
    ReaderError,
    AuditError,
>(
    error: EndpointEnrollmentError<
        CredentialError,
        DiscoveryError,
        OnboardingRepositoryError,
        RefreshRepositoryError,
        CapabilityError,
        ReaderError,
        AuditError,
    >,
) -> Response
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    OnboardingRepositoryError: Error + 'static,
    RefreshRepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    ReaderError: Error + 'static,
    AuditError: Error + 'static,
{
    match error {
        EndpointEnrollmentError::Onboarding(onboarding) => onboarding_error_response(*onboarding),
        EndpointEnrollmentError::OnboardingAuditAfterCreation { endpoint_id, .. } => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("endpoint {endpoint_id} was created but its onboarding audit failed"),
        ),
        EndpointEnrollmentError::InitialRefresh {
            endpoint_id,
            source,
        } => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("endpoint {endpoint_id} was created but its initial refresh failed: {source}"),
        ),
        EndpointEnrollmentError::InitialRefreshAuditAfterCommit {
            endpoint_id,
            source,
        } => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "endpoint {endpoint_id} committed its initial resources but its refresh audit failed: {source}"
            ),
        ),
    }
}

fn onboarding_error_response<CredentialError, DiscoveryError, RepositoryError, AuditError>(
    error: AuditedOnboardEndpointError<
        CredentialError,
        DiscoveryError,
        RepositoryError,
        AuditError,
    >,
) -> Response
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    RepositoryError: Error + 'static,
    AuditError: Error + 'static,
{
    match error {
        AuditedOnboardEndpointError::Audit { .. } => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "audited endpoint onboarding could not be finalized".to_owned(),
        ),
        AuditedOnboardEndpointError::Onboarding(onboarding)
        | AuditedOnboardEndpointError::OnboardingAndAudit { onboarding, .. } => {
            onboard_error_response(*onboarding)
        }
    }
}

fn onboard_error_response<CredentialError, DiscoveryError, RepositoryError>(
    error: OnboardEndpointError<CredentialError, DiscoveryError, RepositoryError>,
) -> Response
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    RepositoryError: Error + 'static,
{
    match error {
        OnboardEndpointError::CredentialNotFound { credential_id } => json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("selected credential {credential_id} was not found"),
        ),
        OnboardEndpointError::Credential(source) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("the selected credential could not be resolved: {source}"),
        ),
        OnboardEndpointError::Discovery(source) => json_error(
            StatusCode::BAD_GATEWAY,
            format!("trusted Redfish discovery failed: {source}"),
        ),
        OnboardEndpointError::InvalidTimeline(source) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("endpoint timeline is invalid after discovery: {source}"),
        ),
        OnboardEndpointError::Repository(source) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            format!("endpoint persistence failed: {source}"),
        ),
    }
}

/// Lists every §12.1 static group in deterministic product order.
async fn group_inventory<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: GroupRepository + EndpointRefreshRepository,
{
    let groups = match GroupManagement::new(state.services.as_ref(), state.services.as_ref())
        .list()
        .await
    {
        Ok(groups) => groups,
        Err(error) => return group_error_response(&error),
    };
    json_ok(Json(GroupListResponse::new(
        groups.iter().map(project_group).collect(),
    )))
}

/// Creates one §9.3 group from a validated name at the product clock time.
async fn create_group<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<CreateGroupRequest>,
) -> Response
where
    Services: GroupRepository + EndpointRefreshRepository,
    Time: Clock,
{
    let Ok(name) = GroupName::parse(request.name()) else {
        return json_error(StatusCode::BAD_REQUEST, "group name is invalid".to_owned());
    };
    let group = match GroupManagement::new(state.services.as_ref(), state.services.as_ref())
        .create(name, state.clock.now())
        .await
    {
        Ok(group) => group,
        Err(error) => return group_error_response(&error),
    };
    json_created(Json(project_group(&group)))
}

/// Loads one group with its current member set.
async fn group_detail<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(group_id): AxumPath<String>,
) -> Response
where
    Services: GroupRepository + EndpointRefreshRepository,
{
    let Ok(group_id) = group_id.parse::<GroupId>() else {
        return json_error(StatusCode::BAD_REQUEST, "group id is invalid".to_owned());
    };
    let group = match GroupManagement::new(state.services.as_ref(), state.services.as_ref())
        .find(group_id)
        .await
    {
        Ok(group) => group,
        Err(error) => return group_error_response(&error),
    };
    json_ok(Json(project_group(&group)))
}

/// Deletes one group and all of its memberships.
async fn delete_group<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(group_id): AxumPath<String>,
) -> Response
where
    Services: GroupRepository + EndpointRefreshRepository,
{
    let Ok(group_id) = group_id.parse::<GroupId>() else {
        return json_error(StatusCode::BAD_REQUEST, "group id is invalid".to_owned());
    };
    match GroupManagement::new(state.services.as_ref(), state.services.as_ref())
        .delete(group_id)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => group_error_response(&error),
    }
}

/// Adds one endpoint membership to one group (idempotent PUT).
async fn add_group_member<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath((group_id, endpoint_id)): AxumPath<(String, String)>,
) -> Response
where
    Services: GroupRepository + EndpointRefreshRepository,
{
    let (Ok(group_id), Ok(endpoint_id)) = (
        group_id.parse::<GroupId>(),
        endpoint_id.parse::<EndpointId>(),
    ) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "group or endpoint id is invalid".to_owned(),
        );
    };
    match GroupManagement::new(state.services.as_ref(), state.services.as_ref())
        .add_member(group_id, endpoint_id)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => group_error_response(&error),
    }
}

/// Removes one endpoint membership from one group (idempotent DELETE).
async fn remove_group_member<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath((group_id, endpoint_id)): AxumPath<(String, String)>,
) -> Response
where
    Services: GroupRepository + EndpointRefreshRepository,
{
    let (Ok(group_id), Ok(endpoint_id)) = (
        group_id.parse::<GroupId>(),
        endpoint_id.parse::<EndpointId>(),
    ) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "group or endpoint id is invalid".to_owned(),
        );
    };
    match GroupManagement::new(state.services.as_ref(), state.services.as_ref())
        .remove_member(group_id, endpoint_id)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => group_error_response(&error),
    }
}

/// Lists every tag binding across every managed endpoint — the §14.2
/// homepage tag-filter union.
async fn tag_inventory<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: TagRepository + EndpointRefreshRepository + EndpointInventoryRepository,
{
    let tags = match TagManagement::new(state.services.as_ref(), state.services.as_ref())
        .list_all()
        .await
    {
        Ok(tags) => tags,
        Err(error) => return tag_error_response(&error),
    };
    json_ok(Json(TagListResponse::new(
        tags.iter().map(project_tag).collect(),
    )))
}

/// Binds one tag name to one managed endpoint (idempotent PUT).
async fn assign_tag<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    Json(request): Json<AssignTagRequest>,
) -> Response
where
    Services: TagRepository + EndpointRefreshRepository + EndpointInventoryRepository,
{
    let endpoint_id = EndpointId::from_uuid(request.endpoint_id());
    let Ok(name) = TagName::parse(request.tag_name()) else {
        return json_error(StatusCode::BAD_REQUEST, "tag name is invalid".to_owned());
    };
    match TagManagement::new(state.services.as_ref(), state.services.as_ref())
        .assign(endpoint_id, name)
        .await
    {
        Ok(_) => no_content(),
        Err(error) => tag_error_response(&error),
    }
}

/// Removes one tag binding from one managed endpoint (idempotent DELETE).
///
/// Removal is a convergent cleanup that never depends on the endpoint's
/// continued existence: an endpoint that was deleted after its tags were
/// assigned leaves residual bindings behind, and this path must stay able to
/// remove them (mirroring the group member removal semantics), so an
/// endpoint outside the managed set still returns 204. A malformed identity
/// remains 400.
///
/// The tag name arrives percent-decoded by the path extractor, so names with
/// spaces (for example `Rack A`) need no special handling in the console;
/// names containing a `/` are sent as `%2F`.
async fn remove_tag<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath((endpoint_id, tag_name)): AxumPath<(String, String)>,
) -> Response
where
    Services: TagRepository + EndpointRefreshRepository + EndpointInventoryRepository,
{
    let Ok(endpoint_id) = endpoint_id.parse::<EndpointId>() else {
        return json_error(StatusCode::BAD_REQUEST, "endpoint id is invalid".to_owned());
    };
    let Ok(name) = TagName::parse(&tag_name) else {
        return json_error(StatusCode::BAD_REQUEST, "tag name is invalid".to_owned());
    };
    match TagManagement::new(state.services.as_ref(), state.services.as_ref())
        .remove(endpoint_id, &name)
        .await
    {
        Ok(()) => no_content(),
        Err(error) => tag_error_response(&error),
    }
}

/// Maps one group-workflow failure to its HTTP status and console message.
fn group_error_response<GroupError, EndpointError>(
    error: &GroupManagementError<GroupError, EndpointError>,
) -> Response
where
    GroupError: Error + 'static,
    EndpointError: Error + 'static,
{
    let (status, message) = match error {
        GroupManagementError::GroupRepository(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "group persistence failed")
        }
        GroupManagementError::EndpointRepository(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "endpoint existence check failed",
        ),
        GroupManagementError::NameConflict { .. } => (
            StatusCode::CONFLICT,
            "a group with this name already exists",
        ),
        GroupManagementError::GroupNotFound { .. } => {
            (StatusCode::NOT_FOUND, "group does not exist")
        }
        GroupManagementError::UnknownEndpoint { .. } => {
            (StatusCode::NOT_FOUND, "endpoint does not exist")
        }
        GroupManagementError::DuplicateGroup { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "group inventory is incoherent",
        ),
    };
    json_error(status, message.to_owned())
}

/// Maps one tag-workflow failure to its HTTP status and console message.
fn tag_error_response<TagError, EndpointError, InventoryError>(
    error: &TagManagementError<TagError, EndpointError, InventoryError>,
) -> Response
where
    TagError: Error + 'static,
    EndpointError: Error + 'static,
    InventoryError: Error + 'static,
{
    let (status, message) = match error {
        TagManagementError::TagRepository(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "tag persistence failed")
        }
        TagManagementError::EndpointRepository(_) | TagManagementError::InventoryRepository(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            "endpoint enumeration failed",
        ),
        TagManagementError::UnknownEndpoint { .. } => {
            (StatusCode::NOT_FOUND, "endpoint does not exist")
        }
        TagManagementError::DuplicateTag { .. } | TagManagementError::DuplicateEndpoint { .. } => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "tag inventory is incoherent",
        ),
    };
    json_error(status, message.to_owned())
}

fn project_group(group: &Group) -> GroupResponse {
    GroupResponse::new(
        group.id().into_uuid(),
        group.name().as_str().to_owned(),
        group
            .member_endpoint_ids()
            .iter()
            .map(|endpoint_id| endpoint_id.into_uuid())
            .collect(),
        group.created_at(),
        group.updated_at(),
    )
}

fn project_tag(tag: &Tag) -> TagResponse {
    TagResponse::new(
        tag.id().into_uuid(),
        tag.endpoint_id().into_uuid(),
        tag.name().as_str().to_owned(),
    )
}

fn no_content() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    no_store(&mut response);
    response
}

fn json_ok<Body: IntoResponse>(body: Body) -> Response {
    let mut response = body.into_response();
    no_store(&mut response);
    response
}

fn json_created<Body: IntoResponse>(body: Body) -> Response {
    let mut response = body.into_response();
    *response.status_mut() = StatusCode::CREATED;
    no_store(&mut response);
    response
}

fn json_error(status: StatusCode, message: String) -> Response {
    json_error_with_status(status, Json(ErrorResponse::new(message)))
}

fn json_error_with_status<Body: IntoResponse>(status: StatusCode, body: Body) -> Response {
    let mut response = body.into_response();
    *response.status_mut() = status;
    no_store(&mut response);
    response
}

fn no_store(response: &mut Response) {
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );
}

fn project_endpoint_summary(
    item: &EndpointInventoryItem,
) -> Result<EndpointSummaryResponse, EndpointInventoryProjectionError> {
    let endpoint = item.endpoint();
    let identity = project_endpoint_identity(endpoint);
    let snapshot = match item.generation() {
        None => EndpointSnapshotSummaryResponse::AwaitingFirstRefresh,
        Some(generation) => EndpointSnapshotSummaryResponse::current(
            NonZeroU64::new(generation.get())
                .ok_or(EndpointInventoryProjectionError::ZeroGeneration)?,
            item.last_successful_refresh_at()
                .ok_or(EndpointInventoryProjectionError::MissingRefreshTime)?,
            CoreResourceCountsResponse::new(
                count_resources(item, ResourceFeature::Systems)?,
                count_resources(item, ResourceFeature::Chassis)?,
                count_resources(item, ResourceFeature::Managers)?,
            ),
        ),
    };
    Ok(EndpointSummaryResponse::new(identity, snapshot))
}

fn project_endpoint_resources(
    inventory: &EndpointResourceInventory,
) -> Result<EndpointResourceInventoryResponse, EndpointInventoryProjectionError> {
    let resources = inventory
        .resources()
        .iter()
        .map(project_core_resource)
        .collect::<Vec<_>>();
    let snapshot = match (inventory.generation(), inventory.observed_at()) {
        (None, None) if resources.is_empty() => {
            EndpointResourceSnapshotResponse::AwaitingFirstRefresh
        }
        (Some(generation), Some(observed_at)) if !resources.is_empty() => {
            EndpointResourceSnapshotResponse::current(
                NonZeroU64::new(generation.get())
                    .ok_or(EndpointInventoryProjectionError::ZeroGeneration)?,
                observed_at,
                resources,
            )
        }
        _ => {
            return Err(EndpointInventoryProjectionError::IncoherentResourceSnapshot);
        }
    };
    Ok(EndpointResourceInventoryResponse::new(
        project_endpoint_identity(inventory.endpoint()),
        snapshot,
    ))
}

fn project_resource_diagnostics(
    diagnostics: &ResourceDiagnostics,
) -> Result<ResourceDiagnosticsResponse, EndpointInventoryProjectionError> {
    Ok(ResourceDiagnosticsResponse::new(
        diagnostics.endpoint_id().into_uuid(),
        diagnostics.odata_id().to_string(),
        diagnostics.odata_type().map(ToString::to_string),
        diagnostics.etag().map(ToString::to_string),
        diagnostics.feature().as_str().to_owned(),
        NonZeroU64::new(diagnostics.generation().get())
            .ok_or(EndpointInventoryProjectionError::ZeroGeneration)?,
        // The persisted payload is guaranteed JSON by snapshot construction,
        // so this parse only fails on a corrupted store; the honest mapping
        // is an internal fault rather than a fabricated diagnostics view.
        serde_json::from_str(diagnostics.typed_payload())
            .map_err(|_| EndpointInventoryProjectionError::InvalidTypedPayload)?,
    ))
}

fn project_endpoint_identity(endpoint: &Endpoint) -> EndpointIdentityResponse {
    let trust = match endpoint.trust() {
        TlsTrust::SystemCa { .. } => TlsTrustModeResponse::SystemCa,
        TlsTrust::PinnedCertificate { .. } => TlsTrustModeResponse::PinnedCertificate,
    };
    EndpointIdentityResponse::new(
        endpoint.id().into_uuid(),
        endpoint.display_name().to_string(),
        endpoint.address().to_string(),
        trust,
        endpoint.created_at(),
        endpoint.updated_at(),
    )
}

fn project_core_resource(resource: &CoreResourceSummary) -> CoreResourceResponse {
    CoreResourceResponse::new(
        CoreResourceSourceResponse::new(
            resource.resource_id().into_uuid(),
            resource.odata_id().to_string(),
            resource.odata_type().map(ToString::to_string),
            resource.etag().map(ToString::to_string),
        ),
        CoreResourceCommonResponse::new(
            resource.common().id().to_owned(),
            resource.common().name().to_owned(),
            resource.common().description().map(str::to_owned),
        ),
        project_core_resource_details(resource.details()),
    )
}

fn project_core_resource_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    match details {
        CoreResourceDetails::ServiceRoot { .. } => project_service_root_details(details),
        CoreResourceDetails::System { .. } => project_system_details(details),
        CoreResourceDetails::Chassis { .. } => project_chassis_details(details),
        CoreResourceDetails::Manager { .. } => project_manager_details(details),
        CoreResourceDetails::Processor { .. } => project_processor_details(details),
        CoreResourceDetails::Memory { .. } => project_memory_details(details),
        CoreResourceDetails::Storage { .. } => project_storage_details(details),
        CoreResourceDetails::NetworkAdapter { .. } => project_network_adapter_details(details),
        CoreResourceDetails::EthernetInterface { .. } => {
            project_ethernet_interface_details(details)
        }
        CoreResourceDetails::Account { .. } => project_account_details(details),
        CoreResourceDetails::Bios { .. } => project_bios_details(details),
        CoreResourceDetails::BootOption { .. } => project_boot_option_details(details),
        CoreResourceDetails::SecureBoot { .. } => project_secure_boot_details(details),
        CoreResourceDetails::Power { .. } => project_power_details(details),
        CoreResourceDetails::Thermal { .. } => project_thermal_details(details),
        CoreResourceDetails::Sensor { .. } => project_sensor_details(details),
        CoreResourceDetails::Control { .. } => project_control_details(details),
        CoreResourceDetails::LogService { .. } => project_log_service_details(details),
        CoreResourceDetails::ManagerNetworkProtocol { .. } => {
            project_manager_network_protocol_details(details)
        }
        CoreResourceDetails::HostInterface { .. } => project_host_interface_details(details),
        CoreResourceDetails::PcieDevice { .. } => project_pcie_device_details(details),
        CoreResourceDetails::Assembly { .. } => project_assembly_details(details),
        CoreResourceDetails::SoftwareInventory { .. } => {
            project_software_inventory_details(details)
        }
        CoreResourceDetails::EventService { .. } => project_event_service_details(details),
        CoreResourceDetails::EventSubscription { .. } => {
            project_event_subscription_details(details)
        }
        CoreResourceDetails::TelemetryService { .. } => project_telemetry_service_details(details),
        CoreResourceDetails::MetricDefinition { .. } => project_metric_definition_details(details),
        CoreResourceDetails::MetricReport { .. } => project_metric_report_details(details),
        CoreResourceDetails::TaskService { .. } => project_task_service_details(details),
        CoreResourceDetails::Task { .. } => project_task_details(details),
    }
}

/// Projects the Service Root projection into the shared wire contract.
///
/// The dispatcher guarantees this receives the `ServiceRoot` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_service_root_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::ServiceRoot {
        vendor,
        product,
        redfish_version,
    } = details
    else {
        return CoreResourceDetailsResponse::ServiceRoot {
            vendor: None,
            product: None,
            redfish_version: None,
        };
    };
    CoreResourceDetailsResponse::ServiceRoot {
        vendor: vendor.clone(),
        product: product.clone(),
        redfish_version: redfish_version.clone(),
    }
}

/// Projects the System projection into the shared wire contract.
///
/// The dispatcher guarantees this receives the `System` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_system_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::System {
        system_type,
        manufacturer,
        model,
        part_number,
        serial_number,
        sku,
        host_name,
        bios_version,
        power_state,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::System {
            system_type: None,
            manufacturer: None,
            model: None,
            part_number: None,
            serial_number: None,
            sku: None,
            host_name: None,
            bios_version: None,
            power_state: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::System {
        system_type: system_type.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        part_number: part_number.clone(),
        serial_number: serial_number.clone(),
        sku: sku.clone(),
        host_name: host_name.clone(),
        bios_version: bios_version.clone(),
        power_state: power_state.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the Chassis projection into the shared wire contract.
///
/// The dispatcher guarantees this receives the `Chassis` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_chassis_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Chassis {
        chassis_type,
        manufacturer,
        model,
        part_number,
        serial_number,
        sku,
        asset_tag,
        power_state,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Chassis {
            chassis_type: String::new(),
            manufacturer: None,
            model: None,
            part_number: None,
            serial_number: None,
            sku: None,
            asset_tag: None,
            power_state: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Chassis {
        chassis_type: chassis_type.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        part_number: part_number.clone(),
        serial_number: serial_number.clone(),
        sku: sku.clone(),
        asset_tag: asset_tag.clone(),
        power_state: power_state.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the Manager projection into the shared wire contract.
///
/// The dispatcher guarantees this receives the `Manager` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_manager_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Manager {
        manager_type,
        manufacturer,
        model,
        part_number,
        serial_number,
        firmware_version,
        version,
        power_state,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Manager {
            manager_type: None,
            manufacturer: None,
            model: None,
            part_number: None,
            serial_number: None,
            firmware_version: None,
            version: None,
            power_state: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Manager {
        manager_type: manager_type.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        part_number: part_number.clone(),
        serial_number: serial_number.clone(),
        firmware_version: firmware_version.clone(),
        version: version.clone(),
        power_state: power_state.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 processor family into the shared wire contract,
/// preserving the numeric core count so clients never re-parse text.
///
/// The dispatcher guarantees this receives the `Processor` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_processor_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Processor {
        processor_type,
        socket,
        manufacturer,
        model,
        total_cores,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Processor {
            processor_type: None,
            socket: None,
            manufacturer: None,
            model: None,
            total_cores: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Processor {
        processor_type: processor_type.clone(),
        socket: socket.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        total_cores: *total_cores,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 memory family into the shared wire contract,
/// preserving the numeric capacity so clients never re-parse text.
///
/// The dispatcher guarantees this receives the `Memory` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_memory_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Memory {
        memory_device_type,
        capacity_mib,
        manufacturer,
        model,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Memory {
            memory_device_type: None,
            capacity_mib: None,
            manufacturer: None,
            model: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Memory {
        memory_device_type: memory_device_type.clone(),
        capacity_mib: *capacity_mib,
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 storage family into the shared wire contract,
/// preserving the numeric controller and drive counts so clients never
/// re-parse text.
///
/// The dispatcher guarantees this receives the `Storage` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_storage_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Storage {
        controller_count,
        drive_count,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Storage {
            controller_count: None,
            drive_count: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Storage {
        controller_count: *controller_count,
        drive_count: *drive_count,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 network-adapter family into the shared wire contract.
///
/// The dispatcher guarantees this receives the `NetworkAdapter` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_network_adapter_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::NetworkAdapter {
        manufacturer,
        model,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::NetworkAdapter {
            manufacturer: None,
            model: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::NetworkAdapter {
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 ethernet-interface family into the shared wire contract,
/// preserving the numeric link speed so clients never re-parse text.
///
/// The dispatcher guarantees this receives the `EthernetInterface` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_ethernet_interface_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::EthernetInterface {
        mac_address,
        speed_mbps,
        interface_enabled,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::EthernetInterface {
            mac_address: None,
            speed_mbps: None,
            interface_enabled: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::EthernetInterface {
        mac_address: mac_address.clone(),
        speed_mbps: *speed_mbps,
        interface_enabled: *interface_enabled,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 accounts family (a `ManagerAccount`) into the shared
/// wire contract. The manager-account schema has no `Status` property, so
/// the projection carries no status field.
///
/// The dispatcher guarantees this receives the `Account` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_account_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Account {
        enabled,
        role_id,
        locked,
    } = details
    else {
        return CoreResourceDetailsResponse::Account {
            enabled: None,
            role_id: None,
            locked: None,
        };
    };
    CoreResourceDetailsResponse::Account {
        enabled: *enabled,
        role_id: role_id.clone(),
        locked: *locked,
    }
}

/// Projects the §2.1 bios family into the shared wire contract, retaining
/// only the attribute-registry metadata that names the BIOS attribute set.
///
/// The dispatcher guarantees this receives the `Bios` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_bios_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Bios { attribute_registry } = details else {
        return CoreResourceDetailsResponse::Bios {
            attribute_registry: None,
        };
    };
    CoreResourceDetailsResponse::Bios {
        attribute_registry: attribute_registry.clone(),
    }
}

/// Projects the §2.1 boot-options family into the shared wire contract;
/// the enabled flag stays a Boolean so clients render it without re-parsing
/// text.
///
/// The dispatcher guarantees this receives the `BootOption` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_boot_option_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::BootOption {
        display_name,
        boot_option_enabled,
        uefi_device_path,
    } = details
    else {
        return CoreResourceDetailsResponse::BootOption {
            display_name: None,
            boot_option_enabled: None,
            uefi_device_path: None,
        };
    };
    CoreResourceDetailsResponse::BootOption {
        display_name: display_name.clone(),
        boot_option_enabled: *boot_option_enabled,
        uefi_device_path: uefi_device_path.clone(),
    }
}

/// Projects the §2.1 secure-boot family into the shared wire contract,
/// retaining the schema mode enumeration as a string so clients render it
/// without re-parsing text.
///
/// The dispatcher guarantees this receives the `SecureBoot` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_secure_boot_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::SecureBoot {
        secure_boot_enable,
        secure_boot_mode,
    } = details
    else {
        return CoreResourceDetailsResponse::SecureBoot {
            secure_boot_enable: None,
            secure_boot_mode: None,
        };
    };
    CoreResourceDetailsResponse::SecureBoot {
        secure_boot_enable: *secure_boot_enable,
        secure_boot_mode: secure_boot_mode.clone(),
    }
}

/// Projects the §2.1 power family into the shared wire contract. The
/// `Power_v1` projection carries no details, so the wire variant is empty.
///
/// The dispatcher guarantees this receives the `Power` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_power_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Power {} = details else {
        return CoreResourceDetailsResponse::Power {};
    };
    CoreResourceDetailsResponse::Power {}
}

/// Projects the §2.1 thermal family into the shared wire contract, carrying
/// only the resource-level status values.
///
/// The dispatcher guarantees this receives the `Thermal` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_thermal_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Thermal { status } = details else {
        return CoreResourceDetailsResponse::Thermal { status: None };
    };
    CoreResourceDetailsResponse::Thermal {
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 sensors family into the shared wire contract,
/// preserving the numeric reading and its UCUM units so clients never
/// re-parse text.
///
/// The dispatcher guarantees this receives the `Sensor` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_sensor_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Sensor {
        reading,
        reading_units,
        reading_type,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Sensor {
            reading: None,
            reading_units: None,
            reading_type: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Sensor {
        reading: *reading,
        reading_units: reading_units.clone(),
        reading_type: reading_type.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 controls family into the shared wire contract,
/// preserving the numeric set point so clients never re-parse text.
///
/// The dispatcher guarantees this receives the `Control` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_control_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Control {
        control_type,
        set_point,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::Control {
            control_type: None,
            set_point: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Control {
        control_type: control_type.clone(),
        set_point: *set_point,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 log-services family into the shared wire contract,
/// preserving the service-enabled flag and the numeric record capacity so
/// clients never re-parse text.
///
/// The dispatcher guarantees this receives the `LogService` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_log_service_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::LogService {
        service_enabled,
        max_log_entries,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::LogService {
            service_enabled: None,
            max_log_entries: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::LogService {
        service_enabled: *service_enabled,
        max_log_entries: *max_log_entries,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 manager-network-protocol family into the shared wire
/// contract, carrying the direct `HostName` and `FQDN` metadata properties
/// and the resource-level status values.
///
/// The dispatcher guarantees this receives the `ManagerNetworkProtocol`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_manager_network_protocol_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::ManagerNetworkProtocol {
        host_name,
        fqdn,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::ManagerNetworkProtocol {
            host_name: None,
            fqdn: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::ManagerNetworkProtocol {
        host_name: host_name.clone(),
        fqdn: fqdn.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 host-interfaces family into the shared wire contract,
/// preserving the interface-enabled flag; the `HostInterfaceType`
/// enumeration stays internal to the persisted payload exactly like the
/// `Account` family's `UserName`, because the shared wire contract carries
/// only the interface state.
///
/// The dispatcher guarantees this receives the `HostInterface` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_host_interface_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::HostInterface {
        interface_enabled,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::HostInterface {
            interface_enabled: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::HostInterface {
        interface_enabled: *interface_enabled,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 pcie-devices family into the shared wire contract,
/// preserving the typed `DeviceType` enumeration string so the console
/// renders the device class without re-parsing text.
///
/// The dispatcher guarantees this receives the `PcieDevice` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_pcie_device_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::PcieDevice {
        device_type,
        manufacturer,
        model,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::PcieDevice {
            device_type: None,
            manufacturer: None,
            model: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::PcieDevice {
        device_type: device_type.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 assembly family into the shared wire contract, carrying
/// the `AssemblyData` member's `Producer` exactly as published.
///
/// The dispatcher guarantees this receives the `Assembly` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_assembly_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Assembly { producer, status } = details else {
        return CoreResourceDetailsResponse::Assembly {
            producer: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::Assembly {
        producer: producer.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the `software-inventory` family under the §2.1 `update-service`
/// feature into the shared wire contract, keeping the typed `ReleaseDate`
/// instant so the console renders the release date without re-parsing text.
///
/// The dispatcher guarantees this receives the `SoftwareInventory` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_software_inventory_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::SoftwareInventory {
        software_id,
        version,
        release_date,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::SoftwareInventory {
            software_id: None,
            version: None,
            release_date: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::SoftwareInventory {
        software_id: software_id.clone(),
        version: version.clone(),
        release_date: *release_date,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 event-service family into the shared wire contract,
/// carrying the service posture: the enabled flag and the resource-level
/// status values.
///
/// The dispatcher guarantees this receives the `EventService` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_event_service_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::EventService {
        service_enabled,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::EventService {
            service_enabled: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::EventService {
        service_enabled: *service_enabled,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects one subscription under the §2.1 `event-service` family into the
/// shared wire contract, carrying the destination, protocol, context, and
/// event-type filters exactly as published.
///
/// The dispatcher guarantees this receives the `EventSubscription` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_event_subscription_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::EventSubscription {
        destination,
        protocol,
        context,
        event_types,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::EventSubscription {
            destination: None,
            protocol: None,
            context: None,
            event_types: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::EventSubscription {
        destination: destination.clone(),
        protocol: protocol.clone(),
        context: context.clone(),
        event_types: event_types.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 telemetry-service family into the shared wire contract,
/// carrying the resource-level status values. The compiled
/// `TelemetryService` type exposes `ServiceEnabled` and the service-capacity
/// fields, but the product defers them to the 0.4.0 telemetry iteration, so
/// there is no enabled flag to project this round.
///
/// The dispatcher guarantees this receives the `TelemetryService` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_telemetry_service_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::TelemetryService { status } = details else {
        return CoreResourceDetailsResponse::TelemetryService { status: None };
    };
    CoreResourceDetailsResponse::TelemetryService {
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects one metric definition under the §2.1 `telemetry-service` family
/// into the shared wire contract, preserving the `MetricType` enumeration
/// string and the UCUM units so clients render them without re-parsing text.
///
/// The dispatcher guarantees this receives the `MetricDefinition` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_metric_definition_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::MetricDefinition { units, metric_type } = details else {
        return CoreResourceDetailsResponse::MetricDefinition {
            units: None,
            metric_type: None,
        };
    };
    CoreResourceDetailsResponse::MetricDefinition {
        units: units.clone(),
        metric_type: metric_type.clone(),
    }
}

/// Projects one metric report under the §2.1 `telemetry-service` family into
/// the shared wire contract, carrying the derived metric-values count and
/// each timestamped reading so clients render the latest value without
/// re-parsing text.
///
/// The dispatcher guarantees this receives the `MetricReport` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_metric_report_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::MetricReport {
        metric_values_count,
        metric_values,
    } = details
    else {
        return CoreResourceDetailsResponse::MetricReport {
            metric_values_count: None,
            metric_values: None,
        };
    };
    CoreResourceDetailsResponse::MetricReport {
        metric_values_count: *metric_values_count,
        metric_values: metric_values.as_ref().map(|values| {
            values
                .iter()
                .map(|value| {
                    MetricValueResponse::new(value.timestamp(), value.value().map(str::to_owned))
                })
                .collect()
        }),
    }
}

/// Projects the §2.1 task-service family into the shared wire contract,
/// carrying the service posture and the completed-task overwrite policy as
/// the schema enumeration string.
///
/// The dispatcher guarantees this receives the `TaskService` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_task_service_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::TaskService {
        service_enabled,
        completed_task_overwrite_policy,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::TaskService {
            service_enabled: None,
            completed_task_overwrite_policy: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::TaskService {
        service_enabled: *service_enabled,
        completed_task_overwrite_policy: completed_task_overwrite_policy.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects one task under the §2.1 `task-service` family into the shared
/// wire contract, keeping the state and status enumeration strings, the
/// numeric completion percentage, and the typed RFC 3339 timeline instants so
/// clients render the task without re-parsing text.
///
/// The dispatcher guarantees this receives the `Task` variant; the fallback
/// keeps a stable empty projection instead of panicking if that contract is
/// ever violated.
fn project_task_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::Task {
        task_state,
        task_status,
        percent_complete,
        start_time,
        end_time,
    } = details
    else {
        return CoreResourceDetailsResponse::Task {
            task_state: None,
            task_status: None,
            percent_complete: None,
            start_time: None,
            end_time: None,
        };
    };
    CoreResourceDetailsResponse::Task {
        task_state: task_state.clone(),
        task_status: task_status.clone(),
        percent_complete: *percent_complete,
        start_time: *start_time,
        end_time: *end_time,
    }
}

fn project_resource_status(status: &ResourceStatusSummary) -> ResourceStatusResponse {
    ResourceStatusResponse::new(
        status.state().map(str::to_owned),
        status.health().map(str::to_owned),
        status.health_rollup().map(str::to_owned),
    )
}

fn project_capability_entry(entry: CapabilityLedgerEntry) -> CapabilityEntryResponse {
    CapabilityEntryResponse::new(
        entry.capability().as_str().to_owned(),
        entry.upstream_feature().to_owned(),
        project_capability_classification(entry.classification()),
        project_ui_location(entry.ui_location()),
        entry.state().map(project_capability_state),
        entry.observed_at(),
    )
}

fn project_capability_classification(
    classification: CapabilityClassification,
) -> CapabilityClassificationResponse {
    match classification {
        CapabilityClassification::UserFacing => CapabilityClassificationResponse::UserFacing,
        CapabilityClassification::Infrastructure => {
            CapabilityClassificationResponse::Infrastructure
        }
        CapabilityClassification::LegacyCompatibility => {
            CapabilityClassificationResponse::LegacyCompatibility
        }
        CapabilityClassification::Internal => CapabilityClassificationResponse::Internal,
    }
}

fn project_capability_state(state: CapabilityState) -> CapabilityStateResponse {
    match state {
        CapabilityState::Supported => CapabilityStateResponse::Supported,
        CapabilityState::ReadOnly => CapabilityStateResponse::ReadOnly,
        CapabilityState::Unauthorized => CapabilityStateResponse::Unauthorized,
        CapabilityState::TemporarilyUnavailable => CapabilityStateResponse::TemporarilyUnavailable,
        CapabilityState::SchemaIncompatible => CapabilityStateResponse::SchemaIncompatible,
        CapabilityState::NotAdvertised => CapabilityStateResponse::NotAdvertised,
        CapabilityState::NotCompiled => CapabilityStateResponse::NotCompiled,
    }
}

fn project_ui_location(location: UiLocation) -> UiLocationResponse {
    match location {
        UiLocation::Overview => UiLocationResponse::Overview,
        UiLocation::Systems => UiLocationResponse::Systems,
        UiLocation::Chassis => UiLocationResponse::Chassis,
        UiLocation::Managers => UiLocationResponse::Managers,
        UiLocation::Assembly => UiLocationResponse::Assembly,
        UiLocation::Processors => UiLocationResponse::Processors,
        UiLocation::Memory => UiLocationResponse::Memory,
        UiLocation::Pcie => UiLocationResponse::Pcie,
        UiLocation::Network => UiLocationResponse::Network,
        UiLocation::Power => UiLocationResponse::Power,
        UiLocation::Thermal => UiLocationResponse::Thermal,
        UiLocation::Sensors => UiLocationResponse::Sensors,
        UiLocation::Bios => UiLocationResponse::Bios,
        UiLocation::Boot => UiLocationResponse::Boot,
        UiLocation::SecureBoot => UiLocationResponse::SecureBoot,
        UiLocation::Storage => UiLocationResponse::Storage,
        UiLocation::Accounts => UiLocationResponse::Accounts,
        UiLocation::Logs => UiLocationResponse::Logs,
        UiLocation::Events => UiLocationResponse::Events,
        UiLocation::Telemetry => UiLocationResponse::Telemetry,
        UiLocation::Update => UiLocationResponse::Update,
        UiLocation::Tasks => UiLocationResponse::Tasks,
        UiLocation::Oem => UiLocationResponse::Oem,
        UiLocation::Diagnostics => UiLocationResponse::Diagnostics,
        UiLocation::Infrastructure => UiLocationResponse::Infrastructure,
    }
}

fn count_resources(
    item: &EndpointInventoryItem,
    feature: ResourceFeature,
) -> Result<u64, EndpointInventoryProjectionError> {
    u64::try_from(item.resource_count(feature))
        .map_err(|_| EndpointInventoryProjectionError::ResourceCountOverflow)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EndpointInventoryProjectionError {
    ZeroGeneration,
    MissingRefreshTime,
    ResourceCountOverflow,
    IncoherentResourceSnapshot,
    InvalidTypedPayload,
}

fn uncached_status(status: StatusCode) -> Response {
    let mut response = status.into_response();
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-store, must-revalidate"),
    );
    response
}

async fn static_asset(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path == "api" || path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    let requested = if path.is_empty() { "index.html" } else { path };
    if let Some(asset) = EmbeddedAssets::get(requested) {
        return embedded_response(requested, asset.data.into_owned());
    }
    if !requested.contains('.')
        && let Some(index) = EmbeddedAssets::get("index.html")
    {
        return embedded_response("index.html", index.data.into_owned());
    }
    StatusCode::NOT_FOUND.into_response()
}

fn embedded_response(path: &str, content: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(content));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(content_type(path)));
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    response
}

fn content_type(path: &str) -> &'static str {
    match Path::new(path).extension().and_then(|value| value.to_str()) {
        Some(extension) if extension.eq_ignore_ascii_case("html") => "text/html; charset=utf-8",
        Some(extension) if extension.eq_ignore_ascii_case("css") => "text/css; charset=utf-8",
        Some(extension) if extension.eq_ignore_ascii_case("js") => "text/javascript; charset=utf-8",
        Some(extension) if extension.eq_ignore_ascii_case("wasm") => "application/wasm",
        Some(extension) if extension.eq_ignore_ascii_case("svg") => "image/svg+xml",
        Some(extension) if extension.eq_ignore_ascii_case("png") => "image/png",
        Some(_) | None => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, fmt};

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt as _;
    use rutilus_application::{
        BoundaryFuture, CapabilitySnapshotRepository, EndpointDiscovery,
        ProtectedCredentialCreation, ResolvedCredential, ResourceDiagnostics, ResourceObservation,
        StoredCapability, TlsIdentityObservation,
    };
    use rutilus_domain::{
        CredentialId, CredentialUsername, CredentialVersionId, Endpoint, EndpointAddress,
        EndpointCapabilityObservation, EndpointDisplayName, EndpointId, RefreshGeneration,
        ResourceEtag, ResourceFeature, ResourceId, ResourceODataId, ResourceODataType,
        ResourceSnapshot, ResourceSnapshotPayload, SeriesKey, TelemetrySample, TelemetrySeries,
        TelemetrySeriesId, TlsCertificate, TlsTrust,
    };
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use time::{Duration, OffsetDateTime};
    use tower::ServiceExt as _;

    use super::*;

    fn test_router() -> Router {
        test_router_with(Ok(Vec::new()))
    }

    fn test_router_with(inventory: Result<Vec<EndpointInventoryItem>, MockWriteError>) -> Router {
        router(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            Arc::new(UnavailableWriteServices { inventory }),
            Arc::new(UnavailableGateway),
            FixedClock,
        )
    }

    #[tokio::test]
    async fn exposes_health_and_build_metadata_as_same_origin_json() -> Result<(), Box<dyn Error>> {
        let health = test_router()
            .oneshot(Request::get("/api/v1/health").body(Body::empty())?)
            .await?;
        assert_eq!(health.status(), StatusCode::OK);
        assert_eq!(json_body(health).await?, json!({ "status": "ok" }));

        let about = test_router()
            .oneshot(Request::get("/api/v1/about").body(Body::empty())?)
            .await?;
        assert_eq!(about.status(), StatusCode::OK);
        assert_eq!(
            about.headers().get(CONTENT_SECURITY_POLICY),
            Some(&HeaderValue::from_static(CSP))
        );
        assert_eq!(
            about.headers().get(CROSS_ORIGIN_OPENER_POLICY),
            Some(&HeaderValue::from_static("same-origin"))
        );
        assert_eq!(
            about.headers().get(PERMISSIONS_POLICY),
            Some(&HeaderValue::from_static(
                "camera=(), geolocation=(), microphone=()"
            ))
        );
        assert_eq!(
            about.headers().get(REFERRER_POLICY),
            Some(&HeaderValue::from_static("no-referrer"))
        );
        assert_eq!(
            about.headers().get(X_CONTENT_TYPE_OPTIONS),
            Some(&HeaderValue::from_static("nosniff"))
        );
        assert_eq!(
            json_body(about).await?,
            json!({
                "product": "rutilus",
                "product_version": "0.1.0-test",
                "nv_redfish_baseline": "0.13.0-test"
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn serves_only_embedded_assets_with_spa_fallback() -> Result<(), Box<dyn Error>> {
        let index = test_router()
            .oneshot(Request::get("/").body(Body::empty())?)
            .await?;
        assert_eq!(index.status(), StatusCode::OK);
        assert_eq!(
            index.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/html; charset=utf-8"))
        );
        assert_eq!(
            index.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "no-cache, no-store, must-revalidate"
            ))
        );
        assert!(text_body(index).await?.contains("id=\"app\""));

        let javascript = test_router()
            .oneshot(Request::get("/rutilus_ui.js").body(Body::empty())?)
            .await?;
        assert_eq!(javascript.status(), StatusCode::OK);
        assert_eq!(
            javascript.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/javascript; charset=utf-8"))
        );

        let wasm = test_router()
            .oneshot(Request::get("/rutilus_ui_bg.wasm").body(Body::empty())?)
            .await?;
        assert_eq!(wasm.status(), StatusCode::OK);
        assert_eq!(
            wasm.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("application/wasm"))
        );
        assert!(bytes_body(wasm).await?.starts_with(b"\0asm"));

        let spa = test_router()
            .oneshot(Request::get("/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(spa.status(), StatusCode::OK);

        let css = test_router()
            .oneshot(Request::get("/app.css").body(Body::empty())?)
            .await?;
        assert_eq!(css.status(), StatusCode::OK);
        assert_eq!(
            css.headers().get(CONTENT_TYPE),
            Some(&HeaderValue::from_static("text/css; charset=utf-8"))
        );

        let missing_asset = test_router()
            .oneshot(Request::get("/missing.js").body(Body::empty())?)
            .await?;
        assert_eq!(missing_asset.status(), StatusCode::NOT_FOUND);
        let missing_api = test_router()
            .oneshot(Request::get("/api/v1/missing").body(Body::empty())?)
            .await?;
        assert_eq!(missing_api.status(), StatusCode::NOT_FOUND);
        let api_root = test_router()
            .oneshot(Request::get("/api").body(Body::empty())?)
            .await?;
        assert_eq!(api_root.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    #[tokio::test]
    async fn exposes_secret_free_complete_endpoint_inventory() -> Result<(), Box<dyn Error>> {
        let waiting = inventory_item("Rack A BMC", "https://192.0.2.10", 10, false)?;
        let current = inventory_item("Rack B BMC", "https://192.0.2.11", 11, true)?;
        let waiting_id = waiting.endpoint().id().to_string();
        let current_id = current.endpoint().id().to_string();
        let response = test_router_with(Ok(vec![current, waiting]))
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        assert_eq!(
            json_body(response).await?,
            json!({
                "endpoints": [
                    {
                        "identity": {
                            "endpoint_id": waiting_id,
                            "display_name": "Rack A BMC",
                            "address": "https://192.0.2.10/",
                            "tls_trust_mode": "pinned_certificate",
                            "created_at": "1970-01-01T00:00:00Z",
                            "updated_at": "1970-01-01T00:00:00Z"
                        },
                        "snapshot": { "state": "awaiting_first_refresh" }
                    },
                    {
                        "identity": {
                            "endpoint_id": current_id,
                            "display_name": "Rack B BMC",
                            "address": "https://192.0.2.11/",
                            "tls_trust_mode": "pinned_certificate",
                            "created_at": "1970-01-01T00:00:00Z",
                            "updated_at": "1970-01-01T00:00:00Z"
                        },
                        "snapshot": {
                            "state": "current",
                            "details": {
                                "generation": 1,
                                "last_successful_refresh_at": "1970-01-01T00:00:01Z",
                                "resource_counts": {
                                    "systems": 1,
                                    "chassis": 0,
                                    "managers": 0
                                }
                            }
                        }
                    }
                ]
            })
        );

        let failed = test_router_with(Err(MockWriteError))
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(failed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            failed.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        let wrong_method = test_router()
            .oneshot(Request::delete("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);
        Ok(())
    }

    #[tokio::test]
    async fn exposes_typed_core_resources_with_source_values() -> Result<(), Box<dyn Error>> {
        let item = core_resource_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        let body = json_body(response).await?;
        assert_eq!(body["endpoint"]["display_name"], "Resource detail BMC");
        assert_eq!(body["endpoint"]["tls_trust_mode"], "pinned_certificate");
        assert_eq!(body["snapshot"]["state"], "current");
        assert_eq!(body["snapshot"]["details"]["generation"], 3);
        assert_eq!(
            body["snapshot"]["details"]["observed_at"],
            "1970-01-01T00:00:01Z"
        );
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 4);
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        assert_eq!(resources[0]["common"]["name"], "Root Service");
        assert_eq!(
            resources[0]["resource"]["details"]["redfish_version"],
            "1.20.0"
        );
        assert_eq!(resources[1]["resource"]["resource_type"], "system");
        assert_eq!(resources[1]["source"]["odata_id"], "/redfish/v1/Systems/1");
        assert_eq!(
            resources[1]["source"]["odata_type"],
            "#ComputerSystem.v1_20_0.ComputerSystem"
        );
        assert_eq!(resources[1]["source"]["etag"], "W/\"system-1\"");
        assert_eq!(
            resources[1]["resource"]["details"]["manufacturer"],
            "Vendor A"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["health"],
            "OK"
        );
        assert_eq!(resources[2]["resource"]["resource_type"], "memory");
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Memory/DIMM1"
        );
        assert_eq!(resources[2]["common"]["name"], "Memory Module One");
        assert_eq!(resources[2]["resource"]["details"]["capacity_mib"], 32768);
        assert_eq!(
            resources[2]["resource"]["details"]["memory_device_type"],
            "DDR4"
        );
        assert_eq!(resources[3]["resource"]["resource_type"], "processor");
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Processors/CPU1"
        );
        assert_eq!(resources[3]["common"]["name"], "Processor One");
        assert_eq!(resources[3]["resource"]["details"]["total_cores"], 64);
        assert_eq!(resources[3]["resource"]["details"]["socket"], "LGA4189");
        assert_eq!(
            resources[3]["resource"]["details"]["status"]["health"],
            "OK"
        );
        let encoded = serde_json::to_string(&body)?;
        assert!(!encoded.contains("credential"));
        assert!(!encoded.contains("\"certificate\":"));
        Ok(())
    }

    #[tokio::test]
    async fn exposes_storage_network_and_ethernet_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = storage_network_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the chassis
        // network adapter sorts before the manager ethernet interface, which
        // sorts before the system storage subsystem.
        assert_eq!(resources[1]["resource"]["resource_type"], "network_adapter");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Chassis/1/NetworkAdapters/1"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["manufacturer"],
            "Vendor A"
        );
        assert_eq!(resources[1]["resource"]["details"]["model"], "NA-25G-2P");
        assert_eq!(
            resources[2]["resource"]["resource_type"],
            "ethernet_interface"
        );
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Managers/1/EthernetInterfaces/1"
        );
        assert_eq!(
            resources[2]["resource"]["details"]["mac_address"],
            "52:54:00:12:34:56"
        );
        assert_eq!(resources[2]["resource"]["details"]["speed_mbps"], 10000);
        assert_eq!(
            resources[2]["resource"]["details"]["interface_enabled"],
            true
        );
        assert_eq!(
            resources[2]["resource"]["details"]["status"]["health"],
            "OK"
        );
        assert_eq!(resources[3]["resource"]["resource_type"], "storage");
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Storage/SATA-1"
        );
        assert_eq!(resources[3]["common"]["name"], "Storage Subsystem One");
        assert_eq!(resources[3]["resource"]["details"]["controller_count"], 2);
        assert_eq!(resources[3]["resource"]["details"]["drive_count"], 6);
        assert_eq!(
            resources[3]["resource"]["details"]["status"]["health"],
            "OK"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_accounts_bios_boot_options_and_secure_boot_typed_resources()
    -> Result<(), Box<dyn Error>> {
        let item = accounts_configuration_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 5);
        // The inventory orders snapshots by `@odata.id`, so the root
        // AccountService member sorts before the system-scoped families.
        assert_eq!(resources[1]["resource"]["resource_type"], "account");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/AccountService/Accounts/admin"
        );
        assert_eq!(resources[1]["common"]["name"], "Administrator Account");
        assert_eq!(
            resources[1]["source"]["odata_type"],
            "#ManagerAccount.v1_14_1.ManagerAccount"
        );
        assert_eq!(resources[1]["resource"]["details"]["enabled"], true);
        assert_eq!(
            resources[1]["resource"]["details"]["role_id"],
            "Administrator"
        );
        assert_eq!(resources[1]["resource"]["details"]["locked"], false);
        assert_eq!(resources[2]["resource"]["resource_type"], "bios");
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Bios"
        );
        assert_eq!(
            resources[2]["resource"]["details"]["attribute_registry"],
            "BiosAttributeRegistry.v1_0_0"
        );
        assert_eq!(resources[3]["resource"]["resource_type"], "boot_option");
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/Systems/1/BootOptions/PXE-1"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["display_name"],
            "PXE Network Boot"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["boot_option_enabled"],
            true
        );
        assert_eq!(
            resources[3]["resource"]["details"]["uefi_device_path"],
            "PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)"
        );
        assert_eq!(resources[4]["resource"]["resource_type"], "secure_boot");
        assert_eq!(
            resources[4]["source"]["odata_id"],
            "/redfish/v1/Systems/1/SecureBoot"
        );
        assert_eq!(
            resources[4]["resource"]["details"]["secure_boot_enable"],
            true
        );
        assert_eq!(
            resources[4]["resource"]["details"]["secure_boot_mode"],
            "DeployedMode"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_log_services_manager_network_protocol_and_host_interfaces_typed_resources()
    -> Result<(), Box<dyn Error>> {
        let item = manager_surface_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the manager host
        // interface sorts before the log service, which sorts before the
        // network protocol singleton.
        assert_eq!(resources[1]["resource"]["resource_type"], "host_interface");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Managers/1/HostInterfaces/1"
        );
        assert_eq!(resources[1]["common"]["name"], "Host Interface One");
        assert_eq!(
            resources[1]["resource"]["details"]["interface_enabled"],
            true
        );
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["health"],
            "OK"
        );
        assert_eq!(resources[2]["resource"]["resource_type"], "log_service");
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Managers/1/LogServices/1"
        );
        assert_eq!(resources[2]["common"]["name"], "BMC Event Log");
        assert_eq!(resources[2]["resource"]["details"]["service_enabled"], true);
        assert_eq!(resources[2]["resource"]["details"]["max_log_entries"], 1000);
        assert_eq!(
            resources[3]["resource"]["resource_type"],
            "manager_network_protocol"
        );
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/Managers/1/NetworkProtocol"
        );
        assert_eq!(resources[3]["resource"]["details"]["host_name"], "bmc-1");
        assert_eq!(
            resources[3]["resource"]["details"]["fqdn"],
            "bmc-1.example.com"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_pcie_devices_assembly_and_software_inventory_typed_resources()
    -> Result<(), Box<dyn Error>> {
        let item = device_family_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the root sorts
        // first, the chassis assembly member sorts before the system PCIe
        // device, which sorts before the update-service inventory member.
        assert_eq!(resources[1]["resource"]["resource_type"], "assembly");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Chassis/1/Assembly#/Assemblies/0"
        );
        assert_eq!(resources[1]["common"]["name"], "Fan Assembly");
        assert_eq!(resources[1]["resource"]["details"]["producer"], "Vendor D");
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["health"],
            "OK"
        );
        assert_eq!(resources[2]["resource"]["resource_type"], "pcie_device");
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Systems/1/PCIeDevices/GPU1"
        );
        assert_eq!(resources[2]["common"]["name"], "PCIe Device One");
        assert_eq!(
            resources[2]["resource"]["details"]["device_type"],
            "SingleFunction"
        );
        assert_eq!(
            resources[2]["resource"]["details"]["manufacturer"],
            "Vendor C"
        );
        assert_eq!(
            resources[2]["resource"]["details"]["model"],
            "PCIE-GEN4-X16"
        );
        assert_eq!(
            resources[3]["resource"]["resource_type"],
            "software_inventory"
        );
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/UpdateService/SoftwareInventory/BIOS"
        );
        assert_eq!(resources[3]["common"]["name"], "System BIOS");
        assert_eq!(
            resources[3]["resource"]["details"]["software_id"],
            "BIOS-2026-1"
        );
        assert_eq!(resources[3]["resource"]["details"]["version"], "2.7.0");
        assert_eq!(
            resources[3]["resource"]["details"]["release_date"],
            "2026-05-01T00:00:00Z"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["status"]["state"],
            "Enabled"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_event_and_task_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = event_task_family_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 5);
        // The inventory orders snapshots by `@odata.id`, so the root sorts
        // first, the event-service singleton with its subscription member
        // sorts before the task-service singleton with its task member.
        assert_eq!(resources[1]["resource"]["resource_type"], "event_service");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/EventService"
        );
        assert_eq!(resources[1]["common"]["name"], "Event Service");
        assert_eq!(resources[1]["resource"]["details"]["service_enabled"], true);
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["health"],
            "OK"
        );
        assert_eq!(
            resources[2]["resource"]["resource_type"],
            "event_subscription"
        );
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/EventService/Subscriptions/1"
        );
        assert_eq!(
            resources[2]["resource"]["details"]["destination"],
            "https://subscriber.example.test/events"
        );
        assert_eq!(resources[2]["resource"]["details"]["protocol"], "Redfish");
        assert_eq!(
            resources[2]["resource"]["details"]["event_types"],
            json!(["Alert", "StatusChange"])
        );
        assert_eq!(resources[3]["resource"]["resource_type"], "task_service");
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/TaskService"
        );
        assert_eq!(resources[3]["common"]["name"], "Task Service");
        assert_eq!(
            resources[3]["resource"]["details"]["completed_task_overwrite_policy"],
            "Oldest"
        );
        assert_eq!(resources[4]["resource"]["resource_type"], "task");
        assert_eq!(
            resources[4]["source"]["odata_id"],
            "/redfish/v1/TaskService/Tasks/1"
        );
        assert_eq!(resources[4]["common"]["name"], "Firmware Update Task");
        assert_eq!(resources[4]["resource"]["details"]["task_state"], "Running");
        assert_eq!(resources[4]["resource"]["details"]["task_status"], "OK");
        assert_eq!(resources[4]["resource"]["details"]["percent_complete"], 42);
        assert_eq!(
            resources[4]["resource"]["details"]["start_time"],
            "2026-08-05T10:20:00Z"
        );
        assert_eq!(
            resources[4]["resource"]["details"]["end_time"],
            serde_json::Value::Null
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_telemetry_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = telemetry_family_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 4);
        // The inventory orders snapshots by `@odata.id`, so the root sorts
        // first, the telemetry-service singleton sorts before its definitions
        // collection member, which sorts before the reports collection member.
        assert_eq!(
            resources[1]["resource"]["resource_type"],
            "telemetry_service"
        );
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/TelemetryService"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["state"],
            "Enabled"
        );
        assert_eq!(
            resources[2]["resource"]["resource_type"],
            "metric_definition"
        );
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/TelemetryService/MetricDefinitions/1"
        );
        assert_eq!(resources[2]["resource"]["details"]["units"], "Cel");
        assert_eq!(
            resources[2]["resource"]["details"]["metric_type"],
            "Numeric"
        );
        assert_eq!(resources[3]["resource"]["resource_type"], "metric_report");
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/TelemetryService/MetricReports/1"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["metric_values_count"],
            2
        );
        // The timestamped readings survive the projection with their RFC 3339
        // instants and original text values.
        assert_eq!(
            resources[3]["resource"]["details"]["metric_values"][0]["timestamp"],
            "2026-08-05T10:20:00Z"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["metric_values"][0]["value"],
            "31.5"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["metric_values"][1]["value"],
            "32.0"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_power_thermal_sensors_and_controls_typed_resources()
    -> Result<(), Box<dyn Error>> {
        let item = telemetry_inventory_item()?;
        let endpoint_id = item.endpoint().id();
        let response = test_router_with(Ok(vec![item]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let resources = body["snapshot"]["details"]["resources"]
            .as_array()
            .ok_or("resources must be an array")?;
        assert_eq!(resources.len(), 5);
        // The inventory orders snapshots by `@odata.id`, so the root service
        // sorts first and the chassis telemetry members sort before the
        // Power singleton ("Controls" < "Power" < "Sensors" < "Thermal").
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        assert_eq!(resources[0]["common"]["name"], "Root Service");
        assert_eq!(resources[1]["resource"]["resource_type"], "control");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Chassis/1/Controls/FanDuty"
        );
        assert_eq!(resources[1]["common"]["name"], "Chassis Fan Duty");
        assert_eq!(
            resources[1]["resource"]["details"]["control_type"],
            "DutyCycle"
        );
        assert_eq!(resources[1]["resource"]["details"]["set_point"], 30.0);
        assert_eq!(
            resources[1]["resource"]["details"]["status"]["state"],
            "Enabled"
        );
        assert_eq!(resources[2]["resource"]["resource_type"], "power");
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Chassis/1/Power"
        );
        assert_eq!(resources[2]["common"]["name"], "Power");
        assert_eq!(
            resources[2]["resource"]["details"],
            json!({}),
            "the Power projection carries no details"
        );
        assert_eq!(resources[3]["resource"]["resource_type"], "sensor");
        assert_eq!(
            resources[3]["source"]["odata_id"],
            "/redfish/v1/Chassis/1/Sensors/InletTemp"
        );
        assert_eq!(resources[3]["common"]["name"], "Chassis Inlet Temperature");
        assert_eq!(
            resources[3]["resource"]["details"]["reading_type"],
            "Temperature"
        );
        assert_eq!(resources[3]["resource"]["details"]["reading"], 27.5);
        assert_eq!(resources[3]["resource"]["details"]["reading_units"], "Cel");
        assert_eq!(resources[4]["resource"]["resource_type"], "thermal");
        assert_eq!(
            resources[4]["source"]["odata_id"],
            "/redfish/v1/Chassis/1/Thermal"
        );
        assert_eq!(
            resources[4]["resource"]["details"]["status"]["health"],
            "OK"
        );
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_core_resource_route_states() -> Result<(), Box<dyn Error>> {
        let waiting = inventory_item("Waiting BMC", "https://192.0.2.20", 20, false)?;
        let endpoint_id = waiting.endpoint().id();
        let waiting_router = test_router_with(Ok(vec![waiting]));

        let bad_id = waiting_router
            .clone()
            .oneshot(Request::get("/api/v1/endpoints/not-a-uuid/resources").body(Body::empty())?)
            .await?;
        assert_eq!(bad_id.status(), StatusCode::BAD_REQUEST);
        let missing = waiting_router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/endpoints/{}/resources",
                    EndpointId::generate()
                ))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        let waiting = waiting_router
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(waiting.status(), StatusCode::OK);
        assert_eq!(
            json_body(waiting).await?["snapshot"],
            json!({ "state": "awaiting_first_refresh" })
        );
        let wrong_method = waiting_router
            .oneshot(
                Request::post(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(wrong_method.status(), StatusCode::METHOD_NOT_ALLOWED);

        let unavailable = test_router_with(Err(MockWriteError))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{endpoint_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            unavailable.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );

        let corrupt = inventory_item("Corrupt BMC", "https://192.0.2.21", 21, true)?;
        let corrupt_id = corrupt.endpoint().id();
        let corrupt = test_router_with(Ok(vec![corrupt]))
            .oneshot(
                Request::get(format!("/api/v1/endpoints/{corrupt_id}/resources"))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(corrupt.status(), StatusCode::INTERNAL_SERVER_ERROR);
        Ok(())
    }

    /// Every operation route maps an unavailable services bundle to a
    /// `503` that is never cached, exactly like the other write paths.
    #[tokio::test]
    async fn operation_routes_report_unavailable_services() -> Result<(), Box<dyn Error>> {
        let router = test_router();
        let body = serde_json::to_vec(&json!({
            "targets": [EndpointId::generate().to_string()],
            "command": { "System": { "Reset": "PowerCycle" } }
        }))?;
        let submitted = router
            .clone()
            .oneshot(
                Request::post("/api/v1/operations")
                    .header("content-type", "application/json")
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(submitted.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            submitted.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );

        let listed = router
            .clone()
            .oneshot(Request::get("/api/v1/operations").body(Body::empty())?)
            .await?;
        assert_eq!(listed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            listed.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );

        let detailed = router
            .oneshot(
                Request::get(format!("/api/v1/operations/{}", OperationId::generate()))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(detailed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            detailed.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        Ok(())
    }

    async fn json_body(response: Response) -> Result<Value, Box<dyn Error>> {
        let bytes = response.into_body().collect().await?.to_bytes();
        Ok(serde_json::from_slice(&bytes)?)
    }

    async fn text_body(response: Response) -> Result<String, Box<dyn Error>> {
        let bytes = bytes_body(response).await?;
        Ok(String::from_utf8(bytes.to_vec())?)
    }

    async fn bytes_body(response: Response) -> Result<axum::body::Bytes, Box<dyn Error>> {
        Ok(response.into_body().collect().await?.to_bytes())
    }

    #[test]
    fn exposes_stable_content_types_and_product_metadata() {
        let product = WebProductInfo::new("1.2.3", "4.5.6");
        assert_eq!(product.product_version(), "1.2.3");
        assert_eq!(product.nv_redfish_baseline(), "4.5.6");
        assert_eq!(content_type("app.wasm"), "application/wasm");
        assert_eq!(content_type("icon.svg"), "image/svg+xml");
        assert_eq!(content_type("icon.png"), "image/png");
        assert_eq!(content_type("unknown.bin"), "application/octet-stream");
    }

    fn inventory_item(
        display_name: &str,
        address: &str,
        certificate_byte: u8,
        refreshed: bool,
    ) -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse(display_name)?,
            EndpointAddress::parse(address)?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![certificate_byte])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let resources = if refreshed {
            let observed_at = created_at + Duration::SECOND;
            let generation = RefreshGeneration::new(1)?;
            vec![
                resource_snapshot(
                    endpoint.id(),
                    ResourceFeature::ServiceRoot,
                    "/redfish/v1",
                    observed_at,
                    generation,
                )?,
                resource_snapshot(
                    endpoint.id(),
                    ResourceFeature::Systems,
                    "/redfish/v1/Systems/1",
                    observed_at,
                    generation,
                )?,
            ]
        } else {
            Vec::new()
        };
        Ok(EndpointInventoryItem::try_new(endpoint, resources)?)
    }

    fn core_resource_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Resource detail BMC")?,
            EndpointAddress::parse("https://192.0.2.30")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![30])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(3)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let system = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Systems,
            "/redfish/v1/Systems/1",
            r#"{"Id":"1","Name":"System One","Description":"Compute","SystemType":"Physical","Manufacturer":"Vendor A","Model":"Model S","PartNumber":"P1","SerialNumber":"S1","SKU":"SKU1","HostName":"compute-1","BiosVersion":"2.3.4","PowerState":"On","Status":{"State":"Enabled","Health":"OK","HealthRollup":"Warning"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#ComputerSystem.v1_20_0.ComputerSystem",
        )?)
        .with_etag(ResourceEtag::parse("W/\"system-1\"")?);
        let processor = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Processors,
            "/redfish/v1/Systems/1/Processors/CPU1",
            r#"{"Id":"CPU1","Name":"Processor One","Description":"Primary CPU","ProcessorType":"CPU","Socket":"LGA4189","Manufacturer":"Vendor A","Model":"Model P","TotalCores":64,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#Processor.v1_15_0.Processor",
        )?);
        let memory = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Memory,
            "/redfish/v1/Systems/1/Memory/DIMM1",
            r#"{"Id":"DIMM1","Name":"Memory Module One","MemoryDeviceType":"DDR4","CapacityMiB":32768,"Manufacturer":"Vendor B","Model":"Model MEM","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#Memory.v1_15_0.Memory",
        )?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![processor, memory, system, root],
        )?)
    }

    fn storage_network_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Storage and network BMC")?,
            EndpointAddress::parse("https://192.0.2.31")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![31])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(4)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let storage = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Storages,
            "/redfish/v1/Systems/1/Storage/SATA-1",
            r#"{"Id":"SATA-1","Name":"Storage Subsystem One","Description":"SATA storage subsystem","ControllerCount":2,"DriveCount":6,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?;
        let network_adapter = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::NetworkAdapters,
            "/redfish/v1/Chassis/1/NetworkAdapters/1",
            r#"{"Id":"1","Name":"Network Adapter One","Manufacturer":"Vendor A","Model":"NA-25G-2P","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?;
        let ethernet_interface = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::EthernetInterfaces,
            "/redfish/v1/Managers/1/EthernetInterfaces/1",
            r#"{"Id":"1","Name":"Ethernet Interface One","MACAddress":"52:54:00:12:34:56","SpeedMbps":10000,"InterfaceEnabled":true,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?;
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, storage, network_adapter, ethernet_interface],
        )?)
    }

    fn accounts_configuration_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Accounts and configuration BMC")?,
            EndpointAddress::parse("https://192.0.2.32")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![32])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(5)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let account = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Accounts,
            "/redfish/v1/AccountService/Accounts/admin",
            r#"{"Id":"admin","Name":"Administrator Account","Description":"Built-in administrator account","UserName":"admin","RoleId":"Administrator","Enabled":true,"Locked":false,"AccountTypes":["Redfish","IPMI"]}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#ManagerAccount.v1_14_1.ManagerAccount",
        )?)
        .with_etag(ResourceEtag::parse("W/\"account-1\"")?);
        let bios = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Bios,
            "/redfish/v1/Systems/1/Bios",
            r#"{"Id":"BIOS","Name":"BIOS Configuration","AttributeRegistry":"BiosAttributeRegistry.v1_0_0","ResetBiosToDefaultsPending":false}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Bios.v1_2_3.Bios")?)
        .with_etag(ResourceEtag::parse("W/\"bios-1\"")?);
        let boot_option = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::BootOptions,
            "/redfish/v1/Systems/1/BootOptions/PXE-1",
            r#"{"Id":"PXE-1","Name":"Network Boot Option","Description":"PXE boot option","BootOptionReference":"Boot0001","DisplayName":"PXE Network Boot","BootOptionEnabled":true,"UefiDevicePath":"PciRoot(0x0)/Pci(0x1C,0x0)/Pci(0x0,0x0)","Alias":"Pxe"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#BootOption.v1_0_6.BootOption")?);
        let secure_boot = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::SecureBoot,
            "/redfish/v1/Systems/1/SecureBoot",
            r#"{"Id":"SecureBoot","Name":"Secure Boot","SecureBootEnable":true,"SecureBootCurrentBoot":"Enabled","SecureBootMode":"DeployedMode"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#SecureBoot.v1_1_2.SecureBoot")?)
        .with_etag(ResourceEtag::parse("W/\"secure-boot-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, account, bios, boot_option, secure_boot],
        )?)
    }

    fn telemetry_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Telemetry BMC")?,
            EndpointAddress::parse("https://192.0.2.33")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![33])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(6)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let power = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Power,
            "/redfish/v1/Chassis/1/Power",
            r#"{"Id":"Power","Name":"Power","Description":"Chassis power control"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Power.v1_17_0.Power")?)
        .with_etag(ResourceEtag::parse("W/\"power-1\"")?);
        let thermal = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Thermal,
            "/redfish/v1/Chassis/1/Thermal",
            r#"{"Id":"Thermal","Name":"Thermal","Description":"Chassis temperature and fan monitoring","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Thermal.v1_7_2.Thermal")?);
        let sensor = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Sensors,
            "/redfish/v1/Chassis/1/Sensors/InletTemp",
            r#"{"Id":"InletTemp","Name":"Chassis Inlet Temperature","ReadingType":"Temperature","Reading":27.5,"ReadingUnits":"Cel","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Sensor.v1_9_0.Sensor")?)
        .with_etag(ResourceEtag::parse("W/\"sensor-inlet-1\"")?);
        let control = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Controls,
            "/redfish/v1/Chassis/1/Controls/FanDuty",
            r#"{"Id":"FanDuty","Name":"Chassis Fan Duty","ControlType":"DutyCycle","SetPoint":30.0,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Control.v1_3_0.Control")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, power, thermal, sensor, control],
        )?)
    }

    fn manager_surface_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Manager surface BMC")?,
            EndpointAddress::parse("https://192.0.2.34")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![34])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(7)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let log_service = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::LogServices,
            "/redfish/v1/Managers/1/LogServices/1",
            r#"{"Id":"1","Name":"BMC Event Log","Description":"Manager event log","ServiceEnabled":true,"MaxNumberOfRecords":1000,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#LogService.v1_9_0.LogService")?)
        .with_etag(ResourceEtag::parse("W/\"log-service-1\"")?);
        let network_protocol = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ManagerNetworkProtocol,
            "/redfish/v1/Managers/1/NetworkProtocol",
            r#"{"Id":"NetworkProtocol","Name":"Manager Network Protocol","HostName":"bmc-1","FQDN":"bmc-1.example.com","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#ManagerNetworkProtocol.v1_12_0.ManagerNetworkProtocol",
        )?)
        .with_etag(ResourceEtag::parse("W/\"network-protocol-1\"")?);
        let host_interface = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::HostInterfaces,
            "/redfish/v1/Managers/1/HostInterfaces/1",
            r#"{"Id":"1","Name":"Host Interface One","Description":"Manager host interface","InterfaceEnabled":true,"HostInterfaceType":"NetworkHostInterface","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#HostInterface.v1_3_3.HostInterface")?)
        .with_etag(ResourceEtag::parse("W/\"host-interface-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, log_service, network_protocol, host_interface],
        )?)
    }

    fn device_family_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Device family BMC")?,
            EndpointAddress::parse("https://192.0.2.35")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![35])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(7)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let assembly = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Assembly,
            "/redfish/v1/Chassis/1/Assembly#/Assemblies/0",
            r#"{"Id":"0","Name":"Fan Assembly","Description":"Cooling fan","Producer":"Vendor D","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Assembly.v1_5_0.AssemblyData")?)
        .with_etag(ResourceEtag::parse("W/\"assembly-data-0\"")?);
        let pcie_device = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::PcieDevices,
            "/redfish/v1/Systems/1/PCIeDevices/GPU1",
            r#"{"Id":"GPU1","Name":"PCIe Device One","Description":"GPU accelerator","DeviceType":"SingleFunction","Manufacturer":"Vendor C","Model":"PCIE-GEN4-X16","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#PCIeDevice.v1_12_0.PCIeDevice")?)
        .with_etag(ResourceEtag::parse("W/\"pcie-device-1\"")?);
        let software_inventory = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::SoftwareInventory,
            "/redfish/v1/UpdateService/SoftwareInventory/BIOS",
            r#"{"Id":"BIOS","Name":"System BIOS","Description":"Host firmware","SoftwareId":"BIOS-2026-1","Version":"2.7.0","ReleaseDate":"2026-05-01T00:00:00Z","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#SoftwareInventory.v1_7_0.SoftwareInventory",
        )?)
        .with_etag(ResourceEtag::parse("W/\"sw-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, assembly, pcie_device, software_inventory],
        )?)
    }

    fn event_task_family_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Event and task BMC")?,
            EndpointAddress::parse("https://192.0.2.36")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![36])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(8)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let event_service = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::EventService,
            "/redfish/v1/EventService",
            r#"{"Id":"EventService","Name":"Event Service","Description":"Event subscription service","ServiceEnabled":true,"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#EventService.v1_12_0.EventService",
        )?)
        .with_etag(ResourceEtag::parse("W/\"event-service-1\"")?);
        let subscription = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::EventSubscription,
            "/redfish/v1/EventService/Subscriptions/1",
            r#"{"Id":"1","Name":"Subscription One","Destination":"https://subscriber.example.test/events","Protocol":"Redfish","Context":"Rack A","EventTypes":["Alert","StatusChange"],"Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#EventDestination.v1_16_0.EventDestination",
        )?)
        .with_etag(ResourceEtag::parse("W/\"subscription-1\"")?);
        let task_service = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::TaskService,
            "/redfish/v1/TaskService",
            r#"{"Id":"TaskService","Name":"Task Service","Description":"Asynchronous task service","ServiceEnabled":true,"CompletedTaskOverWritePolicy":"Oldest","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#TaskService.v1_3_0.TaskService")?);
        let task = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::Task,
            "/redfish/v1/TaskService/Tasks/1",
            r#"{"Id":"1","Name":"Firmware Update Task","Description":"BIOS firmware update","TaskState":"Running","TaskStatus":"OK","PercentComplete":42,"StartTime":"2026-08-05T10:20:00Z","EndTime":null}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#Task.v1_7_4.Task")?)
        .with_etag(ResourceEtag::parse("W/\"task-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, event_service, subscription, task_service, task],
        )?)
    }

    fn telemetry_family_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Telemetry BMC")?,
            EndpointAddress::parse("https://192.0.2.37")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![37])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let generation = RefreshGeneration::new(9)?;
        let root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root Service","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            observed_at,
            generation,
        )?;
        let telemetry_service = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::TelemetryService,
            "/redfish/v1/TelemetryService",
            r#"{"Id":"TelemetryService","Name":"Telemetry Service","Description":"Telemetry collection service","Status":{"State":"Enabled","Health":"OK","HealthRollup":"OK"}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#TelemetryService.v1_4_0.TelemetryService",
        )?);
        let metric_definition = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::MetricDefinition,
            "/redfish/v1/TelemetryService/MetricDefinitions/1",
            r#"{"Id":"1","Name":"Inlet Temperature Definition","MetricType":"Numeric","Units":"Cel"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#MetricDefinition.v1_3_5.MetricDefinition",
        )?);
        let metric_report = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::MetricReport,
            "/redfish/v1/TelemetryService/MetricReports/1",
            r#"{"Id":"1","Name":"Inlet Temperature Report","MetricValuesCount":2,"MetricValues":[{"Timestamp":"2026-08-05T10:20:00Z","MetricValue":"31.5"},{"Timestamp":"2026-08-05T10:21:00Z","MetricValue":"32.0"}]}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#MetricReport.v1_5_2.MetricReport",
        )?)
        .with_etag(ResourceEtag::parse("W/\"report-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, telemetry_service, metric_definition, metric_report],
        )?)
    }

    fn resource_snapshot(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        resource_snapshot_with_payload(
            endpoint_id,
            feature,
            odata_id,
            r#"{"Name":"Web test"}"#,
            observed_at,
            generation,
        )
    }

    fn resource_snapshot_with_payload(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        payload: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(payload)?,
            observed_at,
            generation,
        ))
    }

    /// The services bundle serves the read-path inventory and reports a
    /// controlled failure for every unconfigured write-path boundary.
    #[derive(Clone)]
    struct UnavailableWriteServices {
        inventory: Result<Vec<EndpointInventoryItem>, MockWriteError>,
    }

    /// Every gateway boundary reports a controlled failure so the read-path
    /// tests never touch the network.
    #[derive(Clone, Copy)]
    struct UnavailableGateway;

    #[derive(Clone, Copy)]
    struct UnavailableProtected;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MockWriteError;

    impl fmt::Display for MockWriteError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock product services are unavailable")
        }
    }

    impl Error for MockWriteError {}

    impl EndpointInventoryRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async { self.inventory.clone() })
        }
    }

    impl CredentialInventoryRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl CredentialSecretProtector for UnavailableWriteServices {
        type Protected = UnavailableProtected;
        type Error = MockWriteError;

        fn protect(
            &self,
            _credential_id: CredentialId,
            _version_id: CredentialVersionId,
            _password: SecretString,
        ) -> Result<Self::Protected, Self::Error> {
            Err(MockWriteError)
        }
    }

    impl CredentialCreationRepository<UnavailableProtected> for UnavailableWriteServices {
        type Error = MockWriteError;

        fn create_credential(
            &self,
            _creation: ProtectedCredentialCreation<UnavailableProtected>,
        ) -> BoundaryFuture<'_, Result<Credential, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl CredentialResolver for UnavailableWriteServices {
        type Error = MockWriteError;

        fn resolve(
            &self,
            _credential_id: CredentialId,
        ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl TlsIdentityProbe for UnavailableGateway {
        type Error = MockWriteError;

        fn observe<'a>(
            &'a self,
            _address: &'a EndpointAddress,
        ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl DiscoveredEndpointRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn create_discovered_endpoint<'a>(
            &'a self,
            _endpoint: Endpoint,
            _observations: &'a [EndpointCapabilityObservation],
        ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl EndpointRefreshRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn find_endpoint(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [ResourceObservation],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl CapabilitySnapshotRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn replace_endpoint_capabilities<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [EndpointCapabilityObservation],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl AuditEventWriter for UnavailableWriteServices {
        type Error = MockWriteError;

        fn append_audit_event<'a>(
            &'a self,
            _event: &'a AuditEvent,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl RedfishDiscovery for UnavailableGateway {
        type Error = MockWriteError;

        fn probe_core_capabilities<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl CoreResourceReader for UnavailableGateway {
        type Error = MockWriteError;

        fn read_core_resources<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl AuditEventQuery for UnavailableWriteServices {
        type Error = MockWriteError;

        fn list_recent_events(
            &self,
            _limit: NonZeroU64,
        ) -> BoundaryFuture<'_, Result<Vec<AuditEvent>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl CapabilityQueryRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn find_endpoint_capabilities(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl OperationStore for UnavailableWriteServices {
        type Error = MockWriteError;

        fn create_operation<'a>(
            &'a self,
            _operation: &'a Operation,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn find_operation(
            &self,
            _operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn apply_transition(
            &self,
            _operation_id: OperationId,
            _new_state: OperationState,
            _occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn list_operations(
            &self,
            _state: Option<OperationState>,
        ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl ArtifactRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn create_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
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
            Box::pin(async { Err(MockWriteError) })
        }

        fn artifact_file_path(&self, _artifact_id: ArtifactId) -> std::path::PathBuf {
            std::path::PathBuf::from("unused-artifact-path")
        }
    }

    impl EventRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn append_event<'a>(
            &'a self,
            _event: &'a Event,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn list_recent_events(
            &self,
            _limit: NonZeroU64,
        ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl TelemetryRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn upsert_series<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _series_key: &'a SeriesKey,
        ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn append_sample<'a>(
            &'a self,
            _sample: &'a TelemetrySample,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn list_samples(
            &self,
            _series_id: TelemetrySeriesId,
            _limit: NonZeroU64,
        ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
            Box::pin(async { Ok(Vec::new()) })
        }

        fn prune_before(
            &self,
            _cutoff: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }

    impl GroupRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn create<'a>(
            &'a self,
            _group: &'a Group,
        ) -> BoundaryFuture<'a, Result<Group, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn find(
            &self,
            _group_id: GroupId,
        ) -> BoundaryFuture<'_, Result<Option<Group>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn list(&self) -> BoundaryFuture<'_, Result<Vec<Group>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn add_member(
            &self,
            _group_id: GroupId,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn remove_member(
            &self,
            _group_id: GroupId,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn delete(&self, _group_id: GroupId) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    impl TagRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn assign<'a>(&'a self, _tag: &'a Tag) -> BoundaryFuture<'a, Result<Tag, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn remove<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _tag_name: &'a TagName,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn list_for_endpoint(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Vec<Tag>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn list_by_tag<'a>(
            &'a self,
            _tag_name: &'a TagName,
        ) -> BoundaryFuture<'a, Result<Vec<Tag>, Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }
    }

    #[test]
    fn diagnostics_projection_maps_a_corrupt_stored_payload_to_an_internal_fault()
    -> Result<(), Box<dyn Error>> {
        let valid = ResourceDiagnostics::new(
            EndpointId::generate(),
            ResourceId::generate(),
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            Some(ResourceODataType::parse(
                "#ComputerSystem.v1_20_0.ComputerSystem",
            )?),
            Some(ResourceEtag::parse("W/\"system-1\"")?),
            ResourceFeature::Systems,
            r#"{"Id":"1","Name":"System One"}"#.to_owned(),
            RefreshGeneration::new(7)?,
        );
        let projected = project_resource_diagnostics(&valid)
            .map_err(|_| "valid diagnostics projection must succeed")?;
        assert_eq!(projected.odata_uri(), "/redfish/v1/Systems/1");
        assert_eq!(projected.feature(), "systems");
        assert_eq!(projected.generation().get(), 7);

        // `ResourceDiagnostics::new` is the only constructor that can carry a
        // payload which does not re-parse (the query path always copies a
        // domain-validated snapshot payload), so the corrupt-store branch of
        // the projection is exercised here directly instead of through the
        // route, which cannot produce it.
        let corrupt = ResourceDiagnostics::new(
            EndpointId::generate(),
            ResourceId::generate(),
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            None,
            None,
            ResourceFeature::Systems,
            "not json".to_owned(),
            RefreshGeneration::new(7)?,
        );
        assert_eq!(
            project_resource_diagnostics(&corrupt),
            Err(EndpointInventoryProjectionError::InvalidTypedPayload)
        );
        Ok(())
    }
}
