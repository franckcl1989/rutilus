#![forbid(unsafe_code)]

use std::{error::Error, num::NonZeroU64, path::Path, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Extension, Path as AxumPath, State},
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
    AuditTargetResponse, BatchDetailResponse, BatchListResponse, BatchOperationResponse,
    BatchOperationStateResponse, BatchOutcomeCountsResponse, BatchRefreshResponse,
    BatchSummaryResponse, BeginEndpointTrustRequest, CapabilityClassificationResponse,
    CapabilityEntryResponse, CapabilityStateResponse, CenterBindingRegisterRequest,
    CenterBindingRegisterResponse, CenterBindingRevokeRequest, CenterBindingStateResponse,
    CenterEndpointViewListResponse, CenterEndpointViewResponse, CenterOperationListResponse,
    CenterOperationResponse, CenterOperationSubmitRequest, CenterOperationSubmitResponse,
    CenterSiteResponse, CenterSitesResponse, ConfirmEndpointTrustRequest,
    CoreResourceCommonResponse, CoreResourceCountsResponse, CoreResourceDetailsResponse,
    CoreResourceResponse, CoreResourceSourceResponse, CreateArtifactRequest,
    CreateCredentialRequest, CreateGroupRequest, CreateOperationRequest,
    CredentialInventoryResponse, CredentialSummaryResponse, EndpointCapabilityInventoryResponse,
    EndpointCsvImportRequest, EndpointCsvImportResponse, EndpointCsvImportRowResponse,
    EndpointCsvImportRowStatusResponse, EndpointEnrollmentResponse, EndpointIdentityResponse,
    EndpointInventoryResponse, EndpointRefreshResultResponse, EndpointRefreshStatusResponse,
    EndpointResourceInventoryResponse, EndpointResourceSnapshotResponse,
    EndpointSnapshotSummaryResponse, EndpointSummaryResponse, EndpointTrustChallengeResponse,
    EndpointTrustChallengeStateResponse, EndpointTrustExpectationRequest, EnrollEndpointRequest,
    EnvironmentMetricsControlResponse, EnvironmentMetricsReadingResponse, ErrorResponse,
    EventListResponse, EventResponse, GroupListResponse, GroupResponse, HealthResponse,
    MetricValueResponse, OemNvidiaSystemConfigProfileTruststoreResponse, OperationListResponse,
    OperationResponse, OperationSourceResponse, OperationStateResponse, OperationTargetResponse,
    RefreshEndpointsRequest, ResourceDiagnosticsResponse, ResourceStatusResponse, TagListResponse,
    TagResponse, TelemetrySampleListResponse, TelemetrySampleResponse, TelemetrySeriesListResponse,
    TelemetrySeriesResponse, TlsTrustModeResponse, TrustRejectedResponse, TrustedEndpointResponse,
    UiLocationResponse,
};
use rutilus_application::{
    ARTIFACT_CHUNK_BASE64_MAX_BYTES, ArtifactProgress, ArtifactRepository, ArtifactStore,
    ArtifactStoreError, AuditEventWriter, AuditedOnboardEndpointError, BatchDetail,
    BatchEndpointRefresh, BatchEndpointRefreshError, BatchQuery, BatchSummary, BoundaryFuture,
    CapabilityLedgerEntry, CapabilityQueryRepository, CapabilitySnapshotRepository, Clock,
    CoreResourceDetails, CoreResourceReader, CoreResourceSummary, CredentialCreation,
    CredentialCreationError, CredentialCreationRepository, CredentialInventoryQuery,
    CredentialInventoryQueryError, CredentialInventoryRepository, CredentialResolver,
    CredentialSecretProtector, DiscoveredEndpointRepository, EndpointCapabilityQuery,
    EndpointCapabilityQueryError, EndpointCsvImportExecutor, EndpointCsvImportReport,
    EndpointCsvRowOutcome, EndpointCsvRowResult, EndpointEnrollment, EndpointEnrollmentError,
    EndpointInventoryItem, EndpointInventoryQuery, EndpointInventoryQueryError,
    EndpointInventoryRepository, EndpointRefreshOutcome, EndpointRefreshRepository,
    EndpointResourceInventory, EndpointResourceInventoryQuery, EndpointResourceInventoryQueryError,
    EndpointTrustChallenge, EndpointTrustEstablishment, EndpointTrustExpectation,
    EndpointTrustExpectationError, EnrolledEndpoint, EnvironmentMetricsControlSummary,
    EnvironmentMetricsReadingSummary, EventRepository, GroupManagement, GroupManagementError,
    GroupRepository, NewCredentialRequest, OnboardEndpointError, OnboardEndpointRequest,
    OperationStore, OperationSubmission, RedfishDiscovery, ResourceDiagnostics,
    ResourceDiagnosticsQuery, ResourceDiagnosticsQueryError, ResourceStatusSummary,
    SubmissionError, TagManagement, TagManagementError, TagRepository, TelemetryRepository,
    TlsIdentityProbe, TrustedEndpoint, parse_endpoint_csv,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditAction, AuditActor, AuditEvent, AuditFailure,
    AuditFailureVerification, AuditOperationContext, AuditOperationId, AuditParameterSummary,
    AuditRedfishOperation, AuditSequence, AuditTarget, BatchOperation, BatchOperationId,
    BatchOperationState, BatchOutcomeCounts, CapabilityClassification, CapabilityState,
    CenterBindingId, CenterBindingState, CertificateFingerprintParseError, Credential,
    CredentialId, CredentialName, CredentialUsername, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointDisplayName, EndpointId, Event, Group, GroupId, GroupName, InstanceId, Operation,
    OperationId, OperationSource, OperationState, OperationTarget, PrincipalId, ProductPermission,
    RedfishCommand, ResourceFeature, ResourceId, ResourceODataId, ResourceSnapshot, Tag, TagName,
    TargetId, TelemetrySample, TelemetrySeries, TelemetrySeriesId, TlsTrust, UiLocation,
};
use time::OffsetDateTime;
use tower_http::set_header::SetResponseHeaderLayer;

mod auth;

pub use auth::{
    AuthContext, AuthGate, AuthPolicy, AuthServices, BOOTSTRAP_PRINCIPAL_NAME, IssuedSessionTokens,
    SESSION_COOKIE_NAME,
};

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

/// One registered site in the web console's center view (§15.5, 0.7.0 S6).
///
/// The view carries the registered instance, its binding phase, its online
/// presence (one live §15.1 connection), the projected endpoint count, and
/// the newest reported refresh generation as the last-refresh watermark.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterSiteView {
    site_id: InstanceId,
    display_name: String,
    binding: Option<CenterBindingState>,
    online: bool,
    endpoint_count: u64,
    last_refresh_at: Option<OffsetDateTime>,
}

impl CenterSiteView {
    #[must_use]
    pub const fn new(
        site_id: InstanceId,
        display_name: String,
        binding: Option<CenterBindingState>,
        online: bool,
        endpoint_count: u64,
        last_refresh_at: Option<OffsetDateTime>,
    ) -> Self {
        Self {
            site_id,
            display_name,
            binding,
            online,
            endpoint_count,
            last_refresh_at,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> InstanceId {
        self.site_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub const fn binding(&self) -> Option<CenterBindingState> {
        self.binding
    }

    #[must_use]
    pub const fn online(&self) -> bool {
        self.online
    }

    #[must_use]
    pub const fn endpoint_count(&self) -> u64 {
        self.endpoint_count
    }

    #[must_use]
    pub const fn last_refresh_at(&self) -> Option<OffsetDateTime> {
        self.last_refresh_at
    }
}

/// One projected remote endpoint of the web console's center view (§15.5).
///
/// The summary the site reported: the identity, the display name, the
/// address, the refresh generation watermark, and the health cut — never
/// credentials, sessions, or certificate material.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterEndpointView {
    site_id: Option<InstanceId>,
    endpoint_id: EndpointId,
    display_name: String,
    address: String,
    health: String,
    refresh_generation: u64,
}

impl CenterEndpointView {
    #[must_use]
    pub const fn new(
        site_id: Option<InstanceId>,
        endpoint_id: EndpointId,
        display_name: String,
        address: String,
        health: String,
        refresh_generation: u64,
    ) -> Self {
        Self {
            site_id,
            endpoint_id,
            display_name,
            address,
            health,
            refresh_generation,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> Option<InstanceId> {
        self.site_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    #[must_use]
    pub fn address(&self) -> &str {
        &self.address
    }

    #[must_use]
    pub fn health(&self) -> &str {
        &self.health
    }

    #[must_use]
    pub const fn refresh_generation(&self) -> u64 {
        self.refresh_generation
    }
}

/// One center-dispatched operation of the web console's tracking view
/// (§15.6).
///
/// The offer facts the operation record does not persist — the target, the
/// actor context, and the offer expiry — come from the durable §15.6 offer
/// envelope, so they are `None` for an operation whose offer is not on
/// record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterOperationView {
    operation_id: OperationId,
    site_id: Option<InstanceId>,
    endpoint_id: EndpointId,
    command: RedfishCommand,
    target: Option<String>,
    state: OperationState,
    actor: Option<String>,
    ttl_expires_at: Option<OffsetDateTime>,
    created_at: OffsetDateTime,
}

impl CenterOperationView {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        operation_id: OperationId,
        site_id: Option<InstanceId>,
        endpoint_id: EndpointId,
        command: RedfishCommand,
        target: Option<String>,
        state: OperationState,
        actor: Option<String>,
        ttl_expires_at: Option<OffsetDateTime>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            operation_id,
            site_id,
            endpoint_id,
            command,
            target,
            state,
            actor,
            ttl_expires_at,
            created_at,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn site_id(&self) -> Option<InstanceId> {
        self.site_id
    }

    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// The §15.6 target of the offer, when the offer is on record.
    #[must_use]
    pub fn target(&self) -> Option<&str> {
        self.target.as_deref()
    }

    #[must_use]
    pub const fn state(&self) -> OperationState {
        self.state
    }

    /// The actor context of the offer, when the offer is on record.
    #[must_use]
    pub fn actor(&self) -> Option<&str> {
        self.actor.as_deref()
    }

    /// When the outstanding offer stops being actionable (§15.6).
    #[must_use]
    pub const fn ttl_expires_at(&self) -> Option<OffsetDateTime> {
        self.ttl_expires_at
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// One registered site and its one-time binding code (design D2).
///
/// The raw code is shown to the operator exactly once; no later response
/// repeats it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredCenterSite {
    site_id: InstanceId,
    binding_id: CenterBindingId,
    code: String,
    expires_at: OffsetDateTime,
}

impl RegisteredCenterSite {
    #[must_use]
    pub const fn new(
        site_id: InstanceId,
        binding_id: CenterBindingId,
        code: String,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            site_id,
            binding_id,
            code,
            expires_at,
        }
    }

    #[must_use]
    pub const fn site_id(&self) -> InstanceId {
        self.site_id
    }

    #[must_use]
    pub const fn binding_id(&self) -> CenterBindingId {
        self.binding_id
    }

    /// The one-time binding code; never repeated by any later response.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// One dispatched center operation (§15.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchedCenterOperation {
    operation_id: OperationId,
    ttl_expires_at: OffsetDateTime,
}

impl DispatchedCenterOperation {
    #[must_use]
    pub const fn new(operation_id: OperationId, ttl_expires_at: OffsetDateTime) -> Self {
        Self {
            operation_id,
            ttl_expires_at,
        }
    }

    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn ttl_expires_at(&self) -> OffsetDateTime {
        self.ttl_expires_at
    }
}

/// Why a center operation submission was refused.
///
/// The verdicts mirror the application dispatch use case's judgments so the
/// console maps each refusal to its HTTP verdict; the boundary failure is
/// collapsed into [`Self::Store`] with the runtime's error chain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CenterOperationRefusal {
    /// The acting principal is not authorized to dispatch to the target site
    /// (§16.1, D3).
    NotAuthorized,
    /// The endpoint is not in the center's projection.
    UnknownEndpoint { endpoint_id: EndpointId },
    /// The endpoint belongs to a different site; the offer would be dropped
    /// by the addressed site (§15.6).
    EndpointNotInSite {
        endpoint_id: EndpointId,
        site_id: InstanceId,
    },
    /// The target is not part of the endpoint's projected resources.
    UnknownTarget {
        endpoint_id: EndpointId,
        target: String,
    },
    /// The typed command could not be serialized into its wire payload.
    CommandSerialization,
    /// The center store failed.
    Store,
}

/// The center-view boundary of the web console (design §15.5, §15.6, 0.7.0
/// S6).
///
/// The center runtime implements the boundary over its store, the online
/// session registry, and the §15.6 use cases — the Web crate stays free of
/// persistence and security internals exactly like the product-service
/// boundaries. The view values are the web console's read model of the
/// center; the runtime assembles them from the registered instances, the
/// bindings, the projections, and the durable §15.6 offers.
pub trait CenterServices: Send + Sync {
    /// The boundary's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Lists every registered site with its binding, presence, and endpoint
    /// summary (§15.5).
    fn list_center_sites(&self) -> BoundaryFuture<'_, Result<Vec<CenterSiteView>, Self::Error>>;

    /// Lists the projected endpoints of one site, or of every site when
    /// `site` is `None` (§15.5 endpoint summary).
    fn list_center_endpoints(
        &self,
        site: Option<InstanceId>,
    ) -> BoundaryFuture<'_, Result<Vec<CenterEndpointView>, Self::Error>>;

    /// Lists the center-dispatched operations of one site, or of every site
    /// when `site` is `None` (§15.6 tracking view).
    fn list_center_operations(
        &self,
        site: Option<InstanceId>,
    ) -> BoundaryFuture<'_, Result<Vec<CenterOperationView>, Self::Error>>;

    /// Registers one site and returns its one-time binding code (design D2).
    fn register_center_site(
        &self,
        display_name: &str,
        center_url: &str,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<RegisteredCenterSite, Self::Error>>;

    /// Revokes the active binding of one site (design D2).
    fn revoke_center_binding(
        &self,
        site: InstanceId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Dispatches one §15.6 operation offer to a bound site.
    fn dispatch_center_operation(
        &self,
        site: InstanceId,
        endpoint: EndpointId,
        target: &ResourceODataId,
        command: &RedfishCommand,
        actor: PrincipalId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<DispatchedCenterOperation, CenterOperationRefusal>>;
}

/// The console route surface of one deployment posture (audit follow-up
/// F2 — the posture surfaces must not bleed into each other).
///
/// The Edge postures (Standalone/Site) serve every local-management route
/// and none of the `/api/v1/center/*` management surface — the site console
/// must never dispatch center operations or manage center bindings. The
/// Center posture serves the authentication, administration, audit, and
/// center aggregation surface and none of the direct-BMC routes — an
/// administrator on the center console cannot enroll endpoints, manage
/// credentials, or reach any route that talks to a BMC (§15.1 — the center
/// never enters the customer network; 0.7.0 acceptance "Center 不连接
/// BMC"). The scope is a property of the running posture, never of the
/// request, so the two routers are assembled by [`router_with_auth`] from
/// the posture the runtime serves.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsoleScope {
    /// The Standalone and Site postures: the full local-management surface.
    Edge,
    /// The Center posture: aggregation and administration only.
    Center,
}

impl ConsoleScope {
    /// The console scope of one running posture.
    #[must_use]
    pub const fn of(origin: DeploymentPosture) -> Self {
        match origin {
            DeploymentPosture::Standalone | DeploymentPosture::Site => Self::Edge,
            DeploymentPosture::Center => Self::Center,
        }
    }
}

pub(crate) struct WebState<Services, Gateway, Time> {
    pub(crate) product: WebProductInfo,
    pub(crate) actor: AuditActor,
    pub(crate) origin: DeploymentPosture,
    pub(crate) auth: auth::AuthState,
    pub(crate) services: Arc<Services>,
    pub(crate) gateway: Arc<Gateway>,
    pub(crate) clock: Time,
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
            auth: self.auth.clone(),
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
/// The session policy is [`AuthPolicy::Open`]: every request is served
/// without a session, exactly like the pre-0.6 console. The Standalone
/// runtime and a future Site listener use [`router_with_auth`] to enforce
/// the §16.2 session model.
///
/// The route surface follows the running posture ([`ConsoleScope`], audit
/// follow-up F2): the Edge postures get the full local-management surface
/// without the `/api/v1/center/*` management routes, and the Center posture
/// gets the aggregation and administration surface without any direct-BMC
/// route.
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
    Services: ProductServices + AuthServices + CenterServices + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    router_with_auth(
        product,
        actor,
        origin,
        AuthPolicy::Open,
        services,
        gateway,
        clock,
    )
}

/// Builds the local Web application under one §16.2 session policy and the
/// route surface of the running posture ([`ConsoleScope`], audit follow-up
/// F2).
///
/// The session middleware runs on every route: in `Open` mode it only
/// resolves the unauthenticated actor, while `Guarded` (and an armed
/// `PendingBootstrap` gate) require a session and the route's role mask on
/// everything except the public sign-in surface. The authentication
/// boundaries are composed from the same injected services bundle as the
/// product boundaries.
///
/// The posture decides the assembled surface, and the service bound stays
/// the union of both surfaces because the runtimes inject one services
/// bundle. The posture builders themselves — [`edge_router_with_auth`] and
/// [`center_router_with_auth`] — carry only the boundaries their surface
/// needs, so a center router cannot be assembled over edge-only services
/// and vice versa.
#[allow(clippy::too_many_lines)]
pub fn router_with_auth<Services, Gateway, Time>(
    product: WebProductInfo,
    actor: AuditActor,
    origin: DeploymentPosture,
    policy: AuthPolicy,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
) -> Router
where
    Services: ProductServices + AuthServices + CenterServices + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    match ConsoleScope::of(origin) {
        ConsoleScope::Edge => {
            edge_router_with_auth(product, actor, origin, policy, services, gateway, clock)
        }
        ConsoleScope::Center => {
            center_router_with_auth(product, actor, origin, policy, services, gateway, clock)
        }
    }
}

/// The Edge route surface (audit follow-up F2): every local-management
/// route, and no `/api/v1/center/*` route.
///
/// The bound is [`ProductServices`] — every boundary the local-management
/// surface composes — plus [`AuthServices`]. [`CenterServices`] is
/// deliberately absent: an Edge console cannot be assembled over a
/// center-only services bundle, and its route table never registers the
/// center management surface the S6/S7 dispatcher would otherwise silently
/// drop.
///
/// The function is a declarative route table; the line count grows with the
/// product surface, so the lint is not a signal here.
#[allow(clippy::too_many_lines)]
fn edge_router_with_auth<Services, Gateway, Time>(
    product: WebProductInfo,
    actor: AuditActor,
    origin: DeploymentPosture,
    policy: AuthPolicy,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
) -> Router
where
    Services: ProductServices + AuthServices + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    let state = WebState {
        product,
        actor,
        origin,
        auth: auth::AuthState::new(policy),
        services,
        gateway,
        clock,
    };
    let router = Router::new()
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
        .route(
            "/api/v1/endpoints/refresh",
            post(refresh_endpoints::<Services, Gateway, Time>),
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
            "/api/v1/batches",
            get(list_batches::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/batches/{batch_id}",
            get(batch_detail::<Services, Gateway, Time>),
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
        .route(
            "/api/v1/auth/login",
            post(auth::login::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/logout",
            post(auth::logout::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/bootstrap",
            post(auth::bootstrap_complete::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/password",
            post(auth::change_password::<Services, Gateway, Time>),
        )
        .route("/api/v1/auth/me", get(auth::me::<Services, Gateway, Time>))
        .route(
            "/api/v1/admin/sessions",
            get(auth::list_sessions::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/sessions",
            post(auth::revoke_session::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users",
            get(auth::list_users::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users",
            post(auth::create_user::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users/{principal_id}/state",
            post(auth::set_user_state::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users/{principal_id}/role",
            post(auth::assign_user_role::<Services, Gateway, Time>),
        );
    finish_console_surface(router, state)
}

/// The Center route surface (audit follow-up F2): the authentication,
/// administration, audit, and center aggregation routes — and nothing that
/// talks to a BMC.
///
/// The bound is [`CenterServices`] — the §15.5/§15.6 aggregation boundary —
/// plus [`AuthServices`], [`AuditEventWriter`], and [`AuditEventQuery`].
/// Every edge boundary is deliberately absent: a center console cannot
/// enroll an endpoint, manage credentials, refresh a BMC, or read
/// telemetry, because no route of the surface composes those boundaries
/// (§15.1 — the center never enters the customer network; 0.7.0 acceptance
/// "Center 不连接 BMC").
///
/// The function is a declarative route table; the line count grows with the
/// product surface, so the lint is not a signal here.
#[allow(clippy::too_many_lines)]
fn center_router_with_auth<Services, Gateway, Time>(
    product: WebProductInfo,
    actor: AuditActor,
    origin: DeploymentPosture,
    policy: AuthPolicy,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
) -> Router
where
    Services: CenterServices + AuthServices + AuditEventWriter + AuditEventQuery + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    let state = WebState {
        product,
        actor,
        origin,
        auth: auth::AuthState::new(policy),
        services,
        gateway,
        clock,
    };
    let router = Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/about", get(about::<Services, Gateway, Time>))
        .route("/api/v1/audit", get(audit_query::<Services, Gateway, Time>))
        .route(
            "/api/v1/center/sites",
            get(center_sites::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/center/bindings",
            post(register_center_site::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/center/bindings/revoke",
            post(revoke_center_binding::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/center/endpoints",
            get(center_endpoints::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/center/operations",
            get(center_operations::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/center/operations",
            post(submit_center_operation::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/login",
            post(auth::login::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/logout",
            post(auth::logout::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/bootstrap",
            post(auth::bootstrap_complete::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/auth/password",
            post(auth::change_password::<Services, Gateway, Time>),
        )
        .route("/api/v1/auth/me", get(auth::me::<Services, Gateway, Time>))
        .route(
            "/api/v1/admin/sessions",
            get(auth::list_sessions::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/sessions",
            post(auth::revoke_session::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users",
            get(auth::list_users::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users",
            post(auth::create_user::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users/{principal_id}/state",
            post(auth::set_user_state::<Services, Gateway, Time>),
        )
        .route(
            "/api/v1/admin/users/{principal_id}/role",
            post(auth::assign_user_role::<Services, Gateway, Time>),
        );
    finish_console_surface(router, state)
}

/// The shared router tail: the SPA fallback, the state, the session
/// middleware, and the security headers. The header and middleware stack is
/// identical for both postures, so the two route tables share one tail.
///
/// The router arrives with its state type already fixed by the handler
/// extractors (`State<WebState<..>>`), and the tail re-states it exactly
/// like the pre-F2 route table did; the name is the "console surface" both
/// postures share, never the Edge surface only.
fn finish_console_surface<Services, Gateway, Time>(
    router: Router<WebState<Services, Gateway, Time>>,
    state: WebState<Services, Gateway, Time>,
) -> Router
where
    Services: AuthServices + AuditEventWriter + Send + Sync + 'static,
    Gateway: Send + Sync + 'static,
    Time: Clock + Clone + Send + Sync + 'static,
{
    router
        .fallback(static_asset)
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state,
            auth::auth_middleware::<Services, Gateway, Time>,
        ))
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
        Err(EndpointResourceInventoryQueryError::NotYetProjectable { .. }) => {
            return uncached_status(StatusCode::INTERNAL_SERVER_ERROR);
        }
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
    context: Extension<AuthContext>,
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
        context.actor(),
        context.actor_principal_id(),
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
    context: Extension<AuthContext>,
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
        context.actor(),
        context.actor_principal_id(),
        state.origin,
    );
    let importer = EndpointCsvImportExecutor::new(
        state.gateway.as_ref(),
        &enrollment,
        state.services.as_ref(),
        &state.clock,
        context.actor(),
        context.actor_principal_id(),
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

/// Refreshes several managed endpoints in one bounded, concurrently executed
/// batch, retaining every independent per-endpoint result.
///
/// The batch never flows through the §13 operation state machine: a refresh
/// is a read, and every endpoint commits one new resource Generation under
/// its own start/terminal audit (the same audit lifecycle a single refresh
/// records). Per-endpoint failures are part of the 200 report, exactly like
/// the CSV import row outcomes — the endpoint list errors (empty, duplicate,
/// oversized, unknown endpoint, or a failed pre-check) are the only non-200
/// verdicts.
async fn refresh_endpoints<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
    Json(request): Json<RefreshEndpointsRequest>,
) -> Response
where
    Services: ProductServices,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader,
    Time: Clock,
{
    let endpoint_ids = request
        .endpoint_ids()
        .iter()
        .map(|endpoint_id| EndpointId::from_uuid(*endpoint_id))
        .collect();
    let batch = BatchEndpointRefresh::new(
        state.services.as_ref(),
        state.services.as_ref(),
        state.gateway.as_ref(),
        state.services.as_ref(),
        &state.clock,
        context.actor(),
        context.actor_principal_id(),
        state.origin,
    );
    match batch.execute(endpoint_ids).await {
        Ok(outcomes) => json_ok(Json(project_refresh_report(&outcomes))),
        Err(error) => refresh_error_response(&error),
    }
}

/// Maps one batch-refresh rejection onto the HTTP contract.
///
/// The pre-check failure is the only boundary verdict reachable here — every
/// other failure is a per-endpoint outcome inside the 200 report.
fn refresh_error_response<RepositoryError>(
    error: &BatchEndpointRefreshError<RepositoryError>,
) -> Response
where
    RepositoryError: Error + 'static,
{
    match error {
        BatchEndpointRefreshError::EmptyTargets => json_error(
            StatusCode::BAD_REQUEST,
            "a refresh batch must name at least one endpoint".to_owned(),
        ),
        BatchEndpointRefreshError::TooManyTargets { limit } => json_error(
            StatusCode::BAD_REQUEST,
            format!("a refresh batch may target at most {limit} endpoints"),
        ),
        BatchEndpointRefreshError::DuplicateEndpoint { endpoint_id } => json_error(
            StatusCode::BAD_REQUEST,
            format!("refresh batch targets endpoint {endpoint_id} more than once"),
        ),
        BatchEndpointRefreshError::UnknownEndpoint { endpoint_id } => json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("endpoint {endpoint_id} is not a managed endpoint"),
        ),
        BatchEndpointRefreshError::Precheck(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the refresh targets could not be checked".to_owned(),
        ),
    }
}

/// Projects one refresh batch's independent outcomes onto the wire report.
///
/// The counts are server-derived facts: `total` equals the submitted list
/// length, `succeeded_count` counts only `refreshed` outcomes, and
/// `failed_count` counts every other outcome (including `not_found`) — the
/// handler never recomputes a batch-level number.
fn project_refresh_report(outcomes: &[EndpointRefreshOutcome]) -> BatchRefreshResponse {
    let total = outcomes.len();
    let succeeded_count = outcomes
        .iter()
        .filter(|outcome| outcome.is_success())
        .count();
    BatchRefreshResponse::new(
        u64::try_from(total).unwrap_or(u64::MAX),
        u64::try_from(succeeded_count).unwrap_or(u64::MAX),
        u64::try_from(total.saturating_sub(succeeded_count)).unwrap_or(u64::MAX),
        outcomes.iter().map(project_refresh_outcome).collect(),
    )
}

/// Projects one endpoint's refresh outcome onto its wire row.
///
/// A `failed` row carries the classified reason's label in front of the
/// failure source's own message, so the console renders the classification
/// without parsing error text.
fn project_refresh_outcome(outcome: &EndpointRefreshOutcome) -> EndpointRefreshResultResponse {
    match outcome {
        EndpointRefreshOutcome::Refreshed {
            endpoint_id,
            generation,
            snapshot_count,
        } => EndpointRefreshResultResponse::new(
            endpoint_id.into_uuid(),
            EndpointRefreshStatusResponse::Refreshed,
            Some(generation.get()),
            Some(u64::try_from(*snapshot_count).unwrap_or(u64::MAX)),
            None,
        ),
        EndpointRefreshOutcome::Failed {
            endpoint_id,
            reason,
            message,
        } => EndpointRefreshResultResponse::new(
            endpoint_id.into_uuid(),
            EndpointRefreshStatusResponse::Failed,
            None,
            None,
            Some(format!("{}: {message}", reason.label())),
        ),
        EndpointRefreshOutcome::NotFound { endpoint_id } => EndpointRefreshResultResponse::new(
            endpoint_id.into_uuid(),
            EndpointRefreshStatusResponse::NotFound,
            None,
            None,
            None,
        ),
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

/// Converts one typed Redfish write into a persisted operation (§13.1) or
/// batch (§13.7) and returns its acknowledgement.
///
/// The request names target endpoints only; the application submission use
/// case binds a fresh target identity to each endpoint, verifies that every
/// endpoint is managed, and persists the write with the submitted source
/// (defaulting to `standalone`). One target acknowledges an ordinary
/// `OperationResponse`; several targets are a batch — one batch parent plus
/// one ordinary single-target child operation per endpoint, all persisted
/// atomically — and acknowledge a `BatchOperationResponse` carrying the
/// batch id and the children's operation ids in the submitted order.
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
    if request.targets().len() > 1 {
        match submission
            .submit_batch(source, targets, request.command().clone(), now)
            .await
        {
            Ok((batch, children)) => json_created(Json(project_batch(&batch, &children))),
            Err(error) => submission_error_response(&error),
        }
    } else {
        match submission
            .submit(source, targets, request.command().clone(), now)
            .await
        {
            Ok(operation) => json_created(Json(project_operation(&operation))),
            Err(error) => submission_error_response(&error),
        }
    }
}

/// Maps one submission failure onto the HTTP contract shared by the
/// single-operation and batch submission paths.
fn submission_error_response<StoreError, LookupError>(
    error: &SubmissionError<StoreError, LookupError>,
) -> Response
where
    StoreError: Error + 'static,
    LookupError: Error + 'static,
{
    match error {
        SubmissionError::EmptyTargets => json_error(
            StatusCode::BAD_REQUEST,
            "an operation must target at least one endpoint".to_owned(),
        ),
        SubmissionError::TooManyTargets { limit } => json_error(
            StatusCode::BAD_REQUEST,
            format!("a batch may target at most {limit} endpoints"),
        ),
        SubmissionError::MultipleTargets => json_error(
            StatusCode::BAD_REQUEST,
            "an operation must target exactly one endpoint; submit multiple endpoints as a batch"
                .to_owned(),
        ),
        SubmissionError::DuplicateEndpoint { endpoint_id } => json_error(
            StatusCode::BAD_REQUEST,
            format!("operation targets endpoint {endpoint_id} more than once"),
        ),
        // A body-referenced endpoint that does not exist is unprocessable,
        // exactly like the enrollment path's missing-credential verdict.
        SubmissionError::UnknownEndpoint { endpoint_id } => json_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            format!("target endpoint {endpoint_id} is not a managed endpoint"),
        ),
        SubmissionError::Inventory(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "the target endpoints could not be checked".to_owned(),
        ),
        SubmissionError::Store(_) => json_error(
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
            | SubmissionError::TooManyTargets { .. }
            | SubmissionError::MultipleTargets
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
            | SubmissionError::TooManyTargets { .. }
            | SubmissionError::MultipleTargets
            | SubmissionError::DuplicateEndpoint { .. }
            | SubmissionError::UnknownEndpoint { .. }
            | SubmissionError::Inventory(_),
        ) => uncached_status(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Lists every batch parent with its derived state and outcome summary, in
/// acceptance order (§13.7).
///
/// The verdict and the buckets are server-derived facts: the handler projects
/// exactly what the application query derived from the children and never
/// recomputes a batch-level number.
async fn list_batches<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
) -> Response
where
    Services: ProductServices,
{
    let query = BatchQuery::new(state.services.as_ref());
    // The query surface has exactly one verdict: the store boundary.
    let Ok(batches) = query.list_batches().await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let mut response = Json(BatchListResponse::new(
        batches.iter().map(project_batch_summary).collect(),
    ))
    .into_response();
    no_store(&mut response);
    response
}

/// Returns one batch's full report: the derived summary plus every child
/// operation in target order (§13.7).
async fn batch_detail<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    AxumPath(batch_id): AxumPath<String>,
) -> Response
where
    Services: ProductServices,
{
    let Ok(batch_id) = batch_id.parse::<BatchOperationId>() else {
        return json_error(StatusCode::BAD_REQUEST, "batch id is invalid".to_owned());
    };
    let query = BatchQuery::new(state.services.as_ref());
    match query.batch_detail(batch_id).await {
        Ok(Some(detail)) => json_ok(Json(project_batch_detail(&detail))),
        Ok(None) => uncached_status(StatusCode::NOT_FOUND),
        // The query surface has exactly one verdict: the store boundary.
        Err(_) => uncached_status(StatusCode::SERVICE_UNAVAILABLE),
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

/// Projects one batch parent with its children onto the wire
/// acknowledgement (§13.7).
///
/// The engine constructs the children in submission order (the same order
/// the submitted endpoints were bound to their targets), so the submitted
/// endpoint ids and the child operation ids align positionally:
/// `targets[i]` is the endpoint `child_operation_ids[i]` was created for.
/// (The store boundary's own `list_batch_children` read orders by target
/// identity instead; this projection is the immediate submission
/// acknowledgement, which must echo submission order.)
fn project_batch(batch: &BatchOperation, children: &[Operation]) -> BatchOperationResponse {
    BatchOperationResponse::new(
        batch.id().into_uuid(),
        project_operation_source(batch.source()),
        batch.command(),
        children
            .iter()
            .map(|child| child.targets()[0].endpoint_id().into_uuid())
            .collect(),
        children
            .iter()
            .map(|child| child.id().into_uuid())
            .collect(),
        batch.created_at(),
    )
}

fn project_operation_target(target: &OperationTarget) -> OperationTargetResponse {
    OperationTargetResponse::new(
        target.target_id().into_uuid(),
        target.endpoint_id().into_uuid(),
    )
}

/// Projects one derived batch verdict onto its console wire value.
fn project_batch_state(state: BatchOperationState) -> BatchOperationStateResponse {
    match state {
        BatchOperationState::Queued => BatchOperationStateResponse::Queued,
        BatchOperationState::Running => BatchOperationStateResponse::Running,
        BatchOperationState::Succeeded => BatchOperationStateResponse::Succeeded,
        BatchOperationState::Failed => BatchOperationStateResponse::Failed,
        BatchOperationState::Unknown => BatchOperationStateResponse::Unknown,
        BatchOperationState::Cancelled => BatchOperationStateResponse::Cancelled,
    }
}

/// Projects the domain outcome buckets onto their console wire shape.
fn project_batch_outcomes(counts: BatchOutcomeCounts) -> BatchOutcomeCountsResponse {
    BatchOutcomeCountsResponse::new(
        counts.succeeded(),
        counts.failed(),
        counts.unknown(),
        counts.unsupported(),
        counts.cancelled(),
        counts.total(),
    )
}

/// Projects one derived batch summary onto its console card (§13.7).
fn project_batch_summary(summary: &BatchSummary) -> BatchSummaryResponse {
    BatchSummaryResponse::new(
        summary.batch().id().into_uuid(),
        project_operation_source(summary.batch().source()),
        summary.batch().command(),
        project_batch_state(summary.state()),
        project_batch_outcomes(summary.outcomes()),
        summary.batch().created_at(),
    )
}

/// Projects one batch's full report onto its console detail (§13.7).
fn project_batch_detail(detail: &BatchDetail) -> BatchDetailResponse {
    BatchDetailResponse::new(
        detail.summary().batch().id().into_uuid(),
        project_operation_source(detail.summary().batch().source()),
        detail.summary().batch().command(),
        project_batch_state(detail.summary().state()),
        project_batch_outcomes(detail.summary().outcomes()),
        detail.summary().batch().created_at(),
        detail.children().iter().map(project_operation).collect(),
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
            // surface, the OemDell / OemSmcSysLockdown / OemSmcKcsInterface /
            // OemNvidiaSystemConfigProfile §11.5 OEM families, the
            // PcieDevices/Assembly/SoftwareInventory read families, and the
            // EventService/EventSubscription/TelemetryService/
            // MetricDefinition/MetricReport/TaskService/Task service
            // families) intentionally stay out of the three-field enrollment
            // counts; the typed resource-inventory route carries their full
            // snapshots instead.
            ResourceFeature::ServiceRoot
            | ResourceFeature::Processors
            | ResourceFeature::Memory
            | ResourceFeature::Storages
            | ResourceFeature::NetworkAdapters
            | ResourceFeature::NetworkDeviceFunctions
            | ResourceFeature::EthernetInterfaces
            | ResourceFeature::Accounts
            | ResourceFeature::Bios
            | ResourceFeature::BootOptions
            | ResourceFeature::SecureBoot
            | ResourceFeature::Power
            | ResourceFeature::PowerEquipment
            | ResourceFeature::PowerSupplies
            | ResourceFeature::Thermal
            | ResourceFeature::Sensors
            | ResourceFeature::Controls
            | ResourceFeature::EnvironmentMetrics
            | ResourceFeature::LogServices
            | ResourceFeature::ManagerNetworkProtocol
            | ResourceFeature::HostInterfaces
            | ResourceFeature::OemDell
            | ResourceFeature::OemSmcSysLockdown
            | ResourceFeature::OemSmcKcsInterface
            | ResourceFeature::OemNvidiaSystemConfigProfile
            | ResourceFeature::OemNvidiaPowerCompliance
            | ResourceFeature::OemNvidiaManagedEntity
            | ResourceFeature::OemLenovoSecurityService
            | ResourceFeature::OemAmiServiceRoot
            | ResourceFeature::OemAmiConfigBmc
            | ResourceFeature::OemHpeILoServiceExt
            | ResourceFeature::OemHpeManager
            | ResourceFeature::OemLiteOnPowerSupply
            | ResourceFeature::OemDeltaPowerSupply
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

/// Lists the registered sites of the center's §15.5 site view, filtered by
/// the acting principal's D3 site scope (§16.1 — a scoped role sees exactly
/// its assigned site).
async fn center_sites<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
) -> Response
where
    Services: CenterServices,
{
    let Ok(sites) = state.services.list_center_sites().await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let visible = sites
        .into_iter()
        .filter(|site| {
            auth::view_scope_allows(context.role(), context.assignment_site_id(), site.site_id())
        })
        .map(|site| project_center_site(&site))
        .collect();
    json_ok(Json(CenterSitesResponse::new(visible)))
}

/// Registers one site and returns its one-time binding code (design D2).
///
/// The raw code is shown exactly once in the response — no later view of the
/// binding ever repeats it. The write is audited (§16.3, audit follow-up
/// F3): issuing a binding code is the security-relevant act that admits a
/// site into the center, so the record names the acting principal, the
/// Center origin, the `ManageCenterBindings` permission, and the result.
async fn register_center_site<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
    Json(request): Json<CenterBindingRegisterRequest>,
) -> Response
where
    Services: CenterServices + AuditEventWriter,
    Time: Clock,
{
    let Ok(display_name) = EndpointDisplayName::parse(request.display_name()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "site display name is invalid".to_owned(),
        );
    };
    let now = state.clock.now();
    if let Ok(registered) = state
        .services
        .register_center_site(display_name.as_str(), request.center_url(), now)
        .await
    {
        record_center_write(
            &state,
            &context,
            AuditTarget::Product,
            ProductPermission::ManageCenterBindings,
            AuditAction::RegisterSiteBinding,
            CenterWriteOutcome::Succeeded,
            now,
        )
        .await;
        json_ok(Json(CenterBindingRegisterResponse::new(
            registered.site_id().into_uuid(),
            registered.binding_id().into_uuid(),
            registered.code().to_owned(),
            registered.expires_at(),
        )))
    } else {
        record_center_write(
            &state,
            &context,
            AuditTarget::Product,
            ProductPermission::ManageCenterBindings,
            AuditAction::RegisterSiteBinding,
            CenterWriteOutcome::StoreFailed,
            now,
        )
        .await;
        uncached_status(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// Revokes the active binding of one site (design D2); a site whose binding
/// is already revoked is reported as revoked. The write is audited (§16.3,
/// audit follow-up F3): revoking a binding ends a site's admission, so the
/// record names the acting principal, the Center origin, the
/// `ManageCenterBindings` permission, and the result.
async fn revoke_center_binding<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
    Json(request): Json<CenterBindingRevokeRequest>,
) -> Response
where
    Services: CenterServices + AuditEventWriter,
    Time: Clock,
{
    let site = InstanceId::from_uuid(request.site_id());
    let now = state.clock.now();
    if state
        .services
        .revoke_center_binding(site, now)
        .await
        .is_ok()
    {
        record_center_write(
            &state,
            &context,
            AuditTarget::Product,
            ProductPermission::ManageCenterBindings,
            AuditAction::RevokeSiteBinding,
            CenterWriteOutcome::Succeeded,
            now,
        )
        .await;
        no_content()
    } else {
        record_center_write(
            &state,
            &context,
            AuditTarget::Product,
            ProductPermission::ManageCenterBindings,
            AuditAction::RevokeSiteBinding,
            CenterWriteOutcome::StoreFailed,
            now,
        )
        .await;
        uncached_status(StatusCode::SERVICE_UNAVAILABLE)
    }
}

/// The result of one audited center console write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CenterWriteOutcome {
    /// The write completed.
    Succeeded,
    /// The center store failed the write.
    StoreFailed,
    /// The center refused the write (a §15.6 dispatch refusal).
    Refused,
}

/// Appends the `started` and terminal events of one audited center console
/// write (§16.3, audit follow-up F3): who, the Center origin, the target,
/// the parameter summary, the permission checked, the action, and the
/// result.
///
/// An audit append failure never fails the request — exactly like the
/// authentication lifecycle's `record_outcome`: the audit trail is a
/// best-effort side effect on the web layer, and the request verdict stays
/// the boundary's.
#[allow(clippy::too_many_arguments)]
async fn record_center_write<Services, Gateway, Time>(
    state: &WebState<Services, Gateway, Time>,
    context: &AuthContext,
    target: AuditTarget,
    permission: ProductPermission,
    action: AuditAction,
    outcome: CenterWriteOutcome,
    now: OffsetDateTime,
) where
    Services: AuditEventWriter,
    Time: Clock,
{
    let Ok(context) = AuditOperationContext::try_new_with_actor_principal(
        AuditOperationId::generate(),
        context.actor(),
        state.origin,
        target,
        AuditParameterSummary::EndpointRefresh,
        permission,
        action,
        AuditRedfishOperation::None,
        context.actor_principal_id(),
    ) else {
        return;
    };
    let started = AuditEvent::started(context.clone(), now);
    let _ = state.services.append_audit_event(&started).await;
    let Ok(sequence) = AuditSequence::FIRST.next() else {
        return;
    };
    let terminal = match outcome {
        CenterWriteOutcome::Succeeded => AuditEvent::succeeded(context, sequence, now),
        CenterWriteOutcome::StoreFailed => AuditEvent::failed(
            context,
            sequence,
            AuditFailure::CenterStoreFailed,
            AuditFailureVerification::Inconclusive,
            now,
        ),
        CenterWriteOutcome::Refused => AuditEvent::failed(
            context,
            sequence,
            AuditFailure::CenterRequestRefused,
            AuditFailureVerification::Rejected,
            now,
        ),
    };
    let Ok(terminal) = terminal else {
        return;
    };
    let _ = state.services.append_audit_event(&terminal).await;
}

/// Lists the center's aggregated endpoint view (§15.5), optionally narrowed
/// to one site by the `site_id` query, and filtered by the acting
/// principal's D3 site scope.
async fn center_endpoints<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
    uri: Uri,
) -> Response
where
    Services: CenterServices,
{
    let Ok(site_filter) = parse_center_site_filter(uri.query()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "site id filter is invalid".to_owned(),
        );
    };
    if site_filter.is_some_and(|site| {
        !auth::view_scope_allows(context.role(), context.assignment_site_id(), site)
    }) {
        return json_error(
            StatusCode::FORBIDDEN,
            "this role cannot view the requested site".to_owned(),
        );
    }
    let Ok(endpoints) = state.services.list_center_endpoints(site_filter).await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let visible = endpoints
        .into_iter()
        .filter(|endpoint| {
            // A projection without a site association is a broken row; only
            // a site-associated projection is ever shown.
            endpoint.site_id().is_some_and(|site| {
                auth::view_scope_allows(context.role(), context.assignment_site_id(), site)
            })
        })
        .map(|endpoint| project_center_endpoint(&endpoint))
        .collect();
    json_ok(Json(CenterEndpointViewListResponse::new(visible)))
}

/// Lists the center's operation tracking view (§15.6), optionally narrowed
/// to one site by the `site_id` query, and filtered by the acting
/// principal's D3 site scope.
async fn center_operations<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
    uri: Uri,
) -> Response
where
    Services: CenterServices,
{
    let Ok(site_filter) = parse_center_site_filter(uri.query()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "site id filter is invalid".to_owned(),
        );
    };
    if site_filter.is_some_and(|site| {
        !auth::view_scope_allows(context.role(), context.assignment_site_id(), site)
    }) {
        return json_error(
            StatusCode::FORBIDDEN,
            "this role cannot view the requested site".to_owned(),
        );
    }
    let Ok(operations) = state.services.list_center_operations(site_filter).await else {
        return uncached_status(StatusCode::SERVICE_UNAVAILABLE);
    };
    let visible = operations
        .into_iter()
        .filter(|operation| {
            // An operation without a site association is a broken row; like
            // the endpoint projection, only a site-associated operation is
            // ever shown — a scoped role must never see a row that has no
            // site ownership to check it against (audit follow-up F1).
            operation.site_id().is_some_and(|site| {
                auth::view_scope_allows(context.role(), context.assignment_site_id(), site)
            })
        })
        .map(|operation| project_center_operation(&operation))
        .collect();
    json_ok(Json(CenterOperationListResponse::new(visible)))
}

/// Submits one §15.6 center operation: the typed command, the target, and
/// the site — and nothing else (§15.6 — no URL, no HTTP method, no headers,
/// no body).
///
/// The acting principal's role and D3 site scope are the handler gate; the
/// dispatch use case re-checks the same rule against the persisted
/// assignment. The dispatch is audited (§16.3, audit follow-up F3): the
/// record names the acting principal, the Center origin, the projected
/// endpoint target, the `DispatchCenterOperations` permission, and the
/// result — dispatched, refused by the center, or failed in the store.
async fn submit_center_operation<Services, Gateway, Time>(
    State(state): State<WebState<Services, Gateway, Time>>,
    context: Extension<AuthContext>,
    Json(request): Json<CenterOperationSubmitRequest>,
) -> Response
where
    Services: CenterServices + AuditEventWriter,
    Time: Clock,
{
    let Some(actor) = context.actor_principal_id() else {
        return json_error(
            StatusCode::FORBIDDEN,
            "a signed-in principal is required to dispatch center operations".to_owned(),
        );
    };
    let site = InstanceId::from_uuid(request.site_id());
    if !auth::dispatch_scope_allows(context.role(), context.assignment_site_id(), site) {
        return json_error(
            StatusCode::FORBIDDEN,
            "this role cannot dispatch to the requested site".to_owned(),
        );
    }
    let Ok(target) = ResourceODataId::parse(request.target()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "operation target is invalid".to_owned(),
        );
    };
    let endpoint = EndpointId::from_uuid(request.endpoint_id());
    let now = state.clock.now();
    match state
        .services
        .dispatch_center_operation(site, endpoint, &target, request.command(), actor, now)
        .await
    {
        Ok(dispatched) => {
            record_center_write(
                &state,
                &context,
                AuditTarget::Endpoint(endpoint),
                ProductPermission::DispatchCenterOperations,
                AuditAction::DispatchCenterOperation,
                CenterWriteOutcome::Succeeded,
                now,
            )
            .await;
            json_ok(Json(CenterOperationSubmitResponse::new(
                dispatched.operation_id().into_uuid(),
                dispatched.ttl_expires_at(),
            )))
        }
        Err(refusal) => {
            // A refusal is a verdict, not a store failure: the record shows
            // the dispatch was attempted and refused by the center.
            record_center_write(
                &state,
                &context,
                AuditTarget::Endpoint(endpoint),
                ProductPermission::DispatchCenterOperations,
                AuditAction::DispatchCenterOperation,
                CenterWriteOutcome::Refused,
                now,
            )
            .await;
            center_dispatch_refusal_response(&refusal)
        }
    }
}

/// Maps one center dispatch refusal to its HTTP verdict.
fn center_dispatch_refusal_response(refusal: &CenterOperationRefusal) -> Response {
    let (status, message) = match refusal {
        CenterOperationRefusal::NotAuthorized => (
            StatusCode::FORBIDDEN,
            "this role cannot dispatch to the requested site",
        ),
        CenterOperationRefusal::UnknownEndpoint { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "the endpoint is not in the center's projection",
        ),
        CenterOperationRefusal::EndpointNotInSite { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "the endpoint does not belong to the requested site",
        ),
        CenterOperationRefusal::UnknownTarget { .. } => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "the target is not part of the endpoint's projection",
        ),
        CenterOperationRefusal::CommandSerialization => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "the operation command could not be serialized",
        ),
        CenterOperationRefusal::Store => {
            (StatusCode::SERVICE_UNAVAILABLE, "the center store failed")
        }
    };
    json_error(status, message.to_owned())
}

/// Projects one registered site onto its console wire shape (§15.5).
fn project_center_site(site: &CenterSiteView) -> CenterSiteResponse {
    CenterSiteResponse::new(
        site.site_id().into_uuid(),
        site.display_name().to_owned(),
        site.binding().map(project_center_binding_state),
        site.online(),
        site.endpoint_count(),
        site.last_refresh_at(),
    )
}

fn project_center_binding_state(state: CenterBindingState) -> CenterBindingStateResponse {
    match state {
        CenterBindingState::Pending => CenterBindingStateResponse::Pending,
        CenterBindingState::Bound => CenterBindingStateResponse::Bound,
        CenterBindingState::Revoked => CenterBindingStateResponse::Revoked,
    }
}

/// Projects one projected endpoint onto its console wire shape (§15.5).
fn project_center_endpoint(endpoint: &CenterEndpointView) -> CenterEndpointViewResponse {
    CenterEndpointViewResponse::new(
        endpoint.site_id().map(InstanceId::into_uuid),
        endpoint.endpoint_id().into_uuid(),
        endpoint.display_name().to_owned(),
        endpoint.address().to_owned(),
        endpoint.health().to_owned(),
        endpoint.refresh_generation(),
    )
}

/// Projects one center operation onto its console wire shape (§15.6).
fn project_center_operation(operation: &CenterOperationView) -> CenterOperationResponse {
    CenterOperationResponse::new(
        operation.operation_id().into_uuid(),
        operation.site_id().map(InstanceId::into_uuid),
        operation.endpoint_id().into_uuid(),
        operation.command().clone(),
        operation.target().map(str::to_owned),
        project_operation_state(operation.state()),
        operation.actor().map(str::to_owned),
        operation.ttl_expires_at(),
        operation.created_at(),
    )
}

/// Parses the optional `site_id` query filter of the center views.
fn parse_center_site_filter(query: Option<&str>) -> Result<Option<InstanceId>, ()> {
    let Some(query) = query else {
        return Ok(None);
    };
    let Some(value) = query.strip_prefix("site_id=") else {
        return Err(());
    };
    value.parse::<InstanceId>().map(Some).map_err(|_| ())
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

pub(crate) fn json_ok<Body: IntoResponse>(body: Body) -> Response {
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

pub(crate) fn json_error(status: StatusCode, message: String) -> Response {
    json_error_with_status(status, Json(ErrorResponse::new(message)))
}

pub(crate) fn json_error_with_status<Body: IntoResponse>(
    status: StatusCode,
    body: Body,
) -> Response {
    let mut response = body.into_response();
    *response.status_mut() = status;
    no_store(&mut response);
    response
}

pub(crate) fn no_store(response: &mut Response) {
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
        CoreResourceDetails::OemDell { .. } => project_oem_dell_details(details),
        CoreResourceDetails::OemSmcSysLockdown { .. } => {
            project_oem_smc_sys_lockdown_details(details)
        }
        CoreResourceDetails::OemSmcKcsInterface { .. } => {
            project_oem_smc_kcs_interface_details(details)
        }
        CoreResourceDetails::OemNvidiaSystemConfigProfile { .. } => {
            project_oem_nvidia_system_config_profile_details(details)
        }
        CoreResourceDetails::OemNvidiaSystemConfigProfileStatus { .. } => {
            project_oem_nvidia_system_config_profile_status_details(details)
        }
        CoreResourceDetails::OemNvidiaSystemProfile { .. } => {
            project_oem_nvidia_system_profile_details(details)
        }
        CoreResourceDetails::OemNvidiaSystemProfileFile { .. } => {
            project_oem_nvidia_system_profile_file_details(details)
        }
        CoreResourceDetails::OemNvidiaPowerCompliance { .. } => {
            project_oem_nvidia_power_compliance_details(details)
        }
        CoreResourceDetails::OemNvidiaPowerDomain { .. } => {
            project_oem_nvidia_power_domain_details(details)
        }
        CoreResourceDetails::OemNvidiaPowerPolicy { .. } => {
            project_oem_nvidia_power_policy_details(details)
        }
        CoreResourceDetails::OemNvidiaManagedEntityGroup { .. } => {
            project_oem_nvidia_managed_entity_group_details(details)
        }
        CoreResourceDetails::OemNvidiaPowerStateGroup { .. } => {
            project_oem_nvidia_power_state_group_details(details)
        }
        CoreResourceDetails::OemNvidiaPscState { .. } => {
            project_oem_nvidia_psc_state_details(details)
        }
        CoreResourceDetails::OemNvidiaPsuState { .. } => {
            project_oem_nvidia_psu_state_details(details)
        }
        CoreResourceDetails::OemNvidiaPsuRedundancy { .. } => {
            project_oem_nvidia_psu_redundancy_details(details)
        }
        CoreResourceDetails::OemNvidiaManagedEntity { .. } => {
            project_oem_nvidia_managed_entity_details(details)
        }
        CoreResourceDetails::OemLenovoSecurityService { .. } => {
            project_oem_lenovo_security_service_details(details)
        }
        CoreResourceDetails::Processor { .. } => project_processor_details(details),
        CoreResourceDetails::Memory { .. } => project_memory_details(details),
        CoreResourceDetails::Storage { .. } => project_storage_details(details),
        CoreResourceDetails::NetworkAdapter { .. } => project_network_adapter_details(details),
        CoreResourceDetails::NetworkDeviceFunction { .. } => {
            project_network_device_function_details(details)
        }
        CoreResourceDetails::PowerEquipment { .. } => project_power_equipment_details(details),
        CoreResourceDetails::PowerSupply { .. } => project_power_supply_details(details),
        CoreResourceDetails::EnvironmentMetrics { .. } => {
            project_environment_metrics_details(details)
        }
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

/// Projects the §11.5 Dell OEM family into the shared wire contract.
///
/// The dispatcher guarantees this receives the `OemDell` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_oem_dell_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemDell {
        server_model,
        server_service_tag,
        server_generation,
        server_bmc_mac_address,
        server_name,
    } = details
    else {
        return CoreResourceDetailsResponse::OemDell {
            server_model: None,
            server_service_tag: None,
            server_generation: None,
            server_bmc_mac_address: None,
            server_name: None,
        };
    };
    CoreResourceDetailsResponse::OemDell {
        server_model: server_model.clone(),
        server_service_tag: server_service_tag.clone(),
        server_generation: server_generation.clone(),
        server_bmc_mac_address: server_bmc_mac_address.clone(),
        server_name: server_name.clone(),
    }
}

/// Projects the §11.5 Supermicro `SysLockdown` OEM family into the shared
/// wire contract.
///
/// The dispatcher guarantees this receives the `OemSmcSysLockdown` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_oem_smc_sys_lockdown_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemSmcSysLockdown {
        sys_lockdown_enabled,
    } = details
    else {
        return CoreResourceDetailsResponse::OemSmcSysLockdown {
            sys_lockdown_enabled: None,
        };
    };
    CoreResourceDetailsResponse::OemSmcSysLockdown {
        sys_lockdown_enabled: *sys_lockdown_enabled,
    }
}

/// Projects the §11.5 Supermicro `KcsInterface` OEM family into the shared
/// wire contract.
///
/// The dispatcher guarantees this receives the `OemSmcKcsInterface` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_oem_smc_kcs_interface_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemSmcKcsInterface { privilege } = details else {
        return CoreResourceDetailsResponse::OemSmcKcsInterface { privilege: None };
    };
    CoreResourceDetailsResponse::OemSmcKcsInterface {
        privilege: privilege.clone(),
    }
}

/// Projects the §11.5 NVIDIA system-config-profile chain root into the
/// shared wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaSystemConfigProfile`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_system_config_profile_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaSystemConfigProfile { truststore } = details else {
        return CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile { truststore: None };
    };
    CoreResourceDetailsResponse::OemNvidiaSystemConfigProfile {
        truststore: truststore.as_ref().map(|truststore| {
            OemNvidiaSystemConfigProfileTruststoreResponse::new(
                truststore.nvidia_certificates(),
                truststore.oem_certificates(),
            )
        }),
    }
}

/// Projects the §11.5 NVIDIA `SystemConfigProfileStatus` chain document into
/// the shared wire contract.
///
/// The dispatcher guarantees this receives the
/// `OemNvidiaSystemConfigProfileStatus` variant; the fallback keeps a stable
/// empty projection instead of panicking if that contract is ever violated.
fn project_oem_nvidia_system_config_profile_status_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaSystemConfigProfileStatus {
        pending_list_activation,
        active_profile_index,
        bmc_profile_version,
        factory_reset_status,
        default_profile_index,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus {
            pending_list_activation: None,
            active_profile_index: None,
            bmc_profile_version: None,
            factory_reset_status: None,
            default_profile_index: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaSystemConfigProfileStatus {
        pending_list_activation: pending_list_activation.clone(),
        active_profile_index: *active_profile_index,
        bmc_profile_version: *bmc_profile_version,
        factory_reset_status: factory_reset_status.clone(),
        default_profile_index: *default_profile_index,
    }
}

/// Projects the §11.5 NVIDIA `SystemProfile` chain member into the shared
/// wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaSystemProfile`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_system_profile_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaSystemProfile {
        default,
        owner,
        uuid,
        version,
        profile_name,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaSystemProfile {
            default: None,
            owner: None,
            uuid: None,
            version: None,
            profile_name: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaSystemProfile {
        default: *default,
        owner: owner.clone(),
        uuid: uuid.clone(),
        version: *version,
        profile_name: profile_name.clone(),
    }
}

/// Projects the §11.5 NVIDIA `SystemProfileFile` chain document into the
/// shared wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaSystemProfileFile`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_system_profile_file_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaSystemProfileFile {
        metadata_activate,
        metadata_delete,
        metadata_origin_profile_uuid,
        metadata_more_profiles,
        metadata_project_name,
        metadata_uuid,
        profile,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaSystemProfileFile {
            metadata_activate: None,
            metadata_delete: None,
            metadata_origin_profile_uuid: None,
            metadata_more_profiles: None,
            metadata_project_name: None,
            metadata_uuid: None,
            profile: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaSystemProfileFile {
        metadata_activate: *metadata_activate,
        metadata_delete: *metadata_delete,
        metadata_origin_profile_uuid: metadata_origin_profile_uuid.clone(),
        metadata_more_profiles: *metadata_more_profiles,
        metadata_project_name: metadata_project_name.clone(),
        metadata_uuid: metadata_uuid.clone(),
        profile: profile.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPowerComplianceManager` chain-root
/// document into the shared wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerCompliance`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_power_compliance_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPowerCompliance { manager_type } = details else {
        return CoreResourceDetailsResponse::OemNvidiaPowerCompliance { manager_type: None };
    };
    CoreResourceDetailsResponse::OemNvidiaPowerCompliance {
        manager_type: manager_type.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPowerDomain` member into the shared wire
/// contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerDomain`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_power_domain_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPowerDomain {
        value,
        r#type,
        unit,
        sensor_reading_type,
        sensor_impl,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaPowerDomain {
            value: None,
            r#type: None,
            unit: None,
            sensor_reading_type: None,
            sensor_impl: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaPowerDomain {
        value: *value,
        r#type: r#type.clone(),
        unit: unit.clone(),
        sensor_reading_type: sensor_reading_type.clone(),
        sensor_impl: sensor_impl.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPowerPolicy` document into the shared
/// wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerPolicy`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_power_policy_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPowerPolicy {
        auto_deassert_power_brake,
        min,
        max,
        r#type,
        unit,
        policy_actions,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaPowerPolicy {
            auto_deassert_power_brake: None,
            min: None,
            max: None,
            r#type: None,
            unit: None,
            policy_actions: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaPowerPolicy {
        auto_deassert_power_brake: *auto_deassert_power_brake,
        min: *min,
        max: *max,
        r#type: r#type.clone(),
        unit: unit.clone(),
        policy_actions: policy_actions.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaManagedEntityGroup` member into the
/// shared wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaManagedEntityGroup`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_managed_entity_group_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaManagedEntityGroup {
        current_managed_entity_id,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup {
            current_managed_entity_id: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaManagedEntityGroup {
        current_managed_entity_id: current_managed_entity_id.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPowerStateGroup` document into the
/// shared wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPowerStateGroup`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_power_state_group_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPowerStateGroup {
        psc_id,
        generated_watts,
        number_of_pscs,
        number_of_local_psus,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaPowerStateGroup {
            psc_id: None,
            generated_watts: None,
            number_of_pscs: None,
            number_of_local_psus: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaPowerStateGroup {
        psc_id: psc_id.clone(),
        generated_watts: *generated_watts,
        number_of_pscs: *number_of_pscs,
        number_of_local_psus: *number_of_local_psus,
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPscState` member into the shared wire
/// contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPscState` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_oem_nvidia_psc_state_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPscState {
        psc_id,
        num_of_operational_psus,
        power_brake_assert,
        milliseconds_since_last_heartbeat,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaPscState {
            psc_id: None,
            num_of_operational_psus: None,
            power_brake_assert: None,
            milliseconds_since_last_heartbeat: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaPscState {
        psc_id: psc_id.clone(),
        num_of_operational_psus: *num_of_operational_psus,
        power_brake_assert: *power_brake_assert,
        milliseconds_since_last_heartbeat: *milliseconds_since_last_heartbeat,
        status: status.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPsuState` member into the shared wire
/// contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPsuState` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_oem_nvidia_psu_state_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPsuState {
        psu_id,
        presence,
        input1active,
        input2active,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaPsuState {
            psu_id: None,
            presence: None,
            input1active: None,
            input2active: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaPsuState {
        psu_id: psu_id.clone(),
        presence: *presence,
        input1active: *input1active,
        input2active: *input2active,
    }
}

/// Projects the §11.5 NVIDIA `NvidiaPsuRedundancy` document into the shared
/// wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaPsuRedundancy`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_psu_redundancy_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaPsuRedundancy {
        max_num_supported,
        min_num_needed,
        redundancy_setting,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaPsuRedundancy {
            max_num_supported: None,
            min_num_needed: None,
            redundancy_setting: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaPsuRedundancy {
        max_num_supported: max_num_supported.clone(),
        min_num_needed: min_num_needed.clone(),
        redundancy_setting: redundancy_setting.clone(),
    }
}

/// Projects the §11.5 NVIDIA `NvidiaManagedEntity` member into the shared
/// wire contract.
///
/// The dispatcher guarantees this receives the `OemNvidiaManagedEntity`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_nvidia_managed_entity_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemNvidiaManagedEntity {
        transport_protocol,
        ipv4_address,
        ipv6_address,
        port,
    } = details
    else {
        return CoreResourceDetailsResponse::OemNvidiaManagedEntity {
            transport_protocol: None,
            ipv4_address: None,
            ipv6_address: None,
            port: None,
        };
    };
    CoreResourceDetailsResponse::OemNvidiaManagedEntity {
        transport_protocol: transport_protocol.clone(),
        ipv4_address: ipv4_address.clone(),
        ipv6_address: ipv6_address.clone(),
        port: *port,
    }
}

/// Projects the §11.5 Lenovo `SecurityService` document into the shared wire
/// contract.
///
/// The dispatcher guarantees this receives the `OemLenovoSecurityService`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_oem_lenovo_security_service_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::OemLenovoSecurityService { fw_rollback } = details else {
        return CoreResourceDetailsResponse::OemLenovoSecurityService { fw_rollback: None };
    };
    CoreResourceDetailsResponse::OemLenovoSecurityService {
        fw_rollback: fw_rollback.clone(),
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

/// Projects the §2.1 network-device-function family into the shared wire
/// contract, preserving the `NetDevFuncType` enumeration string so clients
/// never re-parse text.
///
/// The dispatcher guarantees this receives the `NetworkDeviceFunction`
/// variant; the fallback keeps a stable empty projection instead of panicking
/// if that contract is ever violated.
fn project_network_device_function_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::NetworkDeviceFunction {
        net_dev_func_type,
        device_enabled,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::NetworkDeviceFunction {
            net_dev_func_type: None,
            device_enabled: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::NetworkDeviceFunction {
        net_dev_func_type: net_dev_func_type.clone(),
        device_enabled: *device_enabled,
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 power-equipment family into the shared wire contract.
///
/// The dispatcher guarantees this receives the `PowerEquipment` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_power_equipment_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::PowerEquipment {
        equipment_type,
        manufacturer,
        model,
        part_number,
        serial_number,
        version,
        firmware_version,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::PowerEquipment {
            equipment_type: None,
            manufacturer: None,
            model: None,
            part_number: None,
            serial_number: None,
            version: None,
            firmware_version: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::PowerEquipment {
        equipment_type: equipment_type.clone(),
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        part_number: part_number.clone(),
        serial_number: serial_number.clone(),
        version: version.clone(),
        firmware_version: firmware_version.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 power-supply family into the shared wire contract,
/// preserving the numeric capacity so clients never re-parse text.
///
/// The dispatcher guarantees this receives the `PowerSupply` variant; the
/// fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_power_supply_details(details: &CoreResourceDetails) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::PowerSupply {
        power_supply_type,
        power_capacity_watts,
        manufacturer,
        model,
        firmware_version,
        serial_number,
        part_number,
        status,
    } = details
    else {
        return CoreResourceDetailsResponse::PowerSupply {
            power_supply_type: None,
            power_capacity_watts: None,
            manufacturer: None,
            model: None,
            firmware_version: None,
            serial_number: None,
            part_number: None,
            status: None,
        };
    };
    CoreResourceDetailsResponse::PowerSupply {
        power_supply_type: power_supply_type.clone(),
        power_capacity_watts: *power_capacity_watts,
        manufacturer: manufacturer.clone(),
        model: model.clone(),
        firmware_version: firmware_version.clone(),
        serial_number: serial_number.clone(),
        part_number: part_number.clone(),
        status: status.as_ref().map(project_resource_status),
    }
}

/// Projects the §2.1 environment-metrics family into the shared wire
/// contract; every embedded measurement the schema declares is projected
/// through its excerpt reading shape.
///
/// The dispatcher guarantees this receives the `EnvironmentMetrics` variant;
/// the fallback keeps a stable empty projection instead of panicking if that
/// contract is ever violated.
fn project_environment_metrics_details(
    details: &CoreResourceDetails,
) -> CoreResourceDetailsResponse {
    let CoreResourceDetails::EnvironmentMetrics {
        temperature_celsius,
        humidity_percent,
        fan_speeds_percent,
        power_watts,
        energyk_wh,
        power_load_percent,
        power_limit_watts,
        dew_point_celsius,
        absolute_humidity,
        energy_joules,
        ambient_temperature_celsius,
        voltage,
        current_amps,
    } = details
    else {
        return CoreResourceDetailsResponse::EnvironmentMetrics {
            temperature_celsius: None,
            humidity_percent: None,
            fan_speeds_percent: None,
            power_watts: None,
            energyk_wh: None,
            power_load_percent: None,
            power_limit_watts: None,
            dew_point_celsius: None,
            absolute_humidity: None,
            energy_joules: None,
            ambient_temperature_celsius: None,
            voltage: None,
            current_amps: None,
        };
    };
    CoreResourceDetailsResponse::EnvironmentMetrics {
        temperature_celsius: temperature_celsius
            .as_ref()
            .map(project_environment_reading),
        humidity_percent: humidity_percent.as_ref().map(project_environment_reading),
        fan_speeds_percent: fan_speeds_percent
            .as_ref()
            .map(|speeds| speeds.iter().map(project_environment_reading).collect()),
        power_watts: power_watts.as_ref().map(project_environment_reading),
        energyk_wh: energyk_wh.as_ref().map(project_environment_reading),
        power_load_percent: power_load_percent.as_ref().map(project_environment_reading),
        power_limit_watts: power_limit_watts.as_ref().map(project_environment_control),
        dew_point_celsius: dew_point_celsius.as_ref().map(project_environment_reading),
        absolute_humidity: absolute_humidity.as_ref().map(project_environment_reading),
        energy_joules: energy_joules.as_ref().map(project_environment_reading),
        ambient_temperature_celsius: ambient_temperature_celsius
            .as_ref()
            .map(project_environment_reading),
        voltage: voltage.as_ref().map(project_environment_reading),
        current_amps: current_amps.as_ref().map(project_environment_reading),
    }
}

fn project_environment_reading(
    reading: &EnvironmentMetricsReadingSummary,
) -> EnvironmentMetricsReadingResponse {
    EnvironmentMetricsReadingResponse::new(
        reading.data_source_uri().map(str::to_owned),
        reading.reading(),
    )
}

fn project_environment_control(
    control: &EnvironmentMetricsControlSummary,
) -> EnvironmentMetricsControlResponse {
    EnvironmentMetricsControlResponse::new(
        control.data_source_uri().map(str::to_owned),
        control.set_point(),
    )
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

pub(crate) fn uncached_status(status: StatusCode) -> Response {
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
    use std::{collections::HashMap, error::Error, fmt, sync::Mutex};

    use axum::{
        body::Body,
        http::{Request, header::SET_COOKIE},
    };
    use http_body_util::BodyExt as _;
    use rutilus_application::{
        BoundaryFuture, CapabilitySnapshotRepository, ClassifiedBatchChild, EndpointDiscovery,
        EndpointRefreshFailureKind, EndpointRefreshOutcome, MAX_REFRESH_TARGETS,
        ProtectedCredentialCreation, ResolvedCredential, ResourceDiagnostics, ResourceObservation,
        StoredCapability, TlsIdentityObservation,
    };
    use rutilus_domain::{
        Argon2IdHash, BatchOperation, BatchOperationId, BootstrapCode, BootstrapCodeId,
        CredentialId, CredentialUsername, CredentialVersionId, Endpoint, EndpointAddress,
        EndpointCapability, EndpointCapabilityObservation, EndpointDisplayName, EndpointId,
        FailureKind, Operation, OperationId, OperationSource, OperationState, OperationTarget,
        PasswordCredential, Principal, PrincipalId, PrincipalName, PrincipalState, RedfishCommand,
        RefreshGeneration, ResetType, ResourceEtag, ResourceFeature, ResourceId, ResourceODataId,
        ResourceODataType, ResourceSnapshot, ResourceSnapshotPayload, Role, RoleAssignment,
        SeriesKey, Session, SessionId, SystemCommand, TargetId, TelemetrySample, TelemetrySeries,
        TelemetrySeriesId, TlsCertificate, TlsTrust, TotpAuthenticator, TotpAuthenticatorError,
    };
    use secrecy::{ExposeSecret, SecretBox, SecretString};
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
            Arc::new(UnavailableWriteServices {
                inventory,
                batch_store: BatchTestStore::failing(),
                managed_endpoints: None,
                refresh_working: false,
                auth_state: AuthTestState::default(),
                center_state: CenterTestState::default(),
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        )
    }

    /// Builds the router over a services bundle whose batch store is a
    /// working in-memory store — the §13.7 route projections' test bench.
    fn test_batch_router(batch_store: BatchTestStore) -> Router {
        router(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store,
                managed_endpoints: None,
                refresh_working: false,
                auth_state: AuthTestState::default(),
                center_state: CenterTestState::default(),
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        )
    }

    /// Builds the router over a services bundle whose refresh pre-check
    /// answers from a managed-endpoint list instead of failing — the
    /// refresh-route validation tests' bench.
    fn test_refresh_router(managed_endpoints: Vec<Endpoint>) -> Router {
        router(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: Some(managed_endpoints),
                refresh_working: false,
                auth_state: AuthTestState::default(),
                center_state: CenterTestState::default(),
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        )
    }

    /// Builds the router over a services bundle and gateway whose refresh
    /// boundaries all answer like a working product slice — the refresh
    /// route's 200-report test bench.
    fn test_working_refresh_router(managed_endpoints: Vec<Endpoint>) -> Router {
        router(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: Some(managed_endpoints),
                refresh_working: true,
                auth_state: AuthTestState::default(),
                center_state: CenterTestState::default(),
            }),
            Arc::new(UnavailableGateway { working: true }),
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
    async fn exposes_oem_dell_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = oem_dell_inventory_item()?;
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
        assert_eq!(resources.len(), 2);
        // The inventory orders snapshots by `@odata.id`, so the service root
        // (the `/redfish/v1` prefix) sorts before the manager's Dell
        // Attributes document.
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        assert_eq!(resources[1]["resource"]["resource_type"], "oem_dell");
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1"
        );
        assert_eq!(resources[1]["common"]["name"], "Dell Attributes");
        assert_eq!(
            resources[1]["resource"]["details"]["server_model"],
            "PowerEdge R750"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["server_service_tag"],
            "ABC1234"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["server_generation"],
            "16G"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["server_bmc_mac_address"],
            "14:18:77:aa:bb:cc"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["server_name"],
            "rack-1-server-2"
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_oem_smc_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = oem_smc_inventory_item()?;
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
        assert_eq!(resources.len(), 3);
        // The inventory orders snapshots by `@odata.id`, so the service root
        // (the `/redfish/v1` prefix) sorts before the manager's Supermicro
        // documents, with `KCSInterface` before `SysLockdown`.
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        assert_eq!(
            resources[1]["resource"]["resource_type"],
            "oem_smc_kcs_interface"
        );
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Managers/1/KCSInterface"
        );
        assert_eq!(resources[1]["common"]["name"], "KCSInterface");
        assert_eq!(resources[1]["resource"]["details"]["privilege"], "Operator");
        assert_eq!(
            resources[2]["resource"]["resource_type"],
            "oem_smc_sys_lockdown"
        );
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Managers/1/SysLockdown"
        );
        assert_eq!(resources[2]["common"]["name"], "SysLockdown");
        assert_eq!(
            resources[2]["resource"]["details"]["sys_lockdown_enabled"],
            true
        );
        Ok(())
    }

    #[tokio::test]
    async fn exposes_oem_lenovo_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = oem_lenovo_inventory_item()?;
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
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        // The `SecurityService` document carries the flattened `FWRollback`
        // enum spelling verbatim per §12.3 (the `Configurator` nesting of the
        // compiled schema collapses onto the wrapper's accessor).
        assert_eq!(
            resources[1]["resource"]["resource_type"],
            "oem_lenovo_security_service"
        );
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService"
        );
        assert_eq!(
            resources[1]["source"]["odata_type"],
            "#LenovoSecurityService.v1_0_0.LenovoSecurityService"
        );
        assert_eq!(resources[1]["source"]["etag"], "W/\"lenovo-security-1\"");
        assert_eq!(resources[1]["common"]["name"], "Lenovo Security Service");
        assert_eq!(
            resources[1]["resource"]["details"]["fw_rollback"],
            "Enabled"
        );
        Ok(())
    }

    // The 157-line test exceeds the pedantic line budget because the whole
    // NVIDIA wire surface (the system chain plus the power chains) is
    // asserted in one contract; the lint is scoped here exactly like the
    // other fixture-sequence tests.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn exposes_oem_nvidia_typed_resources() -> Result<(), Box<dyn Error>> {
        let item = oem_nvidia_inventory_item()?;
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
        assert_eq!(resources.len(), 14);
        // The inventory orders snapshots by `@odata.id`, so the service root
        // sorts before the manager chain (`Managers` < `Systems`), and within
        // the manager chain the singletons sort before the collection
        // members (`ACLossPolicy` < `ManagedEntityGroups` < `PSURedundancy` <
        // `PowerDomains` < `PowerStateGroup`), and within the system chain
        // the profile collection members sort before the status singleton
        // (`Profiles` < `Status`).
        assert_eq!(resources[0]["resource"]["resource_type"], "service_root");
        // The power-compliance chain root carries the compiled `ManagerType`
        // enumeration spelling verbatim.
        assert_eq!(
            resources[1]["resource"]["resource_type"],
            "oem_nvidia_power_compliance"
        );
        assert_eq!(
            resources[1]["source"]["odata_id"],
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance"
        );
        assert_eq!(
            resources[1]["resource"]["details"]["manager_type"],
            "PowerManager"
        );
        // The ACLossPolicy singleton shares the power-policy variant with
        // the PSU compliance policy.
        assert_eq!(
            resources[2]["resource"]["resource_type"],
            "oem_nvidia_power_policy"
        );
        assert_eq!(
            resources[2]["source"]["odata_id"],
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy"
        );
        assert_eq!(
            resources[2]["resource"]["details"]["policy_actions"],
            "AssertPowerBrake"
        );
        assert_eq!(resources[2]["resource"]["details"]["min"], 200);
        // The managed entity group member carries the compiled id text.
        assert_eq!(
            resources[3]["resource"]["resource_type"],
            "oem_nvidia_managed_entity_group"
        );
        assert_eq!(
            resources[3]["resource"]["details"]["current_managed_entity_id"],
            "BF1"
        );
        // The managed entity member carries the compiled scalar fields.
        assert_eq!(
            resources[4]["resource"]["resource_type"],
            "oem_nvidia_managed_entity"
        );
        assert_eq!(
            resources[4]["source"]["odata_id"],
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1"
        );
        assert_eq!(
            resources[4]["resource"]["details"]["transport_protocol"],
            "HTTPS"
        );
        assert_eq!(
            resources[4]["resource"]["details"]["ipv4_address"],
            "192.0.2.10"
        );
        assert_eq!(resources[4]["resource"]["details"]["port"], 443);
        // The PSU redundancy singleton carries the compiled scalar fields.
        assert_eq!(
            resources[5]["resource"]["resource_type"],
            "oem_nvidia_psu_redundancy"
        );
        assert_eq!(
            resources[5]["resource"]["details"]["redundancy_setting"],
            "NPlusOne"
        );
        // A power domain member carries the compiled scalar fields.
        assert_eq!(
            resources[6]["resource"]["resource_type"],
            "oem_nvidia_power_domain"
        );
        assert_eq!(resources[6]["resource"]["details"]["type"], "Above");
        assert_eq!(resources[6]["resource"]["details"]["value"], 800);
        // The power state group carries the compiled scalar fields.
        assert_eq!(
            resources[7]["resource"]["resource_type"],
            "oem_nvidia_power_state_group"
        );
        assert_eq!(resources[7]["resource"]["details"]["generated_watts"], 2400);
        // A PSC state member carries the compiled scalar fields.
        assert_eq!(
            resources[8]["resource"]["resource_type"],
            "oem_nvidia_psc_state"
        );
        assert_eq!(resources[8]["resource"]["details"]["status"], "Operational");
        // A PSU state member carries the compiled scalar fields.
        assert_eq!(
            resources[9]["resource"]["resource_type"],
            "oem_nvidia_psu_state"
        );
        assert_eq!(resources[9]["resource"]["details"]["presence"], true);
        // The system-config-profile chain follows the manager chain.
        assert_eq!(
            resources[10]["resource"]["resource_type"],
            "oem_nvidia_system_config_profile"
        );
        assert_eq!(
            resources[10]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile"
        );
        assert_eq!(
            resources[10]["common"]["name"],
            "NVIDIA System Config Profile"
        );
        assert_eq!(
            resources[10]["resource"]["details"]["truststore"]["nvidia_certificates"],
            true
        );
        assert_eq!(
            resources[10]["resource"]["details"]["truststore"]["oem_certificates"],
            false
        );
        assert_eq!(
            resources[11]["resource"]["resource_type"],
            "oem_nvidia_system_profile"
        );
        assert_eq!(
            resources[11]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1"
        );
        assert_eq!(resources[11]["resource"]["details"]["owner"], "Nvidia");
        assert_eq!(resources[11]["resource"]["details"]["version"], 1);
        assert_eq!(
            resources[12]["resource"]["resource_type"],
            "oem_nvidia_system_profile_file"
        );
        assert_eq!(
            resources[12]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile"
        );
        assert_eq!(
            resources[12]["resource"]["details"]["metadata_origin_profile_uuid"],
            "11111111-2222-3333-4444-555555555555"
        );
        assert_eq!(
            resources[12]["resource"]["details"]["profile"],
            "eyJwcm9maWxlIjogInRlc3QifQ=="
        );
        assert_eq!(
            resources[13]["resource"]["resource_type"],
            "oem_nvidia_system_config_profile_status"
        );
        assert_eq!(
            resources[13]["source"]["odata_id"],
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status"
        );
        assert_eq!(
            resources[13]["resource"]["details"]["pending_list_activation"],
            "profile-1"
        );
        assert_eq!(
            resources[13]["resource"]["details"]["active_profile_index"],
            1
        );
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

    /// Every batch route maps an unavailable services bundle to a `503` that
    /// is never cached, exactly like the operation routes.
    #[tokio::test]
    async fn batch_routes_report_unavailable_services() -> Result<(), Box<dyn Error>> {
        let router = test_router();

        let listed = router
            .clone()
            .oneshot(Request::get("/api/v1/batches").body(Body::empty())?)
            .await?;
        assert_eq!(listed.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            listed.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );

        let detailed = router
            .oneshot(
                Request::get(format!("/api/v1/batches/{}", BatchOperationId::generate()))
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

    /// The §13.7 routes project the server-derived verdict and buckets: the
    /// listing carries each batch's derived state and outcome counts, and the
    /// detail adds every child in target order. The route never derives a
    /// batch fact itself.
    // The walk covers the listing, the detail, and both error statuses, so
    // the line count is the coverage.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn batch_routes_project_derived_states_and_outcome_buckets() -> Result<(), Box<dyn Error>>
    {
        let store = BatchTestStore::working();
        let base = OffsetDateTime::UNIX_EPOCH;
        // A finished batch: one classified failure, one ordinary failure, two
        // successes — derived `failed` with the unsupported bucket separated.
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle));
        let failed_batch = BatchOperation::new(
            BatchOperationId::generate(),
            OperationSource::Site,
            command.clone(),
            base,
        );
        store.insert(
            &failed_batch,
            &[
                (
                    OperationState::Failed,
                    Some(FailureKind::CapabilityUnsupported),
                ),
                (OperationState::Failed, None),
                (OperationState::Succeeded, None),
                (OperationState::Succeeded, None),
            ],
        )?;
        // A running batch: one child still queued — the partial sum stays
        // below total.
        let running_batch = BatchOperation::new(
            BatchOperationId::generate(),
            OperationSource::Site,
            command,
            base + Duration::SECOND,
        );
        store.insert(
            &running_batch,
            &[
                (OperationState::Succeeded, None),
                (OperationState::Queued, None),
            ],
        )?;
        let router = test_batch_router(store);

        let listed = router
            .clone()
            .oneshot(Request::get("/api/v1/batches").body(Body::empty())?)
            .await?;
        assert_eq!(listed.status(), StatusCode::OK);
        let list = json_body(listed).await?;
        assert_eq!(list["batches"].as_array().map(Vec::len), Some(2));
        assert_eq!(
            list["batches"][0]["batch_id"],
            failed_batch.id().into_uuid().to_string()
        );
        assert_eq!(list["batches"][0]["state"], "failed");
        assert_eq!(
            list["batches"][0]["outcomes"],
            json!({
                "succeeded": 2,
                "failed": 1,
                "unknown": 0,
                "unsupported": 1,
                "cancelled": 0,
                "total": 4
            })
        );
        assert_eq!(
            list["batches"][1]["batch_id"],
            running_batch.id().into_uuid().to_string()
        );
        assert_eq!(list["batches"][1]["state"], "running");
        assert_eq!(list["batches"][1]["outcomes"]["total"], 2);
        assert_eq!(list["batches"][1]["outcomes"]["succeeded"], 1);

        let detailed = router
            .clone()
            .oneshot(
                Request::get(format!("/api/v1/batches/{}", failed_batch.id()))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(detailed.status(), StatusCode::OK);
        let detail = json_body(detailed).await?;
        assert_eq!(
            detail["batch_id"],
            failed_batch.id().into_uuid().to_string()
        );
        assert_eq!(detail["state"], "failed");
        assert_eq!(detail["children"].as_array().map(Vec::len), Some(4));
        assert_eq!(
            detail["command"],
            json!({ "System": { "Reset": "PowerCycle" } })
        );
        // The children are ordinary operation projections in target order.
        let child_ids = detail["children"]
            .as_array()
            .ok_or("children must be a list")?
            .iter()
            .map(|child| {
                child["operation_id"]
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| std::io::Error::other("a child operation id is missing"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut sorted = child_ids.clone();
        sorted.sort();
        assert_eq!(
            child_ids, sorted,
            "the detail must carry the children in target order"
        );

        // A malformed batch id is a client error; an unknown id is 404.
        let bad_id = router
            .clone()
            .oneshot(Request::get("/api/v1/batches/not-a-uuid").body(Body::empty())?)
            .await?;
        assert_eq!(bad_id.status(), StatusCode::BAD_REQUEST);
        let unknown = router
            .oneshot(
                Request::get(format!("/api/v1/batches/{}", BatchOperationId::generate()))
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
        Ok(())
    }

    /// The refresh route rejects an empty, duplicated, or oversized endpoint
    /// list with 400 before any endpoint work can start.
    #[tokio::test]
    async fn refresh_route_rejects_empty_duplicate_and_oversized_batches()
    -> Result<(), Box<dyn Error>> {
        let router = test_router();
        let endpoint_id = EndpointId::generate();

        let empty = router
            .clone()
            .oneshot(
                Request::post("/api/v1/endpoints/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint_ids": []
                    }))?))?,
            )
            .await?;
        assert_eq!(empty.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(empty).await?["message"],
            "a refresh batch must name at least one endpoint"
        );

        let duplicated = router
            .clone()
            .oneshot(
                Request::post("/api/v1/endpoints/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint_ids": [endpoint_id.to_string(), endpoint_id.to_string()]
                    }))?))?,
            )
            .await?;
        assert_eq!(duplicated.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(duplicated).await?["message"],
            format!("refresh batch targets endpoint {endpoint_id} more than once")
        );

        let ids = (0..=MAX_REFRESH_TARGETS)
            .map(|_| EndpointId::generate().to_string())
            .collect::<Vec<_>>();
        let oversized = router
            .oneshot(
                Request::post("/api/v1/endpoints/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint_ids": ids
                    }))?))?,
            )
            .await?;
        assert_eq!(oversized.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            json_body(oversized).await?["message"],
            format!("a refresh batch may target at most {MAX_REFRESH_TARGETS} endpoints")
        );
        Ok(())
    }

    /// A body-referenced endpoint that is not managed is unprocessable,
    /// exactly like the operation submission verdict.
    #[tokio::test]
    async fn refresh_route_rejects_unknown_endpoints_before_any_refresh()
    -> Result<(), Box<dyn Error>> {
        let router = test_refresh_router(Vec::new());
        let endpoint_id = EndpointId::generate();

        let response = router
            .oneshot(
                Request::post("/api/v1/endpoints/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint_ids": [endpoint_id.to_string()]
                    }))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            json_body(response).await?["message"],
            format!("endpoint {endpoint_id} is not a managed endpoint")
        );
        Ok(())
    }

    /// An unavailable services bundle maps the failed pre-check to a 503 that
    /// is never cached, exactly like the operation and batch routes.
    #[tokio::test]
    async fn refresh_route_reports_unavailable_precheck() -> Result<(), Box<dyn Error>> {
        let router = test_router();
        let endpoint_id = EndpointId::generate();

        let response = router
            .oneshot(
                Request::post("/api/v1/endpoints/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint_ids": [endpoint_id.to_string()]
                    }))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        assert_eq!(
            json_body(response).await?["message"],
            "the refresh targets could not be checked"
        );
        Ok(())
    }

    /// A working gateway and services bundle turn one valid refresh batch
    /// into the 200 report: the server-derived counts and one refreshed row
    /// carrying the committed Generation and snapshot count, never cached.
    #[tokio::test]
    async fn refresh_route_returns_the_200_report_for_a_valid_batch() -> Result<(), Box<dyn Error>>
    {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Refresh batch BMC")?,
            EndpointAddress::parse("https://192.0.2.70")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![70])?,
                trusted_at: created_at,
            },
            CredentialId::generate(),
            created_at,
            created_at,
        )?;
        let router = test_working_refresh_router(vec![endpoint.clone()]);

        let response = router
            .oneshot(
                Request::post("/api/v1/endpoints/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&json!({
                        "endpoint_ids": [endpoint.id().to_string()]
                    }))?))?,
            )
            .await?;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        let report = json_body(response).await?;
        assert_eq!(report["total"], 1);
        assert_eq!(report["succeeded_count"], 1);
        assert_eq!(report["failed_count"], 0);
        let results = report["results"]
            .as_array()
            .ok_or("results must be a list")?;
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0]["endpoint_id"],
            endpoint.id().into_uuid().to_string()
        );
        assert_eq!(results[0]["status"], "refreshed");
        assert_eq!(results[0]["generation"], 1);
        assert_eq!(results[0]["snapshot_count"], 2);
        assert_eq!(results[0]["message"], Value::Null);
        Ok(())
    }

    /// The 200 report carries the server-derived counts and one independent
    /// row per endpoint: refreshed rows carry the committed Generation and
    /// snapshot count, failed rows the classified message, and vanished
    /// endpoints their own status.
    #[test]
    fn refresh_report_projection_carries_per_endpoint_results() -> Result<(), Box<dyn Error>> {
        let first = EndpointId::generate();
        let second = EndpointId::generate();
        let missing = EndpointId::generate();
        let generation = RefreshGeneration::new(9)?;
        let outcomes = vec![
            EndpointRefreshOutcome::Refreshed {
                endpoint_id: first,
                generation,
                snapshot_count: 31,
            },
            EndpointRefreshOutcome::Failed {
                endpoint_id: second,
                reason: EndpointRefreshFailureKind::Read,
                message: "connection refused".to_owned(),
            },
            EndpointRefreshOutcome::NotFound {
                endpoint_id: missing,
            },
        ];

        let report = project_refresh_report(&outcomes);

        assert_eq!(report.total(), 3);
        assert_eq!(report.succeeded_count(), 1);
        assert_eq!(report.failed_count(), 2);
        assert_eq!(report.results().len(), 3);
        assert_eq!(report.results()[0].endpoint_id(), first.into_uuid());
        assert_eq!(
            report.results()[0].status(),
            EndpointRefreshStatusResponse::Refreshed
        );
        assert_eq!(report.results()[0].generation(), Some(9));
        assert_eq!(report.results()[0].snapshot_count(), Some(31));
        assert_eq!(report.results()[0].message(), None);
        assert_eq!(report.results()[1].endpoint_id(), second.into_uuid());
        assert_eq!(
            report.results()[1].status(),
            EndpointRefreshStatusResponse::Failed
        );
        assert_eq!(report.results()[1].generation(), None);
        assert_eq!(
            report.results()[1].message(),
            Some("resource read failed: connection refused")
        );
        assert_eq!(report.results()[2].endpoint_id(), missing.into_uuid());
        assert_eq!(
            report.results()[2].status(),
            EndpointRefreshStatusResponse::NotFound
        );
        assert_eq!(report.results()[2].message(), None);
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

    fn oem_dell_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Dell OEM BMC")?,
            EndpointAddress::parse("https://192.0.2.38")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![38])?,
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
        let oem_dell = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemDell,
            "/redfish/v1/Managers/1/Oem/Dell/DellAttributes/1",
            r#"{"Id":"1","Name":"Dell Attributes","Description":"Dell iDRAC attributes","ServerModel":"PowerEdge R750","ServerServiceTag":"ABC1234","ServerGeneration":"16G","ServerBmcMacAddress":"14:18:77:aa:bb:cc","ServerName":"rack-1-server-2"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#DellAttributes.v1_0_0.DellAttributes",
        )?)
        .with_etag(ResourceEtag::parse("W/\"dell-attributes-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, oem_dell],
        )?)
    }

    fn oem_smc_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Supermicro OEM BMC")?,
            EndpointAddress::parse("https://192.0.2.39")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![39])?,
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
        // The compiled Supermicro schemas model no `Id` / `Name`, so the
        // payloads carry only the typed document fields and the product
        // identity is derived from each snapshot's `@odata.id`.
        let sys_lockdown = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemSmcSysLockdown,
            "/redfish/v1/Managers/1/SysLockdown",
            r#"{"SysLockdownEnabled":true}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse("#SysLockdown.v1_0_0.SysLockdown")?)
        .with_etag(ResourceEtag::parse("W/\"sys-lockdown-1\"")?);
        let kcs_interface = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemSmcKcsInterface,
            "/redfish/v1/Managers/1/KCSInterface",
            r#"{"Privilege":"Operator"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#KCSInterface.v1_0_0.KCSInterface",
        )?)
        .with_etag(ResourceEtag::parse("W/\"kcs-interface-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, kcs_interface, sys_lockdown],
        )?)
    }

    fn oem_lenovo_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Lenovo OEM BMC")?,
            EndpointAddress::parse("https://192.0.2.41")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![41])?,
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
        // The compiled `LenovoSecurityService` base requires `Id` / `Name`
        // and the projection follows the upstream `fw_rollback()` accessor
        // surface, so the payload carries the common fields plus the
        // flattened `FWRollback` enum spelling.
        let security_service = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemLenovoSecurityService,
            "/redfish/v1/Managers/1/Oem/Lenovo/SecurityService",
            r#"{"Id":"SecurityService","Name":"Lenovo Security Service","Description":"Lenovo security service","FWRollback":"Enabled"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#LenovoSecurityService.v1_0_0.LenovoSecurityService",
        )?)
        .with_etag(ResourceEtag::parse("W/\"lenovo-security-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![root, security_service],
        )?)
    }

    // The 198-line fixture exceeds the pedantic line budget because it
    // serves the whole NVIDIA chain surface (the system chain plus the power
    // chains) in one inventory; the lint is scoped here exactly like the
    // other fixture builders. The `psc_state` / `psu_state` bindings are two
    // letters apart, so the similar-names lint is scoped off as well.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    fn oem_nvidia_inventory_item() -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let created_at = OffsetDateTime::UNIX_EPOCH;
        let observed_at = created_at + Duration::SECOND;
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("NVIDIA OEM BMC")?,
            EndpointAddress::parse("https://192.0.2.40")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![40])?,
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
        // The whole NVIDIA system-config-profile chain shares the one family
        // code; each snapshot payload carries its `DocumentType`
        // discriminator so the application boundary routes the snapshot to
        // the right details shape.
        let chain_root = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaSystemConfigProfile,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile",
            r#"{"Id":"SystemConfigProfile","Name":"NVIDIA System Config Profile","Description":"Profile service","DocumentType":"system_config_profile","Truststore":{"NvidiaCertificates":true,"OemCertificates":false}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaSystemConfigProfile.NvidiaSystemConfigProfile",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-scp-1\"")?);
        let status = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaSystemConfigProfile,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Status",
            r#"{"Id":"Status","Name":"System Config Profile Status","Description":"Profile service status","DocumentType":"system_config_profile_status","PendingList":{"Activation":"profile-1"},"ActiveProfileIndex":1,"BmcProfileVersion":2,"FactoryResetStatus":"Idle","DefaultProfileIndex":1}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaSystemConfigProfileStatus.NvidiaSystemConfigProfileStatus",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-scp-status-1\"")?);
        let profile = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaSystemConfigProfile,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1",
            r#"{"Id":"1","Name":"Default Profile","Description":"Factory default profile","DocumentType":"system_profile","Default":true,"Owner":"Nvidia","UUID":"11111111-2222-3333-4444-555555555555","Version":1,"ProfileName":"default-profile"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaSystemProfile.NvidiaSystemProfile",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-profile-1\"")?);
        let profile_file = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaSystemConfigProfile,
            "/redfish/v1/Systems/1/Oem/Nvidia/SystemConfigProfile/Profiles/1/ProfileFile",
            r#"{"Id":"ProfileFile","Name":"Profile File","Description":"Signed profile file","DocumentType":"system_profile_file","ProfileFile":{"Metadata":{"Activate":true,"Delete":false,"OriginProfileUUID":"11111111-2222-3333-4444-555555555555","More_Profiles":false,"ProjectName":"BlueField","UUID":"11111111-2222-3333-4444-555555555555"},"Profile":"eyJwcm9maWxlIjogInRlc3QifQ=="}}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaSystemProfileFile.NvidiaSystemProfileFile",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-profile-file-1\"")?);
        // The NVIDIA power-compliance chain shares the one
        // `nvidia-power-compliance` family code; each snapshot payload
        // carries its `DocumentType` discriminator so the application
        // boundary routes the snapshot to the right details shape. The
        // managed-entity chain shares the one `nvidia-managed-entity` family
        // code under the single `ManagedEntity` document kind.
        let power_compliance = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance",
            r#"{"Id":"PowerCompliance","Name":"NVIDIA Power Compliance","Description":"Power compliance manager","DocumentType":"power_compliance_manager","ManagerType":"PowerManager"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPowerComplianceManager.v1_0_0.NvidiaPowerComplianceManager",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-pc-1\"")?);
        let ac_loss_policy = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ACLossPolicy",
            r#"{"Id":"ACLossPolicy","Name":"AC Loss Policy","Description":"AC loss power policy","DocumentType":"power_policy","AutoDeassertPowerBrake":true,"Min":200,"Max":600,"Type":"Inclusive","Unit":"Watts","PolicyActions":"AssertPowerBrake"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPowerPolicy.v1_0_0.NvidiaPowerPolicy",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-acloss-1\"")?);
        let entity_group = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1",
            r#"{"Id":"1","Name":"Managed Entity Group One","Description":"BlueField group","DocumentType":"managed_entity_group","CurrentManagedEntityId":"BF1"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaManagedEntityGroup.v1_0_0.NvidiaManagedEntityGroup",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-group-1\"")?);
        let managed_entity = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaManagedEntity,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/ManagedEntityGroups/1/ManagedEntities/1",
            r#"{"Id":"1","Name":"Managed Entity One","Description":"BlueField managed entity","DocumentType":"managed_entity","TransportProtocol":"HTTPS","IPv4Address":"192.0.2.10","IPv6Address":"2001:db8::10","Port":443}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaManagedEntity.v1_0_0.NvidiaManagedEntity",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-entity-1\"")?);
        let redundancy = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PSURedundancy",
            r#"{"Id":"PSURedundancy","Name":"PSU Redundancy","Description":"PSU redundancy settings","DocumentType":"psu_redundancy","MaxNumSupported":"4","MinNumNeeded":"2","RedundancySetting":"NPlusOne"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPsuRedundancy.v1_0_0.NvidiaPsuRedundancy",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-redundancy-1\"")?);
        let power_domain = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerDomains/1",
            r#"{"Id":"1","Name":"Power Domain One","Description":"Power comparison domain","DocumentType":"power_domain","Value":800,"Type":"Above","Unit":"Watts","SensorReadingType":"Power","SensorImpl":"PhysicalSensor"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPowerDomain.v1_0_0.NvidiaPowerDomain",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-domain-1\"")?);
        let power_state_group = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup",
            r#"{"Id":"PowerStateGroup","Name":"Power State Group","Description":"Power shelf state","DocumentType":"power_state_group","PscId":"PSC1","GeneratedWatts":2400,"NumberOfPscs":1,"NumberOfLocalPsus":2}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPowerStateGroup.v1_0_0.NvidiaPowerStateGroup",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-state-group-1\"")?);
        let psc_state = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerShelfControllers/1",
            r#"{"Id":"1","Name":"Power Shelf Controller One","Description":"PSC state","DocumentType":"psc_state","PscId":"PSC1","NumOfOperationalPsus":4,"PowerBrakeAssert":false,"MillisecondsSinceLastHeartbeat":12,"Status":"Operational"}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPscState.v1_0_0.NvidiaPscState",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-psc-1\"")?);
        let psu_state = resource_snapshot_with_payload(
            endpoint.id(),
            ResourceFeature::OemNvidiaPowerCompliance,
            "/redfish/v1/Managers/1/Oem/Nvidia/PowerCompliance/PowerStateGroup/PowerSupplies/1",
            r#"{"Id":"1","Name":"Power Supply One","Description":"PSU state","DocumentType":"psu_state","PsuId":"PSU1","Presence":true,"Input1Active":true,"Input2Active":false}"#,
            observed_at,
            generation,
        )?
        .with_odata_type(ResourceODataType::parse(
            "#NvidiaPsuState.v1_0_0.NvidiaPsuState",
        )?)
        .with_etag(ResourceEtag::parse("W/\"nvidia-psu-1\"")?);
        Ok(EndpointInventoryItem::try_new(
            endpoint,
            vec![
                root,
                chain_root,
                profile,
                profile_file,
                status,
                power_compliance,
                ac_loss_policy,
                entity_group,
                managed_entity,
                redundancy,
                power_domain,
                power_state_group,
                psc_state,
                psu_state,
            ],
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
        /// The §13.7 batch store behind the batch routes: `fail` keeps the
        /// default bundle unavailable (every existing test's expectation),
        /// while the batch-route tests arm a working in-memory store.
        batch_store: BatchTestStore,
        /// The managed endpoints behind the refresh pre-check: `None` keeps
        /// the refresh surface unavailable (every existing test's
        /// expectation), an empty list makes every referenced endpoint
        /// unknown (the 422 verdict), and a populated list backs the working
        /// refresh tests.
        managed_endpoints: Option<Vec<Endpoint>>,
        /// Whether the refresh execution boundaries (credential resolution,
        /// Generation commit, capability snapshot replace, and audit append)
        /// answer like a working slice: `false` keeps them unavailable (the
        /// default), `true` arms the refresh route's 200-report test.
        refresh_working: bool,
        /// The in-memory authentication state behind the §16.2 auth tests:
        /// the Open test routers never touch it (the auth boundary answers
        /// "nothing found"), while the guarded tests populate it through
        /// `AuthTestState`.
        auth_state: AuthTestState,
        /// The in-memory center-view state behind the center console tests:
        /// the default bundle answers "no registered sites" (every existing
        /// test's expectation), while the center tests seed the views and
        /// record every mutation through `CenterTestState`.
        center_state: CenterTestState,
    }

    /// In-memory batch store for the §13.7 route tests.
    ///
    /// The store holds batch parents and their children exactly like the
    /// production repository — including the per-child failure kinds — so the
    /// route tests exercise the real derived-state and bucket projections end
    /// to end. `fail` mirrors the unavailable-bundle default.
    #[derive(Clone)]
    struct BatchTestStore {
        rows: Arc<Mutex<HashMap<OperationId, Operation>>>,
        batch_rows: Arc<Mutex<HashMap<BatchOperationId, BatchOperation>>>,
        batch_children: Arc<Mutex<HashMap<BatchOperationId, Vec<ClassifiedBatchChild>>>>,
        fail: bool,
    }

    impl BatchTestStore {
        fn failing() -> Self {
            Self::with_failure(true)
        }

        fn working() -> Self {
            Self::with_failure(false)
        }

        fn with_failure(fail: bool) -> Self {
            Self {
                rows: Arc::new(Mutex::new(HashMap::new())),
                batch_rows: Arc::new(Mutex::new(HashMap::new())),
                batch_children: Arc::new(Mutex::new(HashMap::new())),
                fail,
            }
        }

        /// Inserts one batch with its children at the given states and kinds;
        /// the batch and the children are stored exactly as the repository
        /// would persist them.
        fn insert(
            &self,
            batch: &BatchOperation,
            children: &[(OperationState, Option<FailureKind>)],
        ) -> Result<(), MockWriteError> {
            let mut operations = Vec::with_capacity(children.len());
            for (state, _) in children {
                let operation = Operation::try_from_parts(
                    OperationId::generate(),
                    batch.source(),
                    vec![OperationTarget::new(
                        TargetId::generate(),
                        EndpointId::generate(),
                    )],
                    batch.command(),
                    *state,
                    batch.created_at(),
                    batch.created_at() + Duration::SECOND,
                )
                .map_err(|_| MockWriteError)?;
                operations.push(operation);
            }
            operations.sort_by_key(|child| child.targets()[0].target_id());
            self.rows
                .lock()
                .map_err(|_| MockWriteError)?
                .extend(operations.iter().cloned().map(|child| (child.id(), child)));
            self.batch_rows
                .lock()
                .map_err(|_| MockWriteError)?
                .insert(batch.id(), batch.clone());
            self.batch_children
                .lock()
                .map_err(|_| MockWriteError)?
                .insert(
                    batch.id(),
                    operations
                        .into_iter()
                        .zip(children.iter().map(|(_, kind)| *kind))
                        .collect(),
                );
            Ok(())
        }
    }

    /// Every gateway boundary reports a controlled failure so the read-path
    /// tests never touch the network; `working` arms the typed Redfish read
    /// and the capability re-probe for the refresh route's 200-report test.
    #[derive(Clone, Copy)]
    struct UnavailableGateway {
        working: bool,
    }

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
            let working = self.refresh_working;
            Box::pin(async move {
                if !working {
                    return Err(MockWriteError);
                }
                Ok(Some(ResolvedCredential::new(
                    CredentialUsername::parse("administrator").map_err(|_| MockWriteError)?,
                    String::from("secret").into(),
                )))
            })
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
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            let managed = self.managed_endpoints.clone();
            Box::pin(async move {
                let Some(managed) = managed else {
                    return Err(MockWriteError);
                };
                Ok(managed
                    .into_iter()
                    .find(|endpoint| endpoint.id() == endpoint_id))
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            endpoint_id: EndpointId,
            observations: &'a [ResourceObservation],
            observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            let working = self.refresh_working;
            Box::pin(async move {
                if !working {
                    return Err(MockWriteError);
                }
                let generation = RefreshGeneration::new(1).map_err(|_| MockWriteError)?;
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

    impl CapabilitySnapshotRepository for UnavailableWriteServices {
        type Error = MockWriteError;

        fn replace_endpoint_capabilities<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [EndpointCapabilityObservation],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let working = self.refresh_working;
            Box::pin(async move { if working { Ok(()) } else { Err(MockWriteError) } })
        }
    }

    impl AuditEventWriter for UnavailableWriteServices {
        type Error = MockWriteError;

        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let working = self.refresh_working;
            let recorder = self.center_state.audit.clone();
            Box::pin(async move {
                if !working {
                    return Err(MockWriteError);
                }
                if let Some(recorder) = recorder
                    && let Ok(mut events) = recorder.lock()
                {
                    events.push(event.clone());
                }
                Ok(())
            })
        }
    }

    /// The in-memory §16.2 authentication state behind the guarded-route
    /// tests.
    ///
    /// The state mirrors the persistence shapes (principal, role, password,
    /// session, bootstrap rows) without a database, and the crypto surface
    /// is a deterministic fold of the input — good enough to prove the
    /// middleware gates, not to stand in for real cryptography.
    #[derive(Clone, Default)]
    struct AuthTestState {
        inner: Arc<Mutex<AuthTestInner>>,
    }

    #[derive(Default)]
    struct AuthTestInner {
        principals: Vec<Principal>,
        roles: HashMap<PrincipalId, Role>,
        /// The D3 site scope of one role assignment (`None` is the global
        /// assignment); the center scope tests seed it through
        /// `seed_scoped_principal`.
        role_sites: HashMap<PrincipalId, Option<InstanceId>>,
        passwords: HashMap<PrincipalId, PasswordCredential>,
        sessions: Vec<Session>,
        bootstrap_code: Option<BootstrapCode>,
        next_token: u64,
    }

    impl AuthTestState {
        fn seed_principal(&self, name: &str, password: &str, role: Role) {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            let now = OffsetDateTime::now_utc();
            let Ok(name) = PrincipalName::parse(name) else {
                return;
            };
            let principal = Principal::new(PrincipalId::generate(), name, now);
            inner.roles.insert(principal.id(), role);
            inner
                .passwords
                .insert(principal.id(), deterministic_credential(password, now));
            inner.principals.push(principal);
        }

        /// Seeds one principal with a D3 site-scoped role assignment (§16.1
        /// — a center role can be limited to one site).
        fn seed_scoped_principal(&self, name: &str, password: &str, role: Role, site: InstanceId) {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            let now = OffsetDateTime::now_utc();
            let Ok(name) = PrincipalName::parse(name) else {
                return;
            };
            let principal = Principal::new(PrincipalId::generate(), name, now);
            inner.roles.insert(principal.id(), role);
            inner.role_sites.insert(principal.id(), Some(site));
            inner
                .passwords
                .insert(principal.id(), deterministic_credential(password, now));
            inner.principals.push(principal);
        }

        fn seed_bootstrap_code(&self, code: &str) {
            let Ok(mut inner) = self.inner.lock() else {
                return;
            };
            inner.bootstrap_code = Some(BootstrapCode::new(
                BootstrapCodeId::generate(),
                fold_hash(code),
                OffsetDateTime::now_utc(),
            ));
        }
    }

    /// The deterministic "crypto" of the auth test state: a fixed salt and a
    /// byte fold of the password, so hash and verify agree without real
    /// Argon2id work.
    fn deterministic_credential(password: &str, changed_at: OffsetDateTime) -> PasswordCredential {
        // The fixed part sizes are valid by construction; the error arms are
        // totality guards of the domain value objects.
        let Ok(hash) = Argon2IdHash::from_parts(&[0x11; 16], &fold_hash(password)) else {
            unreachable!("the fixed salt and hash lengths are valid");
        };
        let Ok(credential) =
            PasswordCredential::try_from_parts(PrincipalId::generate(), hash, changed_at)
        else {
            unreachable!("the credential parts are valid");
        };
        credential
    }

    /// The deterministic byte fold standing in for SHA-256 in tests.
    fn fold_hash(value: &str) -> [u8; 32] {
        let mut hash = [0_u8; 32];
        for (index, byte) in value.bytes().enumerate() {
            hash[index % 32] ^= byte.rotate_left(u32::try_from(index % 8).unwrap_or(0));
        }
        hash
    }

    /// The auth boundaries of the test bundle: the Open test routers never
    /// touch a session (the state is empty and answers "nothing found"),
    /// while the guarded tests seed the state and drive the full §16.2
    /// lifecycle through it.
    impl AuthServices for UnavailableWriteServices {
        type Error = MockWriteError;

        fn find_session_by_token_hash<'a>(
            &'a self,
            token_hash: &'a [u8; 32],
        ) -> BoundaryFuture<'a, Result<Option<Session>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .sessions
                    .iter()
                    .find(|session| session.token_hash() == token_hash)
                    .cloned())
            })
        }
        fn create_session<'a>(
            &'a self,
            session: &'a Session,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            let session = session.clone();
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                inner.sessions.push(session);
                Ok(())
            })
        }
        fn touch_session(
            &self,
            session_id: SessionId,
            at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                let session = inner
                    .sessions
                    .iter_mut()
                    .find(|session| session.id() == session_id)
                    .ok_or(MockWriteError)?;
                session.touch(at).map_err(|_| MockWriteError)
            })
        }
        fn revoke_session(
            &self,
            session_id: SessionId,
            at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                let session = inner
                    .sessions
                    .iter_mut()
                    .find(|session| session.id() == session_id)
                    .ok_or(MockWriteError)?;
                session.revoke(at).map_err(|_| MockWriteError)
            })
        }
        fn revoke_sessions_for_principal(
            &self,
            principal_id: PrincipalId,
            at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<u64, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                let mut revoked = 0;
                for session in &mut inner.sessions {
                    if session.principal_id() == principal_id
                        && session.revoked_at().is_none()
                        && session.revoke(at).is_ok()
                    {
                        revoked += 1;
                    }
                }
                Ok(revoked)
            })
        }
        fn list_sessions(
            &self,
            principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Vec<Session>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .sessions
                    .iter()
                    .filter(|session| session.principal_id() == principal_id)
                    .cloned()
                    .collect())
            })
        }
        fn find_principal(
            &self,
            principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Option<Principal>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .principals
                    .iter()
                    .find(|principal| principal.id() == principal_id)
                    .cloned())
            })
        }
        fn find_principal_by_name<'a>(
            &'a self,
            name: &'a PrincipalName,
        ) -> BoundaryFuture<'a, Result<Option<Principal>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            let name = name.clone();
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .principals
                    .iter()
                    .find(|principal| principal.name() == &name)
                    .cloned())
            })
        }
        fn list_principals(&self) -> BoundaryFuture<'_, Result<Vec<Principal>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner.principals.clone())
            })
        }
        fn create_principal<'a>(
            &'a self,
            principal: &'a Principal,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            let principal = principal.clone();
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                inner.principals.push(principal);
                Ok(())
            })
        }
        fn set_principal_state(
            &self,
            principal_id: PrincipalId,
            state: PrincipalState,
            at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                let principal = inner
                    .principals
                    .iter_mut()
                    .find(|principal| principal.id() == principal_id)
                    .ok_or(MockWriteError)?;
                principal.set_state(state, at);
                Ok(())
            })
        }
        fn assign_role<'a>(
            &'a self,
            assignment: &'a RoleAssignment,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            let assignment = assignment.clone();
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                inner
                    .roles
                    .insert(assignment.principal_id(), assignment.role());
                inner
                    .role_sites
                    .insert(assignment.principal_id(), assignment.site_id());
                Ok(())
            })
        }
        fn find_role_assignment(
            &self,
            principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner.roles.get(&principal_id).copied().map(|role| {
                    RoleAssignment::new(
                        principal_id,
                        role,
                        None,
                        OffsetDateTime::now_utc(),
                        inner.role_sites.get(&principal_id).copied().flatten(),
                    )
                }))
            })
        }
        fn list_role_assignments(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<RoleAssignment>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .roles
                    .iter()
                    .map(|(principal_id, role)| {
                        RoleAssignment::new(
                            *principal_id,
                            *role,
                            None,
                            OffsetDateTime::now_utc(),
                            None,
                        )
                    })
                    .collect())
            })
        }
        fn find_password_credential(
            &self,
            principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Option<PasswordCredential>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner.passwords.get(&principal_id).cloned())
            })
        }
        fn save_password_credential<'a>(
            &'a self,
            credential: &'a PasswordCredential,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            let credential = credential.clone();
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                inner
                    .passwords
                    .insert(credential.principal_id(), credential);
                Ok(())
            })
        }
        fn list_totp_authenticators(
            &self,
            _principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Vec<TotpAuthenticator>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
        fn record_totp_step(
            &self,
            _authenticator_id: rutilus_domain::TotpAuthenticatorId,
            _step: u64,
        ) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
            Box::pin(async move { Ok(false) })
        }
        fn find_bootstrap_code_by_hash<'a>(
            &'a self,
            code_hash: &'a [u8; 32],
        ) -> BoundaryFuture<'a, Result<Option<BootstrapCode>, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .bootstrap_code
                    .clone()
                    .filter(|code| code.code_hash() == code_hash))
            })
        }
        fn has_unconsumed_bootstrap_code(&self) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            Box::pin(async move {
                let inner = inner.lock().map_err(|_| MockWriteError)?;
                Ok(inner
                    .bootstrap_code
                    .as_ref()
                    .is_some_and(|code| code.used_at().is_none()))
            })
        }
        fn consume_bootstrap_code<'a>(
            &'a self,
            code_id: BootstrapCodeId,
            used_by: PrincipalId,
            password: &'a PasswordCredential,
            authenticator: Option<&'a TotpAuthenticator>,
            session: &'a Session,
            consumed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            let inner = Arc::clone(&self.auth_state.inner);
            let (password, session) = (password.clone(), session.clone());
            let authenticator = authenticator.cloned();
            Box::pin(async move {
                let mut inner = inner.lock().map_err(|_| MockWriteError)?;
                let Some(code) = inner.bootstrap_code.as_mut() else {
                    return Err(MockWriteError);
                };
                if code.id() != code_id || code.used_at().is_some() {
                    return Err(MockWriteError);
                }
                code.consume(used_by, consumed_at)
                    .map_err(|_| MockWriteError)?;
                inner.passwords.insert(used_by, password);
                if authenticator.is_some() {
                    inner.roles.insert(used_by, Role::Administrator);
                }
                inner.sessions.push(session);
                Ok(())
            })
        }
        fn verify_password(&self, hash: &Argon2IdHash, password: &SecretString) -> bool {
            hash == deterministic_credential(password.expose_secret(), OffsetDateTime::now_utc())
                .hash()
        }
        fn verify_totp(
            &self,
            _secret: &SecretBox<[u8; 20]>,
            _code: &str,
            _now: OffsetDateTime,
            _last_used_step: Option<u64>,
        ) -> Result<u64, TotpAuthenticatorError> {
            Err(TotpAuthenticatorError::InvalidCode)
        }
        fn hash_password(&self, password: &SecretString) -> Result<Argon2IdHash, Self::Error> {
            Argon2IdHash::from_parts(&[0x11; 16], &fold_hash(password.expose_secret()))
                .map_err(|_| MockWriteError)
        }
        fn hash_bootstrap_code(&self, code: &str) -> [u8; 32] {
            fold_hash(code)
        }
        fn issue_tokens(&self) -> Result<IssuedSessionTokens, Self::Error> {
            let mut inner = self.auth_state.inner.lock().map_err(|_| MockWriteError)?;
            inner.next_token += 1;
            let session_wire = format!("session-token-{}", inner.next_token);
            let csrf_wire = format!("csrf-token-{}", inner.next_token);
            Ok(IssuedSessionTokens::new(
                session_wire.clone(),
                fold_hash(&session_wire),
                csrf_wire.clone(),
                fold_hash(&csrf_wire),
            ))
        }
        fn token_hash(&self, wire: &str) -> [u8; 32] {
            fold_hash(wire)
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
            let working = self.working;
            Box::pin(async move {
                if !working {
                    return Err(MockWriteError);
                }
                Ok(EndpointDiscovery::new(vec![
                    EndpointCapabilityObservation::new(
                        EndpointCapability::Systems,
                        CapabilityState::Supported,
                    ),
                ]))
            })
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
            let working = self.working;
            Box::pin(async move {
                if !working {
                    return Err(MockWriteError);
                }
                Ok(vec![
                    ResourceObservation::new(
                        ResourceFeature::ServiceRoot,
                        ResourceODataId::parse("/redfish/v1/").map_err(|_| MockWriteError)?,
                        ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)
                            .map_err(|_| MockWriteError)?,
                    ),
                    ResourceObservation::new(
                        ResourceFeature::Systems,
                        ResourceODataId::parse("/redfish/v1/Systems/1")
                            .map_err(|_| MockWriteError)?,
                        ResourceSnapshotPayload::parse(r#"{"Name":"System"}"#)
                            .map_err(|_| MockWriteError)?,
                    ),
                ])
            })
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

        fn create_batch<'a>(
            &'a self,
            _batch: &'a BatchOperation,
            _children: &'a [Operation],
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async { Err(MockWriteError) })
        }

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: FailureKind,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            // The route tests never classify failures; the executor's refusal
            // path owns that write, so this stub is unreachable here.
            Box::pin(async { Err(MockWriteError) })
        }

        fn find_batch(
            &self,
            batch_id: rutilus_domain::BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
            let store = self.batch_store.clone();
            Box::pin(async move {
                if store.fail {
                    return Err(MockWriteError);
                }
                Ok(store
                    .batch_rows
                    .lock()
                    .map_err(|_| MockWriteError)?
                    .get(&batch_id)
                    .cloned())
            })
        }

        fn list_batches(&self) -> BoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
            let store = self.batch_store.clone();
            Box::pin(async move {
                if store.fail {
                    return Err(MockWriteError);
                }
                let mut batches = store
                    .batch_rows
                    .lock()
                    .map_err(|_| MockWriteError)?
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                batches.sort_by_key(|batch| (batch.created_at(), batch.id()));
                Ok(batches)
            })
        }

        fn list_batch_children(
            &self,
            batch_id: rutilus_domain::BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            let store = self.batch_store.clone();
            Box::pin(async move {
                if store.fail {
                    return Err(MockWriteError);
                }
                Ok(store
                    .batch_children
                    .lock()
                    .map_err(|_| MockWriteError)?
                    .get(&batch_id)
                    .cloned()
                    .unwrap_or_default())
            })
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

    /// A clock the tests can move forward, to prove time-driven behavior —
    /// the session expires on its absolute deadline regardless of activity.
    #[derive(Clone, Debug)]
    struct StepClock(Arc<Mutex<OffsetDateTime>>);

    impl StepClock {
        fn at(now: OffsetDateTime) -> Self {
            Self(Arc::new(Mutex::new(now)))
        }

        fn advance(&self, by: Duration) {
            let Ok(mut now) = self.0.lock() else {
                return;
            };
            *now += by;
        }
    }

    impl Clock for StepClock {
        fn now(&self) -> OffsetDateTime {
            self.0.lock().map_or(OffsetDateTime::UNIX_EPOCH, |now| *now)
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

    /// The in-memory center-view state behind the center console tests.
    ///
    /// The bundle answers the seeded views and records every mutation, so the
    /// route tests assert the wire shapes and the site-scope filtering
    /// against a deterministic center.
    /// One recorded center operation submission (§15.6).
    #[derive(Clone, Debug)]
    struct DispatchedSubmission {
        site: InstanceId,
        endpoint: EndpointId,
        target: String,
        command: RedfishCommand,
        actor: PrincipalId,
    }

    #[derive(Clone, Default)]
    struct CenterTestState {
        sites: Arc<Mutex<Vec<CenterSiteView>>>,
        endpoints: Arc<Mutex<Vec<CenterEndpointView>>>,
        operations: Arc<Mutex<Vec<CenterOperationView>>>,
        registered: Arc<Mutex<Vec<(String, String)>>>,
        revoked: Arc<Mutex<Vec<InstanceId>>>,
        dispatched: Arc<Mutex<Vec<DispatchedSubmission>>>,
        /// When armed, every center boundary fails (the 503 verdicts).
        fail: bool,
        /// When armed, the appended audit events are recorded here (audit
        /// follow-up F3 assertions).
        audit: Option<Arc<Mutex<Vec<AuditEvent>>>>,
    }

    impl CenterTestState {
        fn seed_site(&self, site: CenterSiteView) -> Result<(), MockWriteError> {
            self.sites.lock().map_err(|_| MockWriteError)?.push(site);
            Ok(())
        }

        fn seed_endpoint(&self, endpoint: CenterEndpointView) -> Result<(), MockWriteError> {
            self.endpoints
                .lock()
                .map_err(|_| MockWriteError)?
                .push(endpoint);
            Ok(())
        }

        fn seed_operation(&self, operation: CenterOperationView) -> Result<(), MockWriteError> {
            self.operations
                .lock()
                .map_err(|_| MockWriteError)?
                .push(operation);
            Ok(())
        }

        fn registered_owned(&self) -> Result<Vec<(String, String)>, MockWriteError> {
            Ok(self.registered.lock().map_err(|_| MockWriteError)?.clone())
        }

        fn revoked_owned(&self) -> Result<Vec<InstanceId>, MockWriteError> {
            Ok(self.revoked.lock().map_err(|_| MockWriteError)?.clone())
        }

        fn dispatched_owned(&self) -> Result<Vec<DispatchedSubmission>, MockWriteError> {
            Ok(self.dispatched.lock().map_err(|_| MockWriteError)?.clone())
        }
    }

    impl CenterServices for UnavailableWriteServices {
        type Error = MockWriteError;

        fn list_center_sites(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<CenterSiteView>, Self::Error>> {
            let state = self.center_state.clone();
            Box::pin(async move {
                if state.fail {
                    return Err(MockWriteError);
                }
                Ok(state.sites.lock().map_err(|_| MockWriteError)?.clone())
            })
        }

        fn list_center_endpoints(
            &self,
            site: Option<InstanceId>,
        ) -> BoundaryFuture<'_, Result<Vec<CenterEndpointView>, Self::Error>> {
            let state = self.center_state.clone();
            Box::pin(async move {
                if state.fail {
                    return Err(MockWriteError);
                }
                Ok(state
                    .endpoints
                    .lock()
                    .map_err(|_| MockWriteError)?
                    .iter()
                    .filter(|endpoint| site.is_none_or(|site| endpoint.site_id() == Some(site)))
                    .cloned()
                    .collect())
            })
        }

        fn list_center_operations(
            &self,
            site: Option<InstanceId>,
        ) -> BoundaryFuture<'_, Result<Vec<CenterOperationView>, Self::Error>> {
            let state = self.center_state.clone();
            Box::pin(async move {
                if state.fail {
                    return Err(MockWriteError);
                }
                Ok(state
                    .operations
                    .lock()
                    .map_err(|_| MockWriteError)?
                    .iter()
                    .filter(|operation| site.is_none_or(|site| operation.site_id() == Some(site)))
                    .cloned()
                    .collect())
            })
        }

        fn register_center_site(
            &self,
            display_name: &str,
            center_url: &str,
            now: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<RegisteredCenterSite, Self::Error>> {
            let state = self.center_state.clone();
            let display_name = display_name.to_owned();
            let center_url = center_url.to_owned();
            Box::pin(async move {
                if state.fail {
                    return Err(MockWriteError);
                }
                state
                    .registered
                    .lock()
                    .map_err(|_| MockWriteError)?
                    .push((display_name, center_url));
                Ok(RegisteredCenterSite::new(
                    InstanceId::generate(),
                    CenterBindingId::generate(),
                    "23456789ABCDEFGHJKLM".to_owned(),
                    now,
                ))
            })
        }

        fn revoke_center_binding(
            &self,
            site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            let state = self.center_state.clone();
            Box::pin(async move {
                if state.fail {
                    return Err(MockWriteError);
                }
                state.revoked.lock().map_err(|_| MockWriteError)?.push(site);
                Ok(())
            })
        }

        fn dispatch_center_operation(
            &self,
            site: InstanceId,
            endpoint: EndpointId,
            target: &ResourceODataId,
            command: &RedfishCommand,
            actor: PrincipalId,
            now: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<DispatchedCenterOperation, CenterOperationRefusal>> {
            let state = self.center_state.clone();
            let target = target.to_string();
            let command = command.clone();
            Box::pin(async move {
                if state.fail {
                    return Err(CenterOperationRefusal::Store);
                }
                state
                    .dispatched
                    .lock()
                    .map_err(|_| CenterOperationRefusal::Store)?
                    .push(DispatchedSubmission {
                        site,
                        endpoint,
                        target,
                        command,
                        actor,
                    });
                Ok(DispatchedCenterOperation::new(
                    OperationId::generate(),
                    now + Duration::minutes(15),
                ))
            })
        }
    }

    /// Builds the router over a services bundle armed with the center-view
    /// test state — the center console routes' test bench.
    fn test_center_router(center_state: CenterTestState) -> Router {
        router(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Center,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: None,
                refresh_working: false,
                auth_state: AuthTestState::default(),
                center_state,
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        )
    }

    /// Builds the guarded router over one center-view state and one
    /// authentication state, for the site-scope permission tests.
    fn test_center_router_with_auth(
        auth_state: AuthTestState,
        center_state: CenterTestState,
    ) -> Router {
        router_with_auth(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Center,
            AuthPolicy::Guarded,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: None,
                refresh_working: false,
                auth_state,
                center_state,
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        )
    }

    /// One seeded registered site view.
    fn center_site_view(
        site_id: InstanceId,
        binding: Option<CenterBindingState>,
    ) -> CenterSiteView {
        CenterSiteView::new(site_id, format!("Site {site_id}"), binding, false, 0, None)
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

    /// Builds the router under one §16.2 session policy over the auth test
    /// state.
    fn test_router_with_policy(auth_state: AuthTestState, policy: AuthPolicy) -> Router {
        test_router_with_clock(auth_state, policy, FixedClock)
    }

    /// Builds the router under one §16.2 session policy and one explicit
    /// clock, for the tests that move time.
    fn test_router_with_clock<Time>(
        auth_state: AuthTestState,
        policy: AuthPolicy,
        clock: Time,
    ) -> Router
    where
        Time: Clock + Clone + 'static,
    {
        router_with_auth(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            policy,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: None,
                refresh_working: false,
                auth_state,
                center_state: CenterTestState::default(),
            }),
            Arc::new(UnavailableGateway { working: false }),
            clock,
        )
    }

    fn seeded_auth_state() -> AuthTestState {
        let state = AuthTestState::default();
        state.seed_principal("admin", "correct horse battery staple", Role::Administrator);
        state
    }

    /// Signs in through the route and returns the session cookie and the
    /// CSRF token of the response.
    async fn sign_in(
        router: &Router,
        username: &str,
        password: &str,
    ) -> Result<(String, String), Box<dyn Error>> {
        let login_body = format!(r#"{{"username": "{username}", "password": "{password}"}}"#);
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(login_body.clone()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .ok_or("the sign-in response must set the session cookie")?
            .to_str()?
            .split(';')
            .next()
            .ok_or("the session cookie is malformed")?
            .to_owned();
        let body = json_body(response).await?;
        let csrf = body
            .get("csrf_token")
            .and_then(Value::as_str)
            .ok_or("the login response must carry the CSRF token")?
            .to_owned();
        Ok((cookie, csrf))
    }

    #[tokio::test]
    async fn guarded_router_requires_a_session_for_product_routes() -> Result<(), Box<dyn Error>> {
        let router = test_router_with_policy(AuthTestState::default(), AuthPolicy::Guarded);

        // The product surface is closed...
        let endpoints = router
            .clone()
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(endpoints.status(), StatusCode::UNAUTHORIZED);
        // ...while the public sign-in surface stays open.
        let health = router
            .clone()
            .oneshot(Request::get("/api/v1/health").body(Body::empty())?)
            .await?;
        assert_eq!(health.status(), StatusCode::OK);
        let about = router
            .clone()
            .oneshot(Request::get("/api/v1/about").body(Body::empty())?)
            .await?;
        assert_eq!(about.status(), StatusCode::OK);
        let me = router
            .clone()
            .oneshot(Request::get("/api/v1/auth/me").body(Body::empty())?)
            .await?;
        assert_eq!(me.status(), StatusCode::OK);
        let body = json_body(me).await?;
        assert_eq!(body["authenticated"], false);
        assert_eq!(body["bootstrap_pending"], false);
        Ok(())
    }

    #[tokio::test]
    async fn sign_in_opens_the_product_surface_and_sets_a_safe_cookie() -> Result<(), Box<dyn Error>>
    {
        let router = test_router_with_policy(seeded_auth_state(), AuthPolicy::Guarded);
        let (cookie, _csrf) = sign_in(&router, "admin", "correct horse battery staple").await?;

        assert!(cookie.starts_with("rutilus_session="), "{cookie}");

        // The session cookie opens the product surface.
        let endpoints = router
            .clone()
            .oneshot(
                Request::get("/api/v1/endpoints")
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(endpoints.status(), StatusCode::OK);

        // The sign-in response cookie carries the §16.2 flags.
        let login = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username": "admin", "password": "correct horse battery staple"}"#,
                    ))?,
            )
            .await?;
        let set_cookie = login
            .headers()
            .get(SET_COOKIE)
            .ok_or("the sign-in response must set the session cookie")?
            .to_str()?
            .to_owned();
        assert!(set_cookie.contains("HttpOnly"), "{set_cookie}");
        assert!(set_cookie.contains("SameSite=Strict"), "{set_cookie}");
        assert!(
            !set_cookie.contains("Secure"),
            "loopback HTTP must not set Secure"
        );

        // A wrong password is refused, and the attempt is rate limited by
        // username: the fifth refusal still answers, the sixth is refused
        // before any verification.
        for _ in 0..5 {
            let refused = router
                .clone()
                .oneshot(
                    Request::post("/api/v1/auth/login")
                        .header("content-type", "application/json")
                        .body(Body::from(
                            r#"{"username": "admin", "password": "wrong password"}"#,
                        ))?,
                )
                .await?;
            assert_eq!(refused.status(), StatusCode::UNAUTHORIZED);
        }
        let limited = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username": "admin", "password": "correct horse battery staple"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        Ok(())
    }

    #[tokio::test]
    async fn mutating_routes_require_the_csrf_token() -> Result<(), Box<dyn Error>> {
        let router = test_router_with_policy(seeded_auth_state(), AuthPolicy::Guarded);
        let (cookie, csrf) = sign_in(&router, "admin", "correct horse battery staple").await?;

        // A mutating request without the CSRF token is refused...
        let no_csrf = router
            .clone()
            .oneshot(
                Request::post("/api/v1/credentials")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .body(Body::from(
                        r#"{"name": "bmc", "username": "root", "password": "secret"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(no_csrf.status(), StatusCode::UNAUTHORIZED);

        // ...and with the CSRF token the request reaches the handler (the
        // credential boundaries are unavailable in the mock, so the route
        // answers 500 — proving the CSRF gate passed).
        let with_csrf = router
            .clone()
            .oneshot(
                Request::post("/api/v1/credentials")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(
                        r#"{"name": "bmc", "username": "root", "password": "secret"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(with_csrf.status(), StatusCode::INTERNAL_SERVER_ERROR);

        // A wrong CSRF token is refused in constant time.
        let wrong_csrf = router
            .clone()
            .oneshot(
                Request::post("/api/v1/credentials")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", "csrf-token-999")
                    .body(Body::from(
                        r#"{"name": "bmc", "username": "root", "password": "secret"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(wrong_csrf.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn role_masks_are_enforced_on_guarded_routes() -> Result<(), Box<dyn Error>> {
        let state = AuthTestState::default();
        state.seed_principal("admin", "admin secret phrase", Role::Administrator);
        state.seed_principal("viewer", "viewer secret phrase", Role::Viewer);
        let router = test_router_with_policy(state, AuthPolicy::Guarded);

        // A viewer reads the product surface but cannot reach the
        // Administrator surfaces or submit operations.
        let (cookie, csrf) = sign_in(&router, "viewer", "viewer secret phrase").await?;
        let endpoints = router
            .clone()
            .oneshot(
                Request::get("/api/v1/endpoints")
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(endpoints.status(), StatusCode::OK);
        let users = router
            .clone()
            .oneshot(
                Request::get("/api/v1/admin/users")
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(users.status(), StatusCode::FORBIDDEN);
        let submit = router
            .clone()
            .oneshot(
                Request::post("/api/v1/operations")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from(
                        r#"{"source": null, "targets": [], "command": {"kind": "system_reset", "reset_type": "graceful"}}"#,
                    ))?,
            )
            .await?;
        assert_eq!(submit.status(), StatusCode::FORBIDDEN);

        // The administrator reaches both surfaces.
        let (admin_cookie, _admin_csrf) = sign_in(&router, "admin", "admin secret phrase").await?;
        let users = router
            .clone()
            .oneshot(
                Request::get("/api/v1/admin/users")
                    .header("cookie", &admin_cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(users.status(), StatusCode::OK);
        let body = json_body(users).await?;
        assert_eq!(body["users"].as_array().map(Vec::len), Some(2));
        Ok(())
    }

    #[tokio::test]
    async fn bootstrap_claim_arms_the_pending_gate() -> Result<(), Box<dyn Error>> {
        let state = seeded_auth_state();
        state.seed_bootstrap_code("ABCD2345EFGH6789JKLM");
        let gate = AuthGate::open();
        let router = test_router_with_policy(state, AuthPolicy::PendingBootstrap(gate.clone()));

        // Before the claim the console is open...
        let endpoints = router
            .clone()
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(endpoints.status(), StatusCode::OK);
        assert!(!gate.is_guarded());

        // ...the claim binds the code, sets the password, opens a session,
        // and arms the gate in-process.
        let claim = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/bootstrap")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"code": "ABCD2345EFGH6789JKLM", "password": "first product password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(claim.status(), StatusCode::OK);
        assert!(gate.is_guarded(), "the claim must arm the gate");
        let cookie = claim
            .headers()
            .get(SET_COOKIE)
            .ok_or("the claim must set the session cookie")?
            .to_str()?
            .split(';')
            .next()
            .ok_or("the session cookie is malformed")?
            .to_owned();

        // The console is guarded from this request on: the claim's own
        // session works, a sessionless request is refused.
        let closed = router
            .clone()
            .oneshot(Request::get("/api/v1/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(closed.status(), StatusCode::UNAUTHORIZED);
        let open = router
            .clone()
            .oneshot(
                Request::get("/api/v1/endpoints")
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(open.status(), StatusCode::OK);

        // The claim's password signs in afterwards; the consumed code is
        // refused.
        let login = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username": "admin", "password": "first product password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(login.status(), StatusCode::OK);
        let again = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/bootstrap")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"code": "ABCD2345EFGH6789JKLM", "password": "second password"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(again.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    #[tokio::test]
    async fn logout_revokes_the_presenting_session() -> Result<(), Box<dyn Error>> {
        let router = test_router_with_policy(seeded_auth_state(), AuthPolicy::Guarded);
        let (cookie, csrf) = sign_in(&router, "admin", "correct horse battery staple").await?;

        let logout = router
            .clone()
            .oneshot(
                Request::post("/api/v1/auth/logout")
                    .header("content-type", "application/json")
                    .header("cookie", &cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::from("{}"))?,
            )
            .await?;
        assert_eq!(logout.status(), StatusCode::OK);
        let cleared = logout
            .headers()
            .get(SET_COOKIE)
            .ok_or("the logout response must clear the cookie")?
            .to_str()?;
        assert!(cleared.contains("Max-Age=0"), "{cleared}");

        // The revoked session token is refused afterwards.
        let closed = router
            .clone()
            .oneshot(
                Request::get("/api/v1/endpoints")
                    .header("cookie", &cookie)
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(closed.status(), StatusCode::UNAUTHORIZED);
        Ok(())
    }

    /// Fetches the product surface with one session cookie.
    async fn fetch_endpoints(router: &Router, cookie: &str) -> Result<StatusCode, Box<dyn Error>> {
        let response = router
            .clone()
            .oneshot(
                Request::get("/api/v1/endpoints")
                    .header("cookie", cookie)
                    .body(Body::empty())?,
            )
            .await?;
        Ok(response.status())
    }

    #[tokio::test]
    async fn an_active_session_is_rejected_eight_hours_after_sign_in() -> Result<(), Box<dyn Error>>
    {
        // The session lifetime is absolute: `expires_at` is fixed at
        // sign-in plus eight hours, and activity only advances
        // `last_used_at` — so a session that is used continuously is
        // still refused once the deadline passes.
        let started_at = OffsetDateTime::UNIX_EPOCH + Duration::days(1);
        let clock = StepClock::at(started_at);
        let state = seeded_auth_state();
        let router = test_router_with_clock(state.clone(), AuthPolicy::Guarded, clock.clone());
        let (cookie, _csrf) = sign_in(&router, "admin", "correct horse battery staple").await?;

        // Freshly signed in, the session serves the product surface.
        assert_eq!(fetch_endpoints(&router, &cookie).await?, StatusCode::OK);

        // Heavy use — a request every hour — keeps the session alive
        // inside its absolute lifetime, and each touch advances the
        // persisted last-use time.
        for _ in 0..7 {
            clock.advance(Duration::hours(1));
            assert_eq!(fetch_endpoints(&router, &cookie).await?, StatusCode::OK);
        }
        clock.advance(Duration::minutes(59));
        assert_eq!(fetch_endpoints(&router, &cookie).await?, StatusCode::OK);

        // The deadline does not move with the activity: one minute later
        // the same actively used session is refused.
        clock.advance(Duration::minutes(1));
        assert_eq!(
            fetch_endpoints(&router, &cookie).await?,
            StatusCode::UNAUTHORIZED
        );

        // The stored row confirms the semantics: the touch advanced
        // `last_used_at`, while `expires_at` stayed at sign-in plus eight
        // hours.
        let Ok(inner) = state.inner.lock() else {
            return Ok(());
        };
        let session = inner
            .sessions
            .last()
            .ok_or("the sign-in must have created a session")?;
        assert_eq!(session.expires_at(), started_at + Duration::hours(8));
        assert!(session.last_used_at() > started_at);
        Ok(())
    }

    #[tokio::test]
    async fn the_center_sites_route_projects_the_s15_5_site_view() -> Result<(), Box<dyn Error>> {
        let state = CenterTestState::default();
        let site_a = InstanceId::generate();
        let site_b = InstanceId::generate();
        state.seed_site(center_site_view(site_a, Some(CenterBindingState::Bound)))?;
        let last_refresh = OffsetDateTime::UNIX_EPOCH + Duration::SECOND;
        state.seed_site(CenterSiteView::new(
            site_b,
            "Site B".to_owned(),
            Some(CenterBindingState::Pending),
            true,
            3,
            Some(last_refresh),
        ))?;
        let router = test_center_router(state);

        let response = router
            .clone()
            .oneshot(Request::get("/api/v1/center/sites").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store, must-revalidate"))
        );
        let body = json_body(response).await?;
        let sites = body["sites"].as_array().ok_or("sites must be an array")?;
        assert_eq!(sites.len(), 2);
        assert_eq!(sites[0]["site_id"], site_a.to_string());
        assert_eq!(sites[0]["display_name"], format!("Site {site_a}"));
        assert_eq!(sites[0]["binding"], "bound");
        assert_eq!(sites[0]["online"], false);
        assert_eq!(sites[1]["site_id"], site_b.to_string());
        assert_eq!(sites[1]["binding"], "pending");
        assert_eq!(sites[1]["online"], true);
        assert_eq!(sites[1]["endpoint_count"], 3);
        assert_eq!(sites[1]["last_refresh_at"], "1970-01-01T00:00:01Z");

        // A failing center boundary answers 503.
        let response = test_center_router(CenterTestState {
            fail: true,
            ..CenterTestState::default()
        })
        .oneshot(Request::get("/api/v1/center/sites").body(Body::empty())?)
        .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        Ok(())
    }

    #[tokio::test]
    async fn the_binding_routes_generate_the_one_time_code_and_revoke() -> Result<(), Box<dyn Error>>
    {
        let state = CenterTestState::default();
        let router = test_center_router(state.clone());

        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/bindings")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"display_name": "Site One", "center_url": "center.example:8443"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        assert_eq!(body["code"], "23456789ABCDEFGHJKLM");
        assert!(body["site_id"].is_string());
        assert!(body["binding_id"].is_string());
        assert_eq!(body["expires_at"], "1970-01-01T00:00:00Z");
        assert_eq!(
            state.registered_owned()?,
            vec![("Site One".to_owned(), "center.example:8443".to_owned())]
        );

        // An invalid display name is refused before the boundary.
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/bindings")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"display_name": "   ", "center_url": "center.example:8443"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.registered_owned()?.len(), 1);

        // The revoke route records the site and answers 204.
        let site = InstanceId::generate();
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/bindings/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(format!(
                        r#"{{"site_id": "{}"}}"#,
                        site.into_uuid()
                    )))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(state.revoked_owned()?, vec![site]);
        Ok(())
    }

    #[tokio::test]
    async fn the_center_console_never_registers_direct_bmc_routes() -> Result<(), Box<dyn Error>> {
        // Audit follow-up F2: the Center posture serves the aggregation
        // surface only — every route that would enroll, refresh, or manage
        // a BMC directly is absent, so an administrator on the center
        // console cannot reach a single direct-BMC operation (§15.1, 0.7.0
        // acceptance "Center 不连接 BMC").
        let router = test_center_router(CenterTestState::default());
        for path in [
            "/api/v1/endpoints",
            "/api/v1/endpoints/6f6f9e40-2c5a-4b4e-9f6f-7f7f7f7f7f7f/resources",
            "/api/v1/credentials",
            "/api/v1/operations",
            "/api/v1/batches",
            "/api/v1/artifacts",
            "/api/v1/groups",
            "/api/v1/tags",
            "/api/v1/events",
            "/api/v1/telemetry",
        ] {
            let response = router
                .clone()
                .oneshot(Request::get(path).body(Body::empty())?)
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "the center console must not register {path}"
            );
        }
        // The write surface is absent too: enrollment, trust, refresh,
        // credential creation, and operation submission do not exist on the
        // center console.
        for (path, body) in [
            ("/api/v1/endpoints", "{}"),
            ("/api/v1/endpoints/trust", "{}"),
            ("/api/v1/endpoints/refresh", "{}"),
            ("/api/v1/credentials", "{}"),
            ("/api/v1/operations", "{}"),
            ("/api/v1/artifacts", "{}"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .body(Body::from(body))?,
                )
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "the center console must not register POST {path}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_edge_console_never_registers_the_center_management_routes()
    -> Result<(), Box<dyn Error>> {
        // Audit follow-up F2: the Edge postures serve the local-management
        // surface only — the center binding, dispatch, and site-view routes
        // are absent, so a site console cannot manage center bindings or
        // dispatch center operations, and the S6/S7 dispatcher is never
        // silently dropped on the edge.
        let router = test_router();
        for path in [
            "/api/v1/center/sites",
            "/api/v1/center/endpoints",
            "/api/v1/center/operations",
            "/api/v1/center/bindings",
            "/api/v1/center/bindings/revoke",
        ] {
            let response = router
                .clone()
                .oneshot(Request::get(path).body(Body::empty())?)
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "the edge console must not register {path}"
            );
        }
        for path in [
            "/api/v1/center/bindings",
            "/api/v1/center/bindings/revoke",
            "/api/v1/center/operations",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::post(path)
                        .header("content-type", "application/json")
                        .body(Body::from("{}"))?,
                )
                .await?;
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "the edge console must not register POST {path}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_center_operation_view_hides_rows_without_a_site_association()
    -> Result<(), Box<dyn Error>> {
        // Audit follow-up F1: an operation without a site association is a
        // broken row and is never shown — a scoped role must not see a row
        // that has no site ownership to check it against, mirroring the
        // endpoint projection.
        let state = CenterTestState::default();
        let site = InstanceId::generate();
        let endpoint = EndpointId::generate();
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));
        let created = OffsetDateTime::UNIX_EPOCH;
        state.seed_operation(CenterOperationView::new(
            OperationId::generate(),
            Some(site),
            endpoint,
            command.clone(),
            Some("/redfish/v1/Systems/1".to_owned()),
            OperationState::Queued,
            Some("admin".to_owned()),
            Some(created + Duration::minutes(15)),
            created,
        ))?;
        state.seed_operation(CenterOperationView::new(
            OperationId::generate(),
            None,
            endpoint,
            command,
            Some("/redfish/v1/Systems/1".to_owned()),
            OperationState::Queued,
            Some("admin".to_owned()),
            Some(created + Duration::minutes(15)),
            created,
        ))?;
        let router = test_center_router(state);

        let response = router
            .oneshot(Request::get("/api/v1/center/operations").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let operations = body["operations"]
            .as_array()
            .ok_or("operations must be an array")?;
        assert_eq!(operations.len(), 1, "the site-less row must be hidden");
        assert!(
            operations[0]["site_id"].is_string(),
            "the visible row must carry its site association"
        );
        Ok(())
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn the_center_write_routes_record_audit_events() -> Result<(), Box<dyn Error>> {
        // Audit follow-up F3: every center write — register, revoke, and
        // dispatch — appends the §16.3 start/terminal pair naming the
        // acting principal, the Center origin, the permission, and the
        // result. The dispatch requires a signed-in principal, so the test
        // runs guarded with an Administrator session.
        let auth = AuthTestState::default();
        auth.seed_principal("admin", "admin-password", Role::Administrator);
        let mut state = CenterTestState::default();
        let audit = Arc::new(Mutex::new(Vec::new()));
        state.audit = Some(Arc::clone(&audit));
        let center_router = router_with_auth(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Center,
            AuthPolicy::Guarded,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: None,
                refresh_working: true,
                auth_state: auth.clone(),
                center_state: state.clone(),
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        );
        let (cookie, csrf) =
            sign_in_center(&center_router, &auth, "admin", "admin-password").await?;
        // The sign-in itself appends login audit events; the recorder
        // starts clean for the write-route assertions.
        audit.lock().map_err(|_| MockWriteError)?.clear();

        // Register one site: started + succeeded with the binding action.
        // Each audit assertion runs in a scoped block, so the recorder
        // guard is dropped before the next request (the handler appends to
        // the same mutex).
        let response = center_router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/bindings")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
                    .header("cookie", &cookie)
                    .body(Body::from(
                        r#"{"display_name": "Site One", "center_url": "center.example:8443"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        {
            let mut events = audit.lock().map_err(|_| MockWriteError)?;
            assert_eq!(events.len(), 2, "register must append start + terminal");
            assert_eq!(events[0].outcome().kind().as_str(), "started");
            assert_eq!(events[1].outcome().kind().as_str(), "succeeded");
            assert_eq!(
                events[0].context().action().as_str(),
                "register-site-binding"
            );
            assert_eq!(events[0].context().origin().as_str(), "center");
            assert_eq!(
                events[0].context().permission().as_str(),
                "manage-center-bindings"
            );
            events.clear();
        }

        // Revoke one site: started + succeeded with the revoke action.
        let site = InstanceId::generate();
        let response = center_router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/bindings/revoke")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
                    .header("cookie", &cookie)
                    .body(Body::from(format!(
                        r#"{{"site_id": "{}"}}"#,
                        site.into_uuid()
                    )))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        {
            let mut events = audit.lock().map_err(|_| MockWriteError)?;
            assert_eq!(events.len(), 2, "revoke must append start + terminal");
            assert_eq!(events[0].context().action().as_str(), "revoke-site-binding");
            events.clear();
        }

        // Dispatch one operation: started + succeeded with the dispatch
        // action and the endpoint target.
        let endpoint = EndpointId::generate();
        let response = center_router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/operations")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
                    .header("cookie", &cookie)
                    .body(Body::from(format!(
                        r#"{{"site_id": "{}", "endpoint_id": "{}", "target": "/redfish/v1/Systems/1", "command": {{"System": {{"Reset": "PowerCycle"}}}}}}"#,
                        site.into_uuid(),
                        endpoint.into_uuid()
                    )))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        {
            let mut events = audit.lock().map_err(|_| MockWriteError)?;
            assert_eq!(events.len(), 2, "dispatch must append start + terminal");
            assert_eq!(
                events[0].context().action().as_str(),
                "dispatch-center-operation"
            );
            assert_eq!(
                events[0].context().permission().as_str(),
                "dispatch-center-operations"
            );
            assert_eq!(
                events[0].context().target().kind(),
                rutilus_domain::AuditTarget::Endpoint(endpoint).kind()
            );
            events.clear();
        }

        // A refused dispatch records the refusal as the terminal event.
        let failing = CenterTestState {
            fail: true,
            ..state.clone()
        };
        let failing_router = router_with_auth(
            WebProductInfo::new("0.1.0-test", "0.13.0-test"),
            AuditActor::LocalOperator,
            DeploymentPosture::Center,
            AuthPolicy::Guarded,
            Arc::new(UnavailableWriteServices {
                inventory: Ok(Vec::new()),
                batch_store: BatchTestStore::failing(),
                managed_endpoints: None,
                refresh_working: true,
                auth_state: auth.clone(),
                center_state: failing,
            }),
            Arc::new(UnavailableGateway { working: false }),
            FixedClock,
        );
        let (cookie, csrf) =
            sign_in_center(&failing_router, &auth, "admin", "admin-password").await?;
        audit.lock().map_err(|_| MockWriteError)?.clear();
        let response = failing_router
            .oneshot(
                Request::post("/api/v1/center/operations")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
                    .header("cookie", &cookie)
                    .body(Body::from(format!(
                        r#"{{"site_id": "{}", "endpoint_id": "{}", "target": "/redfish/v1/Systems/1", "command": {{"System": {{"Reset": "PowerCycle"}}}}}}"#,
                        site.into_uuid(),
                        endpoint.into_uuid()
                    )))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        {
            let events = audit.lock().map_err(|_| MockWriteError)?;
            assert_eq!(events.len(), 2, "a refused dispatch must still audit");
            assert_eq!(events[1].outcome().kind().as_str(), "failed");
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_center_endpoint_and_operation_views_project_the_aggregated_summary()
    -> Result<(), Box<dyn Error>> {
        let state = CenterTestState::default();
        let site = InstanceId::generate();
        let endpoint = EndpointId::generate();
        state.seed_endpoint(CenterEndpointView::new(
            Some(site),
            endpoint,
            "Rack A BMC".to_owned(),
            "https://192.0.2.10/".to_owned(),
            "ok".to_owned(),
            7,
        ))?;
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));
        let created = OffsetDateTime::UNIX_EPOCH;
        state.seed_operation(CenterOperationView::new(
            OperationId::generate(),
            Some(site),
            endpoint,
            command,
            Some("/redfish/v1/Systems/1".to_owned()),
            OperationState::Queued,
            Some("admin".to_owned()),
            Some(created + Duration::minutes(15)),
            created,
        ))?;
        let router = test_center_router(state);

        let response = router
            .clone()
            .oneshot(Request::get("/api/v1/center/endpoints").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let endpoints = body["endpoints"]
            .as_array()
            .ok_or("endpoints must be an array")?;
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0]["site_id"], site.to_string());
        assert_eq!(endpoints[0]["endpoint_id"], endpoint.to_string());
        assert_eq!(endpoints[0]["display_name"], "Rack A BMC");
        assert_eq!(endpoints[0]["address"], "https://192.0.2.10/");
        assert_eq!(endpoints[0]["health"], "ok");
        assert_eq!(endpoints[0]["refresh_generation"], 7);

        // The site_id query narrows the projection.
        let response = router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/center/endpoints?site_id={}",
                    InstanceId::generate().into_uuid()
                ))
                .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            json_body(response).await?["endpoints"]
                .as_array()
                .map(Vec::len),
            Some(0)
        );

        let response = router
            .clone()
            .oneshot(Request::get("/api/v1/center/operations").body(Body::empty())?)
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let operations = body["operations"]
            .as_array()
            .ok_or("operations must be an array")?;
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0]["site_id"], site.to_string());
        assert_eq!(operations[0]["endpoint_id"], endpoint.to_string());
        assert_eq!(operations[0]["target"], "/redfish/v1/Systems/1");
        assert_eq!(operations[0]["state"], "queued");
        assert_eq!(operations[0]["actor"], "admin");
        assert_eq!(operations[0]["ttl_expires_at"], "1970-01-01T00:15:00Z");
        assert_eq!(operations[0]["created_at"], "1970-01-01T00:00:00Z");
        assert_eq!(
            operations[0]["command"]["System"]["Reset"],
            "GracefulShutdown"
        );

        // An invalid site filter is a bad request.
        let response = router
            .oneshot(
                Request::get("/api/v1/center/operations?site_id=not-a-uuid").body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn the_operation_submission_route_carries_exactly_the_s15_6_set()
    -> Result<(), Box<dyn Error>> {
        // A signed-in Administrator backs the submission: the dispatch
        // judgment requires a principal (§16.1), and the open routers have
        // none.
        let auth = AuthTestState::default();
        auth.seed_principal("admin", "admin-password", Role::Administrator);
        let state = CenterTestState::default();
        let site = InstanceId::generate();
        let endpoint = EndpointId::generate();
        let router = test_center_router_with_auth(auth.clone(), state.clone());
        let (cookie, csrf) = sign_in_center(&router, &auth, "admin", "admin-password").await?;
        let submit = |body: String| {
            let router = router.clone();
            let cookie = cookie.clone();
            let csrf = csrf.clone();
            async move {
                let request = Request::post("/api/v1/center/operations")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &csrf)
                    .header("cookie", &cookie)
                    .body(Body::from(body))
                    .map_err(Box::<dyn Error>::from)?;
                let response = router
                    .oneshot(request)
                    .await
                    .map_err(Box::<dyn Error>::from)?;
                Ok::<Response, Box<dyn Error>>(response)
            }
        };

        let body = serde_json::to_string(&json!({
            "site_id": site.into_uuid(),
            "endpoint_id": endpoint.into_uuid(),
            "target": "/redfish/v1/Systems/1",
            "command": { "System": { "Reset": "GracefulShutdown" } }
        }))?;
        let response = submit(body.clone()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let acknowledgement = json_body(response).await?;
        assert!(acknowledgement["operation_id"].is_string());
        assert_eq!(acknowledgement["ttl_expires_at"], "1970-01-01T00:15:00Z");
        let dispatched = state.dispatched_owned()?;
        assert_eq!(dispatched.len(), 1);
        let record = &dispatched[0];
        assert_eq!(record.site, site);
        assert_eq!(record.endpoint, endpoint);
        assert_eq!(record.target, "/redfish/v1/Systems/1");
        assert!(matches!(
            &record.command,
            RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown))
        ));
        assert_eq!(record.actor.to_string().len(), 36);

        // A smuggled HTTP body is refused by the strict wire contract.
        let smuggled = serde_json::to_string(&json!({
            "site_id": site.into_uuid(),
            "endpoint_id": endpoint.into_uuid(),
            "target": "/redfish/v1/Systems/1",
            "command": { "System": { "Reset": "GracefulShutdown" } },
            "url": "https://bmc.example/redfish/v1/Systems/1",
            "method": "POST",
            "headers": {},
            "body": {}
        }))?;
        let response = submit(smuggled).await?;
        assert_eq!(
            response.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "a submission that smuggles an HTTP body is refused by the strict wire contract"
        );

        // An invalid target is refused before the boundary.
        let invalid_target = serde_json::to_string(&json!({
            "site_id": site.into_uuid(),
            "endpoint_id": endpoint.into_uuid(),
            "target": "not an odata id with control\x01chars",
            "command": { "System": { "Reset": "GracefulShutdown" } }
        }))?;
        let response = submit(invalid_target).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    /// Signs in through the route and returns the session cookie and the
    /// CSRF token of the response (the guarded center routers).
    async fn sign_in_center(
        router: &Router,
        _state: &AuthTestState,
        username: &str,
        password: &str,
    ) -> Result<(String, String), Box<dyn Error>> {
        sign_in(router, username, password).await
    }

    #[tokio::test]
    async fn the_center_views_apply_the_d3_site_scope_of_the_role_assignment()
    -> Result<(), Box<dyn Error>> {
        let auth = AuthTestState::default();
        auth.seed_principal("admin", "admin-password", Role::Administrator);
        let site_a = InstanceId::generate();
        let site_b = InstanceId::generate();
        auth.seed_scoped_principal("operator", "operator-password", Role::Operator, site_a);
        let state = CenterTestState::default();
        state.seed_site(center_site_view(site_a, Some(CenterBindingState::Bound)))?;
        state.seed_site(center_site_view(site_b, Some(CenterBindingState::Bound)))?;
        let router = test_center_router_with_auth(auth.clone(), state);

        // The global Administrator sees every site.
        let (admin_cookie, _) = sign_in_center(&router, &auth, "admin", "admin-password").await?;
        let response = fetch_center_sites(&router, &admin_cookie).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        assert_eq!(
            body["sites"].as_array().map(Vec::len),
            Some(2),
            "the Administrator is global"
        );

        // The site-scoped Operator sees exactly the assigned site.
        let (operator_cookie, _) =
            sign_in_center(&router, &auth, "operator", "operator-password").await?;
        let response = fetch_center_sites(&router, &operator_cookie).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = json_body(response).await?;
        let sites = body["sites"].as_array().ok_or("sites must be an array")?;
        assert_eq!(
            sites.len(),
            1,
            "a scoped role sees exactly its assigned site"
        );
        assert_eq!(sites[0]["site_id"], site_a.to_string());

        // The scoped Operator cannot request another site's view explicitly.
        let response = fetch_center_sites_filtered(&router, &operator_cookie, site_b).await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    #[tokio::test]
    async fn the_center_mutation_routes_enforce_the_role_and_the_site_scope()
    -> Result<(), Box<dyn Error>> {
        let auth = AuthTestState::default();
        auth.seed_principal("admin", "admin-password", Role::Administrator);
        let site_a = InstanceId::generate();
        let site_b = InstanceId::generate();
        auth.seed_scoped_principal("operator", "operator-password", Role::Operator, site_a);
        auth.seed_scoped_principal("viewer", "viewer-password", Role::Viewer, site_a);
        let state = CenterTestState::default();
        let router = test_center_router_with_auth(auth.clone(), state);

        // The binding surface is Administrator only.
        let (operator_cookie, operator_csrf) =
            sign_in_center(&router, &auth, "operator", "operator-password").await?;
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/bindings")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &operator_csrf)
                    .header("cookie", &operator_cookie)
                    .body(Body::from(
                        r#"{"display_name": "Site One", "center_url": "center.example:8443"}"#,
                    ))?,
            )
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "the binding surface is Administrator only"
        );

        // An Operator may submit to the assigned site...
        let body = serde_json::to_string(&json!({
            "site_id": site_a.into_uuid(),
            "endpoint_id": EndpointId::generate().into_uuid(),
            "target": "/redfish/v1/Systems/1",
            "command": { "System": { "Reset": "GracefulShutdown" } }
        }))?;
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/operations")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &operator_csrf)
                    .header("cookie", &operator_cookie)
                    .body(Body::from(body.clone()))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);

        // ...but not to another site (D3).
        let out_of_scope = serde_json::to_string(&json!({
            "site_id": site_b.into_uuid(),
            "endpoint_id": EndpointId::generate().into_uuid(),
            "target": "/redfish/v1/Systems/1",
            "command": { "System": { "Reset": "GracefulShutdown" } }
        }))?;
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/operations")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &operator_csrf)
                    .header("cookie", &operator_cookie)
                    .body(Body::from(out_of_scope))?,
            )
            .await?;
        assert_eq!(
            response.status(),
            StatusCode::FORBIDDEN,
            "a scoped Operator cannot dispatch outside the assigned site"
        );

        // The Viewer never dispatches, even inside its scope.
        let (viewer_cookie, viewer_csrf) =
            sign_in_center(&router, &auth, "viewer", "viewer-password").await?;
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/center/operations")
                    .header("content-type", "application/json")
                    .header("x-csrf-token", &viewer_csrf)
                    .header("cookie", &viewer_cookie)
                    .body(Body::from(body))?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        Ok(())
    }

    /// Fetches the center site list under one session cookie.
    async fn fetch_center_sites(router: &Router, cookie: &str) -> Result<Response, Box<dyn Error>> {
        let response = router
            .clone()
            .oneshot(
                Request::get("/api/v1/center/sites")
                    .header("cookie", cookie)
                    .body(Body::empty())?,
            )
            .await?;
        Ok(response)
    }

    /// Fetches the center site list narrowed to one site under one session
    /// cookie — the endpoint/operation site-filter read uses the same
    /// handler judgment, so this one path pins the verdict.
    async fn fetch_center_sites_filtered(
        router: &Router,
        cookie: &str,
        site: InstanceId,
    ) -> Result<Response, Box<dyn Error>> {
        let response = router
            .clone()
            .oneshot(
                Request::get(format!(
                    "/api/v1/center/endpoints?site_id={}",
                    site.into_uuid()
                ))
                .header("cookie", cookie)
                .body(Body::empty())?,
            )
            .await?;
        Ok(response)
    }
}
