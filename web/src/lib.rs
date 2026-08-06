#![forbid(unsafe_code)]

use std::{error::Error, num::NonZeroU64, path::Path, sync::Arc};

use axum::{
    Json, Router,
    body::Body,
    extract::{Path as AxumPath, State},
    http::{
        HeaderValue, StatusCode, Uri,
        header::{CACHE_CONTROL, CONTENT_TYPE, HeaderName},
    },
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rust_embed::RustEmbed;
use rutilus_api::{
    AboutResponse, AuditEventResponse, AuditOutcomeResponse, AuditQueryResponse,
    AuditTargetResponse, BeginEndpointTrustRequest, CapabilityClassificationResponse,
    CapabilityEntryResponse, CapabilityStateResponse, ConfirmEndpointTrustRequest,
    CoreResourceCommonResponse, CoreResourceCountsResponse, CoreResourceDetailsResponse,
    CoreResourceResponse, CoreResourceSourceResponse, CreateCredentialRequest,
    CredentialInventoryResponse, CredentialSummaryResponse, EndpointCapabilityInventoryResponse,
    EndpointCsvImportRequest, EndpointCsvImportResponse, EndpointCsvImportRowResponse,
    EndpointCsvImportRowStatusResponse, EndpointEnrollmentResponse, EndpointIdentityResponse,
    EndpointInventoryResponse, EndpointResourceInventoryResponse, EndpointResourceSnapshotResponse,
    EndpointSnapshotSummaryResponse, EndpointSummaryResponse, EndpointTrustChallengeResponse,
    EndpointTrustChallengeStateResponse, EndpointTrustExpectationRequest, EnrollEndpointRequest,
    ErrorResponse, HealthResponse, ResourceStatusResponse, TlsTrustModeResponse,
    TrustRejectedResponse, TrustedEndpointResponse, UiLocationResponse,
};
use rutilus_application::{
    AuditEventWriter, AuditedOnboardEndpointError, BoundaryFuture, CapabilityLedgerEntry,
    CapabilityQueryRepository, CapabilitySnapshotRepository, Clock, CoreResourceDetails,
    CoreResourceReader, CoreResourceSummary, CredentialCreation, CredentialCreationError,
    CredentialCreationRepository, CredentialInventoryQuery, CredentialInventoryQueryError,
    CredentialInventoryRepository, CredentialResolver, CredentialSecretProtector,
    DiscoveredEndpointRepository, EndpointCapabilityQuery, EndpointCapabilityQueryError,
    EndpointCsvImportExecutor, EndpointCsvImportReport, EndpointCsvRowOutcome,
    EndpointCsvRowResult, EndpointEnrollment, EndpointEnrollmentError, EndpointInventoryItem,
    EndpointInventoryQuery, EndpointInventoryQueryError, EndpointInventoryRepository,
    EndpointRefreshRepository, EndpointResourceInventory, EndpointResourceInventoryQuery,
    EndpointResourceInventoryQueryError, EndpointTrustChallenge, EndpointTrustEstablishment,
    EndpointTrustExpectation, EndpointTrustExpectationError, EnrolledEndpoint,
    NewCredentialRequest, OnboardEndpointError, OnboardEndpointRequest, RedfishDiscovery,
    ResourceStatusSummary, TlsIdentityProbe, TrustedEndpoint, parse_endpoint_csv,
};
use rutilus_domain::{
    AuditActor, AuditEvent, CapabilityClassification, CapabilityState,
    CertificateFingerprintParseError, Credential, CredentialId, CredentialName, CredentialUsername,
    DeploymentPosture, Endpoint, EndpointAddress, EndpointDisplayName, EndpointId, ResourceFeature,
    ResourceSnapshot, TlsTrust, UiLocation,
};
use tower_http::set_header::SetResponseHeaderLayer;

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
            // The 0.2 resource families (Processors, Memory, and later
            // Storage, Network, Accounts) intentionally stay out of the
            // three-field enrollment counts; the typed resource-inventory
            // route carries their full snapshots instead.
            ResourceFeature::ServiceRoot
            | ResourceFeature::Processors
            | ResourceFeature::Memory => {}
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
        ProtectedCredentialCreation, ResolvedCredential, ResourceObservation, StoredCapability,
        TlsIdentityObservation,
    };
    use rutilus_domain::{
        CredentialId, CredentialUsername, CredentialVersionId, Endpoint, EndpointAddress,
        EndpointCapabilityObservation, EndpointDisplayName, EndpointId, RefreshGeneration,
        ResourceEtag, ResourceId, ResourceODataId, ResourceODataType, ResourceSnapshot,
        ResourceSnapshotPayload, TlsCertificate, TlsTrust,
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

    #[derive(Clone, Copy)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            OffsetDateTime::UNIX_EPOCH
        }
    }
}
