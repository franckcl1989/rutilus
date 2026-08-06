#![forbid(unsafe_code)]

//! End-to-end Axum tests for the 0.4 §14.4 telemetry paths:
//! `GET /api/v1/telemetry` and `GET /api/v1/telemetry/{series_id}/samples`.
//!
//! Every application boundary is served by an in-memory fake, with a real
//! in-memory telemetry store, so the Web Router is exercised without
//! persistence or network access. The current-value aggregate of the series
//! listing is computed the same way the handler computes it — the newest
//! retained sample through the bounded newest-first listing with limit one —
//! so the fake's `list_samples` must honor that contract.

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
    EndpointCapabilityObservation, EndpointId, Event, Operation, OperationId, OperationState,
    ResourceSnapshot, SeriesKey, TelemetrySample, TelemetrySeries, TelemetrySeriesId, TlsTrust,
};
use rutilus_web::{AuditEventQuery, WebProductInfo, router};
use secrecy::SecretString;
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use tower::ServiceExt as _;

/// One stored series with its retained samples, in append order.
#[derive(Default)]
struct MockState {
    series: Vec<(TelemetrySeries, Vec<TelemetrySample>)>,
    fail_series_listing: bool,
    fail_sample_listing: bool,
}

/// Implements every application boundary behind the injected services bundle,
/// with a functioning in-memory telemetry store.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>) -> Self {
        Self { state }
    }
}

/// Implements the Redfish boundaries without opening a socket; the telemetry
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
        Box::pin(async { Err(MockError::Persistence) })
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

    /// Lists every series in seeding order; the handler's per-series
    /// current-value query then asks for the newest sample.
    fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|_| MockError::Lock)?;
            if state.fail_series_listing {
                return Err(MockError::Persistence);
            }
            Ok(state
                .series
                .iter()
                .map(|(series, _samples)| series.clone())
                .collect())
        })
    }

    /// Lists the newest samples first: the fake stores in append order, so
    /// the reversed tail is the console's newest-first view, exactly like
    /// the real store's `observed_at`-descending order.
    fn list_samples(
        &self,
        series_id: TelemetrySeriesId,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
        Box::pin(async move {
            let state = self.state.lock().map_err(|_| MockError::Lock)?;
            if state.fail_sample_listing {
                return Err(MockError::Persistence);
            }
            let take = usize::try_from(limit.get()).map_err(|_| MockError::Persistence)?;
            let samples = state
                .series
                .iter()
                .find(|(series, _)| series.id() == series_id)
                .map(|(_series, samples)| samples.iter().rev().take(take).copied().collect())
                .unwrap_or_default();
            Ok(samples)
        })
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

/// Seeds one series with the given readings and returns its stable identity.
///
/// The readings are stamped with the product clock at one-second intervals
/// starting at the given base, so the newest-first order is deterministic.
/// The series' `sample_count` mirrors the readings, exactly like the real
/// store maintains it.
fn seeded_series(
    state: &Arc<Mutex<MockState>>,
    endpoint_id: EndpointId,
    series_key: &str,
    base: OffsetDateTime,
    readings: &[f64],
) -> Result<TelemetrySeriesId, Box<dyn Error>> {
    let series = TelemetrySeries::from_parts(
        TelemetrySeriesId::generate(),
        endpoint_id,
        SeriesKey::parse(series_key)?,
        u64::try_from(readings.len()).map_err(|_| std::io::Error::other("too many readings"))?,
    );
    let mut samples = Vec::new();
    for (index, value) in readings.iter().enumerate() {
        // The fixture runs at most a handful of readings, so the index fits
        // the `u32` factor `Duration` multiplies by; the `try_from` makes
        // the guarantee explicit instead of casting silently.
        let step = u32::try_from(index).map_err(|_| std::io::Error::other("too many readings"))?;
        let observed_at = base + Duration::SECOND * step;
        samples.push(
            TelemetrySample::new(series.id(), observed_at, *value)?.with_bmc_timestamp(observed_at),
        );
    }
    let series_id = series.id();
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .series
        .push((series, samples));
    Ok(series_id)
}

#[tokio::test]
async fn telemetry_route_lists_series_with_current_value_aggregates() -> Result<(), Box<dyn Error>>
{
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = EndpointId::generate();
    let base = OffsetDateTime::UNIX_EPOCH;
    let power_id = seeded_series(&state, endpoint, "PowerMetrics", base, &[100.0, 94.0])?;
    // A series whose upsert preceded its first successful append reports no
    // current value; the seeded id is regenerated so the assertion only pins
    // the response's own id shape for the empty series.
    let empty_id = seeded_series(&state, endpoint, "ThermalMetrics", base, &[])?;
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/telemetry").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(
        body,
        json!({
            "series": [
                {
                    "series_id": power_id.to_string(),
                    "endpoint_id": endpoint.to_string(),
                    "series_key": "PowerMetrics",
                    "sample_count": 2,
                    "latest_value": 94.0,
                    "latest_observed_at": "1970-01-01T00:00:01Z"
                },
                {
                    "series_id": empty_id.to_string(),
                    "endpoint_id": endpoint.to_string(),
                    "series_key": "ThermalMetrics",
                    "sample_count": 0,
                    "latest_value": null,
                    "latest_observed_at": null
                }
            ]
        })
    );
    Ok(())
}

#[tokio::test]
async fn telemetry_route_returns_an_empty_series_list_before_any_sampling()
-> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/telemetry").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body, json!({ "series": [] }));
    Ok(())
}

#[tokio::test]
async fn samples_route_lists_the_bounded_history_newest_first() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = EndpointId::generate();
    let base = OffsetDateTime::UNIX_EPOCH;
    let series_id = seeded_series(
        &state,
        endpoint,
        "PowerMetrics",
        base,
        &[1.0, 2.0, 3.0, 4.0, 5.0],
    )?;
    let router = test_router(MockServices::new(state));

    let response = get(
        &router,
        &format!("/api/v1/telemetry/{series_id}/samples?limit=3"),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(
        body,
        json!({
            "samples": [
                {
                    "series_id": series_id.to_string(),
                    "observed_at": "1970-01-01T00:00:04Z",
                    "bmc_timestamp": "1970-01-01T00:00:04Z",
                    "value": 5.0
                },
                {
                    "series_id": series_id.to_string(),
                    "observed_at": "1970-01-01T00:00:03Z",
                    "bmc_timestamp": "1970-01-01T00:00:03Z",
                    "value": 4.0
                },
                {
                    "series_id": series_id.to_string(),
                    "observed_at": "1970-01-01T00:00:02Z",
                    "bmc_timestamp": "1970-01-01T00:00:02Z",
                    "value": 3.0
                }
            ]
        })
    );
    Ok(())
}

#[tokio::test]
async fn samples_route_defaults_the_limit_when_absent() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = EndpointId::generate();
    let base = OffsetDateTime::UNIX_EPOCH;
    let series_id = seeded_series(&state, endpoint, "PowerMetrics", base, &[1.0, 2.0])?;
    let router = test_router(MockServices::new(state));

    let response = get(&router, &format!("/api/v1/telemetry/{series_id}/samples")).await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    let samples = body["samples"]
        .as_array()
        .ok_or("samples must be an array")?;
    assert_eq!(
        samples.len(),
        2,
        "the default limit must serve the whole history"
    );
    Ok(())
}

#[tokio::test]
async fn samples_route_lists_an_unknown_series_as_empty() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(state));
    let unknown = TelemetrySeriesId::generate();

    let response = get(&router, &format!("/api/v1/telemetry/{unknown}/samples")).await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body, json!({ "samples": [] }));
    Ok(())
}

#[tokio::test]
async fn samples_route_rejects_invalid_series_ids_and_limits() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(state));
    let known = TelemetrySeriesId::generate();

    for path in [
        "/api/v1/telemetry/not-a-uuid/samples",
        &format!("/api/v1/telemetry/{known}/samples?limit=0"),
        &format!("/api/v1/telemetry/{known}/samples?limit=1001"),
        &format!("/api/v1/telemetry/{known}/samples?limit=abc"),
        &format!("/api/v1/telemetry/{known}/samples?limit="),
        &format!("/api/v1/telemetry/{known}/samples?limit=-1"),
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
async fn telemetry_route_reports_failed_listings_as_unavailable() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .fail_series_listing = true;
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/telemetry").await?;

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}

#[tokio::test]
async fn samples_route_reports_a_failed_listing_as_unavailable() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(MockState::default()));
    let endpoint = EndpointId::generate();
    let series_id = seeded_series(
        &state,
        endpoint,
        "PowerMetrics",
        OffsetDateTime::UNIX_EPOCH,
        &[1.0],
    )?;
    state
        .lock()
        .map_err(|_| MockError::Lock)?
        .fail_sample_listing = true;
    let router = test_router(MockServices::new(state));

    let response = get(&router, &format!("/api/v1/telemetry/{series_id}/samples")).await?;

    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    Ok(())
}
