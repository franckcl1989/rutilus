#![forbid(unsafe_code)]

//! End-to-end Axum tests for the §14.2 homepage aggregation path:
//! `GET /api/v1/overview`.
//!
//! Every application boundary is served by an in-memory fake seeded with a
//! small fleet — endpoints with typed resource payloads, capability
//! observations, operations, and events — so the Web Router is exercised
//! without persistence or network access. The aggregate blocks are
//! server-derived facts, so the assertions pin the wire shape the console
//! renders, exactly like the single-block path tests pin their projections.

use std::{
    collections::HashMap,
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
    CapabilitySnapshotRepository, ClassifiedBatchChild, Clock, CoreResourceReadOutcome,
    CoreResourceReader, CredentialCreationRepository, CredentialInventoryRepository,
    CredentialResolver, CredentialSecretProtector, DiscoveredEndpointRepository,
    EndpointInventoryItem, EndpointInventoryRepository, EndpointRefreshRepository, EventRepository,
    OperationStore, ProtectedCredentialCreation, RedfishDiscovery, ResolvedCredential,
    ResourceDecodeFailure, ResourceObservation, StoredCapability, TelemetryRepository,
    TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, CapabilityState, Credential,
    CredentialId, CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint,
    EndpointAddress, EndpointCapability, EndpointCapabilityObservation, EndpointDisplayName,
    EndpointId, Event, EventId, EventSeverity, InstanceId, MessageId, Operation, OperationId,
    OperationSource, OperationState, OperationTarget, PrincipalId, RedfishCommand,
    RefreshGeneration, ResourceFeature, ResourceId, ResourceODataId, ResourceSnapshot,
    ResourceSnapshotPayload, SeriesKey, TargetId, TelemetrySample, TelemetrySeries,
    TelemetrySeriesId, TlsCertificate, TlsTrust,
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

/// The deterministic serving time of every test: `OffsetDateTime::UNIX_EPOCH`
/// exactly like the other fixed-clock suites, so the staleness buckets are
/// absolute.
const NOW: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

/// Which mock boundary fails on the next request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockFailure {
    Inventory,
    Capabilities,
    Operations,
    Events,
}

#[derive(Default)]
struct MockState {
    inventory: Vec<EndpointInventoryItem>,
    capabilities: HashMap<EndpointId, Vec<StoredCapability>>,
    operations: Vec<Operation>,
    events: Vec<Event>,
    fail: Option<MockFailure>,
}

/// Implements every application boundary behind the injected services bundle,
/// with the seeded fleet state the overview assertions read.
#[derive(Clone)]
struct MockServices {
    state: Arc<Mutex<MockState>>,
}

impl MockServices {
    fn new(state: Arc<Mutex<MockState>>) -> Self {
        Self { state }
    }
}

/// Implements the Redfish boundaries without opening a socket; the overview
/// path never exercises them.
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
        Box::pin(async { Ok(Vec::new()) })
    }

    fn list_samples(
        &self,
        _series_id: TelemetrySeriesId,
        _limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
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
        _state_filter: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        let state = self.state.clone();
        Box::pin(async move {
            let state = state.lock().map_err(|_| MockError::Lock)?;
            if state.fail == Some(MockFailure::Operations) {
                return Err(MockError::Persistence);
            }
            Ok(state.operations.clone())
        })
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
        let state = self.state.clone();
        Box::pin(async move {
            let state = state.lock().map_err(|_| MockError::Lock)?;
            if state.fail == Some(MockFailure::Inventory) {
                return Err(MockError::Persistence);
            }
            Ok(state.inventory.clone())
        })
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
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
        let state = self.state.clone();
        Box::pin(async move {
            let state = state.lock().map_err(|_| MockError::Lock)?;
            if state.fail == Some(MockFailure::Capabilities) {
                return Err(MockError::Persistence);
            }
            Ok(state.capabilities.get(&endpoint_id).cloned())
        })
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

    /// Lists the newest events first: the fake stores in append order, so
    /// the reversed tail is the console's newest-first view.
    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        let state = self.state.clone();
        Box::pin(async move {
            let state = state.lock().map_err(|_| MockError::Lock)?;
            if state.fail == Some(MockFailure::Events) {
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
    ) -> BoundaryFuture<'a, Result<CoreResourceReadOutcome, Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        NOW
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

/// Builds one managed endpoint whose trust predates the fixed clock.
fn managed_endpoint(name: &str, index: u8) -> Result<Endpoint, Box<dyn Error>> {
    Ok(Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse(name)?,
        EndpointAddress::parse(&format!("https://192.0.2.{index}"))?,
        TlsTrust::SystemCa {
            certificate: TlsCertificate::from_der(format!("certificate {index}").into_bytes())?,
            verified_at: NOW,
        },
        CredentialId::generate(),
        NOW,
        NOW,
    )?)
}

/// Builds one typed resource snapshot of the endpoint's latest Generation.
fn typed_snapshot(
    endpoint_id: EndpointId,
    feature: ResourceFeature,
    odata_id: &str,
    payload: &str,
    observed_at: OffsetDateTime,
) -> Result<ResourceSnapshot, Box<dyn Error>> {
    Ok(ResourceSnapshot::new(
        ResourceId::generate(),
        endpoint_id,
        feature,
        ResourceODataId::parse(odata_id)?,
        ResourceSnapshotPayload::parse(payload)?,
        observed_at,
        RefreshGeneration::new(1)?,
    ))
}

/// The typed Service Root payload with the given `Vendor`.
fn service_root_payload(vendor: Option<&str>) -> String {
    match vendor {
        Some(vendor) => format!(r#"{{"Id":"Root","Name":"Root","Vendor":"{vendor}"}}"#),
        None => r#"{"Id":"Root","Name":"Root"}"#.to_owned(),
    }
}

/// The typed System payload with the given `Status.Health`.
fn system_payload(health: Option<&str>) -> String {
    match health {
        Some(health) => {
            format!(r#"{{"Id":"1","Name":"System","Status":{{"Health":"{health}"}}}}"#)
        }
        None => r#"{"Id":"1","Name":"System"}"#.to_owned(),
    }
}

/// The typed `SoftwareInventory` payload with the given `Version`;
/// `ReleaseDate` is a required wire property, pinned as null.
fn software_inventory_payload(version: Option<&str>) -> String {
    match version {
        Some(version) => {
            format!(r#"{{"Id":"BIOS","Name":"BIOS","Version":"{version}","ReleaseDate":null}}"#)
        }
        None => r#"{"Id":"BIOS","Name":"BIOS","ReleaseDate":null}"#.to_owned(),
    }
}

/// Builds one refreshed endpoint: a Service Root with the given vendor, a
/// System with the given health, and one `SoftwareInventory` member per given
/// version — the §12.2 typed resource surface the aggregate reads.
fn refreshed_item(
    name: &str,
    index: u8,
    vendor: Option<&str>,
    health: Option<&str>,
    firmware_versions: &[Option<&str>],
    refreshed_at: OffsetDateTime,
) -> Result<(Endpoint, EndpointInventoryItem), Box<dyn Error>> {
    let endpoint = managed_endpoint(name, index)?;
    let endpoint_id = endpoint.id();
    let mut snapshots = vec![
        typed_snapshot(
            endpoint_id,
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            &service_root_payload(vendor),
            refreshed_at,
        )?,
        typed_snapshot(
            endpoint_id,
            ResourceFeature::Systems,
            "/redfish/v1/Systems/1",
            &system_payload(health),
            refreshed_at,
        )?,
    ];
    for (offset, version) in firmware_versions.iter().enumerate() {
        snapshots.push(typed_snapshot(
            endpoint_id,
            ResourceFeature::SoftwareInventory,
            &format!("/redfish/v1/UpdateService/SoftwareInventory/{offset}"),
            &software_inventory_payload(*version),
            refreshed_at,
        )?);
    }
    Ok((
        endpoint.clone(),
        EndpointInventoryItem::try_new(endpoint, snapshots)?,
    ))
}

/// Builds one persisted operation with the given §13.2 state.
fn stored_operation(state: OperationState) -> Result<Operation, Box<dyn Error>> {
    Ok(Operation::try_from_parts(
        OperationId::generate(),
        OperationSource::Standalone,
        vec![OperationTarget::new(
            TargetId::generate(),
            EndpointId::generate(),
        )],
        RedfishCommand::System(rutilus_domain::SystemCommand::Reset(
            rutilus_domain::ResetType::PowerCycle,
        )),
        state,
        NOW,
        NOW,
    )?)
}

/// Builds one event recorded from the given endpoint; the receive time is one
/// second after the BMC's event timestamp, so the domain timeline constraint
/// holds.
fn recorded_event(endpoint_id: EndpointId, seconds: i64) -> Result<Event, Box<dyn Error>> {
    let at = |seconds: i64| NOW + Duration::seconds(seconds);
    Ok(Event::new(
        EventId::generate(),
        endpoint_id,
        MessageId::parse("Alert.1.0.PowerSupplyFailure")?,
        EventSeverity::Critical,
        None,
        at(seconds),
        at(seconds + 1),
    )?)
}

/// Builds one stored capability observation with the given final state.
fn stored_capability(capability: EndpointCapability, state: CapabilityState) -> StoredCapability {
    StoredCapability::new(EndpointCapabilityObservation::new(capability, state), NOW)
}

/// Seeds the fleet of the aggregate assertions: one freshly refreshed ACME
/// endpoint (ok health, two firmware members sharing one version), one stale
/// ACME endpoint (critical health, one firmware member), one endpoint awaiting
/// its first refresh, two active operations plus one succeeded, and two
/// events.
fn seeded_state() -> Result<Arc<Mutex<MockState>>, Box<dyn Error>> {
    let (current, current_item) = refreshed_item(
        "Rack A BMC",
        10,
        Some("ACME"),
        Some("OK"),
        &[Some("1.2.3"), Some("1.2.3")],
        NOW - Duration::MINUTE,
    )?;
    let current_id = current.id();
    let (stale_endpoint, stale_item) = refreshed_item(
        "Rack B BMC",
        11,
        Some("ACME"),
        Some("Critical"),
        &[Some("2.0.0")],
        NOW - Duration::days(9),
    )?;
    let stale_id = stale_endpoint.id();
    let waiting = managed_endpoint("Rack C BMC", 12)?;

    let seeded = Arc::new(Mutex::new(MockState {
        inventory: vec![
            current_item,
            stale_item,
            EndpointInventoryItem::try_new(waiting, Vec::new())?,
        ],
        capabilities: HashMap::from([
            (
                current_id,
                vec![
                    stored_capability(EndpointCapability::Systems, CapabilityState::Supported),
                    stored_capability(
                        EndpointCapability::SessionService,
                        CapabilityState::NotAdvertised,
                    ),
                ],
            ),
            (
                stale_id,
                vec![stored_capability(
                    EndpointCapability::Managers,
                    CapabilityState::Supported,
                )],
            ),
        ]),
        operations: vec![
            stored_operation(OperationState::Running)?,
            stored_operation(OperationState::Queued)?,
            stored_operation(OperationState::Succeeded)?,
        ],
        events: vec![
            recorded_event(current_id, 10)?,
            recorded_event(stale_id, 20)?,
        ],
        fail: None,
    }));
    Ok(seeded)
}

#[tokio::test]
async fn overview_route_aggregates_every_dashboard_block() -> Result<(), Box<dyn Error>> {
    let state = seeded_state()?;
    let router = test_router(MockServices::new(Arc::clone(&state)));

    let response = get(&router, "/api/v1/overview").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers().get("cache-control"),
        Some(&axum::http::HeaderValue::from_static(
            "no-store, must-revalidate"
        ))
    );
    let mut body = json_body(response).await?;
    // The recent-event tail is asserted field-wise below (its ids are
    // generated per seed), so it is lifted out of the envelope comparison.
    let recent_events = body
        .get("recent_events")
        .cloned()
        .ok_or("the response must carry recent events")?;
    body.as_object_mut()
        .ok_or("the response body must be an object")?
        .remove("recent_events");
    assert_eq!(
        body,
        json!({
            "endpoints": {
                "total": 3,
                "with_current_snapshot": 2,
                "awaiting_first_refresh": 1
            },
            "vendors": [
                { "vendor": null, "count": 1 },
                { "vendor": "ACME", "count": 2 }
            ],
            "health": [
                { "level": "critical", "count": 1 },
                { "level": "ok", "count": 1 },
                { "level": "unknown", "count": 1 }
            ],
            "firmware": {
                "endpoints_with_inventory": 2,
                "entries": 3,
                "distinct_versions": 2
            },
            "capabilities": {
                "observed_entries": 3,
                "supported_entries": 2
            },
            "running_operations": 2,
            "freshness": [
                { "bucket": "never_refreshed", "count": 1 },
                { "bucket": "within_one_hour", "count": 1 },
                { "bucket": "older_than_seven_days", "count": 1 }
            ]
        })
    );
    // The recent-event tail carries the full §14.4 wire shape: ids, the
    // source endpoint, the raw MessageId, and the message text. The ids are
    // generated per seed, so the block is asserted field-wise instead of in
    // the envelope comparison above.
    let events = recent_events
        .as_array()
        .ok_or("the response must carry recent events")?;
    assert_eq!(events.len(), 2);
    assert!(events[0]["id"].as_str().is_some());
    assert!(events[0]["endpoint_id"].as_str().is_some());
    assert_eq!(events[0]["message_id"], "Alert.1.0.PowerSupplyFailure");
    assert_eq!(events[0]["severity"], "critical");
    assert_eq!(events[0]["event_timestamp"], "1970-01-01T00:00:20Z");
    assert_eq!(events[0]["observed_at"], "1970-01-01T00:00:21Z");
    assert_eq!(events[1]["event_timestamp"], "1970-01-01T00:00:10Z");
    assert_eq!(events[1]["observed_at"], "1970-01-01T00:00:11Z");
    Ok(())
}

#[tokio::test]
async fn overview_route_bounds_the_recent_events_tail() -> Result<(), Box<dyn Error>> {
    let (_, current_item) = refreshed_item(
        "Rack A BMC",
        10,
        Some("ACME"),
        Some("OK"),
        &[],
        NOW - Duration::MINUTE,
    )?;
    let endpoint_id = current_item.endpoint().id();
    let mut events = Vec::new();
    for seconds in 0..7 {
        events.push(recorded_event(endpoint_id, seconds)?);
    }
    let state = Arc::new(Mutex::new(MockState {
        inventory: vec![current_item],
        capabilities: HashMap::new(),
        operations: Vec::new(),
        events,
        fail: None,
    }));
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/overview").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    let events = body["recent_events"]
        .as_array()
        .ok_or("the response must carry recent events")?;
    assert_eq!(events.len(), 5);
    assert_eq!(events[0]["event_timestamp"], "1970-01-01T00:00:06Z");
    assert_eq!(events[4]["event_timestamp"], "1970-01-01T00:00:02Z");
    Ok(())
}

#[tokio::test]
async fn overview_route_returns_an_empty_dashboard_for_an_empty_fleet() -> Result<(), Box<dyn Error>>
{
    let state = Arc::new(Mutex::new(MockState::default()));
    let router = test_router(MockServices::new(state));

    let response = get(&router, "/api/v1/overview").await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(
        body,
        json!({
            "endpoints": {
                "total": 0,
                "with_current_snapshot": 0,
                "awaiting_first_refresh": 0
            },
            "vendors": [],
            "health": [],
            "firmware": {
                "endpoints_with_inventory": 0,
                "entries": 0,
                "distinct_versions": 0
            },
            "capabilities": {
                "observed_entries": 0,
                "supported_entries": 0
            },
            "running_operations": 0,
            "recent_events": [],
            "freshness": []
        })
    );
    Ok(())
}

#[tokio::test]
async fn overview_route_reports_any_boundary_failure_as_unavailable() -> Result<(), Box<dyn Error>>
{
    for failure in [
        MockFailure::Inventory,
        MockFailure::Capabilities,
        MockFailure::Operations,
        MockFailure::Events,
    ] {
        let state = seeded_state()?;
        state.lock().map_err(|_| MockError::Lock)?.fail = Some(failure);
        let router = test_router(MockServices::new(state));

        let response = get(&router, "/api/v1/overview").await?;

        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "the {failure:?} failure must make the whole dashboard unavailable"
        );
        assert_eq!(
            response.headers().get("cache-control"),
            Some(&axum::http::HeaderValue::from_static(
                "no-store, must-revalidate"
            ))
        );
    }
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
