#![forbid(unsafe_code)]

//! End-to-end Axum tests for the §12.4 Advanced Diagnostics read path.
//!
//! Every application boundary is served by an in-memory fake so the Web
//! Router is exercised without persistence or network access. The diagnostics
//! view is read-only by construction: the path only ever serves a stored
//! snapshot, and §12.4 forbids changing Method, submitting arbitrary JSON,
//! and bypassing the normal permission and task model.

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
    CapabilitySnapshotRepository, ClassifiedBatchChild, Clock, CoreResourceReadOutcome,
    CoreResourceReader, CredentialCreationRepository, CredentialInventoryRepository,
    CredentialResolver, CredentialSecretProtector, DiscoveredEndpointRepository,
    EndpointInventoryItem, EndpointInventoryRepository, EndpointRefreshRepository, EventRepository,
    OperationStore, ProtectedCredentialCreation, RedfishDiscovery, ResolvedCredential,
    ResourceDecodeFailure, ResourceExtendedInfo, ResourceObservation, StoredCapability,
    SystemCaEvaluation, TelemetryRepository, TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, Credential, CredentialId,
    CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapabilityObservation, EndpointDisplayName, EndpointId, Event, InstanceId, Operation,
    OperationId, OperationState, PrincipalId, RedfishCommand, RefreshGeneration, ResourceEtag,
    ResourceFeature, ResourceId, ResourceODataId, ResourceODataType, ResourceSnapshot,
    ResourceSnapshotPayload, SeriesKey, TelemetrySample, TelemetrySeries, TelemetrySeriesId,
    TlsCertificate, TlsTrust,
};
use rutilus_web::{
    CenterEndpointView, CenterOperationRefusal, CenterOperationView, CenterServices,
    CenterSiteView, DispatchedCenterOperation, RegisteredCenterSite, SessionRevocation,
    WebProductInfo, router,
};
use secrecy::SecretString;
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt as _;

/// One committed refresh Generation the stateful mock retains, so the
/// inventory read can serve exactly what the refresh pipeline committed
/// (snapshots and §12.4 decode-failure records together).
#[derive(Clone)]
struct CommittedRefresh {
    endpoint: Endpoint,
    snapshots: Vec<ResourceSnapshot>,
    decode_failures: Vec<ResourceDecodeFailure>,
}

/// Implements every application boundary behind the injected services bundle.
///
/// Only the endpoint-inventory read is served; every other boundary reports
/// the controlled failure because the diagnostics path never calls them. The
/// refresh surfaces are stateful for the end-to-end refresh test: the mock
/// BMC's read outcome is committed through the same boundaries the web
/// refresh route exercises, and the inventory read then serves the committed
/// Generation.
#[derive(Clone)]
struct MockServices {
    inventory: Result<Vec<EndpointInventoryItem>, MockError>,
    refresh_endpoint: Option<Endpoint>,
    refresh_credential: Option<(CredentialUsername, SecretString)>,
    committed: Arc<Mutex<Option<(EndpointId, CommittedRefresh)>>>,
}

impl MockServices {
    fn ok(items: Vec<EndpointInventoryItem>) -> Self {
        Self {
            inventory: Ok(items),
            refresh_endpoint: None,
            refresh_credential: None,
            committed: Arc::new(Mutex::new(None)),
        }
    }

    fn failed() -> Self {
        Self {
            inventory: Err(MockError::Persistence),
            refresh_endpoint: None,
            refresh_credential: None,
            committed: Arc::new(Mutex::new(None)),
        }
    }

    /// Serves one managed endpoint and credential for the refresh pipeline.
    fn refreshing(endpoint: Endpoint, credential: (CredentialUsername, SecretString)) -> Self {
        Self {
            inventory: Ok(Vec::new()),
            refresh_endpoint: Some(endpoint),
            refresh_credential: Some(credential),
            committed: Arc::new(Mutex::new(None)),
        }
    }

    fn committed_refresh(&self) -> Result<Option<(EndpointId, CommittedRefresh)>, MockError> {
        self.committed
            .lock()
            .map(|committed| committed.clone())
            .map_err(|_| MockError::Persistence)
    }
}

/// Implements every Redfish boundary exercised by the trust and enrollment
/// flows without opening a socket.
#[derive(Clone)]
struct MockGateway {
    certificate: TlsCertificate,
    evaluation: SystemCaEvaluation,
    /// Whether the mock BMC's core resource read also reports one
    /// undecodable member: the member is skipped (§0.2.0) and the capture
    /// record flows through the refresh pipeline into the diagnostics view.
    undecodable_member: bool,
}

impl MockGateway {
    fn verified(certificate: TlsCertificate) -> Self {
        Self {
            certificate,
            evaluation: SystemCaEvaluation::Verified,
            undecodable_member: false,
        }
    }

    /// A mock BMC whose core resource read decodes every member but one:
    /// the skipped member is reported as a §12.4 decode-failure capture.
    fn with_undecodable_member(certificate: TlsCertificate) -> Self {
        Self {
            certificate,
            evaluation: SystemCaEvaluation::Verified,
            undecodable_member: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockError {
    Persistence,
    Probe,
}

impl fmt::Display for MockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Persistence => "mock persistence failed",
            Self::Probe => "mock TLS probe failed",
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
                return Err(MockError::Persistence);
            }
            Credential::try_new(
                credential_id,
                name,
                username,
                version_id,
                created_at,
                created_at,
            )
            .map_err(|_| MockError::Persistence)
        })
    }
}

impl CredentialInventoryRepository for MockServices {
    type Error = MockError;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

impl CredentialResolver for MockServices {
    type Error = MockError;

    fn resolve(
        &self,
        _credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        let credential = self.refresh_credential.clone();
        Box::pin(async move {
            // `ResolvedCredential` is not `Clone`, so the parts are stored and
            // rebuilt per call, exactly like the infra adapter's test double.
            Ok(credential.map(|(username, password)| ResolvedCredential::new(username, password)))
        })
    }
}

impl EndpointInventoryRepository for MockServices {
    type Error = MockError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        let inventory = self.inventory.clone();
        let committed = self.committed_refresh();
        Box::pin(async move {
            // A refresh committed through this mock replaces the served
            // inventory: the item carries exactly the committed Generation —
            // snapshots and decode-failure records together, exactly like the
            // persisted inventory read.
            if let Some((
                _endpoint_id,
                CommittedRefresh {
                    endpoint,
                    snapshots,
                    decode_failures,
                },
            )) = committed?
            {
                let item = EndpointInventoryItem::try_new(endpoint, snapshots)
                    .map_err(|_| MockError::Persistence)?
                    .with_decode_failures(decode_failures);
                return Ok(vec![item]);
            }
            inventory
        })
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

impl EndpointRefreshRepository for MockServices {
    type Error = MockError;

    fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        let endpoint = self.refresh_endpoint.clone();
        Box::pin(async move { Ok(endpoint.filter(|endpoint| endpoint.id() == endpoint_id)) })
    }

    fn commit_resource_generation<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [ResourceObservation],
        decode_failures: &'a [ResourceDecodeFailure],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        let endpoint = self.refresh_endpoint.clone();
        let committed = Arc::clone(&self.committed);
        Box::pin(async move {
            let endpoint = endpoint.ok_or(MockError::Persistence)?;
            let generation = RefreshGeneration::new(1).map_err(|_| MockError::Persistence)?;
            let snapshots = observations
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
                .collect::<Vec<_>>();
            committed
                .lock()
                .map_err(|_| MockError::Persistence)?
                .replace((
                    endpoint_id,
                    CommittedRefresh {
                        endpoint,
                        snapshots: snapshots.clone(),
                        decode_failures: decode_failures.to_vec(),
                    },
                ));
            Ok(snapshots)
        })
    }
}

impl AuditEventWriter for MockServices {
    type Error = MockError;

    fn append_audit_event<'a>(
        &'a self,
        _event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        // The refresh end-to-end test drives the audited refresh pipeline,
        // whose start and terminal facts must be appends, not failures.
        Box::pin(async { Ok(()) })
    }
}

impl rutilus_web::AuditEventQuery for MockServices {
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
        // The refresh end-to-end test drives the complete refresh pipeline,
        // whose capability snapshot replace must succeed.
        Box::pin(async { Ok(()) })
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

impl RedfishDiscovery for MockGateway {
    type Error = MockError;

    fn probe_core_capabilities<'a>(
        &'a self,
        _address: &'a EndpointAddress,
        _trust: &'a TlsTrust,
        _username: &'a CredentialUsername,
        _password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<rutilus_application::EndpointDiscovery, Self::Error>> {
        Box::pin(async { Ok(rutilus_application::EndpointDiscovery::new(Vec::new())) })
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
        let undecodable_member = self.undecodable_member;
        Box::pin(async move {
            if undecodable_member {
                // The mock BMC serves a Systems collection whose second
                // member cannot be decoded into the compiled schema: the
                // member is skipped (§0.2.0) and the capture record travels
                // with the read outcome into the refresh pipeline.
                let decode_failure = ResourceDecodeFailure::try_new(
                    ResourceODataId::parse("/redfish/v1/Systems/2")
                        .map_err(|_| MockError::Probe)?,
                    Some(
                        ResourceODataType::parse("#ComputerSystem.v1_20_0.ComputerSystem")
                            .map_err(|_| MockError::Probe)?,
                    ),
                    ResourceFeature::Systems,
                    Some("Vendor".to_owned()),
                    "schema decode failed: missing required field".to_owned(),
                    vec![ResourceExtendedInfo::new(
                        "Base.1.13.ResourceNotFound".to_owned(),
                        Some("The requested resource could not be found.".to_owned()),
                        Some("Critical".to_owned()),
                        Some("Remove and re-add the resource.".to_owned()),
                        vec!["MemberId".to_owned()],
                    )],
                )
                .map_err(|_| MockError::Probe)?;
                Ok(CoreResourceReadOutcome::new(
                    vec![
                        ResourceObservation::new(
                            ResourceFeature::ServiceRoot,
                            ResourceODataId::parse("/redfish/v1").map_err(|_| MockError::Probe)?,
                            ResourceSnapshotPayload::parse(r#"{"Id":"RootService","Name":"Root"}"#)
                                .map_err(|_| MockError::Probe)?,
                        ),
                        ResourceObservation::new(
                            ResourceFeature::Systems,
                            ResourceODataId::parse("/redfish/v1/Systems/1")
                                .map_err(|_| MockError::Probe)?,
                            ResourceSnapshotPayload::parse(r#"{"Id":"1","Name":"System One"}"#)
                                .map_err(|_| MockError::Probe)?,
                        ),
                    ],
                    vec![decode_failure],
                ))
            } else {
                Err(MockError::Probe)
            }
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

async fn get(router: &Router, path: &str) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(Request::get(path).body(Body::empty())?)
        .await?)
}

async fn post(
    router: &Router,
    path: &str,
    body: Value,
) -> Result<axum::response::Response, Box<dyn Error>> {
    Ok(router
        .clone()
        .oneshot(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))?,
        )
        .await?)
}

async fn json_body(response: axum::response::Response) -> Result<Value, Box<dyn Error>> {
    let bytes = response.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

fn known_endpoint() -> Result<Endpoint, Box<dyn Error>> {
    Ok(Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse("Diagnostics BMC")?,
        EndpointAddress::parse("https://192.0.2.96")?,
        TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(b"diagnostics test certificate".to_vec())?,
            trusted_at: OffsetDateTime::UNIX_EPOCH,
        },
        CredentialId::generate(),
        OffsetDateTime::UNIX_EPOCH,
        OffsetDateTime::UNIX_EPOCH,
    )?)
}

/// Builds one complete current Generation: the mandatory Service Root plus
/// one typed System snapshot carrying identity metadata, so the diagnostics
/// response can assert every §12.4 field.
fn current_item(
    endpoint: Endpoint,
    resource_id: ResourceId,
) -> Result<EndpointInventoryItem, Box<dyn Error>> {
    current_item_with_payload(
        endpoint,
        resource_id,
        r#"{"Id":"1","Name":"System One","Description":"Primary compute system","SystemType":"Physical","Oem":{"Vendor":{"OemFlag":true}}}"#,
    )
}

/// Builds one complete current Generation with the System snapshot carrying
/// the given stored payload, for the tests that vary what the gateway-mapped
/// snapshot retains (e.g. `@Message.ExtendedInfo`).
fn current_item_with_payload(
    endpoint: Endpoint,
    resource_id: ResourceId,
    system_payload: &str,
) -> Result<EndpointInventoryItem, Box<dyn Error>> {
    let endpoint_id = endpoint.id();
    let observed_at = endpoint.updated_at();
    let generation = RefreshGeneration::new(7)?;
    Ok(EndpointInventoryItem::try_new(
        endpoint,
        vec![
            ResourceSnapshot::new(
                ResourceId::generate(),
                endpoint_id,
                ResourceFeature::ServiceRoot,
                ResourceODataId::parse("/redfish/v1")?,
                ResourceSnapshotPayload::parse(r#"{"Id":"RootService","Name":"Root"}"#)?,
                observed_at,
                generation,
            ),
            ResourceSnapshot::new(
                resource_id,
                endpoint_id,
                ResourceFeature::Systems,
                ResourceODataId::parse("/redfish/v1/Systems/1")?,
                ResourceSnapshotPayload::parse(system_payload)?,
                observed_at,
                generation,
            )
            .with_odata_type(ResourceODataType::parse(
                "#ComputerSystem.v1_20_0.ComputerSystem",
            )?)
            .with_etag(ResourceEtag::parse("W/\"system-1\"")?),
        ],
    )?)
}

#[tokio::test]
async fn serves_diagnostics_for_a_current_snapshot() -> Result<(), Box<dyn Error>> {
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    let resource_id = ResourceId::generate();
    let item = current_item(endpoint, resource_id)?;
    let router = test_router(
        MockServices::ok(vec![item]),
        MockGateway::verified(TlsCertificate::from_der(
            b"diagnostics snapshot certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics"),
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
    let object = body.as_object().ok_or("body must be an object")?;
    assert_eq!(
        object.len(),
        9,
        "the diagnostics wire shape must stay the stable nine fields"
    );
    assert_eq!(body["endpoint_id"], endpoint_id.to_string());
    assert_eq!(body["odata_uri"], "/redfish/v1/Systems/1");
    assert_eq!(body["odata_type"], "#ComputerSystem.v1_20_0.ComputerSystem");
    assert_eq!(body["etag"], "W/\"system-1\"");
    assert_eq!(body["feature"], "systems");
    assert_eq!(body["generation"], 7);
    // The typed payload survives verbatim, OEM Namespace section included:
    // the snapshot store is the honest source of the decoded read-only
    // response, and this path never fabricates fields.
    assert_eq!(
        body["typed_payload"],
        serde_json::from_str::<Value>(
            r#"{"Id":"1","Name":"System One","Description":"Primary compute system","SystemType":"Physical","Oem":{"Vendor":{"OemFlag":true}}}"#
        )?
    );
    // The snapshot carries no `@Message.ExtendedInfo` and the Generation
    // recorded no decode failure: both lists are empty and still present.
    assert_eq!(body["extended_info"], serde_json::json!([]));
    assert_eq!(body["decode_failures"], serde_json::json!([]));
    Ok(())
}

#[tokio::test]
async fn serves_extended_info_from_the_stored_payload() -> Result<(), Box<dyn Error>> {
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    let resource_id = ResourceId::generate();
    let item = current_item_with_payload(
        endpoint,
        resource_id,
        r#"{"Id":"1","Name":"System One","Description":"Primary compute system","SystemType":"Physical","@Message.ExtendedInfo":[{"MessageId":"Base.1.13.Success","Severity":"OK","Resolution":"No action required","RelatedProperties":["Id"],"VendorExtra":true}]}"#,
    )?;
    let router = test_router(
        MockServices::ok(vec![item]),
        MockGateway::verified(TlsCertificate::from_der(
            b"diagnostics extended info certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics"),
    )
    .await?;

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    // The gateway-mapped snapshot is the data source: the entry arrives from
    // the stored payload, with the Redfish-defined fields projected and the
    // vendor-added property ignored by the strict entry shape.
    assert_eq!(
        body["extended_info"],
        serde_json::json!([{
            "message_id": "Base.1.13.Success",
            "message": null,
            "severity": "OK",
            "resolution": "No action required",
            "related_properties": ["Id"]
        }])
    );
    assert_eq!(body["decode_failures"], serde_json::json!([]));
    Ok(())
}

#[tokio::test]
async fn serves_decode_failure_records_while_the_endpoint_stays_usable()
-> Result<(), Box<dyn Error>> {
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    let resource_id = ResourceId::generate();
    let decode_failure = ResourceDecodeFailure::try_new(
        ResourceODataId::parse("/redfish/v1/Systems/2")?,
        Some(ResourceODataType::parse(
            "#ComputerSystem.v1_20_0.ComputerSystem",
        )?),
        ResourceFeature::Systems,
        Some("Vendor".to_owned()),
        "schema decode failed: missing required field".to_owned(),
        vec![ResourceExtendedInfo::new(
            "Base.1.13.ResourceNotFound".to_owned(),
            Some("The requested resource could not be found.".to_owned()),
            Some("Critical".to_owned()),
            Some("Remove and re-add the resource.".to_owned()),
            vec!["MemberId".to_owned()],
        )],
    )?;
    let item = current_item(endpoint, resource_id)?.with_decode_failures(vec![decode_failure]);
    let router = test_router(
        MockServices::ok(vec![item]),
        MockGateway::verified(TlsCertificate::from_der(
            b"diagnostics decode failure certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics"),
    )
    .await?;

    // The member decode failure is a sibling record, not an endpoint-wide
    // condition (§0.2.0 / §2.0): the diagnostics view still serves the
    // endpoint's current Generation with 200, and the record is displayed.
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["odata_uri"], "/redfish/v1/Systems/1");
    assert_eq!(body["generation"], 7);
    assert_eq!(
        body["decode_failures"],
        serde_json::json!([{
            "odata_uri": "/redfish/v1/Systems/2",
            "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
            "feature": "systems",
            "oem_namespace": "Vendor",
            "error_summary": "schema decode failed: missing required field",
            "extended_info": [{
                "message_id": "Base.1.13.ResourceNotFound",
                "message": "The requested resource could not be found.",
                "severity": "Critical",
                "resolution": "Remove and re-add the resource.",
                "related_properties": ["MemberId"]
            }]
        }])
    );
    Ok(())
}

#[tokio::test]
async fn refresh_capture_flows_into_the_diagnostics_response() -> Result<(), Box<dyn Error>> {
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    let services = MockServices::refreshing(
        endpoint,
        (
            CredentialUsername::parse("admin")?,
            SecretString::from("password"),
        ),
    );
    let router = test_router(
        services.clone(),
        MockGateway::with_undecodable_member(TlsCertificate::from_der(
            b"diagnostics refresh certificate".to_vec(),
        )?),
    );

    // The refresh batch drives the production pipeline end to end: the mock
    // BMC's read outcome — the decoded members plus the undecodable member's
    // §12.4 capture — is committed as one refresh Generation.
    let response = post(
        &router,
        "/api/v1/endpoints/refresh",
        serde_json::json!({ "endpoint_ids": [endpoint_id.to_string()] }),
    )
    .await?;
    assert_eq!(
        response.status(),
        axum::http::StatusCode::OK,
        "the refresh batch must report the endpoint outcome inside the 200 report"
    );

    let (committed_endpoint_id, committed) = services
        .committed_refresh()?
        .ok_or("the refresh must commit one Generation")?;
    assert_eq!(committed_endpoint_id, endpoint_id);
    let system = committed
        .snapshots
        .iter()
        .find(|snapshot| snapshot.feature() == ResourceFeature::Systems)
        .ok_or("the committed Generation must carry the decoded System")?;

    // The endpoint stays fully usable (§0.2.0): the diagnostics view serves
    // the decoded System with 200, and the skipped member's decode failure
    // is displayed as a sibling record.
    let response = get(
        &router,
        &format!(
            "/api/v1/endpoints/{endpoint_id}/resources/{}/diagnostics",
            system.resource_id()
        ),
    )
    .await?;
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = json_body(response).await?;
    assert_eq!(body["odata_uri"], "/redfish/v1/Systems/1");
    assert_eq!(body["generation"], 1);
    assert_eq!(
        body["decode_failures"],
        serde_json::json!([{
            "odata_uri": "/redfish/v1/Systems/2",
            "odata_type": "#ComputerSystem.v1_20_0.ComputerSystem",
            "feature": "systems",
            "oem_namespace": "Vendor",
            "error_summary": "schema decode failed: missing required field",
            "extended_info": [{
                "message_id": "Base.1.13.ResourceNotFound",
                "message": "The requested resource could not be found.",
                "severity": "Critical",
                "resolution": "Remove and re-add the resource.",
                "related_properties": ["MemberId"]
            }]
        }])
    );
    Ok(())
}

#[tokio::test]
async fn distinguishes_diagnostics_route_states() -> Result<(), Box<dyn Error>> {
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    let resource_id = ResourceId::generate();
    let item = current_item(endpoint, resource_id)?;
    let router = test_router(
        MockServices::ok(vec![item]),
        MockGateway::verified(TlsCertificate::from_der(
            b"diagnostics states certificate".to_vec(),
        )?),
    );

    let bad_endpoint_id = get(
        &router,
        &format!("/api/v1/endpoints/not-a-uuid/resources/{resource_id}/diagnostics"),
    )
    .await?;
    assert_eq!(
        bad_endpoint_id.status(),
        axum::http::StatusCode::BAD_REQUEST
    );
    // A5-4: the JSON error body is part of the contract — a bare 400
    // regression would otherwise leave the console without a reason.
    let body = json_body(bad_endpoint_id).await?;
    assert_eq!(body["message"], "endpoint id is invalid");
    let bad_resource_id = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/resources/not-a-uuid/diagnostics"),
    )
    .await?;
    assert_eq!(
        bad_resource_id.status(),
        axum::http::StatusCode::BAD_REQUEST
    );
    let body = json_body(bad_resource_id).await?;
    assert_eq!(body["message"], "resource id is invalid");

    let missing_endpoint = get(
        &router,
        &format!(
            "/api/v1/endpoints/{}/resources/{resource_id}/diagnostics",
            EndpointId::generate()
        ),
    )
    .await?;
    assert_eq!(missing_endpoint.status(), axum::http::StatusCode::NOT_FOUND);
    let missing_resource = get(
        &router,
        &format!(
            "/api/v1/endpoints/{endpoint_id}/resources/{}/diagnostics",
            ResourceId::generate()
        ),
    )
    .await?;
    assert_eq!(missing_resource.status(), axum::http::StatusCode::NOT_FOUND);

    let wrong_method = router
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics"
            ))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        wrong_method.status(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED
    );
    Ok(())
}

#[tokio::test]
async fn reports_inventory_failures_as_service_unavailable() -> Result<(), Box<dyn Error>> {
    let router = test_router(
        MockServices::failed(),
        MockGateway::verified(TlsCertificate::from_der(
            b"diagnostics failure certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!(
            "/api/v1/endpoints/{}/resources/{}/diagnostics",
            EndpointId::generate(),
            ResourceId::generate()
        ),
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
async fn reports_duplicate_endpoint_inventory_as_internal_error() -> Result<(), Box<dyn Error>> {
    let endpoint = known_endpoint()?;
    let endpoint_id = endpoint.id();
    let resource_id = ResourceId::generate();
    let item = current_item(endpoint, resource_id)?;
    // A corrupted store can emit the same endpoint twice; the query boundary
    // must surface the inconsistency as an internal fault rather than
    // guessing which inventory wins.
    let router = test_router(
        MockServices::ok(vec![item.clone(), item]),
        MockGateway::verified(TlsCertificate::from_der(
            b"diagnostics duplicate certificate".to_vec(),
        )?),
    );

    let response = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/resources/{resource_id}/diagnostics"),
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
