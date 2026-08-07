#![forbid(unsafe_code)]

//! End-to-end Axum tests for the §12.4 Advanced Diagnostics read path.
//!
//! Every application boundary is served by an in-memory fake so the Web
//! Router is exercised without persistence or network access. The diagnostics
//! view is read-only by construction: the path only ever serves a stored
//! snapshot, and §12.4 forbids changing Method, submitting arbitrary JSON,
//! and bypassing the normal permission and task model.

use std::{error::Error, fmt, num::NonZeroU64, path::PathBuf, sync::Arc};

use axum::{Router, body::Body, http::Request};
use http_body_util::BodyExt as _;
use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository,
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialCreationRepository,
    CredentialInventoryRepository, CredentialResolver, CredentialSecretProtector,
    DiscoveredEndpointRepository, EndpointInventoryItem, EndpointInventoryRepository,
    EndpointRefreshRepository, EventRepository, OperationStore, ProtectedCredentialCreation,
    RedfishDiscovery, ResolvedCredential, ResourceObservation, StoredCapability,
    SystemCaEvaluation, TelemetryRepository, TlsIdentityObservation, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, Credential, CredentialId,
    CredentialUsername, CredentialVersionId, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapabilityObservation, EndpointDisplayName, EndpointId, Event, Operation, OperationId,
    OperationState, RefreshGeneration, ResourceEtag, ResourceFeature, ResourceId, ResourceODataId,
    ResourceODataType, ResourceSnapshot, ResourceSnapshotPayload, SeriesKey, TelemetrySample,
    TelemetrySeries, TelemetrySeriesId, TlsCertificate, TlsTrust,
};
use rutilus_web::{WebProductInfo, router};
use secrecy::SecretString;
use serde_json::Value;
use time::OffsetDateTime;
use tower::ServiceExt as _;

/// Implements every application boundary behind the injected services bundle.
///
/// Only the endpoint-inventory read is served; every other boundary reports
/// the controlled failure because the diagnostics path never calls them.
#[derive(Clone)]
struct MockServices {
    inventory: Result<Vec<EndpointInventoryItem>, MockError>,
}

impl MockServices {
    fn ok(items: Vec<EndpointInventoryItem>) -> Self {
        Self {
            inventory: Ok(items),
        }
    }

    fn failed() -> Self {
        Self {
            inventory: Err(MockError::Persistence),
        }
    }
}

/// Implements every Redfish boundary exercised by the trust and enrollment
/// flows without opening a socket.
#[derive(Clone)]
struct MockGateway {
    certificate: TlsCertificate,
    evaluation: SystemCaEvaluation,
}

impl MockGateway {
    fn verified(certificate: TlsCertificate) -> Self {
        Self {
            certificate,
            evaluation: SystemCaEvaluation::Verified,
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
        Box::pin(async { Ok(None) })
    }
}

impl EndpointInventoryRepository for MockServices {
    type Error = MockError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        Box::pin(async { self.inventory.clone() })
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

impl AuditEventWriter for MockServices {
    type Error = MockError;

    fn append_audit_event<'a>(
        &'a self,
        _event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async { Err(MockError::Persistence) })
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

    fn list_operations(
        &self,
        _state: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
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
        Box::pin(async { Err(MockError::Probe) })
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
        Box::pin(async { Err(MockError::Probe) })
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
                ResourceSnapshotPayload::parse(
                    r#"{"Id":"1","Name":"System One","Description":"Primary compute system","SystemType":"Physical","Oem":{"Vendor":{"OemFlag":true}}}"#,
                )?,
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
        7,
        "the diagnostics wire shape must stay the stable seven fields"
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
    let bad_resource_id = get(
        &router,
        &format!("/api/v1/endpoints/{endpoint_id}/resources/not-a-uuid/diagnostics"),
    )
    .await?;
    assert_eq!(
        bad_resource_id.status(),
        axum::http::StatusCode::BAD_REQUEST
    );

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
