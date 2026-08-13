//! Real-store integration tests of the center-side use cases (0.7.0 S5).
//!
//! The application use cases are tested against in-memory mocks in the
//! application crate; this module drives the same use cases against the
//! real `SqliteStore`, exactly like the site-side `center_sync_integration`
//! module. The binding flow, the session admission, the §15.5 projection,
//! and the §15.6 dispatch and reply tracking all run against one migrated
//! database.

use rutilus_application::{
    CenterBindingFlow, CenterOperationDispatch, CenterOperationRequest, CenterOperationTracking,
    CenterProjection, CenterReplyConsumer, CenterSessionAdmission, CenterTrustAnchor,
    IssuedSiteCertificate, ResolvedSite, SiteCertificateIssuer,
};
use rutilus_center_protocol::{
    ArtifactChunk, ArtifactManifest, EndpointSnapshot, Envelope, EnvelopeMessage, EventBatch,
    EventRecord, EventSeverity as WireEventSeverity, OperationAccepted, OperationCompleted,
    ResourceDelta, ResourceDeltaOp, ResourceSummary, TlsTrust,
};
use rutilus_domain::{
    ArtifactId, CenterBindingId, CertificateFingerprint, EndpointId, EventId, InstanceId,
    InstanceKind, OperationSource, OperationState, PrincipalId, RedfishCommand, ResetType, Role,
    RoleAssignment, SiteInstance, SystemCommand,
};
use rutilus_entity::{artifact, center_inbox, endpoint, event};
use rutilus_security::MasterKey;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use std::{
    error::Error,
    sync::{Arc, Mutex},
};
use time::{Duration, OffsetDateTime};

use crate::SqliteStore;
/// A certificate issuer that records the issuance and answers with a
/// deterministic certificate, for the binding-flow integration test.
struct TestIssuer {
    anchor: CenterTrustAnchor,
    issued: Mutex<Vec<(InstanceId, CertificateFingerprint)>>,
}

impl TestIssuer {
    fn new() -> Self {
        Self {
            anchor: CenterTrustAnchor::new(
                CertificateFingerprint::from_bytes([0xAA; 32]),
                CertificateFingerprint::from_bytes([0xBB; 32]),
            ),
            issued: Mutex::new(Vec::new()),
        }
    }
}

impl SiteCertificateIssuer for TestIssuer {
    type Error = std::io::Error;

    fn issue_site_certificate(
        &self,
        site: InstanceId,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<IssuedSiteCertificate, Self::Error> {
        self.issued
            .lock()
            .map_err(|_| std::io::Error::other("the issuer lock was poisoned"))?
            .push((site, site_fingerprint));
        Ok(IssuedSiteCertificate::new(
            String::from("certificate-pem"),
            String::from("key-pem"),
            site_fingerprint,
        ))
    }

    fn center_trust_anchor(&self) -> CenterTrustAnchor {
        self.anchor
    }
}

async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    // The dispatch tests persist operation commands, so every store in this
    // module carries the command encryption key like the production runtime.
    let store = SqliteStore::open_with_command_key(
        directory.path().join("rutilus.db"),
        Arc::new(MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))),
    )
    .await?;
    Ok((directory, store))
}

fn base_time() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

fn site_fingerprint() -> CertificateFingerprint {
    CertificateFingerprint::from_bytes([0x42; 32])
}

#[tokio::test]
async fn the_binding_flow_registers_and_binds_a_site_against_the_real_store()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let issuer = TestIssuer::new();
    let flow = CenterBindingFlow::new(&store, &issuer);
    let base = base_time();

    let registered = flow
        .register_site("https://center.example", "Site One", base)
        .await?;
    // The registration created the instance row and the pending binding.
    let instance = store
        .find_instance(registered.instance_id())
        .await?
        .ok_or("the instance row is missing")?;
    assert_eq!(instance.kind(), InstanceKind::Site);
    assert_eq!(instance.display_name(), "Site One");
    let pending = store
        .find_binding(registered.binding_id())
        .await?
        .ok_or("the pending binding is missing")?;
    assert_eq!(pending.binding_code_hash(), Some(registered.code().hash()));

    let outcome = flow
        .bind_site(
            registered.code().as_str(),
            site_fingerprint(),
            base + Duration::MINUTE,
        )
        .await?;
    assert_eq!(outcome.site_instance_id(), registered.instance_id());
    assert_eq!(
        outcome.issued_certificate().fingerprint(),
        site_fingerprint()
    );
    assert_eq!(
        outcome.trust_anchor(),
        &CenterTrustAnchor::new(
            CertificateFingerprint::from_bytes([0xAA; 32]),
            CertificateFingerprint::from_bytes([0xBB; 32])
        )
    );
    let bound = store
        .find_binding(registered.binding_id())
        .await?
        .ok_or("the bound binding is missing")?;
    assert_eq!(bound.state(), rutilus_domain::CenterBindingState::Bound);
    assert_eq!(bound.site_cert_fingerprint(), Some(site_fingerprint()));

    // A wrong code is refused against the real store.
    let other = flow
        .register_site("https://center.example", "Site Two", base)
        .await?;
    assert!(matches!(
        flow.bind_site(
            "23456789ABCDEFGHJKLN",
            site_fingerprint(),
            base + Duration::MINUTE
        )
        .await,
        Err(rutilus_application::CenterBindingFlowError::CodeMismatch)
    ));
    assert_ne!(other.instance_id(), registered.instance_id());

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn the_session_admission_resolves_bound_sites_against_the_real_store()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let issuer = TestIssuer::new();
    let flow = CenterBindingFlow::new(&store, &issuer);
    let base = base_time();
    let registered = flow
        .register_site("https://center.example", "Site One", base)
        .await?;
    flow.bind_site(
        registered.code().as_str(),
        site_fingerprint(),
        base + Duration::MINUTE,
    )
    .await?;

    let admission = CenterSessionAdmission::new(&store);
    let matching = rutilus_application::SiteIdentity::from_parts(
        CertificateFingerprint::from_bytes([0x99; 32]),
        Some(registered.instance_id().to_string()),
        Some(site_fingerprint()),
    );
    let verdict = admission.resolve(&matching).await?;
    assert_eq!(
        verdict,
        rutilus_application::AdmissionVerdict::Admitted(ResolvedSite::new(
            registered.instance_id(),
            registered.binding_id(),
            site_fingerprint()
        ))
    );

    // A certificate whose extension matches no bound binding is refused.
    let unknown = rutilus_application::SiteIdentity::from_parts(
        CertificateFingerprint::from_bytes([0x99; 32]),
        Some(registered.instance_id().to_string()),
        Some(CertificateFingerprint::from_bytes([0x43; 32])),
    );
    assert!(matches!(
        admission.resolve(&unknown).await?,
        rutilus_application::AdmissionVerdict::Rejected { .. }
    ));

    store.close().await?;
    drop(directory);
    Ok(())
}

fn resolved_site(instance_id: InstanceId, binding_id: CenterBindingId) -> ResolvedSite {
    ResolvedSite::new(instance_id, binding_id, site_fingerprint())
}

#[tokio::test]
async fn the_projection_upserts_resources_and_consumes_the_delete_deltas()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let base = base_time();
    let site = SiteInstance::new(
        InstanceId::generate(),
        String::from("Site One"),
        InstanceKind::Site,
        base,
    );
    store.create_instance(&site).await?;
    let resolved = resolved_site(site.id(), CenterBindingId::generate());
    let projection = CenterProjection::new(&store, &store);
    let endpoint_id = EndpointId::generate();

    projection
        .on_frame(
            &resolved,
            1,
            &EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
                endpoint_id: endpoint_id.to_string(),
                display_name: String::from("Rack A PDU"),
                address: String::from("https://192.0.2.10"),
                trust: TlsTrust::PinnedCertificate as i32,
                refresh_generation: 3,
                resources: Vec::new(),
                health: String::from("ok"),
            }),
            base,
        )
        .await?;
    let projected = store
        .find_endpoint_projection(endpoint_id)
        .await?
        .ok_or("the endpoint projection is missing")?;
    assert_eq!(projected.site_id(), Some(site.id()));
    let stored = endpoint::Entity::find_by_id(endpoint_id.into_uuid())
        .one(&store.database)
        .await?
        .ok_or("the endpoint row is missing")?;
    assert_eq!(stored.refresh_generation, 3);
    assert_eq!(stored.health, "ok");

    projection
        .on_frame(
            &resolved,
            2,
            &EnvelopeMessage::ResourceDelta(ResourceDelta {
                endpoint_id: endpoint_id.to_string(),
                op: ResourceDeltaOp::Upsert as i32,
                resource: Some(ResourceSummary {
                    feature: String::from("power"),
                    odata_id: String::from("/redfish/v1/Power"),
                    odata_type: String::from("#Power.v1_6_1.Power"),
                    etag: String::from("\"abc\""),
                    generation: 4,
                }),
                payload_json: b"{\"power\":\"on\"}".to_vec(),
                observed_at_unix: 1_700_000_010,
            }),
            base,
        )
        .await?;
    assert!(
        store
            .has_resource_projection(endpoint_id, "/redfish/v1/Power")
            .await?
    );

    // The §21 endpoint-level delete converges the projection.
    projection
        .on_frame(
            &resolved,
            3,
            &EnvelopeMessage::ResourceDelta(ResourceDelta {
                endpoint_id: endpoint_id.to_string(),
                op: ResourceDeltaOp::Delete as i32,
                resource: None,
                payload_json: Vec::new(),
                observed_at_unix: 0,
            }),
            base,
        )
        .await?;
    assert!(store.find_endpoint_projection(endpoint_id).await?.is_none());
    assert!(
        !store
            .has_resource_projection(endpoint_id, "/redfish/v1/Power")
            .await?,
        "the resource rows cascade away with the endpoint projection"
    );

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn the_projection_deduplicates_events_and_records_the_site() -> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let base = base_time();
    let site = SiteInstance::new(
        InstanceId::generate(),
        String::from("Site One"),
        InstanceKind::Site,
        base,
    );
    store.create_instance(&site).await?;
    let resolved = resolved_site(site.id(), CenterBindingId::generate());
    let projection = CenterProjection::new(&store, &store);
    let endpoint_id = EndpointId::generate();
    let event_id = EventId::generate();

    // The §15.5 scope check requires the event's endpoint to be a
    // projection of the reporting site before any record is stored.
    projection
        .on_frame(
            &resolved,
            1,
            &EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
                endpoint_id: endpoint_id.to_string(),
                display_name: String::from("Rack A PDU"),
                address: String::from("https://192.0.2.10"),
                trust: TlsTrust::SystemCa as i32,
                refresh_generation: 1,
                resources: Vec::new(),
                health: String::from("ok"),
            }),
            base,
        )
        .await?;
    let batch = EventBatch {
        events: vec![EventRecord {
            event_id: event_id.to_string(),
            message_id: String::from("ResourceEvent.1.0.ResourceUpdated"),
            severity: WireEventSeverity::Warning as i32,
            target: String::new(),
            occurred_at_unix: 1_699_999_990,
            payload_json: Vec::new(),
            endpoint_id: endpoint_id.to_string(),
        }],
    };
    projection
        .on_frame(
            &resolved,
            1,
            &EnvelopeMessage::EventBatch(batch.clone()),
            base,
        )
        .await?;
    // The at-least-once re-delivery is absorbed by the §14.4 dedup.
    projection
        .on_frame(&resolved, 2, &EnvelopeMessage::EventBatch(batch), base)
        .await?;

    let rows = event::Entity::find()
        .filter(event::Column::Id.eq(event_id.into_uuid()))
        .all(&store.database)
        .await?;
    assert_eq!(rows.len(), 1, "the re-delivered event must be deduplicated");
    assert_eq!(rows[0].site_id, Some(site.id().into_uuid()));

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn the_projection_assembles_artifacts_and_verifies_the_digest() -> Result<(), Box<dyn Error>>
{
    let (directory, store) = store_with_directory().await?;
    let base = base_time();
    let site = SiteInstance::new(
        InstanceId::generate(),
        String::from("Site One"),
        InstanceKind::Site,
        base,
    );
    store.create_instance(&site).await?;
    let resolved = resolved_site(site.id(), CenterBindingId::generate());
    let projection = CenterProjection::new(&store, &store);
    let artifact_id = ArtifactId::generate();
    let bytes = b"firmware-bytes".to_vec();
    // sha256("firmware-bytes"), pinned so the test needs no hashing
    // dependency.
    let digest = [
        0xb3, 0xd2, 0x05, 0x31, 0x51, 0x44, 0x94, 0x18, 0x94, 0x6e, 0xb6, 0x20, 0x09, 0xc0, 0x5b,
        0xc3, 0xfe, 0x73, 0xd3, 0x00, 0x34, 0x16, 0x48, 0xfe, 0x09, 0xb3, 0xe0, 0x85, 0x5b, 0xaa,
        0x4e, 0x87,
    ];

    projection
        .on_frame(
            &resolved,
            1,
            &EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                artifact_id: artifact_id.to_string(),
                name: String::from("firmware.bin"),
                total_bytes: bytes.len() as u64,
                sha256: digest.to_vec(),
            }),
            base,
        )
        .await?;
    // The wire contract positions chunk `i` at the byte range
    // `[i * CENTER_ARTIFACT_CHUNK_SIZE, (i + 1) * CENTER_ARTIFACT_CHUNK_SIZE)`,
    // so a payload shorter than one transfer chunk travels as a single
    // chunk with index 0.
    projection
        .on_frame(
            &resolved,
            2,
            &EnvelopeMessage::ArtifactChunk(ArtifactChunk {
                artifact_id: artifact_id.to_string(),
                index: 0,
                data: bytes.clone(),
            }),
            base + Duration::SECOND,
        )
        .await?;
    let row = artifact::Entity::find_by_id(artifact_id.into_uuid())
        .one(&store.database)
        .await?
        .ok_or("the artifact row is missing")?;
    assert_eq!(row.state, "ready");
    assert_eq!(
        row.uploaded_bytes,
        i64::try_from(bytes.len()).unwrap_or(i64::MAX)
    );
    assert_eq!(row.site_id, Some(site.id().into_uuid()));
    let file = std::fs::read(store.artifact_file_path(artifact_id))?;
    assert_eq!(file, bytes);

    store.close().await?;
    drop(directory);
    Ok(())
}

// The full dispatch-to-reply lifecycle is spelled out as its own
// assertions, which exceeds the pedantic line budget (the repository tests
// allow the same lint on their exhaustive assertion tests).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn dispatch_enqueues_the_offer_and_replies_advance_the_tracking_record()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let base = base_time();
    let site = SiteInstance::new(
        InstanceId::generate(),
        String::from("Site One"),
        InstanceKind::Site,
        base,
    );
    store.create_instance(&site).await?;
    let actor = PrincipalId::generate();
    store
        .create_principal(&rutilus_domain::Principal::new(
            actor,
            rutilus_domain::PrincipalName::parse("operator")?,
            base,
        ))
        .await?;
    store
        .assign_role(&RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            base,
            None,
        ))
        .await?;
    let endpoint_id = EndpointId::generate();
    // The dispatch routing needs the endpoint projection and its resource.
    let resolved = resolved_site(site.id(), CenterBindingId::generate());
    let projection = CenterProjection::new(&store, &store);
    projection
        .on_frame(
            &resolved,
            1,
            &EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
                endpoint_id: endpoint_id.to_string(),
                display_name: String::from("Rack A PDU"),
                address: String::from("https://192.0.2.10"),
                trust: TlsTrust::SystemCa as i32,
                refresh_generation: 1,
                resources: Vec::new(),
                health: String::from("ok"),
            }),
            base,
        )
        .await?;
    projection
        .on_frame(
            &resolved,
            2,
            &EnvelopeMessage::ResourceDelta(ResourceDelta {
                endpoint_id: endpoint_id.to_string(),
                op: ResourceDeltaOp::Upsert as i32,
                resource: Some(ResourceSummary {
                    feature: String::from("systems"),
                    odata_id: String::from("/redfish/v1/Systems/1"),
                    odata_type: String::from("#ComputerSystem.v1_20_0.ComputerSystem"),
                    etag: String::new(),
                    generation: 1,
                }),
                payload_json: b"{}".to_vec(),
                observed_at_unix: 1_699_999_990,
            }),
            base,
        )
        .await?;

    let dispatch = CenterOperationDispatch::new(&store, &store, &store);
    let request = CenterOperationRequest::new(
        site.id(),
        endpoint_id,
        rutilus_domain::ResourceODataId::parse("/redfish/v1/Systems/1")?,
        RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown)),
        actor,
    );
    let dispatched = dispatch.dispatch(&request, base).await?;
    assert_eq!(
        dispatched.expires_at(),
        base + rutilus_application::CENTER_OFFER_TTL
    );

    // The offer sits in the site's durable outbox.
    let pending = store.list_pending_outbox(site.id(), 10).await?;
    assert_eq!(pending.len(), 1);
    let envelope: Envelope = serde_json::from_str(pending[0].payload_json())?;
    let Some(EnvelopeMessage::OperationOffer(offer)) = envelope.message else {
        return Err("the outbox entry is not an operation offer".into());
    };
    assert_eq!(offer.operation_id, dispatched.operation_id().to_string());
    assert_eq!(offer.site_id, site.id().to_string());
    assert_eq!(offer.target, "/redfish/v1/Systems/1");
    assert_eq!(offer.actor_context, actor.to_string());
    assert!(offer.command_json.contains(&b'{'));

    // The tracking record exists in the operations table.
    let operation = store
        .find_operation(dispatched.operation_id())
        .await?
        .ok_or("the tracking record is missing")?;
    assert_eq!(operation.source(), OperationSource::Center);
    assert_eq!(operation.state(), OperationState::Queued);

    // The site's replies advance the record: accepted, then completed.
    let tracking = CenterOperationTracking::new(&store, &store);
    tracking
        .on_reply(
            site.id(),
            &Envelope {
                sequence: 1,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                    operation_id: dispatched.operation_id().to_string(),
                    accepted_at_unix: base.unix_timestamp(),
                })),
            },
            base + Duration::SECOND,
        )
        .await?;
    let operation = store
        .find_operation(dispatched.operation_id())
        .await?
        .ok_or("the tracking record is missing")?;
    assert_eq!(operation.state(), OperationState::Running);
    tracking
        .on_reply(
            site.id(),
            &Envelope {
                sequence: 2,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::OperationCompleted(OperationCompleted {
                    operation_id: dispatched.operation_id().to_string(),
                    succeeded: true,
                    summary: String::from("reset verified"),
                })),
            },
            base + Duration::seconds(2),
        )
        .await?;
    let operation = store
        .find_operation(dispatched.operation_id())
        .await?
        .ok_or("the tracking record is missing")?;
    assert_eq!(operation.state(), OperationState::Succeeded);

    // The reply receipts: one durable row per operation id (the §17.5
    // idempotency key), its phase advanced to the terminal report.
    let receipts = center_inbox::Entity::find()
        .filter(center_inbox::Column::OperationId.eq(dispatched.operation_id().to_string()))
        .all(&store.database)
        .await?;
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0].state, "completed");
    assert_eq!(receipts[0].instance_id, site.id().into_uuid());

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn a_site_scoped_operator_cannot_dispatch_to_another_site() -> Result<(), Box<dyn Error>> {
    let (directory, store) = store_with_directory().await?;
    let base = base_time();
    let site = SiteInstance::new(
        InstanceId::generate(),
        String::from("Site One"),
        InstanceKind::Site,
        base,
    );
    store.create_instance(&site).await?;
    let other = SiteInstance::new(
        InstanceId::generate(),
        String::from("Site Two"),
        InstanceKind::Site,
        base,
    );
    store.create_instance(&other).await?;
    let actor = PrincipalId::generate();
    store
        .create_principal(&rutilus_domain::Principal::new(
            actor,
            rutilus_domain::PrincipalName::parse("operator")?,
            base,
        ))
        .await?;
    // The D3 scoped assignment: the operator manages only Site One.
    store
        .assign_role(&RoleAssignment::new(
            actor,
            Role::Operator,
            None,
            base,
            Some(site.id()),
        ))
        .await?;
    let endpoint_id = EndpointId::generate();
    let resolved = resolved_site(site.id(), CenterBindingId::generate());
    let projection = CenterProjection::new(&store, &store);
    projection
        .on_frame(
            &resolved,
            1,
            &EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
                endpoint_id: endpoint_id.to_string(),
                display_name: String::from("Rack A PDU"),
                address: String::from("https://192.0.2.10"),
                trust: TlsTrust::SystemCa as i32,
                refresh_generation: 1,
                resources: Vec::new(),
                health: String::from("ok"),
            }),
            base,
        )
        .await?;
    projection
        .on_frame(
            &resolved,
            2,
            &EnvelopeMessage::ResourceDelta(ResourceDelta {
                endpoint_id: endpoint_id.to_string(),
                op: ResourceDeltaOp::Upsert as i32,
                resource: Some(ResourceSummary {
                    feature: String::from("systems"),
                    odata_id: String::from("/redfish/v1/Systems/1"),
                    odata_type: String::from("#ComputerSystem.v1_20_0.ComputerSystem"),
                    etag: String::new(),
                    generation: 1,
                }),
                payload_json: b"{}".to_vec(),
                observed_at_unix: 1_699_999_990,
            }),
            base,
        )
        .await?;

    let dispatch = CenterOperationDispatch::new(&store, &store, &store);
    // The endpoint belongs to Site One, but the offer is addressed to Site
    // Two: the scoped operator cannot dispatch there.
    let request = CenterOperationRequest::new(
        other.id(),
        endpoint_id,
        rutilus_domain::ResourceODataId::parse("/redfish/v1/Systems/1")?,
        RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown)),
        actor,
    );
    assert!(matches!(
        dispatch.dispatch(&request, base).await,
        Err(rutilus_application::CenterDispatchError::NotAuthorized)
    ));

    store.close().await?;
    drop(directory);
    Ok(())
}
