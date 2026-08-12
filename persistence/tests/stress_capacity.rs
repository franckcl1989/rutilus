//! §0.9.0 database stress and capacity suite (design §0.9.0「最低验证规模」,
//! `redfish-management-product-final-design.md:2800-2810` — the design's
//! "测试后发布真实容量建议" line).
//!
//! The suite drives the persistence layer through the repository public API
//! at the minimum validation scale: one site with 200 endpoints, one center
//! with 100 sites, and a 5,000-endpoint center aggregation. Every assertion
//! is a correctness invariant — row counts, §9.5 Generation consistency,
//! §17 queue and cursor ordering, and the §15.4 at-least-once redelivery
//! no-ops — and the `println!` timings are the measured-capacity evidence
//! the design asks to publish. No wall-clock value is ever asserted: CI
//! variance is not a test input.

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::time::Instant;

use rutilus_application::{
    CenterTrustMode, EndpointProjectionWrite, ProjectionIgnoreReason, ProjectionWriteOutcome,
    ResourceProjectionWrite,
};
use rutilus_center_protocol::{EnvelopeMessage, OperationOffer};
use rutilus_domain::{
    CAPABILITY_LEDGER_ORDER, CapabilityState, CredentialId, CredentialName, CredentialUsername,
    CredentialVersionId, Endpoint, EndpointAddress, EndpointCapabilityObservation,
    EndpointDisplayName, EndpointId, InboxEntry, InboxEntryId, InboxEntryState, InboxEvent,
    InstanceId, InstanceKind, OperationId, OutboxEntry, RedfishCommand, ResetType, ResourceEtag,
    ResourceFeature, ResourceODataId, ResourceODataType, ResourceSnapshot, ResourceSnapshotPayload,
    SiteInstance, SyncCursor, SyncCursorId, SyncStream, SystemCommand, TlsCertificate, TlsTrust,
};
use rutilus_entity::{
    center_inbox, center_outbox, credential, credential_version, endpoint, endpoint_address,
    endpoint_capability, endpoint_credential, endpoint_trust, instance, resource,
    resource_snapshot, sync_cursor,
};
use rutilus_persistence::{
    AckOutcome, CreateInboxOutcome, InboxAdvanceOutcome, NewCredential, NewResourceSnapshot,
    ProjectedEndpointSummary, ResourceSnapshotRepositoryError, SqliteStore,
};
use rutilus_security::{MasterKey, encrypt_credential};
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait, PaginatorTrait};
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};

/// §0.9.0 minimum validation scale: one site manages at least 200 endpoints.
const SITE_ENDPOINT_COUNT: usize = 200;
/// §0.9.0 minimum validation scale: one center serves at least 100 sites.
const CENTER_SITE_COUNT: usize = 100;
/// §0.9.0 minimum validation scale: the center aggregation holds at least
/// 5,000 endpoint projections (100 sites x 50).
const CENTER_ENDPOINT_COUNT: usize = 5_000;
const PROJECTIONS_PER_SITE: usize = CENTER_ENDPOINT_COUNT / CENTER_SITE_COUNT;
const _: () = assert!(PROJECTIONS_PER_SITE * CENTER_SITE_COUNT == CENTER_ENDPOINT_COUNT);

/// Outbox envelopes queued per site in the 100-site queue test.
const OUTBOX_PER_SITE: usize = 10;
/// Outbox envelopes acknowledged per site; the rest stay pending.
const OUTBOX_ACK_PER_SITE: usize = 5;
/// Inbox entries inserted per site; one of them walks the full §17.5
/// idempotency lifecycle.
const INBOX_PER_SITE: usize = 4;
/// The four §17 sync streams every site advances.
const CURSOR_STREAMS: [SyncStream; 4] = [
    SyncStream::Endpoint,
    SyncStream::Health,
    SyncStream::Event,
    SyncStream::Artifact,
];
/// Endpoints of the 5,000-projection test that also receive §15.5 resource
/// deltas.
const RESOURCE_PROJECTED_ENDPOINTS: usize = 200;
/// Resource deltas per projected endpoint.
const RESOURCES_PER_ENDPOINT: usize = 3;
/// Endpoint projections deleted in the 5,000-projection test.
const DELETED_PROJECTION_COUNT: usize = 50;
/// Capability observations in every site endpoint's snapshot (the first
/// eight §2.1 ledger entries).
const CAPABILITY_OBSERVATION_COUNT: usize = 8;

/// The fixed test command key: the queue payloads rest as ciphertext
/// envelopes exactly like the production runtime's store (the same key
/// convention as the repository unit tests).
fn test_key() -> Arc<MasterKey> {
    Arc::new(MasterKey::from_boxed_bytes(Box::new([0x5a; 32])))
}

/// Opens one command-encrypted store in a fresh temporary directory.
async fn open_store() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store =
        SqliteStore::open_with_command_key(directory.path().join("rutilus.db"), test_key()).await?;
    Ok((directory, store))
}

/// Opens a second read connection to the store's database file so the tests
/// can assert exact table row counts (the store's own connection pool is
/// private).
async fn counting_connection(
    directory: &std::path::Path,
) -> Result<DatabaseConnection, Box<dyn Error>> {
    let normalized = directory
        .join("rutilus.db")
        .to_string_lossy()
        .replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized}?mode=rwc"));
    options.max_connections(1).sqlx_logging(false);
    Ok(Database::connect(options).await?)
}

/// A deterministic capability snapshot: the first eight §2.1 ledger entries
/// with cycling observation states, so the same page is provably stored for
/// every endpoint.
fn capability_observations() -> Vec<EndpointCapabilityObservation> {
    const STATES: [CapabilityState; 7] = [
        CapabilityState::Supported,
        CapabilityState::ReadOnly,
        CapabilityState::Unauthorized,
        CapabilityState::TemporarilyUnavailable,
        CapabilityState::SchemaIncompatible,
        CapabilityState::NotAdvertised,
        CapabilityState::NotCompiled,
    ];
    CAPABILITY_LEDGER_ORDER
        .iter()
        .take(CAPABILITY_OBSERVATION_COUNT)
        .enumerate()
        .map(|(index, capability)| {
            EndpointCapabilityObservation::new(*capability, STATES[index % STATES.len()])
        })
        .collect()
}

/// One site endpoint fixture: an `index`-derived name and address,
/// alternating trust decisions, and a timeline anchored at `created_at`.
fn site_endpoint(
    credential_id: CredentialId,
    index: usize,
    created_at: OffsetDateTime,
) -> Result<Endpoint, Box<dyn Error>> {
    let updated_at = created_at + Duration::SECOND;
    let trust = if index.is_multiple_of(2) {
        TlsTrust::SystemCa {
            certificate: TlsCertificate::from_der(b"stress leaf certificate".to_vec())?,
            verified_at: updated_at,
        }
    } else {
        TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(b"stress leaf certificate".to_vec())?,
            trusted_at: updated_at,
        }
    };
    Ok(Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse(&format!("BMC {index:03}"))?,
        EndpointAddress::parse(&format!("https://192.0.2.{}/redfish", index + 1))?,
        trust,
        credential_id,
        created_at,
        updated_at,
    )?)
}

/// One complete §9.5 refresh Generation: the Service Root plus six tracked
/// resources, with the generation stamped into the payloads and the `ETag`
/// carried on the power row.
fn generation_observations(
    index: usize,
    generation: u64,
) -> Result<Vec<NewResourceSnapshot>, Box<dyn Error>> {
    Ok(vec![
        NewResourceSnapshot::new(
            ResourceFeature::ServiceRoot,
            ResourceODataId::parse("/redfish/v1/")?,
            ResourceSnapshotPayload::parse(&format!(r#"{{"Name":"Root {index} v{generation}"}}"#))?,
        )
        .with_odata_type(ResourceODataType::parse(
            "#ServiceRoot.v1_19_0.ServiceRoot",
        )?),
        NewResourceSnapshot::new(
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(&format!(
                r#"{{"Name":"System {index} v{generation}"}}"#
            ))?,
        ),
        NewResourceSnapshot::new(
            ResourceFeature::Managers,
            ResourceODataId::parse("/redfish/v1/Managers/1")?,
            ResourceSnapshotPayload::parse(&format!(
                r#"{{"Name":"Manager {index} v{generation}"}}"#
            ))?,
        ),
        NewResourceSnapshot::new(
            ResourceFeature::Chassis,
            ResourceODataId::parse("/redfish/v1/Chassis/1")?,
            ResourceSnapshotPayload::parse(&format!(
                r#"{{"Name":"Chassis {index} v{generation}"}}"#
            ))?,
        ),
        NewResourceSnapshot::new(
            ResourceFeature::Power,
            ResourceODataId::parse("/redfish/v1/Chassis/1/Power")?,
            ResourceSnapshotPayload::parse(&format!(
                r#"{{"Name":"Power {index} v{generation}"}}"#
            ))?,
        )
        .with_etag(ResourceEtag::parse(&format!("W/\"power-{index}\""))?),
        NewResourceSnapshot::new(
            ResourceFeature::Thermal,
            ResourceODataId::parse("/redfish/v1/Chassis/1/Thermal")?,
            ResourceSnapshotPayload::parse(&format!(
                r#"{{"Name":"Thermal {index} v{generation}"}}"#
            ))?,
        ),
        NewResourceSnapshot::new(
            ResourceFeature::Sensors,
            ResourceODataId::parse("/redfish/v1/Chassis/1/Sensors/InletTemp")?,
            ResourceSnapshotPayload::parse(&format!(
                r#"{{"Name":"InletTemp {index} v{generation}"}}"#
            ))?,
        ),
    ])
}

/// One operation offer envelope for the outbox enqueue path: a real §13
/// command serialized as the §9.4 wire payload.
fn offer_message(site: &SiteInstance) -> Result<EnvelopeMessage, Box<dyn Error>> {
    let command = RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle));
    Ok(EnvelopeMessage::OperationOffer(OperationOffer {
        operation_id: OperationId::generate().to_string(),
        endpoint_id: EndpointId::generate().to_string(),
        site_id: site.id().to_string(),
        command_json: serde_json::to_vec(&command)?,
        target: String::from("/redfish/v1/Systems/1"),
        expires_at_unix: 0,
        actor_context: String::from("stress-suite"),
    }))
}

/// The refresh-generation watermark of projection `index`: 1..=5 cycling.
fn projection_generation(index: usize) -> u64 {
    u64::try_from(index % 5).unwrap_or(0) + 1
}

/// The §15.5 projection facts one endpoint index writes, kept for the
/// read-back assertions.
struct ExpectedProjection {
    endpoint_id: EndpointId,
    display_name: String,
    address: String,
    health: String,
    refresh_generation: u64,
    site_id: InstanceId,
}

/// The projection facts of endpoint `index`, owned by `site_id`.
fn expected_projection(index: usize, site_id: InstanceId) -> ExpectedProjection {
    ExpectedProjection {
        endpoint_id: EndpointId::generate(),
        display_name: format!("E-{index:04}"),
        address: format!("https://198.51.{}.{}/redfish", index / 256, index % 256),
        health: ["ok", "degraded", "unknown"][index % 3].to_owned(),
        refresh_generation: projection_generation(index),
        site_id,
    }
}

/// The §15.5 endpoint projection of one expected endpoint: stable identity
/// and address, with the given generation watermark and health cut.
fn projection_write(
    expected: &ExpectedProjection,
    refresh_generation: u64,
    health: &str,
) -> EndpointProjectionWrite {
    let trust_mode = if refresh_generation.is_multiple_of(2) {
        CenterTrustMode::SystemCa
    } else {
        CenterTrustMode::PinnedCertificate
    };
    EndpointProjectionWrite::new(
        expected.endpoint_id,
        expected.display_name.clone(),
        expected.address.clone(),
        trust_mode,
        refresh_generation,
        health.to_owned(),
    )
}

/// The three §15.5 resource deltas of one projected endpoint.
fn resource_projections(
    expected: &ExpectedProjection,
    generation: u64,
    observed_at: OffsetDateTime,
) -> Vec<ResourceProjectionWrite> {
    vec![
        ResourceProjectionWrite::new(
            expected.endpoint_id,
            String::from("/redfish/v1/Systems/1"),
            ResourceFeature::Systems,
            Some(String::from("#ComputerSystem.v1_20_0.ComputerSystem")),
            None,
            generation,
            Some(format!(r#"{{"Name":"{} system"}}"#, expected.display_name)),
            observed_at,
        ),
        ResourceProjectionWrite::new(
            expected.endpoint_id,
            String::from("/redfish/v1/Chassis/1/Power"),
            ResourceFeature::Power,
            Some(String::from("#Power.v1_17_0.Power")),
            Some(String::from("W/\"power\"")),
            generation,
            Some(format!(r#"{{"Name":"{} power"}}"#, expected.display_name)),
            observed_at,
        ),
        ResourceProjectionWrite::new(
            expected.endpoint_id,
            String::from("/redfish/v1/Chassis/1/Thermal"),
            ResourceFeature::Thermal,
            None,
            None,
            generation,
            Some(format!(r#"{{"Name":"{} thermal"}}"#, expected.display_name)),
            observed_at,
        ),
    ]
}

// The three scale tests each spell out their exhaustive assertion sets,
// which exceeds the pedantic line budget (the repository tests allow the
// same lint on their exhaustive assertion tests).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn two_hundred_endpoints_round_trip_with_generation_consistent_refreshes()
-> Result<(), Box<dyn Error>> {
    let (directory, store) = open_store().await?;
    let key = test_key();
    let base = OffsetDateTime::now_utc();

    // §0.9.0 single-site scale: 200 endpoints, each with its own encrypted
    // credential, address, trust decision, and capability snapshot.
    let started = Instant::now();
    let mut endpoints = Vec::with_capacity(SITE_ENDPOINT_COUNT);
    for index in 0..SITE_ENDPOINT_COUNT {
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let secret: SecretString = format!("site secret {index}").into();
        let protected = encrypt_credential(&key, credential_id, version_id, &secret)?;
        store
            .create_credential(NewCredential::new(
                CredentialName::parse(&format!("Site credential {index}"))?,
                CredentialUsername::parse("administrator")?,
                protected,
            ))
            .await?;
        let created_at = base + Duration::seconds(i64::try_from(index)?);
        let endpoint = site_endpoint(credential_id, index, created_at)?;
        store
            .create_discovered_endpoint(endpoint.clone(), &capability_observations())
            .await?;
        endpoints.push(endpoint);
    }
    println!(
        "wrote {SITE_ENDPOINT_COUNT} credentials and endpoint aggregates (address, trust, capability snapshot) in {:.2}s",
        started.elapsed().as_secs_f64()
    );

    // The complete inventory round-trips: every aggregate loads back equal
    // to what was created, and every capability snapshot is intact with the
    // endpoint's own update time.
    let capabilities_expected = capability_observations();
    let started = Instant::now();
    let loaded = store.list_endpoints().await?;
    assert_eq!(loaded.len(), SITE_ENDPOINT_COUNT);
    for endpoint in &endpoints {
        assert_eq!(
            store.find_endpoint(endpoint.id()).await?,
            Some(endpoint.clone())
        );
        let capabilities = store
            .find_endpoint_capabilities(endpoint.id())
            .await?
            .ok_or("stored endpoint capabilities are missing")?;
        assert_eq!(capabilities.len(), capabilities_expected.len());
        assert!(
            capabilities_expected.iter().all(|observation| capabilities
                .iter()
                .any(|stored| stored.observation() == *observation)),
            "every written capability observation must read back"
        );
        assert!(
            capabilities
                .iter()
                .all(|stored| stored.observed_at() == endpoint.updated_at()),
            "every observation must carry the endpoint's refresh clock time"
        );
    }
    println!(
        "reloaded all {SITE_ENDPOINT_COUNT} endpoint aggregates and capability snapshots in {:.3}s",
        started.elapsed().as_secs_f64()
    );

    // §9.5: refresh commits in Generation units. The first Generation of
    // every endpoint is one atomic transaction: all snapshots carry
    // Generation 1 and one observation time.
    let started = Instant::now();
    let mut first_generations = Vec::with_capacity(SITE_ENDPOINT_COUNT);
    for (index, endpoint) in endpoints.iter().enumerate() {
        let observed_at = endpoint.updated_at() + Duration::SECOND;
        let committed = store
            .commit_resource_generation(
                endpoint.id(),
                &generation_observations(index, 1)?,
                &[],
                observed_at,
            )
            .await?;
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.generation().get() == 1),
            "the first Generation must be atomically consistent"
        );
        assert!(
            committed
                .iter()
                .all(|snapshot| snapshot.observed_at() == observed_at),
            "one Generation must carry exactly one observation time"
        );
        assert_eq!(
            committed
                .iter()
                .filter(|snapshot| snapshot.feature() == ResourceFeature::ServiceRoot)
                .count(),
            1
        );
        first_generations.push(committed);
    }
    println!(
        "committed {SITE_ENDPOINT_COUNT} first refresh generations (7 snapshots each) in {:.2}s",
        started.elapsed().as_secs_f64()
    );

    // §9.5: the second Generation replaces the current version atomically —
    // every snapshot carries Generation 2, the reloaded current view equals
    // the committed Generation, and the resource identities stay stable
    // across Generations.
    let started = Instant::now();
    for (index, endpoint) in endpoints.iter().enumerate() {
        let observed_at = endpoint.updated_at() + Duration::seconds(2);
        let second = store
            .commit_resource_generation(
                endpoint.id(),
                &generation_observations(index, 2)?,
                &[],
                observed_at,
            )
            .await?;
        assert!(
            second
                .iter()
                .all(|snapshot| snapshot.generation().get() == 2),
            "the second Generation must be atomically consistent"
        );
        assert!(
            second
                .iter()
                .all(|snapshot| snapshot.observed_at() == observed_at)
        );
        assert_eq!(
            store
                .find_current_resource_generation(endpoint.id())
                .await?,
            Some(second.clone()),
            "the current view must be exactly the committed Generation"
        );
        assert_eq!(
            second
                .iter()
                .find(|snapshot| snapshot.feature() == ResourceFeature::Systems)
                .map(ResourceSnapshot::resource_id),
            first_generations[index]
                .iter()
                .find(|snapshot| snapshot.feature() == ResourceFeature::Systems)
                .map(ResourceSnapshot::resource_id),
            "a stable @odata.id must keep its resource identity across Generations"
        );
    }
    println!(
        "committed {SITE_ENDPOINT_COUNT} second refresh generations and reloaded the current views in {:.2}s",
        started.elapsed().as_secs_f64()
    );

    // §9.5: a failed refresh never tears the current Generation. A
    // feature-changed observation rolls the whole Generation back and the
    // last complete snapshot stays the current view.
    let invalid_generation = [
        NewResourceSnapshot::new(
            ResourceFeature::Managers,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(r#"{"Name":"Changed"}"#)?,
        ),
        NewResourceSnapshot::new(
            ResourceFeature::ServiceRoot,
            ResourceODataId::parse("/redfish/v1/")?,
            ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)?,
        ),
    ];
    assert!(matches!(
        store
            .commit_resource_generation(
                endpoints[0].id(),
                &invalid_generation,
                &[],
                endpoints[0].updated_at() + Duration::seconds(3),
            )
            .await,
        Err(ResourceSnapshotRepositoryError::FeatureChanged {
            stored: ResourceFeature::Systems,
            observed: ResourceFeature::Managers,
            ..
        })
    ));
    let current = store
        .find_current_resource_generation(endpoints[0].id())
        .await?
        .ok_or("endpoint disappeared")?;
    assert!(
        current
            .iter()
            .all(|snapshot| snapshot.generation().get() == 2),
        "a failed refresh must preserve the last complete Generation"
    );

    // Exact row counts: 200 credentials, 200 endpoint aggregates of five
    // rows each, 8 capabilities per endpoint, and exactly two complete
    // Generations per endpoint (7 resources x 14 snapshots).
    let database = counting_connection(directory.path()).await?;
    let endpoint_rows = u64::try_from(SITE_ENDPOINT_COUNT)?;
    let capability_rows = u64::try_from(SITE_ENDPOINT_COUNT * CAPABILITY_OBSERVATION_COUNT)?;
    assert_eq!(
        credential::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        credential_version::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint_address::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint_trust::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint_credential::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint_capability::Entity::find().count(&database).await?,
        capability_rows
    );
    assert_eq!(resource::Entity::find().count(&database).await?, 1_400_u64);
    assert_eq!(
        resource_snapshot::Entity::find().count(&database).await?,
        2_800_u64
    );

    store.close().await?;
    Ok(())
}

// The exhaustive per-site assertions exceed the pedantic line budget (the
// repository tests allow the same lint on their exhaustive assertion tests).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn one_hundred_sites_advance_outbox_inbox_and_sync_cursors() -> Result<(), Box<dyn Error>> {
    let (directory, store) = open_store().await?;
    let base = OffsetDateTime::now_utc();

    // §0.9.0 single-center scale: 100 registered sites.
    let started = Instant::now();
    let mut sites = Vec::with_capacity(CENTER_SITE_COUNT);
    for index in 0..CENTER_SITE_COUNT {
        let site = SiteInstance::new(
            InstanceId::generate(),
            format!("Site {index:03}"),
            InstanceKind::Site,
            base + Duration::minutes(i64::try_from(index)?),
        );
        store.create_instance(&site).await?;
        sites.push(site);
    }
    println!(
        "created {CENTER_SITE_COUNT} site instances in {:.2}s",
        started.elapsed().as_secs_f64()
    );

    // Outbox: 10 envelopes per site through the production enqueue path —
    // the per-instance sequence allocation, the §9.4 payload serialization,
    // and the at-rest protection.
    let started = Instant::now();
    let mut enqueued = Vec::with_capacity(CENTER_SITE_COUNT);
    for (site_index, site) in sites.iter().enumerate() {
        let mut entries = Vec::with_capacity(OUTBOX_PER_SITE);
        for sequence in 0..OUTBOX_PER_SITE {
            let message = offer_message(site)?;
            let created_at =
                base + Duration::seconds(i64::try_from(site_index * OUTBOX_PER_SITE + sequence)?);
            entries.push(
                store
                    .enqueue_outbox_entry(site.id(), &message, created_at)
                    .await?,
            );
        }
        enqueued.push(entries);
    }
    println!(
        "enqueued {} outbox envelopes ({CENTER_SITE_COUNT} sites x {OUTBOX_PER_SITE}) in {:.2}s",
        CENTER_SITE_COUNT * OUTBOX_PER_SITE,
        started.elapsed().as_secs_f64()
    );

    // §15.2: acknowledging five envelopes per site moves them out of the
    // delivery scan, and a repeated Ack is a no-op, never an error.
    let started = Instant::now();
    for entries in &enqueued {
        for entry in entries.iter().take(OUTBOX_ACK_PER_SITE) {
            assert_eq!(
                store
                    .ack_outbox_entry(entry.id(), entry.created_at() + Duration::SECOND)
                    .await?,
                AckOutcome::Acknowledged
            );
        }
        assert_eq!(
            store
                .ack_outbox_entry(entries[0].id(), entries[0].created_at() + Duration::SECOND,)
                .await?,
            AckOutcome::AlreadyAcknowledged,
            "a repeated Ack must be an idempotent no-op"
        );
    }
    println!(
        "acknowledged {} outbox envelopes ({OUTBOX_ACK_PER_SITE} per site) in {:.3}s",
        CENTER_SITE_COUNT * OUTBOX_ACK_PER_SITE,
        started.elapsed().as_secs_f64()
    );

    // §17: every site's queue is sequence-ordered, the next allocation
    // continues after the stored maximum, and acked entries leave the
    // pending scan without leaking into another site's.
    let outbox_per_site = u64::try_from(OUTBOX_PER_SITE)?;
    let expected_sequences = (1_i64..=i64::try_from(OUTBOX_PER_SITE)?).collect::<Vec<_>>();
    for site in &sites {
        assert_eq!(
            store.next_outbox_sequence(site.id()).await?,
            i64::try_from(OUTBOX_PER_SITE)? + 1,
            "the per-instance sequence allocation must continue after the maximum"
        );
        let pending = store
            .list_pending_outbox(site.id(), outbox_per_site)
            .await?;
        assert_eq!(
            pending
                .iter()
                .map(OutboxEntry::sequence)
                .collect::<Vec<_>>(),
            expected_sequences[OUTBOX_ACK_PER_SITE..],
            "the pending scan must replay the unacked sequences in order"
        );
        let all = store.list_outbox_entries(site.id()).await?;
        assert_eq!(all.len(), OUTBOX_PER_SITE);
        assert_eq!(
            all.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            expected_sequences
        );
    }

    // §17.5 inbox: the operation id is the idempotency key. One entry per
    // site walks the full lifecycle — the in-progress duplicate is parked,
    // the progress re-delivery is a no-op, and the resolved duplicate is
    // answered with the recorded outcome instead of a second execution.
    let started = Instant::now();
    let mut resolved_operations = Vec::with_capacity(CENTER_SITE_COUNT);
    for site in &sites {
        let operation_id = OperationId::generate();
        let received_at = base + Duration::hours(i64::try_from(sites.len())?);
        let entry = InboxEntry::new(
            InboxEntryId::generate(),
            operation_id,
            site.id(),
            format!(r#"{{"operation_id":"{operation_id}"}}"#),
            received_at + Duration::hours(1),
            received_at,
        );
        assert_eq!(
            store.create_inbox_entry(&entry).await?,
            CreateInboxOutcome::Created
        );
        assert_eq!(
            store.create_inbox_entry(&entry).await?,
            CreateInboxOutcome::DuplicateInProgress
        );
        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::Advanced(InboxEntryState::Accepted)
        );
        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::AlreadyInState,
            "a repeated progress envelope must be a no-op"
        );
        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Completed)
                .await?,
            InboxAdvanceOutcome::Advanced(InboxEntryState::Completed)
        );
        assert_eq!(
            store.create_inbox_entry(&entry).await?,
            CreateInboxOutcome::DuplicateResolved(InboxEntryState::Completed)
        );
        resolved_operations.push(operation_id);
        for index in 1..INBOX_PER_SITE {
            let operation_id = OperationId::generate();
            let entry = InboxEntry::new(
                InboxEntryId::generate(),
                operation_id,
                site.id(),
                format!(r#"{{"operation_id":"{operation_id}"}}"#),
                received_at + Duration::hours(i64::try_from(index)?),
                received_at,
            );
            assert_eq!(
                store.create_inbox_entry(&entry).await?,
                CreateInboxOutcome::Created
            );
        }
    }
    for operation_id in &resolved_operations {
        let stored = store
            .find_inbox_entry_by_operation(*operation_id)
            .await?
            .ok_or("stored inbox entry is missing")?;
        assert_eq!(stored.state(), InboxEntryState::Completed);
    }
    println!(
        "advanced {CENTER_SITE_COUNT} inbox idempotency lifecycles ({INBOX_PER_SITE} entries per site) in {:.2}s",
        started.elapsed().as_secs_f64()
    );

    // §17 sync cursors: every site advances its four streams twice; the
    // upsert keeps exactly one row per (site, stream) with the latest value.
    let started = Instant::now();
    for site in &sites {
        for stream in CURSOR_STREAMS {
            let first = SyncCursor::new(
                SyncCursorId::generate(),
                site.id(),
                stream,
                String::from("100"),
                base,
            );
            store.set_sync_cursor(&first).await?;
            let second = SyncCursor::new(
                SyncCursorId::generate(),
                site.id(),
                stream,
                String::from("200"),
                base + Duration::SECOND,
            );
            store.set_sync_cursor(&second).await?;
            let stored = store
                .get_sync_cursor(site.id(), stream)
                .await?
                .ok_or("stored sync cursor is missing")?;
            assert_eq!(stored.cursor_value(), "200");
            assert_eq!(stored.updated_at(), base + Duration::SECOND);
            assert_eq!(stored.id(), first.id(), "the upsert keeps the original row");
        }
    }
    println!(
        "set {} sync cursors ({CENTER_SITE_COUNT} sites x {} streams x 2 advances) in {:.2}s",
        CENTER_SITE_COUNT * CURSOR_STREAMS.len() * 2,
        CURSOR_STREAMS.len(),
        started.elapsed().as_secs_f64()
    );

    // Exact row counts: one row per instance, envelope, inbox entry, and
    // cursor — nothing doubled by the idempotent writes above.
    let database = counting_connection(directory.path()).await?;
    let site_rows = u64::try_from(CENTER_SITE_COUNT)?;
    let outbox_rows = u64::try_from(CENTER_SITE_COUNT * OUTBOX_PER_SITE)?;
    let inbox_rows = u64::try_from(CENTER_SITE_COUNT * INBOX_PER_SITE)?;
    let cursor_rows = u64::try_from(CENTER_SITE_COUNT * CURSOR_STREAMS.len())?;
    assert_eq!(instance::Entity::find().count(&database).await?, site_rows);
    assert_eq!(
        center_outbox::Entity::find().count(&database).await?,
        outbox_rows
    );
    assert_eq!(
        center_inbox::Entity::find().count(&database).await?,
        inbox_rows
    );
    assert_eq!(
        sync_cursor::Entity::find().count(&database).await?,
        cursor_rows
    );

    store.close().await?;
    Ok(())
}

// The exhaustive write/read/redelivery/delete assertions exceed the pedantic
// line budget (the repository tests allow the same lint on their exhaustive
// assertion tests).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn five_thousand_endpoint_projections_round_trip_at_the_center() -> Result<(), Box<dyn Error>>
{
    let (directory, store) = open_store().await?;
    let base = OffsetDateTime::now_utc();

    let mut sites = Vec::with_capacity(CENTER_SITE_COUNT);
    for index in 0..CENTER_SITE_COUNT {
        let site = SiteInstance::new(
            InstanceId::generate(),
            format!("Site {index:03}"),
            InstanceKind::Site,
            base + Duration::minutes(i64::try_from(index)?),
        );
        store.create_instance(&site).await?;
        sites.push(site);
    }

    // §0.9.0 center scale: 5,000 endpoint projections — 50 per site, unique
    // addresses, distinct generation watermarks and health cuts (§15.5).
    let started = Instant::now();
    let mut expected_projections = Vec::with_capacity(CENTER_ENDPOINT_COUNT);
    for index in 0..CENTER_ENDPOINT_COUNT {
        let site_id = sites[index / PROJECTIONS_PER_SITE].id();
        let expected = expected_projection(index, site_id);
        let projection = projection_write(&expected, expected.refresh_generation, &expected.health);
        assert_eq!(
            store
                .upsert_endpoint_projection(&projection, site_id, base)
                .await?,
            ProjectionWriteOutcome::Applied
        );
        expected_projections.push(expected);
    }
    println!(
        "upserted {CENTER_ENDPOINT_COUNT} endpoint projections ({CENTER_SITE_COUNT} sites x {PROJECTIONS_PER_SITE}) in {:.2}s",
        started.elapsed().as_secs_f64()
    );

    // §15.5 endpoint view: the 5,000-row list and the per-site listing agree
    // with exactly what was written — identity, site, address, health, and
    // the refresh-generation watermark.
    let started = Instant::now();
    let listed = store.list_projected_endpoints(None).await?;
    assert_eq!(listed.len(), CENTER_ENDPOINT_COUNT);
    let by_display_name = listed
        .iter()
        .map(|summary| (summary.display_name().to_owned(), summary))
        .collect::<HashMap<String, &ProjectedEndpointSummary>>();
    for expected in &expected_projections {
        let summary = by_display_name
            .get(&expected.display_name)
            .ok_or("projected endpoint summary is missing")?;
        assert_eq!(summary.endpoint_id(), expected.endpoint_id);
        assert_eq!(summary.site_id(), Some(expected.site_id));
        assert_eq!(summary.address(), expected.address);
        assert_eq!(summary.health(), expected.health);
        assert_eq!(summary.refresh_generation(), expected.refresh_generation);
    }
    let per_site_count = u64::try_from(PROJECTIONS_PER_SITE)?;
    for site in &sites {
        let per_site = store.list_projected_endpoints(Some(site.id())).await?;
        assert_eq!(per_site.len(), PROJECTIONS_PER_SITE);
        assert!(
            per_site
                .iter()
                .all(|summary| summary.site_id() == Some(site.id()))
        );
        let (count, last_refresh_at) = store.center_site_projection_summary(site.id()).await?;
        assert_eq!(count, per_site_count);
        assert!(
            last_refresh_at.is_some(),
            "every site must expose a last-refresh watermark"
        );
    }
    println!(
        "listed {CENTER_ENDPOINT_COUNT} projected endpoint summaries ({CENTER_SITE_COUNT} per-site views) in {:.3}s",
        started.elapsed().as_secs_f64()
    );

    // §15.4 at-least-once redelivery: re-upserting every projection with a
    // newer generation watermark is applied in place — the row counts never
    // double and the listed watermarks advance.
    let started = Instant::now();
    for expected in &expected_projections {
        let projection = projection_write(expected, expected.refresh_generation + 10, "ok");
        assert_eq!(
            store
                .upsert_endpoint_projection(&projection, expected.site_id, base + Duration::SECOND)
                .await?,
            ProjectionWriteOutcome::Applied
        );
    }
    println!(
        "re-upserted {CENTER_ENDPOINT_COUNT} endpoint projections (at-least-once redelivery) in {:.2}s",
        started.elapsed().as_secs_f64()
    );
    let listed = store.list_projected_endpoints(None).await?;
    assert_eq!(
        listed.len(),
        CENTER_ENDPOINT_COUNT,
        "redelivery must never double a projection row"
    );
    let by_display_name = listed
        .iter()
        .map(|summary| (summary.display_name().to_owned(), summary))
        .collect::<HashMap<String, &ProjectedEndpointSummary>>();
    for expected in &expected_projections {
        let summary = by_display_name
            .get(&expected.display_name)
            .ok_or("projected endpoint summary is missing")?;
        assert_eq!(
            summary.refresh_generation(),
            expected.refresh_generation + 10,
            "the redelivered projection must replace the watermark in place"
        );
    }

    // §15.5 site scoping: one site's frame can never overwrite another
    // site's projection — the conflicting write is absorbed, and a unique
    // address conflict rolls the whole write back. Endpoint 0 belongs to
    // site 0; endpoint `PROJECTIONS_PER_SITE` belongs to site 1.
    let cross_site = projection_write(&expected_projections[0], 99, "ok");
    let other_site = expected_projections[PROJECTIONS_PER_SITE].site_id;
    assert!(matches!(
        store
            .upsert_endpoint_projection(&cross_site, other_site, base)
            .await,
        Ok(ProjectionWriteOutcome::Ignored {
            reason: ProjectionIgnoreReason::EndpointBelongsToOtherSite
        })
    ));
    let stored = store
        .find_endpoint_projection(expected_projections[0].endpoint_id)
        .await?
        .ok_or("projected endpoint is missing")?;
    assert_eq!(stored.site_id(), Some(expected_projections[0].site_id));
    let address_conflict = EndpointProjectionWrite::new(
        EndpointId::generate(),
        String::from("Address conflict"),
        expected_projections[0].address.clone(),
        CenterTrustMode::SystemCa,
        1,
        String::from("ok"),
    );
    assert!(matches!(
        store
            .upsert_endpoint_projection(&address_conflict, expected_projections[0].site_id, base)
            .await,
        Ok(ProjectionWriteOutcome::Ignored {
            reason: ProjectionIgnoreReason::AddressAlreadyProjected
        })
    ));

    // §15.5 resource deltas: 200 endpoints x 3 resources = 600 identity and
    // snapshot rows; the same-generation redelivery replaces in place, and
    // the next generation appends its own snapshot rows.
    let started = Instant::now();
    for expected in expected_projections
        .iter()
        .take(RESOURCE_PROJECTED_ENDPOINTS)
    {
        for resource in resource_projections(expected, 1, base + Duration::SECOND) {
            assert_eq!(
                store
                    .upsert_resource_projection(
                        &resource,
                        expected.site_id,
                        base + Duration::SECOND
                    )
                    .await?,
                ProjectionWriteOutcome::Applied
            );
        }
    }
    for expected in expected_projections
        .iter()
        .take(RESOURCE_PROJECTED_ENDPOINTS)
    {
        for resource in resource_projections(expected, 1, base + Duration::SECOND) {
            store
                .upsert_resource_projection(&resource, expected.site_id, base + Duration::SECOND)
                .await?;
        }
    }
    println!(
        "upserted {} resource projections ({RESOURCE_PROJECTED_ENDPOINTS} endpoints x {RESOURCES_PER_ENDPOINT}, plus the idempotent redelivery) in {:.2}s",
        RESOURCE_PROJECTED_ENDPOINTS * RESOURCES_PER_ENDPOINT,
        started.elapsed().as_secs_f64()
    );
    for expected in expected_projections
        .iter()
        .take(RESOURCE_PROJECTED_ENDPOINTS)
    {
        assert!(
            store
                .has_resource_projection(expected.endpoint_id, "/redfish/v1/Systems/1")
                .await?
        );
        assert!(
            store
                .has_resource_projection(expected.endpoint_id, "/redfish/v1/Chassis/1/Power")
                .await?
        );
        assert!(
            store
                .has_resource_projection(expected.endpoint_id, "/redfish/v1/Chassis/1/Thermal")
                .await?
        );
    }
    let started = Instant::now();
    for expected in expected_projections
        .iter()
        .take(RESOURCE_PROJECTED_ENDPOINTS)
    {
        for resource in resource_projections(expected, 2, base + Duration::seconds(2)) {
            store
                .upsert_resource_projection(
                    &resource,
                    expected.site_id,
                    base + Duration::seconds(2),
                )
                .await?;
        }
    }
    println!(
        "appended generation 2 to {} resource projections in {:.2}s",
        RESOURCE_PROJECTED_ENDPOINTS * RESOURCES_PER_ENDPOINT,
        started.elapsed().as_secs_f64()
    );
    // A resource delta naming another site's endpoint is absorbed, and one
    // naming an unknown endpoint too.
    let cross_site_resources = resource_projections(&expected_projections[0], 1, base);
    assert!(matches!(
        store
            .upsert_resource_projection(&cross_site_resources[0], other_site, base)
            .await,
        Ok(ProjectionWriteOutcome::Ignored {
            reason: ProjectionIgnoreReason::EndpointBelongsToOtherSite
        })
    ));
    let unknown_resource = ResourceProjectionWrite::new(
        EndpointId::generate(),
        String::from("/redfish/v1/Systems/1"),
        ResourceFeature::Systems,
        None,
        None,
        1,
        Some(String::from(r#"{"Name":"Unknown"}"#)),
        base,
    );
    assert!(matches!(
        store
            .upsert_resource_projection(&unknown_resource, other_site, base)
            .await,
        Ok(ProjectionWriteOutcome::Ignored {
            reason: ProjectionIgnoreReason::UnknownEndpoint
        })
    ));

    // §21 endpoint-level deletes converge the projection: 50 deletes, the
    // repeated delete is an idempotent no-op, and deleting one resource
    // bearing endpoint cascades its resource rows away.
    let started = Instant::now();
    for index in 0..DELETED_PROJECTION_COUNT {
        let item = &expected_projections[CENTER_ENDPOINT_COUNT - 1 - index];
        assert_eq!(
            store
                .delete_endpoint_projection(item.endpoint_id, item.site_id)
                .await?,
            ProjectionWriteOutcome::Applied
        );
    }
    let last = &expected_projections[CENTER_ENDPOINT_COUNT - 1];
    assert_eq!(
        store
            .delete_endpoint_projection(last.endpoint_id, last.site_id)
            .await?,
        ProjectionWriteOutcome::Applied,
        "deleting a projection that is already gone must stay idempotent"
    );
    println!(
        "deleted {DELETED_PROJECTION_COUNT} endpoint projections (plus one idempotent repeat) in {:.3}s",
        started.elapsed().as_secs_f64()
    );
    assert_eq!(
        store
            .delete_endpoint_projection(
                expected_projections[0].endpoint_id,
                expected_projections[0].site_id,
            )
            .await?,
        ProjectionWriteOutcome::Applied
    );
    let listed = store.list_projected_endpoints(None).await?;
    assert_eq!(
        listed.len(),
        CENTER_ENDPOINT_COUNT - DELETED_PROJECTION_COUNT - 1
    );

    // Exact row counts: every projection write, redelivery, scoped refusal,
    // and delete lands exactly once in the shared tables.
    let database = counting_connection(directory.path()).await?;
    let endpoint_rows = u64::try_from(CENTER_ENDPOINT_COUNT - DELETED_PROJECTION_COUNT - 1)?;
    let resource_rows = u64::try_from(
        RESOURCE_PROJECTED_ENDPOINTS * RESOURCES_PER_ENDPOINT - RESOURCES_PER_ENDPOINT,
    )?;
    let snapshot_rows = u64::try_from(
        RESOURCE_PROJECTED_ENDPOINTS * RESOURCES_PER_ENDPOINT * 2 - RESOURCES_PER_ENDPOINT * 2,
    )?;
    assert_eq!(
        endpoint::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint_address::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        endpoint_trust::Entity::find().count(&database).await?,
        endpoint_rows
    );
    assert_eq!(
        resource::Entity::find().count(&database).await?,
        resource_rows
    );
    assert_eq!(
        resource_snapshot::Entity::find().count(&database).await?,
        snapshot_rows
    );

    store.close().await?;
    Ok(())
}
