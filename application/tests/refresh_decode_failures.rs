#![forbid(unsafe_code)]

//! Through-path tests for the §12.4 decode-failure capture (§19 test
//! layering: application integration tier).
//!
//! The production chain under test: the typed core read's outcome carries
//! every member-level decode failure (the infra gateway captures these as
//! `DecodeFailureObservation` records), the refresh commits them in the same
//! transaction as the resource snapshots
//! (`application/src/endpoint_refresh.rs:350-355` hands
//! `outcome.decode_failures()` to `commit_resource_generation`), and the
//! persistence store writes them to `resource_decode_failures` keyed by the
//! same Generation (`persistence/src/resource_snapshot_repository.rs:81-147`).
//! The endpoint stays fully usable: the undecodable member is skipped as one
//! odd member (§0.2.0) while the record keeps the skipped path visible.
//!
//! Unlike the Web end-to-end suite (`web/tests/diagnostics_path.rs`, which
//! serves every boundary from in-memory fakes) and the gateway unit tests,
//! this file composes the real `EndpointRefresh` use case with the real
//! `SqliteStore`, so the same-generation transaction and its atomic
//! visibility (§9.5) are pinned through the production pipeline — the gap
//! registered in `docs/known-limitations.md` §九.

use std::{
    error::Error,
    fmt,
    sync::{Arc, Mutex},
};

use rutilus_application::{
    BoundaryFuture, CapabilityQueryRepository, Clock, CoreResourceReadOutcome, CoreResourceReader,
    CredentialResolver, EndpointDiscovery, EndpointRefresh, EndpointRefreshError, RedfishDiscovery,
    ResolvedCredential, ResourceDecodeFailure, ResourceExtendedInfo, ResourceObservation,
};
use rutilus_domain::{
    CAPABILITY_LEDGER_ORDER, CapabilityState, CredentialId, CredentialName, CredentialUsername,
    CredentialVersionId, Endpoint, EndpointAddress, EndpointCapabilityObservation,
    EndpointDisplayName, EndpointId, RefreshGeneration, ResourceFeature, ResourceODataId,
    ResourceSnapshotPayload, TlsCertificate, TlsTrust,
};
use rutilus_persistence::{
    EndpointRefreshPersistenceError, NewCredential, ResourceSnapshotRepositoryError, SqliteStore,
};
use rutilus_security::{MasterKey, encrypt_credential};
use secrecy::SecretString;
use time::{Duration, OffsetDateTime};

/// A refresh whose typed core read decodes every member but one: the mock
/// BMC serves a Systems collection whose second member cannot be decoded
/// into the compiled schema, so that member is skipped (§0.2.0) and the
/// capture record travels with the read outcome into the refresh pipeline.
///
/// The capture mirrors the infra gateway's member-level capture
/// (`infra-redfish/src/redfish_gateway.rs` `capture_*` helpers): the record
/// carries no `@odata.type` — the gateway capture sites never retain it
/// (known-limitations §八 note) — and a standard feature carries no OEM
/// namespace.
struct CaptureReader {
    events: Arc<Mutex<Vec<&'static str>>>,
    undecodable_member: bool,
    probe_succeeds: bool,
}

impl CaptureReader {
    fn capturing(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            events,
            undecodable_member: true,
            probe_succeeds: true,
        }
    }

    /// A mock BMC whose core read decodes every member: the Generation
    /// commits no decode-failure record.
    fn clean(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            events,
            undecodable_member: false,
            probe_succeeds: true,
        }
    }

    /// A capturing read whose capability re-probe fails after the resource
    /// Generation committed (§9.5: the last complete snapshot — and its
    /// records — is retained).
    fn fail_probe(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
        Self {
            events,
            undecodable_member: true,
            probe_succeeds: false,
        }
    }
}

impl CoreResourceReader for CaptureReader {
    type Error = MockError;

    fn read_core_resources<'a>(
        &'a self,
        _address: &'a EndpointAddress,
        _trust: &'a TlsTrust,
        _username: &'a CredentialUsername,
        _password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<CoreResourceReadOutcome, Self::Error>> {
        let events = Arc::clone(&self.events);
        let undecodable_member = self.undecodable_member;
        Box::pin(async move {
            record(&events, "read")?;
            let observations = observations().map_err(|_| MockError::Reader)?;
            let mut captures = Vec::new();
            if undecodable_member {
                capture_undecodable_member(&mut captures, &events)?;
            }
            Ok(CoreResourceReadOutcome::new(observations, captures))
        })
    }
}

impl RedfishDiscovery for CaptureReader {
    type Error = MockError;

    fn probe_core_capabilities<'a>(
        &'a self,
        _address: &'a EndpointAddress,
        _trust: &'a TlsTrust,
        _username: &'a CredentialUsername,
        _password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
        let events = Arc::clone(&self.events);
        let probe_succeeds = self.probe_succeeds;
        Box::pin(async move {
            record(&events, "probe")?;
            if probe_succeeds {
                Ok(EndpointDiscovery::new(capability_observations()))
            } else {
                Err(MockError::Reader)
            }
        })
    }
}

/// Captures one member whose document cannot be decoded into the compiled
/// schema, exactly like the gateway's member-level capture helpers: the
/// record is produced by the read itself (never fabricated at the commit
/// boundary) and keeps the skipped path visible to diagnostics.
fn capture_undecodable_member(
    captures: &mut Vec<ResourceDecodeFailure>,
    events: &Mutex<Vec<&'static str>>,
) -> Result<(), MockError> {
    record(events, "capture")?;
    captures.push(
        ResourceDecodeFailure::try_new(
            ResourceODataId::parse("/redfish/v1/Systems/2").map_err(|_| MockError::Reader)?,
            // The gateway capture sites never retain the failed document's
            // `@odata.type` (known-limitations §八 note).
            None,
            ResourceFeature::Systems,
            // A standard feature carries no OEM namespace
            // (`oem_namespace_for(ResourceFeature::Systems)` is `None`).
            None,
            "the member document is incompatible with the compiled schema".to_owned(),
            vec![ResourceExtendedInfo::new(
                "Base.1.13.ResourceNotFound".to_owned(),
                Some("The requested resource could not be found.".to_owned()),
                Some("Critical".to_owned()),
                Some("Remove and re-add the resource.".to_owned()),
                vec!["MemberId".to_owned()],
            )],
        )
        .map_err(|_| MockError::Reader)?,
    );
    Ok(())
}

struct MockCredentials {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl CredentialResolver for MockCredentials {
    type Error = MockError;

    fn resolve(
        &self,
        _credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        let events = Arc::clone(&self.events);
        Box::pin(async move {
            record(&events, "credential")?;
            Ok(Some(ResolvedCredential::new(
                CredentialUsername::parse("administrator").map_err(|_| MockError::Credential)?,
                String::from("secret").into(),
            )))
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockError {
    Events,
    Credential,
    Reader,
}

impl fmt::Display for MockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "mock {self:?} failure")
    }
}

impl Error for MockError {}

struct FixedClock(OffsetDateTime);

impl Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

#[tokio::test]
async fn refresh_commits_captured_decode_failures_with_the_generation() -> Result<(), Box<dyn Error>>
{
    let events = Arc::new(Mutex::new(Vec::new()));
    let (directory, store, endpoint, created_at) = store_with_endpoint().await?;
    let endpoint_id = endpoint.id();
    let observed_at = created_at + Duration::SECOND;
    let service = EndpointRefresh::new(
        &store,
        MockCredentials {
            events: Arc::clone(&events),
        },
        CaptureReader::capturing(Arc::clone(&events)),
        FixedClock(observed_at),
    );

    let snapshots = service.execute(endpoint_id).await?;

    assert_eq!(snapshots.len(), 2);
    let generation = snapshots[0].generation();
    assert_eq!(
        generation.get(),
        1,
        "the first refresh commits Generation 1"
    );
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.generation() == generation),
        "one refresh commits exactly one Generation"
    );
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.observed_at() == observed_at),
        "every committed snapshot carries the refresh clock time"
    );
    assert_eq!(
        recorded(&events)?,
        ["credential", "read", "capture", "probe"],
        "the member capture must run inside the read, and the Generation must commit before the capability probe"
    );
    // The refresh result is exactly the committed Generation: the snapshots
    // and the decode-failure records are atomically visible together (§9.5).
    assert_eq!(
        store.find_current_resource_generation(endpoint_id).await?,
        Some(snapshots)
    );
    assert_eq!(
        store
            .find_current_decode_failures(endpoint_id, generation)
            .await?,
        vec![decode_failure()?],
        "the capture record must land in `resource_decode_failures` with exactly the Generation of the snapshots"
    );
    // The complete pipeline also replaced the endpoint's capability snapshot
    // at the refresh clock time.
    assert_eq!(
        CapabilityQueryRepository::find_endpoint_capabilities(&store, endpoint_id)
            .await?
            .map(|capabilities| capabilities.len()),
        Some(CAPABILITY_LEDGER_ORDER.len())
    );

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn failed_generation_commit_drops_captured_decode_failures_with_the_snapshots()
-> Result<(), Box<dyn Error>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (directory, store, endpoint, created_at) = store_with_endpoint().await?;
    let endpoint_id = endpoint.id();
    // The refresh clock predates the endpoint, so the same-generation commit
    // is refused mid-transaction (§9.5 keeps the last complete snapshot): the
    // captured decode-failure record must roll back with the Generation it
    // describes.
    let service = EndpointRefresh::new(
        &store,
        MockCredentials {
            events: Arc::clone(&events),
        },
        CaptureReader::capturing(Arc::clone(&events)),
        FixedClock(created_at - Duration::SECOND),
    );

    let result = service.execute(endpoint_id).await;

    assert!(matches!(
        result,
        Err(EndpointRefreshError::Commit(
            EndpointRefreshPersistenceError::Snapshot(
                ResourceSnapshotRepositoryError::ObservationPredatesEndpoint { endpoint_id: id }
            )
        )) if id == endpoint_id
    ));
    assert_eq!(
        recorded(&events)?,
        ["credential", "read", "capture"],
        "the failed commit must stop the refresh before the capability probe"
    );
    assert_eq!(
        store.find_current_resource_generation(endpoint_id).await?,
        Some(Vec::new()),
        "no snapshot of the failed Generation may persist"
    );
    assert_eq!(
        store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
            .await?,
        Vec::new(),
        "the failed Generation's records must roll back with the snapshots"
    );

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn capability_probe_failure_keeps_the_committed_generation_and_its_records()
-> Result<(), Box<dyn Error>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (directory, store, endpoint, created_at) = store_with_endpoint().await?;
    let endpoint_id = endpoint.id();
    let observed_at = created_at + Duration::SECOND;
    let service = EndpointRefresh::new(
        &store,
        MockCredentials {
            events: Arc::clone(&events),
        },
        CaptureReader::fail_probe(Arc::clone(&events)),
        FixedClock(observed_at),
    );

    let result = service.execute(endpoint_id).await;

    assert!(matches!(
        result,
        Err(EndpointRefreshError::CapabilityProbe(MockError::Reader))
    ));
    assert_eq!(
        recorded(&events)?,
        ["credential", "read", "capture", "probe"]
    );
    // §9.5 / §13.7: the resource Generation committed before the probe
    // failed, so the snapshots and their decode-failure records stay
    // atomically visible even though the refresh reports failure.
    let snapshots = store
        .find_current_resource_generation(endpoint_id)
        .await?
        .ok_or("the committed Generation must be retained")?;
    assert_eq!(snapshots.len(), 2);
    assert!(
        snapshots
            .iter()
            .all(|snapshot| snapshot.generation().get() == 1)
    );
    assert_eq!(
        store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
            .await?,
        vec![decode_failure()?]
    );
    // The capability snapshot was never replaced: the failed probe retained
    // the previous snapshot (none existed) instead of overwriting it.
    assert_eq!(
        CapabilityQueryRepository::find_endpoint_capabilities(&store, endpoint_id).await?,
        Some(Vec::new())
    );

    store.close().await?;
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn records_stay_scoped_to_their_generation_across_refreshes() -> Result<(), Box<dyn Error>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (directory, store, endpoint, created_at) = store_with_endpoint().await?;
    let endpoint_id = endpoint.id();
    let clean_refresh_at = created_at + Duration::SECOND;
    let capturing_refresh_at = created_at + Duration::seconds(2);

    // First refresh: every member decodes, so the Generation commits an
    // empty record set through the same outcome wire.
    let clean = EndpointRefresh::new(
        &store,
        MockCredentials {
            events: Arc::clone(&events),
        },
        CaptureReader::clean(Arc::clone(&events)),
        FixedClock(clean_refresh_at),
    );
    let first = clean.execute(endpoint_id).await?;
    assert!(
        first
            .iter()
            .all(|snapshot| snapshot.generation().get() == 1)
    );
    assert_eq!(
        store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
            .await?,
        Vec::new()
    );

    // Second refresh: one member cannot be decoded; its capture record lands
    // with Generation 2, and the clean Generation 1 stays record-free — a
    // stale record from an older Generation can never ride along with a
    // newer one (records are managed by Generation, not accumulated).
    let capturing = EndpointRefresh::new(
        &store,
        MockCredentials {
            events: Arc::clone(&events),
        },
        CaptureReader::capturing(Arc::clone(&events)),
        FixedClock(capturing_refresh_at),
    );
    let second = capturing.execute(endpoint_id).await?;
    assert!(
        second
            .iter()
            .all(|snapshot| snapshot.generation().get() == 2)
    );
    assert_eq!(
        store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(2)?)
            .await?,
        vec![decode_failure()?]
    );
    assert_eq!(
        store
            .find_current_decode_failures(endpoint_id, RefreshGeneration::new(1)?)
            .await?,
        Vec::new(),
        "the clean Generation must stay record-free after the next refresh"
    );

    store.close().await?;
    drop(directory);
    Ok(())
}

/// Opens a migrated store holding one real credential and one managed
/// endpoint, exactly like the production enrollment shape: the refresh's
/// endpoint lookup and the same-generation commit run against real rows.
async fn store_with_endpoint()
-> Result<(tempfile::TempDir, SqliteStore, Endpoint, OffsetDateTime), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
    let credential_id = CredentialId::generate();
    let version_id = CredentialVersionId::generate();
    let key = MasterKey::from_boxed_bytes(Box::new([0x64; 32]));
    let secret = SecretString::from(String::from("refresh decode-failure test secret"));
    let protected = encrypt_credential(&key, credential_id, version_id, &secret)?;
    store
        .create_credential(NewCredential::new(
            CredentialName::parse("Refresh decode-failure credential")?,
            CredentialUsername::parse("administrator")?,
            protected,
        ))
        .await?;
    let created_at = OffsetDateTime::now_utc();
    let endpoint = Endpoint::try_new(
        EndpointId::generate(),
        EndpointDisplayName::parse("Refresh decode-failure BMC")?,
        EndpointAddress::parse("https://192.0.2.90")?,
        TlsTrust::PinnedCertificate {
            certificate: TlsCertificate::from_der(b"refresh decode-failure certificate".to_vec())?,
            trusted_at: created_at,
        },
        credential_id,
        created_at,
        created_at,
    )?;
    store.create_endpoint(endpoint.clone()).await?;
    Ok((directory, store, endpoint, created_at))
}

/// The decoded members of the mock BMC's core surface: the mandatory Service
/// Root plus one typed System. The second System member never reaches the
/// outcome — it is the capture's subject instead.
fn observations() -> Result<Vec<ResourceObservation>, Box<dyn Error>> {
    Ok(vec![
        ResourceObservation::new(
            ResourceFeature::ServiceRoot,
            ResourceODataId::parse("/redfish/v1")?,
            ResourceSnapshotPayload::parse(r#"{"Id":"RootService","Name":"Root"}"#)?,
        ),
        ResourceObservation::new(
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(r#"{"Id":"1","Name":"System One"}"#)?,
        ),
    ])
}

/// The exact §12.4 record the capture produces for the undecodable System
/// member: the assertion target for the persisted round-trip.
fn decode_failure() -> Result<ResourceDecodeFailure, Box<dyn Error>> {
    Ok(ResourceDecodeFailure::try_new(
        ResourceODataId::parse("/redfish/v1/Systems/2")?,
        None,
        ResourceFeature::Systems,
        None,
        "the member document is incompatible with the compiled schema".to_owned(),
        vec![ResourceExtendedInfo::new(
            "Base.1.13.ResourceNotFound".to_owned(),
            Some("The requested resource could not be found.".to_owned()),
            Some("Critical".to_owned()),
            Some("Remove and re-add the resource.".to_owned()),
            vec!["MemberId".to_owned()],
        )],
    )?)
}

/// Every §2.1 capability as a `Supported` observation, so the re-probed
/// snapshot covers the complete compiled ledger — the same surface the infra
/// probe produces.
fn capability_observations() -> Vec<EndpointCapabilityObservation> {
    CAPABILITY_LEDGER_ORDER
        .into_iter()
        .map(|capability| {
            EndpointCapabilityObservation::new(capability, CapabilityState::Supported)
        })
        .collect()
}

fn record(events: &Mutex<Vec<&'static str>>, value: &'static str) -> Result<(), MockError> {
    events.lock().map_err(|_| MockError::Events)?.push(value);
    Ok(())
}

fn recorded(events: &Mutex<Vec<&'static str>>) -> Result<Vec<&'static str>, MockError> {
    events
        .lock()
        .map(|events| events.clone())
        .map_err(|_| MockError::Events)
}
