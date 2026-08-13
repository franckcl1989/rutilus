//! Refreshes several managed endpoints in one bounded, concurrently executed
//! batch with independent per-endpoint results.
//!
//! A refresh is a read: it re-probes one endpoint's typed resource surface and
//! atomically commits one new resource Generation (design §9.5). Only writes
//! become [`Operation`]s (§13.1), so this use case deliberately never touches
//! the operation state machine — the batch is a composition layer over the
//! established per-endpoint [`AuditedEndpointRefresh`], which already owns the
//! start/terminal audit lifecycle of every single refresh.
//!
//! The per-endpoint result shape follows the CSV import precedent
//! ([`crate::EndpointCsvImportExecutor`]): validation and listing failures are
//! the only use-case-level errors, and every per-endpoint failure is part of
//! the successful result — the batch never turns into an error or a success
//! because some endpoints failed.
//!
//! Concurrency is bounded by two gates (design §7.8 "读取有全局和端点级
//! Semaphore"): the global batch gate — a [`Semaphore`] with
//! [`MAX_CONCURRENT_REFRESHES`] permits, so one batch never drives more than
//! four Redfish reads at once regardless of how many endpoints it names
//! (bounded by [`MAX_REFRESH_TARGETS`]) — and the process-wide endpoint-level
//! gate [`endpoint_read_gate`], one permit per managed endpoint, so two
//! concurrent refreshes of the same endpoint (two overlapping batches, or any
//! refresh entrance racing the batch) never overlap. Same-endpoint
//! serialization keeps the §9.5 Generation order honest: the older
//! observation always commits before the newer one, so a stale observation
//! can never land as the latest Generation and roll the telemetry and
//! overview surfaces backward.

use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    sync::{Arc, Mutex, OnceLock},
};

use futures::future::join_all;
use rutilus_domain::{
    AuditActor, DeploymentPosture, EndpointId, PrincipalId, RefreshGeneration, ResourceSnapshot,
};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::{
    AuditEventWriter, AuditedEndpointRefresh, AuditedEndpointRefreshError,
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialResolver,
    EndpointRefreshError, EndpointRefreshRepository, RedfishDiscovery,
};

/// The maximum number of endpoints one refresh batch may name.
///
/// The ceiling mirrors the §13.7 write-batch target limit
/// (`rutilus_operation_engine::MAX_BATCH_TARGETS`) so a refresh batch and a
/// write batch stay equally bounded: the same 128-endpoint ceiling keeps one
/// request's result list and its server-side work bounded on both sides of
/// the product. A refresh is a read and deliberately does not flow through
/// the operation engine (§13.1 turns only writes into Operations), so the
/// batch keeps its own constant instead of importing the write path's.
pub const MAX_REFRESH_TARGETS: usize = 128;

/// The number of endpoints whose refreshes may run concurrently inside one
/// batch.
///
/// Four concurrent Redfish reads bound one request's in-flight network and
/// persistence work while still pipelining a large batch: a full
/// [`MAX_REFRESH_TARGETS`]-endpoint batch completes in at most 32 sequential
/// waves.
pub const MAX_CONCURRENT_REFRESHES: usize = 4;

/// The process-wide registry of per-endpoint refresh gates (design §7.8
/// "读取有全局和端点级 Semaphore").
///
/// Every refresh of one endpoint — inside any batch, across any number of
/// concurrent `execute` calls — passes through the same one-permit gate, so
/// two refreshes of one endpoint never overlap. The overlap is the §9.5
/// regression the gate prevents: the commit boundary assigns Generations
/// monotonically in commit order, so an older observation whose commit lands
/// after a newer one would become the "latest" Generation and roll the
/// telemetry and overview projections backward. Serializing the endpoint
/// makes commit order equal observation order.
///
/// Entries are intentionally retained for the process lifetime: a gate must
/// never be dropped while a refresh holds its permit, because dropping the
/// registry's last `Arc` would free the semaphore and admit a concurrent
/// refresh of the same endpoint.
///
/// The registry therefore has no reclamation path — and none is reachable
/// today: the site has no endpoint-deletion use case (endpoint rows are
/// only created; the site's managed-endpoint path exposes no removal, and
/// the §21 delete convergence in `center_sync` reacts to endpoints that
/// vanished by manual database change or restore, with deletion itself
/// named a future use case there). The registry is process-internal: one
/// entry per managed endpoint per process lifecycle, never released,
/// bounded by the all-time
/// fleet size. A future endpoint-removal path must wire reclamation here —
/// reclaiming a gate only after every refresh of that endpoint has finished
/// (never while a permit is held), so the registry never shrinks underneath
/// an in-flight refresh.
static ENDPOINT_READ_GATES: OnceLock<Mutex<HashMap<EndpointId, Arc<Semaphore>>>> = OnceLock::new();

/// Returns the process-wide one-permit read gate of one endpoint, or `None`
/// when the registry cannot be locked.
///
/// The gate is created on first use and shared by every refresh of the
/// endpoint — the batch entrance ([`BatchEndpointRefresh::execute`]) and the
/// enrollment first-refresh entrance (`crate::EndpointEnrollment`) pass
/// through the same gate, so an enrollment initial refresh can never overlap
/// a concurrent batch refresh of the same endpoint. The permit is held for
/// the whole refresh (read, Generation commit, capability re-probe, and
/// snapshot replace), exactly like the batch permit. A poisoned registry is
/// the same process-level break as a closed semaphore, so the caller reports
/// it as the endpoint's own classified coordination failure instead of
/// panicking.
pub(crate) fn endpoint_read_gate(endpoint_id: EndpointId) -> Option<Arc<Semaphore>> {
    let mut gates = ENDPOINT_READ_GATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()?;
    Some(
        gates
            .entry(endpoint_id)
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone(),
    )
}

/// Coordinates one bounded batch of independent endpoint refreshes.
///
/// Every endpoint is refreshed through the same boundaries the single
/// endpoint refresh composes: the repository performs the managed-endpoint
/// pre-check and commits each complete resource Generation, the credential
/// resolver supplies the endpoint's selected credential, the reader performs
/// the typed Redfish read and capability re-probe, and the audit writer
/// records each endpoint's own start/terminal audit lifecycle. The batch
/// itself is never persisted and never audited as a whole: a read batch has
/// no lifecycle of its own, and the per-endpoint snapshots and audits already
/// cover the responsibility chain (design §13.7 derives batch facts only from
/// persisted write children, which a read batch has none of).
pub struct BatchEndpointRefresh<Repository, Credentials, Reader, Audit, Time> {
    repository: Repository,
    credentials: Credentials,
    reader: Reader,
    audit: Audit,
    clock: Time,
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    origin: DeploymentPosture,
}

impl<Repository, Credentials, Reader, Audit, Time>
    BatchEndpointRefresh<Repository, Credentials, Reader, Audit, Time>
where
    Repository: EndpointRefreshRepository + CapabilitySnapshotRepository,
    Credentials: CredentialResolver,
    Reader: CoreResourceReader + RedfishDiscovery,
    Audit: AuditEventWriter,
    Time: Clock,
{
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository: Repository,
        credentials: Credentials,
        reader: Reader,
        audit: Audit,
        clock: Time,
        actor: AuditActor,
        actor_principal_id: Option<PrincipalId>,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            repository,
            credentials,
            reader,
            audit,
            clock,
            actor,
            actor_principal_id,
            origin,
        }
    }

    /// Validates the endpoint list, then refreshes every endpoint under a
    /// [`MAX_CONCURRENT_REFRESHES`] concurrency gate and returns one outcome
    /// per endpoint in submission order.
    ///
    /// Validation happens completely before any refresh starts: an empty
    /// list, an oversized list, a repeated endpoint, or a referenced endpoint
    /// that is not managed rejects the whole batch, and no endpoint is ever
    /// touched (not even audited) by a rejected request. The managed-endpoint
    /// pre-check uses the same [`EndpointRefreshRepository::find_endpoint`]
    /// read as the operation submission use case, so a rejected batch never
    /// leaves a durable row.
    ///
    /// Execution reuses [`AuditedEndpointRefresh`] for every endpoint, so
    /// each refresh keeps its own start/terminal audit facts, commits one new
    /// resource Generation as one atomic write, and retains the last complete
    /// snapshot on failure (§9.5). Outcomes are independent: one failed
    /// endpoint never changes another endpoint's outcome, and the batch never
    /// fails or succeeds as a whole because of partial results.
    ///
    /// Each endpoint's refresh additionally passes through the process-wide
    /// endpoint-level gate [`endpoint_read_gate`] (design §7.8), so a batch
    /// overlapping another refresh of the same endpoint waits instead of
    /// racing it: the older observation commits first and a stale snapshot
    /// can never become the latest Generation.
    ///
    /// # Errors
    ///
    /// Returns [`BatchEndpointRefreshError::EmptyTargets`] for an empty list,
    /// [`BatchEndpointRefreshError::TooManyTargets`] when the list exceeds
    /// [`MAX_REFRESH_TARGETS`], [`BatchEndpointRefreshError::DuplicateEndpoint`]
    /// for a repeated endpoint id,
    /// [`BatchEndpointRefreshError::UnknownEndpoint`] when a referenced
    /// endpoint is not managed, and [`BatchEndpointRefreshError::Precheck`]
    /// when the endpoint pre-check cannot run. Per-endpoint refresh failures
    /// are outcomes, not errors.
    pub async fn execute(
        &self,
        endpoint_ids: Vec<EndpointId>,
    ) -> Result<
        Vec<EndpointRefreshOutcome>,
        BatchEndpointRefreshError<<Repository as EndpointRefreshRepository>::Error>,
    > {
        self.validate_endpoint_ids(&endpoint_ids).await?;
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_REFRESHES));
        let refreshes = endpoint_ids
            .into_iter()
            .map(|endpoint_id| self.refresh_one(Arc::clone(&semaphore), endpoint_id))
            .collect::<Vec<_>>();
        Ok(join_all(refreshes).await)
    }

    /// Validates one endpoint list against the shared batch rules.
    ///
    /// The validation order mirrors the operation submission use case: the
    /// list must be non-empty (an empty refresh batch could never refresh
    /// anything) and bounded by [`MAX_REFRESH_TARGETS`] (one request's result
    /// list and server-side work stay bounded), must not repeat an endpoint
    /// (one endpoint, one outcome row), and every referenced endpoint must be
    /// a managed endpoint (refreshing an unmanaged BMC is a misconfigured
    /// request, not a batch). Only after every check passes does any refresh
    /// start, so a rejected request never triggers a single Redfish read or
    /// audit write.
    ///
    /// # Errors
    ///
    /// Returns [`BatchEndpointRefreshError::EmptyTargets`],
    /// [`BatchEndpointRefreshError::TooManyTargets`],
    /// [`BatchEndpointRefreshError::DuplicateEndpoint`],
    /// [`BatchEndpointRefreshError::UnknownEndpoint`], or
    /// [`BatchEndpointRefreshError::Precheck`] as documented on
    /// [`Self::execute`].
    async fn validate_endpoint_ids(
        &self,
        endpoint_ids: &[EndpointId],
    ) -> Result<(), BatchEndpointRefreshError<<Repository as EndpointRefreshRepository>::Error>>
    {
        if endpoint_ids.is_empty() {
            return Err(BatchEndpointRefreshError::EmptyTargets);
        }
        if endpoint_ids.len() > MAX_REFRESH_TARGETS {
            return Err(BatchEndpointRefreshError::TooManyTargets {
                limit: MAX_REFRESH_TARGETS,
            });
        }
        let mut seen = BTreeSet::new();
        for endpoint_id in endpoint_ids {
            if !seen.insert(*endpoint_id) {
                return Err(BatchEndpointRefreshError::DuplicateEndpoint {
                    endpoint_id: *endpoint_id,
                });
            }
        }
        for endpoint_id in endpoint_ids {
            let found = self
                .repository
                .find_endpoint(*endpoint_id)
                .await
                .map_err(BatchEndpointRefreshError::Precheck)?;
            if found.is_none() {
                return Err(BatchEndpointRefreshError::UnknownEndpoint {
                    endpoint_id: *endpoint_id,
                });
            }
        }
        Ok(())
    }

    /// Refreshes one endpoint under the batch semaphore permit and the
    /// process-wide endpoint-level gate, then projects its independent
    /// outcome.
    ///
    /// The batch permit and the endpoint gate permit are both held for the
    /// whole refresh — the read, the Generation commit, the capability
    /// re-probe, and the snapshot replace — so the concurrent window is
    /// exactly the per-endpoint work, not a slice of it, and two refreshes
    /// of the same endpoint can never overlap (design §7.8).
    async fn refresh_one(
        &self,
        semaphore: Arc<Semaphore>,
        endpoint_id: EndpointId,
    ) -> EndpointRefreshOutcome {
        // The semaphore is created by `execute` and dropped with it; it is
        // never closed, so this is a controlled dead-end only if the
        // coordinator itself broke — reported as the endpoint's own
        // classified failure rather than poisoning the batch.
        let Ok(_permit) = semaphore.acquire().await else {
            return EndpointRefreshOutcome::Failed {
                endpoint_id,
                reason: EndpointRefreshFailureKind::Coordination,
                message: "the refresh concurrency gate is closed".to_owned(),
            };
        };
        // The endpoint-level gate is process-wide and never closed, so its
        // acquire can only fail if the registry itself broke — the same
        // controlled dead-end, reported as the endpoint's own classified
        // failure.
        let Some(gate) = endpoint_read_gate(endpoint_id) else {
            return EndpointRefreshOutcome::Failed {
                endpoint_id,
                reason: EndpointRefreshFailureKind::Coordination,
                message: "the endpoint refresh gate registry is unavailable".to_owned(),
            };
        };
        let Ok(_endpoint_permit) = gate.acquire().await else {
            return EndpointRefreshOutcome::Failed {
                endpoint_id,
                reason: EndpointRefreshFailureKind::Coordination,
                message: "the endpoint refresh gate is closed".to_owned(),
            };
        };
        let refresh = AuditedEndpointRefresh::new(
            &self.repository,
            &self.credentials,
            &self.reader,
            &self.audit,
            &self.clock,
            self.actor,
            self.actor_principal_id,
            self.origin,
        );
        match refresh.execute(endpoint_id).await {
            Ok(snapshots) => refreshed_outcome(endpoint_id, &snapshots),
            Err(failure) => failure_outcome(endpoint_id, &failure),
        }
    }
}

/// The independent terminal result of one endpoint inside a refresh batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EndpointRefreshOutcome {
    /// The endpoint's complete resource Generation committed and its
    /// capability snapshot was replaced.
    Refreshed {
        endpoint_id: EndpointId,
        generation: RefreshGeneration,
        snapshot_count: usize,
    },
    /// The endpoint refresh failed for a classified reason; the last complete
    /// snapshot is retained (§9.5).
    Failed {
        endpoint_id: EndpointId,
        reason: EndpointRefreshFailureKind,
        message: String,
    },
    /// The endpoint disappeared between the batch pre-check and its refresh.
    NotFound { endpoint_id: EndpointId },
}

impl EndpointRefreshOutcome {
    /// Returns the stable Endpoint this outcome reports.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        match self {
            Self::Refreshed { endpoint_id, .. }
            | Self::Failed { endpoint_id, .. }
            | Self::NotFound { endpoint_id } => *endpoint_id,
        }
    }

    /// Reports whether this endpoint's refresh fully succeeded.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Refreshed { .. })
    }
}

/// The classified reason one endpoint's refresh failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointRefreshFailureKind {
    /// The mandatory refresh audit could not be recorded.
    Audit,
    /// The endpoint could not be loaded from persistence.
    Load,
    /// The endpoint's selected credential could not be resolved.
    Credential,
    /// The typed Redfish core resource read failed.
    Read,
    /// The complete resource Generation could not be committed.
    Commit,
    /// The capability re-probe failed after the Generation committed.
    CapabilityProbe,
    /// The capability snapshot could not be atomically replaced.
    CapabilityCommit,
    /// The refresh coordinator could not schedule this endpoint.
    Coordination,
}

impl EndpointRefreshFailureKind {
    /// The human-readable label of this classified failure.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Audit => "refresh audit failed",
            Self::Load => "endpoint lookup failed",
            Self::Credential => "credential resolution failed",
            Self::Read => "resource read failed",
            Self::Commit => "generation commit failed",
            Self::CapabilityProbe => "capability re-probe failed",
            Self::CapabilityCommit => "capability snapshot replace failed",
            Self::Coordination => "refresh scheduling failed",
        }
    }
}

/// A controlled failure while validating or coordinating one refresh batch.
///
/// The single generic parameter is the pre-check boundary's error type, so
/// every lookup failure stays reachable as the source of an error chain.
/// Per-endpoint refresh failures are never this error: they are outcomes.
#[derive(Debug, Error)]
pub enum BatchEndpointRefreshError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    /// The batch would have no endpoint to refresh.
    #[error("a refresh batch must name at least one endpoint")]
    EmptyTargets,
    /// The batch would exceed the supported endpoint ceiling.
    #[error("a refresh batch may target at most {limit} endpoints")]
    TooManyTargets { limit: usize },
    /// The same endpoint is referenced more than once in one batch.
    #[error("refresh batch targets endpoint {endpoint_id} more than once")]
    DuplicateEndpoint { endpoint_id: EndpointId },
    /// A referenced endpoint is not a managed endpoint.
    #[error("endpoint {endpoint_id} is not a managed endpoint")]
    UnknownEndpoint { endpoint_id: EndpointId },
    /// The managed-endpoint pre-check could not run.
    #[error("failed to pre-check the refresh targets: {0}")]
    Precheck(#[source] RepositoryError),
}

/// Projects one successful refresh: the committed Generation and the number
/// of snapshots that Generation carries.
///
/// The commit boundary rejects empty observations (its `EmptyGeneration`
/// verdict), so a successful commit always returns at least one snapshot;
/// every snapshot of one Generation shares the Generation value. An empty
/// success is nevertheless reported as a classified failure instead of
/// inventing a Generation: the boundary misbehaved, and no snapshot facts
/// were durably observed.
fn refreshed_outcome(
    endpoint_id: EndpointId,
    snapshots: &[ResourceSnapshot],
) -> EndpointRefreshOutcome {
    let Some(first) = snapshots.first() else {
        return EndpointRefreshOutcome::Failed {
            endpoint_id,
            reason: EndpointRefreshFailureKind::Commit,
            message: "the refresh committed an empty generation".to_owned(),
        };
    };
    EndpointRefreshOutcome::Refreshed {
        endpoint_id,
        generation: first.generation(),
        snapshot_count: snapshots.len(),
    }
}

/// Classifies one audited refresh failure into its outcome.
///
/// The dominant fact decides the outcome: an endpoint that disappeared
/// between the pre-check and its refresh is [`EndpointRefreshOutcome::NotFound`],
/// and every other failure is [`EndpointRefreshOutcome::Failed`] carrying the
/// classified reason and the failure source's own message. A refresh whose
/// terminal audit also failed is classified by the refresh failure — the
/// refresh is the dominant fact, and the audit integrity failure is already
/// recorded in the endpoint's own audit trail.
fn failure_outcome<
    RepositoryError,
    CapabilityError,
    CredentialError,
    ReaderError,
    DiscoveryError,
    AuditError,
>(
    endpoint_id: EndpointId,
    failure: &AuditedEndpointRefreshError<
        RepositoryError,
        CapabilityError,
        CredentialError,
        ReaderError,
        DiscoveryError,
        AuditError,
    >,
) -> EndpointRefreshOutcome
where
    RepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    CredentialError: Error + 'static,
    ReaderError: Error + 'static,
    DiscoveryError: Error + 'static,
    AuditError: Error + 'static,
{
    if matches!(
        failure,
        AuditedEndpointRefreshError::Refresh { source, .. }
        | AuditedEndpointRefreshError::RefreshAndAudit {
            refresh: source, ..
        }
            if matches!(source.as_ref(), EndpointRefreshError::EndpointNotFound { .. })
    ) {
        return EndpointRefreshOutcome::NotFound { endpoint_id };
    }
    let (reason, message) = classify_failure(failure);
    EndpointRefreshOutcome::Failed {
        endpoint_id,
        reason,
        message,
    }
}

/// Maps one audited refresh failure onto its classified reason and message.
///
/// The message carries the failure source's own text, exactly like the CSV
/// import row outcomes; the classification itself is the structured kind the
/// reporting surface can label without parsing text.
fn classify_failure<
    RepositoryError,
    CapabilityError,
    CredentialError,
    ReaderError,
    DiscoveryError,
    AuditError,
>(
    failure: &AuditedEndpointRefreshError<
        RepositoryError,
        CapabilityError,
        CredentialError,
        ReaderError,
        DiscoveryError,
        AuditError,
    >,
) -> (EndpointRefreshFailureKind, String)
where
    RepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    CredentialError: Error + 'static,
    ReaderError: Error + 'static,
    DiscoveryError: Error + 'static,
    AuditError: Error + 'static,
{
    match failure {
        AuditedEndpointRefreshError::Audit { source, .. } => {
            (EndpointRefreshFailureKind::Audit, source.to_string())
        }
        AuditedEndpointRefreshError::Refresh { source, .. }
        | AuditedEndpointRefreshError::RefreshAndAudit {
            refresh: source, ..
        } => match source.as_ref() {
            EndpointRefreshError::LoadEndpoint(_)
            | EndpointRefreshError::EndpointNotFound { .. } => {
                (EndpointRefreshFailureKind::Load, source.to_string())
            }
            EndpointRefreshError::Credential(_)
            | EndpointRefreshError::CredentialNotFound { .. } => {
                (EndpointRefreshFailureKind::Credential, source.to_string())
            }
            EndpointRefreshError::Read(_) => (EndpointRefreshFailureKind::Read, source.to_string()),
            EndpointRefreshError::Commit(_) => {
                (EndpointRefreshFailureKind::Commit, source.to_string())
            }
            EndpointRefreshError::CapabilityProbe(_) => (
                EndpointRefreshFailureKind::CapabilityProbe,
                source.to_string(),
            ),
            EndpointRefreshError::CapabilityCommit(_) => (
                EndpointRefreshFailureKind::CapabilityCommit,
                source.to_string(),
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet},
        error::Error,
        fmt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use rutilus_domain::{
        AuditEvent, AuditOutcomeKind, CapabilityState, CredentialId, CredentialUsername, Endpoint,
        EndpointAddress, EndpointCapability, EndpointCapabilityObservation, EndpointDisplayName,
        RefreshGeneration, ResourceFeature, ResourceId, ResourceODataId, ResourceSnapshotPayload,
        TlsCertificate, TlsTrust,
    };
    use time::OffsetDateTime;

    use crate::{EndpointDiscovery, ResolvedCredential};

    use super::*;

    #[tokio::test]
    async fn refreshes_every_endpoint_in_submission_order() -> Result<(), Box<dyn Error>> {
        let endpoints = endpoints(3)?;
        let ids = endpoint_ids(&endpoints);
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let batch = batch(
            MockRepository::succeed(endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );

        let outcomes = batch.execute(ids.clone()).await?;

        assert_eq!(outcomes.len(), 3);
        for (index, endpoint_id) in ids.iter().enumerate() {
            let outcome = &outcomes[index];
            assert_eq!(outcome.endpoint_id(), *endpoint_id);
            assert!(outcome.is_success());
            assert!(matches!(
                outcome,
                EndpointRefreshOutcome::Refreshed {
                    generation,
                    snapshot_count,
                    ..
                } if generation.get() == 1 && *snapshot_count == 2
            ));
        }
        // Every endpoint's refresh is fully audited: one start and one
        // confirmed terminal fact per endpoint, in refresh order.
        let audit = recorded_audit_events(&audit_state)?;
        assert_eq!(audit.len(), 6);
        assert!(
            audit
                .iter()
                .all(|event| event.outcome().kind() == AuditOutcomeKind::Started
                    || event.outcome().kind() == AuditOutcomeKind::Succeeded)
        );
        Ok(())
    }

    #[tokio::test]
    async fn rejects_empty_duplicate_and_oversized_batches_before_any_refresh()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let batch = batch(
            MockRepository::succeed(endpoints(1)?, Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );

        let empty = batch.execute(Vec::new()).await;
        let error = empty.err().ok_or("an empty batch must be rejected")?;
        assert!(matches!(error, BatchEndpointRefreshError::EmptyTargets));
        assert_eq!(
            error.to_string(),
            "a refresh batch must name at least one endpoint"
        );

        let endpoint_id = EndpointId::generate();
        let duplicated = batch.execute(vec![endpoint_id, endpoint_id]).await;
        let error = duplicated
            .err()
            .ok_or("a duplicated endpoint must be rejected")?;
        assert!(matches!(
            error,
            BatchEndpointRefreshError::DuplicateEndpoint { endpoint_id: id } if id == endpoint_id
        ));
        assert_eq!(
            error.to_string(),
            format!("refresh batch targets endpoint {endpoint_id} more than once")
        );

        let oversized_ids = (0..=MAX_REFRESH_TARGETS)
            .map(|_| EndpointId::generate())
            .collect();
        let oversized = batch.execute(oversized_ids).await;
        let error = oversized
            .err()
            .ok_or("an oversized batch must be rejected")?;
        assert!(matches!(
            error,
            BatchEndpointRefreshError::TooManyTargets { limit } if limit == MAX_REFRESH_TARGETS
        ));
        assert_eq!(
            error.to_string(),
            format!("a refresh batch may target at most {MAX_REFRESH_TARGETS} endpoints")
        );
        assert!(
            recorded(&lifecycle)?.is_empty(),
            "a rejected batch must never load or audit an endpoint"
        );
        assert_eq!(recorded_audit_events(&audit_state)?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_endpoint_precheck_rejects_without_starting_any_refresh()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(2)?;
        let missing = EndpointId::generate();
        let batch = batch(
            MockRepository::succeed(endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );
        let mut ids = endpoint_ids(&endpoints);
        ids.insert(1, missing);

        let result = batch.execute(ids).await;

        assert!(matches!(
            result,
            Err(BatchEndpointRefreshError::UnknownEndpoint { endpoint_id: id }) if id == missing
        ));
        assert_eq!(
            recorded(&lifecycle)?,
            ["load", "load"],
            "only the two pre-check lookups may run — never a refresh"
        );
        assert_eq!(recorded_audit_events(&audit_state)?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn per_endpoint_failures_are_part_of_ok_and_never_poison_the_batch()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(3)?;
        let failing_address = endpoints[2].address().to_string();
        let batch = batch(
            MockRepository::succeed(endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::fail_at(&failing_address, Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );

        let outcomes = batch.execute(endpoint_ids(&endpoints)).await?;

        assert_eq!(outcomes.len(), 3);
        assert!(outcomes[0].is_success());
        assert!(outcomes[1].is_success());
        let failed = &outcomes[2];
        assert!(!failed.is_success());
        assert!(matches!(
            failed,
            EndpointRefreshOutcome::Failed {
                endpoint_id,
                reason: EndpointRefreshFailureKind::Read,
                message,
            } if *endpoint_id == failed.endpoint_id()
                && message.contains("resource read failed")
        ));
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_vanishing_after_the_precheck_reports_not_found() -> Result<(), Box<dyn Error>>
    {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(2)?;
        let vanished = endpoints[1].id();
        let batch = batch(
            MockRepository::vanishing(vec![vanished], endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );

        let outcomes = batch.execute(endpoint_ids(&endpoints)).await?;

        assert!(outcomes[0].is_success());
        assert_eq!(outcomes[1].endpoint_id(), vanished);
        assert_eq!(
            outcomes[1],
            EndpointRefreshOutcome::NotFound {
                endpoint_id: vanished
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn audit_failure_classifies_the_endpoint_as_failed() -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(1)?;
        let endpoint_id = endpoints[0].id();
        let batch = batch(
            MockRepository::succeed(endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), Arc::clone(&audit_state), 2),
        );

        let outcomes = batch.execute(vec![endpoint_id]).await?;

        assert!(matches!(
            &outcomes[0],
            EndpointRefreshOutcome::Failed {
                endpoint_id: id,
                reason: EndpointRefreshFailureKind::Audit,
                ..
            } if *id == endpoint_id
        ));
        assert_eq!(
            recorded(&lifecycle)?,
            [
                "load",
                "audit",
                "load",
                "credential",
                "read",
                "commit",
                "probe",
                "snapshot",
                "audit"
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn empty_committed_generation_reports_the_endpoint_as_failed()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(1)?;
        let endpoint_id = endpoints[0].id();
        let batch = batch(
            MockRepository::empty_commit(endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );

        let outcomes = batch.execute(vec![endpoint_id]).await?;

        assert_eq!(outcomes.len(), 1);
        assert_eq!(
            outcomes[0],
            EndpointRefreshOutcome::Failed {
                endpoint_id,
                reason: EndpointRefreshFailureKind::Commit,
                message: "the refresh committed an empty generation".to_owned(),
            }
        );
        // The refresh ran its full lifecycle: the empty commit is projected
        // into the classified failure, never short-circuited.
        assert_eq!(
            recorded(&lifecycle)?,
            [
                "load",
                "audit",
                "load",
                "credential",
                "read",
                "commit",
                "probe",
                "snapshot",
                "audit"
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn concurrent_refreshes_never_exceed_max_concurrent_refreshes()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(8)?;
        let tracker = Arc::new(Mutex::new(ConcurrencyTracker::default()));
        let batch = batch(
            MockRepository::succeed(endpoints.clone(), Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed_slowly(Arc::clone(&lifecycle), Arc::clone(&tracker)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
        );

        let outcomes = batch.execute(endpoint_ids(&endpoints)).await?;

        assert_eq!(outcomes.len(), 8);
        assert!(outcomes.iter().all(EndpointRefreshOutcome::is_success));
        let tracker = tracker.lock().map_err(|_| MockError::Events)?;
        assert_eq!(
            tracker.max_in_flight, MAX_CONCURRENT_REFRESHES,
            "the semaphore must cap concurrent Redfish reads at the constant"
        );
        assert!(tracker.max_in_flight > 1, "the batch must actually overlap");
        Ok(())
    }

    // The test drives two overlapping batches through a blocked read and
    // asserts the full serialized lifecycle plus the Generation/observation
    // correlation, so the line count is the coverage, not a signal.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn concurrent_same_endpoint_refreshes_serialize_so_an_older_observation_never_becomes_latest()
    -> Result<(), Box<dyn Error>> {
        // Two batches refreshing the same endpoint concurrently must never
        // overlap that endpoint's refresh (design §7.8 endpoint-level gate).
        // The persistence commit assigns Generations monotonically in commit
        // order (`next_generation`), so an overlapping older observation
        // committed after a newer one would become the "latest" Generation
        // (§9.5 regression): the telemetry and overview projections would
        // roll backward. The first batch's read is held in flight; the
        // second batch must wait at the endpoint-level gate instead of
        // reading, and the commit order must then equal the observation
        // order.
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoints = endpoints(1)?;
        let endpoint_id = endpoints[0].id();
        let observation_tracker = Arc::new(Mutex::new(ObservationTracker::default()));
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        // The two batches share one mock set through `'static` references
        // (the spawned tasks outlive this scope); leaking the test-only
        // mocks is harmless — the test process owns them for its lifetime.
        let repository: &'static MockRepository = Box::leak(Box::new(
            MockRepository::succeed(endpoints.clone(), Arc::clone(&lifecycle))
                .with_observation_tracker(Arc::clone(&observation_tracker)),
        ));
        let reader: &'static MockReader = Box::leak(Box::new(
            MockReader::succeed(Arc::clone(&lifecycle))
                .with_observation_tracker(Arc::clone(&observation_tracker))
                .with_first_read_block(Arc::new(FirstReadBlock::new(reached_tx, release_rx))),
        ));
        let credentials: &'static MockCredentials =
            Box::leak(Box::new(MockCredentials::available(Arc::clone(&lifecycle))));
        let audit: &'static MockAudit = Box::leak(Box::new(MockAudit::succeed(
            Arc::clone(&lifecycle),
            Arc::clone(&audit_state),
        )));
        let clock: &'static FixedClock = Box::leak(Box::new(FixedClock(OffsetDateTime::now_utc())));
        let first = BatchEndpointRefresh::new(
            repository,
            credentials,
            reader,
            audit,
            clock,
            AuditActor::System,
            None,
            DeploymentPosture::Site,
        );
        let second = BatchEndpointRefresh::new(
            repository,
            credentials,
            reader,
            audit,
            clock,
            AuditActor::System,
            None,
            DeploymentPosture::Site,
        );

        let first_task = tokio::spawn({
            let ids = vec![endpoint_id];
            async move { first.execute(ids).await }
        });
        // The first refresh is now provably in flight inside its read.
        reached_rx.await.map_err(|_| MockError::Events)?;
        let second_task = tokio::spawn({
            let ids = vec![endpoint_id];
            async move { second.execute(ids).await }
        });
        // Give the second batch time to reach the endpoint-level gate. While
        // the first observation is still in flight there must be exactly one
        // read and no commit: the second refresh waits at the gate instead of
        // overlapping the first.
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let events = recorded(&lifecycle)?;
            assert_eq!(
                events.iter().filter(|event| **event == "read").count(),
                1,
                "the second refresh must wait at the endpoint gate instead of reading"
            );
            assert_eq!(
                events.iter().filter(|event| **event == "commit").count(),
                0,
                "no Generation may commit while an observation is still in flight"
            );
        }
        let _ = release_tx.send(());
        let first_outcomes = first_task.await.map_err(|_| MockError::Events)??;
        let second_outcomes = second_task.await.map_err(|_| MockError::Events)??;
        assert!(first_outcomes[0].is_success());
        assert!(second_outcomes[0].is_success());

        // The two refreshes ran back to back: one complete refresh phase
        // (audit, credential, read, commit, probe, snapshot, audit) then the
        // other, with only the two pre-check lookups interleaved arbitrarily
        // at the start, so the load-filtered stream is exactly two
        // contiguous phases.
        let refresh_phase = [
            "audit",
            "credential",
            "read",
            "commit",
            "probe",
            "snapshot",
            "audit",
        ];
        let filtered = recorded(&lifecycle)?
            .into_iter()
            .filter(|event| **event != *"load")
            .collect::<Vec<_>>();
        assert_eq!(filtered.len(), refresh_phase.len() * 2);
        assert_eq!(&filtered[..refresh_phase.len()], refresh_phase);
        assert_eq!(&filtered[refresh_phase.len()..], refresh_phase);

        // Generation assignment follows commit order (the real boundary's
        // rule), and serialization made commit order equal observation
        // order: Generation 1 carries the first observation and Generation
        // 2 — the latest — carries the second, newer observation. An older
        // observation never lands as the latest Generation.
        let tracker = observation_tracker.lock().map_err(|_| MockError::Events)?;
        assert_eq!(
            tracker.commits,
            [
                CommitRecord {
                    endpoint_id,
                    generation: 1,
                    reads: 1,
                },
                CommitRecord {
                    endpoint_id,
                    generation: 2,
                    reads: 2,
                },
            ]
        );
        Ok(())
    }

    /// The single mock failure mode shared by every boundary.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Repository,
        Credential,
        Reader,
        Audit,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock {self:?} failure")
        }
    }

    impl Error for MockError {}

    #[derive(Default)]
    struct MockAuditState {
        attempts: usize,
        events: Vec<AuditEvent>,
    }

    struct MockAudit {
        lifecycle: Arc<Mutex<Vec<&'static str>>>,
        state: Arc<Mutex<MockAuditState>>,
        fail_on: Option<usize>,
    }

    impl MockAudit {
        fn succeed(
            lifecycle: Arc<Mutex<Vec<&'static str>>>,
            state: Arc<Mutex<MockAuditState>>,
        ) -> Self {
            Self {
                lifecycle,
                state,
                fail_on: None,
            }
        }

        fn fail_on(
            lifecycle: Arc<Mutex<Vec<&'static str>>>,
            state: Arc<Mutex<MockAuditState>>,
            attempt: usize,
        ) -> Self {
            Self {
                lifecycle,
                state,
                fail_on: Some(attempt),
            }
        }
    }

    impl AuditEventWriter for MockAudit {
        type Error = MockError;

        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> crate::BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                record(&self.lifecycle, "audit")?;
                let mut state = self.state.lock().map_err(|_| MockError::Events)?;
                state.attempts += 1;
                if self.fail_on == Some(state.attempts) {
                    return Err(MockError::Audit);
                }
                state.events.push(event.clone());
                Ok(())
            })
        }
    }

    /// One managed endpoint per generated identity, on distinct addresses.
    fn endpoints(count: usize) -> Result<Vec<Endpoint>, Box<dyn Error>> {
        let mut endpoints = Vec::with_capacity(count);
        for index in 0..count {
            let now = OffsetDateTime::now_utc();
            endpoints.push(Endpoint::try_new(
                EndpointId::generate(),
                EndpointDisplayName::parse(&format!("Batch BMC {index}"))?,
                EndpointAddress::parse(&format!("https://192.0.2.1{index}"))?,
                TlsTrust::SystemCa {
                    certificate: TlsCertificate::from_der(b"batch refresh certificate".to_vec())?,
                    verified_at: now,
                },
                CredentialId::generate(),
                now,
                now,
            )?);
        }
        Ok(endpoints)
    }

    fn endpoint_ids(endpoints: &[Endpoint]) -> Vec<EndpointId> {
        endpoints.iter().map(Endpoint::id).collect()
    }

    /// One commit of one endpoint's Generation: the Generation the commit
    /// boundary assigned (monotonically, in commit order — the same
    /// `next_generation` rule as the real store) and how many observations of
    /// the endpoint had been completed when the commit landed.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CommitRecord {
        endpoint_id: EndpointId,
        generation: u64,
        reads: u64,
    }

    /// Correlates observation order with commit order across the reader and
    /// the repository, keyed by endpoint address.
    #[derive(Default)]
    struct ObservationTracker {
        /// Completed reads per endpoint address, in completion order.
        reads: BTreeMap<String, u64>,
        /// Every commit, in commit order, with the observation count at the
        /// time the commit landed.
        commits: Vec<CommitRecord>,
    }

    struct MockRepository {
        endpoints: BTreeMap<EndpointId, Endpoint>,
        /// Endpoints that disappear between the pre-check and the refresh.
        vanishing: BTreeSet<EndpointId>,
        /// When armed, the Generation commit answers with an empty snapshot
        /// list so the projection's empty-commit defense is exercised end to
        /// end instead of only by construction.
        empty_commit: bool,
        lookup_counts: Arc<Mutex<BTreeMap<EndpointId, usize>>>,
        /// The per-endpoint Generation counter, mirroring the real commit
        /// boundary's `next_generation` rule.
        commits: Arc<Mutex<BTreeMap<EndpointId, u64>>>,
        observation_tracker: Option<Arc<Mutex<ObservationTracker>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl MockRepository {
        fn succeed(endpoints: Vec<Endpoint>, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                endpoints: endpoints
                    .into_iter()
                    .map(|endpoint| (endpoint.id(), endpoint))
                    .collect(),
                vanishing: BTreeSet::new(),
                empty_commit: false,
                lookup_counts: Arc::new(Mutex::new(BTreeMap::new())),
                commits: Arc::new(Mutex::new(BTreeMap::new())),
                observation_tracker: None,
                events,
            }
        }

        /// The commit boundary succeeds but returns no snapshots — the
        /// boundary-misbehavior case the outcome projection must classify.
        fn empty_commit(endpoints: Vec<Endpoint>, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                endpoints: endpoints
                    .into_iter()
                    .map(|endpoint| (endpoint.id(), endpoint))
                    .collect(),
                vanishing: BTreeSet::new(),
                empty_commit: true,
                lookup_counts: Arc::new(Mutex::new(BTreeMap::new())),
                commits: Arc::new(Mutex::new(BTreeMap::new())),
                observation_tracker: None,
                events,
            }
        }

        fn vanishing(
            vanishing: Vec<EndpointId>,
            endpoints: Vec<Endpoint>,
            events: Arc<Mutex<Vec<&'static str>>>,
        ) -> Self {
            Self {
                endpoints: endpoints
                    .into_iter()
                    .map(|endpoint| (endpoint.id(), endpoint))
                    .collect(),
                vanishing: vanishing.into_iter().collect(),
                empty_commit: false,
                lookup_counts: Arc::new(Mutex::new(BTreeMap::new())),
                commits: Arc::new(Mutex::new(BTreeMap::new())),
                observation_tracker: None,
                events,
            }
        }

        /// Shares the observation tracker with the reader so commit order can
        /// be correlated with observation order.
        fn with_observation_tracker(mut self, tracker: Arc<Mutex<ObservationTracker>>) -> Self {
            self.observation_tracker = Some(tracker);
            self
        }
    }

    impl EndpointRefreshRepository for MockRepository {
        type Error = MockError;

        fn find_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> crate::BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            let vanishing = self.vanishing.clone();
            let endpoints = self.endpoints.clone();
            let counts = Arc::clone(&self.lookup_counts);
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                record(&events, "load")?;
                let mut counts = counts.lock().map_err(|_| MockError::Events)?;
                let lookup = counts.entry(endpoint_id).or_default();
                *lookup += 1;
                // The pre-check is the first lookup of every endpoint; a
                // vanishing endpoint answers `None` to every later lookup.
                if *lookup > 1 && vanishing.contains(&endpoint_id) {
                    return Ok(None);
                }
                Ok(endpoints.get(&endpoint_id).cloned())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            endpoint_id: EndpointId,
            observations: &'a [crate::ResourceObservation],
            _decode_failures: &'a [crate::ResourceDecodeFailure],
            observed_at: OffsetDateTime,
        ) -> crate::BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async move {
                record(&self.events, "commit")?;
                if self.empty_commit {
                    return Ok(Vec::new());
                }
                // The Generation is assigned monotonically in commit order,
                // exactly like the real boundary's `next_generation` — this
                // is the rule that makes an overlapping older observation
                // committed after a newer one become the "latest" Generation.
                let mut commits = self.commits.lock().map_err(|_| MockError::Events)?;
                let next = commits.entry(endpoint_id).or_default();
                *next += 1;
                let generation =
                    RefreshGeneration::new(*next).map_err(|_| MockError::Repository)?;
                if let Some(tracker) = &self.observation_tracker {
                    let mut tracker = tracker.lock().map_err(|_| MockError::Events)?;
                    let address = self
                        .endpoints
                        .get(&endpoint_id)
                        .ok_or(MockError::Repository)?
                        .address()
                        .as_url()
                        .to_string();
                    let reads = tracker.reads.get(&address).copied().unwrap_or(0);
                    tracker.commits.push(CommitRecord {
                        endpoint_id,
                        generation: *next,
                        reads,
                    });
                }
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

    impl CapabilitySnapshotRepository for MockRepository {
        type Error = MockError;

        fn replace_endpoint_capabilities<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [EndpointCapabilityObservation],
            _observed_at: OffsetDateTime,
        ) -> crate::BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                record(&self.events, "snapshot")?;
                Ok(())
            })
        }
    }

    struct MockCredentials {
        events: Arc<Mutex<Vec<&'static str>>>,
        available: bool,
    }

    impl MockCredentials {
        fn available(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                available: true,
            }
        }
    }

    impl CredentialResolver for MockCredentials {
        type Error = MockError;

        fn resolve(
            &self,
            _credential_id: CredentialId,
        ) -> crate::BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
            Box::pin(async move {
                record(&self.events, "credential")?;
                if self.available {
                    Ok(Some(ResolvedCredential::new(
                        CredentialUsername::parse("administrator")
                            .map_err(|_| MockError::Credential)?,
                        String::from("secret").into(),
                    )))
                } else {
                    Ok(None)
                }
            })
        }
    }

    #[derive(Default)]
    struct ConcurrencyTracker {
        in_flight: usize,
        max_in_flight: usize,
    }

    /// Deterministically holds one test's first read in flight until the test
    /// releases it: the armed read signals `reached` and then waits on
    /// `release`, so the test can pin one refresh inside its read while a
    /// second refresh is expected to wait at the endpoint-level gate.
    struct FirstReadBlock {
        armed: AtomicBool,
        reached: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl FirstReadBlock {
        fn new(
            reached: tokio::sync::oneshot::Sender<()>,
            release: tokio::sync::oneshot::Receiver<()>,
        ) -> Self {
            Self {
                armed: AtomicBool::new(true),
                reached: Mutex::new(Some(reached)),
                release: Mutex::new(Some(release)),
            }
        }
    }

    struct MockReader {
        events: Arc<Mutex<Vec<&'static str>>>,
        succeeds: bool,
        fail_at_address: Option<String>,
        tracker: Option<Arc<Mutex<ConcurrencyTracker>>>,
        slow: bool,
        observation_tracker: Option<Arc<Mutex<ObservationTracker>>>,
        first_read_block: Option<Arc<FirstReadBlock>>,
    }

    impl MockReader {
        fn succeed(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                succeeds: true,
                fail_at_address: None,
                tracker: None,
                slow: false,
                observation_tracker: None,
                first_read_block: None,
            }
        }

        fn fail_at(address: &str, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                succeeds: true,
                fail_at_address: Some(address.to_owned()),
                tracker: None,
                slow: false,
                observation_tracker: None,
                first_read_block: None,
            }
        }

        fn succeed_slowly(
            events: Arc<Mutex<Vec<&'static str>>>,
            tracker: Arc<Mutex<ConcurrencyTracker>>,
        ) -> Self {
            Self {
                events,
                succeeds: true,
                fail_at_address: None,
                tracker: Some(tracker),
                slow: true,
                observation_tracker: None,
                first_read_block: None,
            }
        }

        /// Shares the observation tracker with the repository so commit order
        /// can be correlated with observation order.
        fn with_observation_tracker(mut self, tracker: Arc<Mutex<ObservationTracker>>) -> Self {
            self.observation_tracker = Some(tracker);
            self
        }

        /// Holds the first read of this reader in flight until the test
        /// releases it.
        fn with_first_read_block(mut self, block: Arc<FirstReadBlock>) -> Self {
            self.first_read_block = Some(block);
            self
        }
    }

    impl CoreResourceReader for MockReader {
        type Error = MockError;

        fn read_core_resources<'a>(
            &'a self,
            address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a secrecy::SecretString,
        ) -> crate::BoundaryFuture<'a, Result<crate::CoreResourceReadOutcome, Self::Error>>
        {
            let tracker = self.tracker.clone();
            let slow = self.slow;
            let succeeds = self.succeeds;
            let fail_at = self.fail_at_address.clone();
            let events = Arc::clone(&self.events);
            let observation_tracker = self.observation_tracker.clone();
            let first_read_block = self.first_read_block.clone();
            Box::pin(async move {
                record(&events, "read")?;
                if let Some(tracker) = &tracker {
                    let mut tracker = tracker.lock().map_err(|_| MockError::Events)?;
                    tracker.in_flight += 1;
                    tracker.max_in_flight = tracker.max_in_flight.max(tracker.in_flight);
                }
                if let Some(tracker) = &observation_tracker {
                    let mut tracker = tracker.lock().map_err(|_| MockError::Events)?;
                    let reads = tracker
                        .reads
                        .entry(address.as_url().to_string())
                        .or_default();
                    *reads += 1;
                }
                if let Some(block) = &first_read_block
                    && block.armed.swap(false, Ordering::SeqCst)
                {
                    if let Some(reached) =
                        block.reached.lock().map_err(|_| MockError::Events)?.take()
                    {
                        let _ = reached.send(());
                    }
                    let release = block.release.lock().map_err(|_| MockError::Events)?.take();
                    if let Some(release) = release {
                        let _ = release.await;
                    }
                }
                if slow {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                let result = if !succeeds || fail_at.as_deref() == Some(address.as_url().as_str()) {
                    Err(MockError::Reader)
                } else {
                    Ok(crate::CoreResourceReadOutcome::new(
                        observations().map_err(|_| MockError::Reader)?,
                        Vec::new(),
                    ))
                };
                if let Some(tracker) = &tracker {
                    tracker.lock().map_err(|_| MockError::Events)?.in_flight -= 1;
                }
                result
            })
        }
    }

    impl RedfishDiscovery for MockReader {
        type Error = MockError;

        fn probe_core_capabilities<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a secrecy::SecretString,
        ) -> crate::BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
            Box::pin(async move {
                record(&self.events, "probe")?;
                Ok(EndpointDiscovery::new(capability_observations()))
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn batch(
        repository: MockRepository,
        credentials: MockCredentials,
        reader: MockReader,
        audit: MockAudit,
    ) -> BatchEndpointRefresh<MockRepository, MockCredentials, MockReader, MockAudit, FixedClock>
    {
        BatchEndpointRefresh::new(
            repository,
            credentials,
            reader,
            audit,
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::System,
            None,
            DeploymentPosture::Site,
        )
    }

    fn observations() -> Result<Vec<crate::ResourceObservation>, Box<dyn Error>> {
        Ok(vec![
            crate::ResourceObservation::new(
                ResourceFeature::ServiceRoot,
                ResourceODataId::parse("/redfish/v1/")?,
                ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)?,
            ),
            crate::ResourceObservation::new(
                ResourceFeature::Systems,
                ResourceODataId::parse("/redfish/v1/Systems/1")?,
                ResourceSnapshotPayload::parse(r#"{"Name":"System"}"#)?,
            ),
        ])
    }

    fn capability_observations() -> Vec<EndpointCapabilityObservation> {
        vec![EndpointCapabilityObservation::new(
            EndpointCapability::Systems,
            CapabilityState::Supported,
        )]
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

    fn recorded_audit_events(state: &Mutex<MockAuditState>) -> Result<Vec<AuditEvent>, MockError> {
        state
            .lock()
            .map(|state| state.events.clone())
            .map_err(|_| MockError::Events)
    }
}
