//! The center's operation dispatch and reply tracking (design §15.6, §16.1,
//! 0.7.0 S5).
//!
//! The center never executes operations (§15.6 — only the site's explicit
//! `Accepted` transfers execution responsibility). It constructs the
//! §15.6 offer — `RedfishCommand` + `Target` + `OperationId` +
//! `ExpiresAt` + `ActorContext` — and nothing else (no URL, no HTTP
//! method, no headers, no body, no script) — records the operation in its
//! tracking view, and enqueues the offer into the site's durable outbox.
//! The site's replies (`Accepted`, `Rejected`, `Progress`, `Completed`)
//! advance the recorded state and land in the center's inbox as the
//! durable reply receipt.
//!
//! # The permission check (§16.1, D3)
//!
//! Only the built-in roles may dispatch, and a center role can be scoped to
//! one site (D3: the `role_assignments.site_id` column): the `Administrator`
//! is global, the `Operator` dispatches to every site or to the one site of
//! a scoped assignment, and the `Viewer` never dispatches
//! ([`allows_dispatch`]).
//!
//! # The offer TTL
//!
//! Every offer carries the expiry
//! [`CENTER_OFFER_TTL`] (15 minutes) — the site refuses an offer past its
//! expiry with `OperationRejectedReason::Expired` (§15.6 recheck).

use std::error::Error;

use rutilus_center_protocol::{
    Envelope, EnvelopeMessage, OperationAccepted, OperationCompleted, OperationOffer,
    OperationProgress, OperationRejected,
};
use rutilus_domain::{
    EndpointId, FailureKind, InboxEntry, InboxEntryId, InboxEntryState, InboxEvent, InstanceId,
    Operation, OperationEvent, OperationId, OperationSource, OperationState, OperationTarget,
    OutboxEntry, OutboxEntryId, PrincipalId, RedfishCommand, ResourceODataId, Role, RoleAssignment,
    TargetId,
};
use rutilus_operation_engine::OperationStore;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::{
    BoundaryFuture, CenterInbox, CenterOutbox, InboxInsertOutcome,
    center::projection::{CenterContentConsumer, CenterProjectionRepository},
    center::session::ResolvedSite,
};

/// How long a dispatched operation offer stays actionable at the site:
/// 15 minutes (§15.6 — the site refuses an expired offer; the short bound
/// matches the D2 binding-code TTL and keeps a stale dispatch from
/// executing late).
pub const CENTER_OFFER_TTL: Duration = Duration::seconds(15 * 60);

/// The candidate states of the §17.5 idempotency scan: every non-terminal
/// state (the mirror of [`OperationState::is_terminal`]). The scan queries
/// one state at a time so it rides the state index (`ix_operations_state`,
/// §13.6) instead of listing the whole operation table — terminal
/// operations are retired history for the dispatch key.
const IDEMPOTENCY_CANDIDATE_STATES: [OperationState; 5] = [
    OperationState::Queued,
    OperationState::Validating,
    OperationState::Running,
    OperationState::WaitingRemote,
    OperationState::Verifying,
];

/// How many pending §15.6 offers one idempotency scan reads at most.
///
/// The scan needs only the pending offers of the involved site — an
/// acknowledged row is delivered history (§15.4), so the state filter keeps
/// the scan from ever decrypting it — and the bound caps the decryption
/// work of a pathological queue. Each undecided operation holds at most one
/// pending offer (the TTL retirement acknowledges an expired one before a
/// fresh offer is delivered under the same id), so the realistic working
/// set stays far below the bound.
///
/// The bound is not a hard cap on the scan's visibility: a candidate whose
/// pending offer sits beyond the truncation is resolved from the
/// fall-through history reads (`offer_history` for the single-candidate
/// repair, `offer_history_full` for the multi-candidate fall-through)
/// instead of being mistaken for a never-queued record, so the pending
/// truncation never re-mints an id.
const CENTER_DISPATCH_OFFER_SCAN_LIMIT: u64 = 256;

/// One center-initiated operation dispatch (§15.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterOperationRequest {
    site_id: InstanceId,
    endpoint_id: EndpointId,
    target_odata_id: ResourceODataId,
    command: RedfishCommand,
    actor: PrincipalId,
}

impl CenterOperationRequest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        site_id: InstanceId,
        endpoint_id: EndpointId,
        target_odata_id: ResourceODataId,
        command: RedfishCommand,
        actor: PrincipalId,
    ) -> Self {
        Self {
            site_id,
            endpoint_id,
            target_odata_id,
            command,
            actor,
        }
    }

    /// The site the offer is addressed to.
    #[must_use]
    pub const fn site_id(&self) -> InstanceId {
        self.site_id
    }

    /// The endpoint the operation targets.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// The Redfish target of the operation.
    #[must_use]
    pub fn target_odata_id(&self) -> &ResourceODataId {
        &self.target_odata_id
    }

    /// The typed write command of the operation (§15.6 — the wire carries
    /// only the typed command, never URL, method, headers, or body).
    #[must_use]
    pub fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// The acting principal (the `ActorContext` of the offer).
    #[must_use]
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
}

/// The record of one dispatched operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchedOperation {
    operation_id: OperationId,
    expires_at: OffsetDateTime,
}

impl DispatchedOperation {
    #[must_use]
    pub const fn new(operation_id: OperationId, expires_at: OffsetDateTime) -> Self {
        Self {
            operation_id,
            expires_at,
        }
    }

    /// The stable operation id shared by the offer and the tracking record.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// When the offer stops being actionable at the site.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// The role-assignment boundary of the dispatch permission check (§16.1).
pub trait CenterRoleRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Reads one principal's role assignment.
    fn find_role_assignment(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>>;
}

impl<Roles> CenterRoleRepository for &Roles
where
    Roles: CenterRoleRepository + ?Sized,
{
    type Error = Roles::Error;

    fn find_role_assignment(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>> {
        Roles::find_role_assignment(*self, principal_id)
    }
}

/// The §16.1 dispatch judgment: may one role assignment dispatch an
/// operation to the target site?
///
/// The `Administrator` is the global role. The `Operator` dispatches to
/// every site when the assignment is unscoped (D3: `site_id` is `None`),
/// and only to the assigned site when it is scoped. The `Viewer` is
/// read-only and never dispatches.
#[must_use]
pub fn allows_dispatch(
    role: Role,
    assignment_site: Option<InstanceId>,
    target_site: InstanceId,
) -> bool {
    match role {
        Role::Administrator => true,
        Role::Operator => assignment_site.is_none() || assignment_site == Some(target_site),
        Role::Viewer => false,
    }
}

/// The center-side dispatch use case (design §15.6, S5).
///
/// `Store` is the projection and operation boundary on one store, `Outbox`
/// the durable §15.4 queue, and `Roles` the role boundary. The dispatch
/// records the operation before the offer is enqueued, so by the time the
/// site answers, the tracking record exists; an enqueue failure leaves the
/// recorded operation `Queued` — the caller sees the failure, and a retry
/// of the same undecided dispatch returns the existing operation instead
/// of a fresh identity, delivering the offer the failure stranded (§17.5
/// idempotency: one operation id, one offer, one execution).
pub struct CenterOperationDispatch<Store, Outbox, Roles> {
    store: Store,
    outbox: Outbox,
    roles: Roles,
}

impl<Store, Outbox, Roles> CenterOperationDispatch<Store, Outbox, Roles> {
    #[must_use]
    pub const fn new(store: Store, outbox: Outbox, roles: Roles) -> Self {
        Self {
            store,
            outbox,
            roles,
        }
    }
}

/// A controlled failure of one dispatch.
#[derive(Debug, Error)]
pub enum CenterDispatchError<ProjectionError, OperationError, OutboxError, RoleError>
where
    ProjectionError: Error + 'static,
    OperationError: Error + 'static,
    OutboxError: Error + 'static,
    RoleError: Error + 'static,
{
    /// The acting principal has no role assignment, or its role cannot
    /// dispatch to the target site (§16.1).
    #[error("the acting principal is not authorized to dispatch to the target site")]
    NotAuthorized,
    /// The endpoint is not in the center's projection.
    #[error("endpoint {endpoint_id} is not projected")]
    UnknownEndpoint { endpoint_id: EndpointId },
    /// The endpoint belongs to a different site; the offer would be dropped
    /// by the addressed site (§15.6).
    #[error("endpoint {endpoint_id} does not belong to site {site_id}")]
    EndpointNotInSite {
        endpoint_id: EndpointId,
        site_id: InstanceId,
    },
    /// The target is not part of the endpoint's projected resources.
    #[error("target {target} is not in the projection of endpoint {endpoint_id}")]
    UnknownTarget {
        endpoint_id: EndpointId,
        target: String,
    },
    /// The typed command could not be serialized into its wire payload.
    #[error("the command could not be serialized: {0}")]
    CommandSerialization(#[source] serde_json::Error),
    /// A terminal `Unknown` operation already covers this dispatch key —
    /// the site may have landed the write (§13.5: `Unknown` means the
    /// outcome cannot be proven). The dispatch is refused with the existing
    /// operation id instead of minting a fresh one, so a retry can never
    /// double-execute a write whose result the site could not prove
    /// (R6-E-01).
    #[error("operation {operation_id} ended Unknown and may have landed; the dispatch is refused")]
    UnknownOutcomePending { operation_id: OperationId },
    /// The projection repository failed; carries its own error.
    #[error("the projection repository failed: {0}")]
    Projection(#[source] ProjectionError),
    /// The operation store failed; carries its own error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationError),
    /// The durable outbox failed; carries its own error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
    /// The role repository failed; carries its own error.
    #[error("the role repository failed: {0}")]
    Role(#[source] RoleError),
}

/// The concrete failure type of one dispatch.
type DispatchErrorOf<Store, Outbox, Roles> = CenterDispatchError<
    <Store as CenterProjectionRepository>::Error,
    <Store as OperationStore>::Error,
    <Outbox as CenterOutbox>::Error,
    <Roles as CenterRoleRepository>::Error,
>;

impl<Store, Outbox, Roles> CenterOperationDispatch<Store, Outbox, Roles>
where
    Store: CenterProjectionRepository + OperationStore,
    Outbox: CenterOutbox,
    Roles: CenterRoleRepository,
{
    /// Dispatches one §15.6 operation offer to a bound site.
    ///
    /// The permission check runs first (the actor's role against the target
    /// site, §16.1/D3), then the routing checks (the endpoint must be the
    /// target site's projection, and the target must be part of it), then
    /// the tracking record and the offer. The offer wire shape carries
    /// exactly the §15.6 set — the typed command, the target, the
    /// operation id, the expiry, and the actor context — and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`CenterDispatchError::NotAuthorized`] when the actor's role
    /// cannot dispatch to the site, the routing variants for an endpoint or
    /// target outside the site's projection, and the boundary variants for
    /// persistence failures.
    pub async fn dispatch(
        &self,
        request: &CenterOperationRequest,
        now: OffsetDateTime,
    ) -> Result<DispatchedOperation, DispatchErrorOf<Store, Outbox, Roles>> {
        // §16.1: the actor's role, scoped by the D3 site association.
        let assignment = self
            .roles
            .find_role_assignment(request.actor)
            .await
            .map_err(CenterDispatchError::Role)?;
        let Some(assignment) = assignment else {
            return Err(CenterDispatchError::NotAuthorized);
        };
        if !allows_dispatch(assignment.role(), assignment.site_id(), request.site_id) {
            return Err(CenterDispatchError::NotAuthorized);
        }
        // §15.6 routing: the offer is addressed to one site, so its
        // endpoint must be that site's projection.
        let Some(endpoint) = self
            .store
            .find_endpoint_projection(request.endpoint_id)
            .await
            .map_err(CenterDispatchError::Projection)?
        else {
            return Err(CenterDispatchError::UnknownEndpoint {
                endpoint_id: request.endpoint_id,
            });
        };
        if endpoint.site_id() != Some(request.site_id) {
            return Err(CenterDispatchError::EndpointNotInSite {
                endpoint_id: request.endpoint_id,
                site_id: request.site_id,
            });
        }
        let target = request.target_odata_id.as_str();
        if !self
            .store
            .has_resource(request.endpoint_id, target)
            .await
            .map_err(CenterDispatchError::Projection)?
        {
            return Err(CenterDispatchError::UnknownTarget {
                endpoint_id: request.endpoint_id,
                target: target.to_owned(),
            });
        }
        // §15.6 idempotency: a retry of an undecided dispatch — the same
        // site, endpoint, target, and command with an active tracking
        // record — returns the existing operation instead of a fresh
        // identity: a second offer would double-execute at the site, and a
        // retry after an enqueue failure would orphan the first `Queued`
        // record (§17.5).
        if let Some(existing) = self.find_undecided(request, now).await? {
            return Ok(existing);
        }
        // R6-E-01 (§13.5): an `Unknown` outcome means the site cannot prove
        // whether the write landed — a fresh dispatch of the same key could
        // double-execute it. The refusal carries the existing operation id,
        // so the operator can reconcile against that record instead of
        // re-dispatching blindly.
        if let Some(operation_id) = self.find_unknown_outcome(request).await? {
            return Err(CenterDispatchError::UnknownOutcomePending { operation_id });
        }
        // The tracking record precedes the offer, so the site's reply
        // always finds its record.
        let operation_id = OperationId::generate();
        let expires_at = now + CENTER_OFFER_TTL;
        let operation = Operation::new(
            operation_id,
            OperationSource::Center,
            vec![OperationTarget::new(
                TargetId::generate(),
                request.endpoint_id,
            )],
            request.command.clone(),
            now,
        );
        self.store
            .create_operation(&operation)
            .await
            .map_err(CenterDispatchError::Operation)?;
        self.enqueue_offer(request, operation_id, expires_at, now)
            .await?;
        Ok(DispatchedOperation::new(operation_id, expires_at))
    }

    /// Finds the operation a retry of an undecided dispatch must reuse: an
    /// active center-sourced operation on the same (site, endpoint, target,
    /// command), judged from the tracking records and the §15.6 offer scan.
    ///
    /// - A pending offer is still actionable: the dispatch is in flight and
    ///   the retry returns the existing operation with its original expiry.
    /// - The pending offer's TTL passed: the retry retires the stale rows
    ///   and delivers a fresh offer under the same id — same §17.5 key, so
    ///   the site can never execute it twice.
    /// - No pending offer row exists: the retry resolves the candidate
    ///   through the directed read over the plaintext `operation_id`
    ///   column (R6-E-04) — the fall-through repair read, which addresses
    ///   one operation's newest row without decrypting the site's queue. An
    ///   acknowledged offer whose reply receipt was lost is re-delivered
    ///   under the same id, or returned in flight with its original expiry,
    ///   so the site's §17.5 idempotency still binds; an acknowledged
    ///   offer for a different target is a different operation on the same
    ///   endpoint and command, and the retry starts fresh below; a record
    ///   the directed read does not know at all was never enqueued, and a
    ///   fresh id cannot double-execute anything. The repair for the
    ///   offerless record alone runs only for a single candidate, where no
    ///   other operation could own the retry — and the same directed-read
    ///   judgment governs the single candidate, so a different-target
    ///   dispatch is never blind-merged into its id (F1, W3F-1) and an
    ///   in-flight or scan-truncated offer returns in flight or
    ///   re-delivers under the same id exactly like the multi-candidate
    ///   path (W3F-5).
    ///
    /// The tracking scan queries every candidate state on the state index
    /// (`ix_operations_state`, §13.6) instead of listing the whole table,
    /// and the offer scan reads only the pending queue (bounded by
    /// [`CENTER_DISPATCH_OFFER_SCAN_LIMIT`]), so a retry of a live dispatch
    /// never decrypts an acknowledged offer row; the rare fall-through
    /// branch resolves each candidate the pending scan cannot see through
    /// [`Self::resolve_candidate`]'s directed read — one row per candidate,
    /// never a scan of the site's queue.
    async fn find_undecided(
        &self,
        request: &CenterOperationRequest,
        now: OffsetDateTime,
    ) -> Result<Option<DispatchedOperation>, DispatchErrorOf<Store, Outbox, Roles>> {
        let mut operations = Vec::new();
        for state in IDEMPOTENCY_CANDIDATE_STATES {
            operations.extend(
                self.store
                    .list_operations(Some(state))
                    .await
                    .map_err(CenterDispatchError::Operation)?,
            );
        }
        let mut candidates = operations
            .into_iter()
            .filter(|operation| {
                operation.source() == OperationSource::Center
                    && !operation.state().is_terminal()
                    && operation
                        .targets()
                        .first()
                        .is_some_and(|target| target.endpoint_id() == request.endpoint_id)
                    && operation.command() == request.command
            })
            .collect::<Vec<_>>();
        // Each per-state query returns its own acceptance order; the sort
        // restores the deterministic order of one full listing, so a
        // multi-candidate retry picks the same operation as before.
        candidates.sort_by_key(|operation| (operation.created_at(), operation.id()));
        let candidates = candidates
            .into_iter()
            .map(|operation| operation.id())
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Ok(None);
        }
        // The offer facts ride in the site's durable outbox — the center
        // queue holds exactly the §15.6 offers — not in the tracking
        // record, so the retry scan rebuilds them from the pending queue:
        // an acknowledged row is delivered history (§15.4), never part of
        // an undecided dispatch, and the bound caps the decryption work of
        // a pathological queue.
        let entries = self
            .outbox
            .list_pending(request.site_id, CENTER_DISPATCH_OFFER_SCAN_LIMIT)
            .await
            .map_err(CenterDispatchError::Outbox)?;
        let facts = entries.iter().filter_map(offer_facts).collect::<Vec<_>>();
        if candidates.len() == 1 && !facts.iter().any(|fact| fact.operation_id == candidates[0]) {
            let operation_id = candidates[0];
            // The single-candidate repair read (W3F-1, W3F-5): the
            // candidate is resolved with exactly the judgment the
            // multi-candidate path applies — the retry must never
            // blind-merge a different-target dispatch into the existing
            // id, and an in-flight or scan-truncated offer returns in
            // flight or re-delivers under the same id as the documentation
            // promises. Only a record the directed read does not know at
            // all was never enqueued — the offer a failed dispatch
            // stranded — and its offer is delivered now; a known candidate
            // whose newest offer targets a different resource is a
            // different operation on the same endpoint and command, and
            // the retry starts fresh below. The pre-migration rows (no
            // `operation_id` column value) are backfilled by the directed
            // read itself, so an acknowledged pre-migration offer is never
            // mistaken for a never-enqueued record.
            if let Some(dispatched) = self
                .resolve_candidate(request, operation_id, &facts, now)
                .await?
            {
                return Ok(Some(dispatched));
            }
            if self
                .outbox
                .find_offer_by_operation(request.site_id, operation_id)
                .await
                .map_err(CenterDispatchError::Outbox)?
                .is_some()
            {
                return Ok(None);
            }
            tracing::warn!(
                "site {}: delivering the offer a failed dispatch stranded for operation \
                 {operation_id}",
                request.site_id
            );
            return self
                .deliver_retry(request, operation_id, now)
                .await
                .map(Some);
        }
        // The fall-through repair read: the pending scan is bounded by
        // [`CENTER_DISPATCH_OFFER_SCAN_LIMIT`] and skips the acknowledged
        // rows, so each candidate it cannot see is resolved through the
        // directed read over the plaintext `operation_id` column (R6-E-04)
        // — one row per candidate, never a scan of the site's whole queue.
        // A retry must never mint a fresh id for a delivered operation:
        // the id is the §17.5 key, so the directed read is the honest
        // fall-through — a fall-through that hid a delivered operation's
        // offers would start fresh under a new id and double-execute the
        // write at the site.
        for operation_id in candidates {
            if let Some(dispatched) = self
                .resolve_candidate(request, operation_id, &facts, now)
                .await?
            {
                return Ok(Some(dispatched));
            }
        }
        Ok(None)
    }

    /// Resolves one candidate against its offer facts with the §15.6
    /// judgment: `Some` when the candidate is the same dispatch as the
    /// request — in flight with the newest offer's expiry, or retired and
    /// re-delivered under the same id — and `None` when the candidate
    /// carries no facts or its offers target a different resource (a
    /// different operation on the same endpoint and command; the retry
    /// starts fresh below).
    ///
    /// The candidate's pending facts are the primary source — the bounded
    /// scan of [`Self::find_undecided`]. When the pending scan cannot see
    /// the candidate at all, the directed read over the plaintext
    /// `operation_id` column (R6-E-04) supplies the candidate's newest
    /// durable row — exactly the fall-through repair the pre-column
    /// history reads performed, without decrypting the site's queue: an
    /// acknowledged offer is delivered history (§15.4) whose reply receipt
    /// may have been lost — re-delivered under the same id, or returned in
    /// flight, so the site's §17.5 idempotency still binds — and a pending
    /// offer beyond the scan's limit is the truncation case, resolved
    /// exactly like the pending scan would. A candidate neither source
    /// knows was never enqueued: nothing was ever delivered for it, so the
    /// fresh start below cannot double-execute anything (the single-
    /// candidate repair in `find_undecided` is the repair path for such a
    /// record alone).
    async fn resolve_candidate(
        &self,
        request: &CenterOperationRequest,
        operation_id: OperationId,
        pending: &[OfferFact],
        now: OffsetDateTime,
    ) -> Result<Option<DispatchedOperation>, DispatchErrorOf<Store, Outbox, Roles>> {
        let rows = pending
            .iter()
            .filter(|fact| fact.operation_id == operation_id)
            .collect::<Vec<_>>();
        // R6-E-04: the fall-through repair read is the directed lookup —
        // the newest durable row of the operation, one row instead of a
        // scan of the site's whole queue (the pre-migration rows are
        // backfilled by the read itself).
        let mut directed: Option<OfferFact> = None;
        let mut newest = rows.iter().copied().max_by_key(|fact| fact.sequence);
        if newest.is_none()
            && let Some(entry) = self
                .outbox
                .find_offer_by_operation(request.site_id, operation_id)
                .await
                .map_err(CenterDispatchError::Outbox)?
        {
            directed = offer_facts(&entry);
            newest = directed.as_ref();
        }
        let Some(newest) = newest else {
            return Ok(None);
        };
        if newest.target != request.target_odata_id.as_str() {
            // A different operation on the same endpoint and command;
            // the retry of this request starts fresh below.
            return Ok(None);
        }
        if now > newest.expires_at {
            // The offer's §15.6 TTL passed: retire the stale rows and
            // deliver a fresh offer under the same id — the acknowledge
            // is idempotent, so an already-acknowledged row stays retired
            // history.
            for fact in rows {
                self.outbox
                    .acknowledge(fact.entry_id, now)
                    .await
                    .map_err(CenterDispatchError::Outbox)?;
            }
            if let Some(directed) = &directed {
                self.outbox
                    .acknowledge(directed.entry_id, now)
                    .await
                    .map_err(CenterDispatchError::Outbox)?;
            }
            return self
                .deliver_retry(request, operation_id, now)
                .await
                .map(Some);
        }
        Ok(Some(DispatchedOperation::new(
            operation_id,
            newest.expires_at,
        )))
    }

    /// Finds a terminal `Unknown` operation covering the dispatch key
    /// (R6-E-01, §13.5): a center-sourced operation on the same endpoint
    /// and command that ended `Unknown` — the site could not prove whether
    /// the write landed. The addressed site is confirmed through the
    /// durable offer row, so an `Unknown` operation whose offer lives in
    /// another site's queue (the endpoint was re-homed since) does not
    /// block this site's dispatch; the newest row per operation survives
    /// the ack-time pruning, so the confirmation is the directed read.
    async fn find_unknown_outcome(
        &self,
        request: &CenterOperationRequest,
    ) -> Result<Option<OperationId>, DispatchErrorOf<Store, Outbox, Roles>> {
        let unknown = self
            .store
            .list_operations(Some(OperationState::Unknown))
            .await
            .map_err(CenterDispatchError::Operation)?;
        let mut matches = unknown
            .into_iter()
            .filter(|operation| {
                operation.source() == OperationSource::Center
                    && operation
                        .targets()
                        .first()
                        .is_some_and(|target| target.endpoint_id() == request.endpoint_id)
                    && operation.command() == request.command
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|operation| (operation.created_at(), operation.id()));
        for operation in matches {
            if self
                .outbox
                .find_offer_by_operation(request.site_id, operation.id())
                .await
                .map_err(CenterDispatchError::Outbox)?
                .is_some()
            {
                return Ok(Some(operation.id()));
            }
        }
        Ok(None)
    }

    /// Delivers a fresh §15.6 offer under an existing operation id — the
    /// retry of an undecided dispatch whose offer was stranded by an
    /// enqueue failure or whose TTL passed. The id is the §17.5 key, so the
    /// site's idempotency still binds: one operation, one offer, one
    /// execution.
    async fn deliver_retry(
        &self,
        request: &CenterOperationRequest,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> Result<DispatchedOperation, DispatchErrorOf<Store, Outbox, Roles>> {
        let expires_at = now + CENTER_OFFER_TTL;
        self.enqueue_offer(request, operation_id, expires_at, now)
            .await?;
        Ok(DispatchedOperation::new(operation_id, expires_at))
    }

    /// Enqueues the §15.6 offer of one operation: the typed command as the
    /// §9.4 payload, plus the target, the stable ids, the expiry, and the
    /// actor context — never URL, method, headers, body, or script.
    async fn enqueue_offer(
        &self,
        request: &CenterOperationRequest,
        operation_id: OperationId,
        expires_at: OffsetDateTime,
        now: OffsetDateTime,
    ) -> Result<(), DispatchErrorOf<Store, Outbox, Roles>> {
        let command_json = serde_json::to_vec(&request.command)
            .map_err(CenterDispatchError::CommandSerialization)?;
        let offer = OperationOffer {
            operation_id: operation_id.to_string(),
            endpoint_id: request.endpoint_id.to_string(),
            site_id: request.site_id.to_string(),
            command_json,
            target: request.target_odata_id.as_str().to_owned(),
            expires_at_unix: expires_at.unix_timestamp(),
            actor_context: request.actor.to_string(),
        };
        self.outbox
            .enqueue(
                request.site_id,
                &EnvelopeMessage::OperationOffer(offer),
                now,
            )
            .await
            .map_err(CenterDispatchError::Outbox)?;
        Ok(())
    }
}

/// The §15.6 offer facts of one outbox row, rebuilt for the retry scan and
/// the reply-site fallback.
///
/// The tracking operation record does not persist the offer target, the
/// offer expiry, or the addressed site, so the rebuilds take them from the
/// durable offer envelopes exactly like the center's tracking view does.
struct OfferFact {
    operation_id: OperationId,
    site_id: Option<InstanceId>,
    target: String,
    expires_at: OffsetDateTime,
    entry_id: OutboxEntryId,
    sequence: i64,
}

/// The §15.6 offer facts of one outbox entry: `Some(facts)` for an offer
/// row, `None` for every other row. An offer whose expiry cannot be parsed
/// reports the epoch — an unreadable TTL is treated as past (fail closed,
/// like the flush that retires such rows) — and an offer whose addressed
/// site cannot be parsed reports `None` for the site (the V5E-1 reply
/// fallback then fails closed on that row).
fn offer_facts(entry: &OutboxEntry) -> Option<OfferFact> {
    let envelope: Envelope = serde_json::from_str(entry.payload_json()).ok()?;
    let EnvelopeMessage::OperationOffer(offer) = envelope.message? else {
        return None;
    };
    let operation_id = offer.operation_id.parse().ok()?;
    Some(OfferFact {
        operation_id,
        site_id: offer.site_id.parse().ok(),
        target: offer.target,
        expires_at: OffsetDateTime::from_unix_timestamp(offer.expires_at_unix)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        entry_id: entry.id(),
        sequence: entry.sequence(),
    })
}

/// The tracking target of one site reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyTarget {
    /// The site accepted the offer and is executing the operation.
    Running,
    /// The site accepted the offer as an asynchronous remote task and is
    /// monitoring it (§13.6 — the wire `OperationProgress.state` names the
    /// `waiting-remote` state, R6-E-06).
    WaitingRemote,
    /// The site refused the offer or the operation failed.
    Failed,
    /// The site reports a provable endpoint-side limitation: this write's
    /// capability is unsupported (E3-4). The domain state machine has no
    /// unsupported state, so the tracking record lands in the honest
    /// terminal [`OperationState::Failed`] while the classification is
    /// recorded as the operation's §13.7 failure kind — the receipt stays
    /// distinct from an ordinary failure.
    Unsupported,
    /// The site cancelled the operation and can prove that it stopped.
    Cancelled,
    /// The site cannot prove the operation's final result.
    Unknown,
    /// The operation completed successfully.
    Succeeded,
}

impl ReplyTarget {
    /// The domain events that lead from the tracking record's current state
    /// to the target; events that do not apply are absorbed, so a duplicate
    /// reply is an idempotent no-op. The terminal reports carry the
    /// lead-in events of the execution path, so a report that arrives after
    /// a lost `Accepted` reply heals the lagging record exactly like the
    /// succeeded path does.
    fn events(self) -> &'static [OperationEvent] {
        match self {
            Self::Running => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
            ],
            // `WaitingRemote` leads through the same execution path and
            // then into the remote-task tracking (§13.6, R6-E-06); the
            // events that do not apply are absorbed, so a progress report
            // that arrives after a lost `Accepted` heals the lagging record
            // exactly like the running path.
            Self::WaitingRemote => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
                OperationEvent::RemoteTaskStarted,
            ],
            // `Unsupported` lands in the same honest terminal state (E3-4):
            // the domain state machine has no unsupported state, and the
            // receipt path records the classification separately.
            Self::Failed | Self::Unsupported => &[OperationEvent::Failed],
            Self::Cancelled => &[OperationEvent::CancellationRequested],
            Self::Unknown => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
                OperationEvent::OutcomeUnknown,
            ],
            Self::Succeeded => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
                OperationEvent::ExecutionAccepted,
                OperationEvent::VerificationPassed,
            ],
        }
    }
}

/// The reply-receipt boundary of the processor: every §15.6 reply frame.
pub trait CenterReplyConsumer: Send + Sync {
    /// The consumer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Handles one reply frame from a site.
    fn on_reply<'a>(
        &'a self,
        site: InstanceId,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

/// The center-side reply tracking: advances the recorded operation state
/// and logs the reply receipt (design §15.6, S5).
///
/// Every reply is processed on arrival — the recorded operation's state
/// machine is the idempotency point, so a re-delivered reply is absorbed —
/// and the reply envelope is logged into the site's inbox row under the
/// operation id as the durable receipt. The addressed site of a reply is
/// verified before any credit (a reply routed through another site's
/// connection must never advance a foreign operation): the endpoint's
/// projection first, and the operation's durable offer facts when the
/// projection is gone (V5E-1) or disagrees with the replying site (R6-E-03
/// — the endpoint may have been re-homed after the dispatch, and the
/// replying site's own queue holding the offer proves the credit), so a
/// terminal reply still credits after the endpoint was deleted or moved.
/// A reply the tracking cannot credit is recorded as an absorbing receipt
/// before it is absorbed (R6-E-08), so nothing the site said vanishes
/// without a trace. `Store` is therefore also the center-outbox boundary:
/// the store that persists the §15.6 offers (the same `&SqliteStore` the
/// runtime hands the tracking).
pub struct CenterOperationTracking<Store, Inbox> {
    store: Store,
    inbox: Inbox,
}

impl<Store, Inbox> CenterOperationTracking<Store, Inbox> {
    #[must_use]
    pub const fn new(store: Store, inbox: Inbox) -> Self {
        Self { store, inbox }
    }
}

/// A controlled failure of one reply-tracking step.
#[derive(Debug, Error)]
pub enum CenterOperationTrackingError<OperationError, ProjectionError, OutboxError, InboxError>
where
    OperationError: Error + 'static,
    ProjectionError: Error + 'static,
    OutboxError: Error + 'static,
    InboxError: Error + 'static,
{
    /// The operation store failed; carries its own error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationError),
    /// The projection repository failed while verifying the reply's site;
    /// carries its own error.
    #[error("the projection repository failed: {0}")]
    Projection(#[source] ProjectionError),
    /// The center outbox failed while rebuilding the reply's offer facts;
    /// carries its own error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
    /// The durable inbox failed; carries its own error.
    #[error("the center inbox failed: {0}")]
    Inbox(#[source] InboxError),
    /// The reply envelope could not be serialized into its payload record.
    #[error("the reply could not be serialized into its payload record: {0}")]
    Payload(#[source] serde_json::Error),
}

/// The concrete failure type of one reply-tracking step.
type TrackingErrorOf<Store, Inbox> = CenterOperationTrackingError<
    <Store as OperationStore>::Error,
    <Store as CenterProjectionRepository>::Error,
    <Store as CenterOutbox>::Error,
    <Inbox as CenterInbox>::Error,
>;

impl<Store, Inbox> CenterReplyConsumer for CenterOperationTracking<Store, Inbox>
where
    Store: OperationStore + CenterProjectionRepository + CenterOutbox,
    Inbox: CenterInbox,
{
    type Error = TrackingErrorOf<Store, Inbox>;

    fn on_reply<'a>(
        &'a self,
        site: InstanceId,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let Some(operation_id) = reply_operation_id(envelope.message.as_ref()) else {
                // R6-E-08: a reply with an unparseable operation id cannot
                // be tracked, but it must not vanish without a trace — the
                // absorbing receipt records what the site said (the phase
                // stays `Received` and the envelope is stored verbatim,
                // with the raw id inside it; the receipt key is the
                // deterministic derivation of the raw id, because a corrupt
                // id cannot key a receipt directly). The frame is then
                // absorbed so it never ends the connection.
                self.record_absorbed_reply(
                    site,
                    envelope,
                    raw_reply_operation_id(envelope.message.as_ref()),
                    now,
                )
                .await?;
                tracing::warn!("site {site}: absorbing a reply with an unparseable operation id");
                return Ok(());
            };
            let Some(target) = reply_target(envelope.message.as_ref()) else {
                tracing::warn!("site {site}: dropping a reply with an unknown operation state");
                return Ok(());
            };
            let Some(mut operation) = self
                .store
                .find_operation(operation_id)
                .await
                .map_err(CenterOperationTrackingError::Operation)?
            else {
                // R6-E-08: a reply for an operation the center has no
                // record of (a restore that predates the offer, a manual DB
                // change) is absorbed — the connection must survive it —
                // and the absorbing receipt records what the site said: the
                // phase stays `Received` and the envelope is stored
                // verbatim under the operation id, so the reply leaves a
                // trace in the audit trail.
                self.record_reply(site, envelope, operation_id, now).await?;
                tracing::warn!(
                    "site {site}: absorbing a reply for the unknown operation {operation_id}"
                );
                return Ok(());
            };
            // The reply must come from the site the offer was addressed to:
            // a reply routed through another site's connection would
            // otherwise advance a foreign operation. The offer's site is
            // the endpoint's site in the center projection (§15.5) — the
            // reverse lookup from the tracking record — and, when the
            // projection no longer exists, the operation's recorded offer
            // facts (V5E-1).
            let expected_site = self.offer_site(&operation, site).await?;
            if expected_site != Some(site) {
                tracing::warn!(
                    "site {site}: refusing a reply for operation {operation_id} addressed to \
                     site {expected_site:?}"
                );
                // The refusal is recorded, not absorbed: the receipt row
                // names the replying site, and its phase stays untouched —
                // the center never credits the reply. The frame is still
                // acknowledged: the receipt is the durable evidence of what
                // the site said, and re-delivering the frame would wedge
                // the connection and every later frame of the site's report
                // on an anomaly the receipt already records (the same
                // at-least-once cost judgment as the projection's absorbed
                // frames). After the V5E-1 fallback this path fires only
                // when the operation's offer facts are gone from the outbox
                // history too — a manual DB change or a restore that
                // predates the offer — which the receipt trail and the warn
                // name for the operator.
                self.record_reply(site, envelope, operation_id, now).await?;
                return Ok(());
            }
            // E3-4: a `failed-unsupported` receipt is classified as the
            // operation's §13.7 failure kind. The kind is written before
            // the state transition — the same ordering as the site's
            // refusal path (`operation_executor`), so a crash between the
            // two writes leaves either an unclassified failure or an
            // orphaned kind on a non-terminal row, both harmless per the
            // `OperationStore::record_failure_kind` contract. The write is
            // unconditional on the credited path: the kind is a fact of
            // the reply being credited, and a re-delivered receipt
            // re-records the same value idempotently.
            if target == ReplyTarget::Unsupported {
                self.store
                    .record_failure_kind(operation_id, FailureKind::CapabilityUnsupported)
                    .await
                    .map_err(CenterOperationTrackingError::Operation)?;
            }
            // The state machine is the idempotency point: the events that
            // do not apply (the record is already at the target or
            // terminal) are absorbed, and only a changed state is written.
            let loaded_state = operation.state();
            for event in target.events() {
                let _ = operation.apply(*event, now);
            }
            if operation.state() != loaded_state {
                self.store
                    .apply_transition(operation_id, operation.state(), now)
                    .await
                    .map_err(CenterOperationTrackingError::Operation)?;
            }
            // The durable reply receipt: one inbox row per operation id
            // mirroring the reply phase, so the audit trail shows exactly
            // what the site said.
            self.log_reply(site, envelope, operation_id, envelope.message.as_ref(), now)
                .await?;
            Ok(())
        })
    }
}

impl<Store, Inbox> CenterOperationTracking<Store, Inbox>
where
    Store: OperationStore + CenterProjectionRepository + CenterOutbox,
    Inbox: CenterInbox,
{
    /// The site an operation's offer was addressed to: the endpoint's site
    /// in the center projection (§15.5), and — when the projection is gone
    /// or disagrees with the replying site — the operation's recorded offer
    /// facts (V5E-1, R6-E-03).
    ///
    /// The projection is the primary source when it names the replying
    /// site. When the endpoint is no longer projected — the endpoint was
    /// deleted by the site after the operation ran, or the center was
    /// restored from a database that predates the projection — the reply is
    /// verified against the operation's durable offer facts instead of
    /// being refused (V5E-1): the center's outbox holds exactly the §15.6
    /// offers, so the replying site's own queue carries the offer the
    /// center addressed to it, and the offer envelope records the addressed
    /// site. When the projection names a *different* site than the replying
    /// one (R6-E-03), the offer facts arbitrate before any refusal: the
    /// endpoint may have been re-homed after the dispatch, and the reply
    /// still credits when the replying site's own queue holds the offer —
    /// only when the projection AND the offer facts both disagree is the
    /// reply refused. A legitimate reply always comes from the site whose
    /// queue holds the offer, so the fallback restores the credit for the
    /// very replies the deleted or moved projection would have stranded; a
    /// reply from any other site finds no offer in its queue and stays
    /// refused. `None` — the reply is refused (fail closed) — only when
    /// the projection and the offer facts are both missing or both
    /// disagree.
    async fn offer_site(
        &self,
        operation: &Operation,
        site: InstanceId,
    ) -> Result<Option<InstanceId>, TrackingErrorOf<Store, Inbox>> {
        let Some(endpoint_id) = operation
            .targets()
            .first()
            .map(|target| target.endpoint_id())
        else {
            return Ok(None);
        };
        if let Some(projection) = self
            .store
            .find_endpoint_projection(endpoint_id)
            .await
            .map_err(CenterOperationTrackingError::Projection)?
        {
            let projected_site = projection.site_id();
            if projected_site == Some(site) {
                return Ok(projected_site);
            }
            // R6-E-03: the projection disagrees with the replying site —
            // the endpoint was re-homed after the dispatch. The durable
            // offer facts arbitrate: the replying site's own queue holding
            // the offer proves the center addressed it there, so the reply
            // credits; only when the facts also disagree is the reply
            // refused.
            return self.offer_site_from_offer_facts(operation.id(), site).await;
        }
        self.offer_site_from_offer_facts(operation.id(), site).await
    }

    /// The expected site of one operation rebuilt from its recorded §15.6
    /// offer facts (V5E-1): the replying site's durable outbox holds the
    /// offer the center addressed to it, and the offer envelope records the
    /// addressed site.
    ///
    /// The read is the directed lookup over the plaintext `operation_id`
    /// column (R6-E-04) — the newest durable row of the operation, one row
    /// instead of a scan of the replying site's whole queue; the
    /// pre-migration rows are backfilled by the read itself. The offer's
    /// recorded site is the expected site; a row whose envelope's site
    /// disagrees with the queue it lives in (a manual DB change) is
    /// returned as-is, and the caller's site comparison refuses it.
    async fn offer_site_from_offer_facts(
        &self,
        operation_id: OperationId,
        site: InstanceId,
    ) -> Result<Option<InstanceId>, TrackingErrorOf<Store, Inbox>> {
        let Some(entry) = self
            .store
            .find_offer_by_operation(site, operation_id)
            .await
            .map_err(CenterOperationTrackingError::Outbox)?
        else {
            return Ok(None);
        };
        Ok(offer_facts(&entry).and_then(|fact| fact.site_id))
    }

    /// Persists the reply envelope as the operation's inbox receipt — the
    /// durable record of what the site said — without advancing the receipt
    /// phase.
    async fn record_reply(
        &self,
        site: InstanceId,
        envelope: &Envelope,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> Result<(), TrackingErrorOf<Store, Inbox>> {
        let payload_json =
            serde_json::to_string(envelope).map_err(CenterOperationTrackingError::Payload)?;
        let entry = InboxEntry::new(
            InboxEntryId::generate(),
            operation_id,
            site,
            payload_json,
            now,
            now,
        );
        self.inbox
            .insert(&entry)
            .await
            .map_err(CenterOperationTrackingError::Inbox)?;
        Ok(())
    }

    /// Records one reply that the tracking cannot credit as an absorbing
    /// receipt (R6-E-08): the envelope is stored verbatim at the `Received`
    /// phase — the durable trace of what the site said — even though no
    /// tracking record can absorb it. A raw operation id that does not
    /// parse as a `OperationId` cannot key a receipt directly, so its
    /// receipt key is the deterministic derivation
    /// ([`absorbed_receipt_operation_id`]): the same raw id always lands
    /// on the same key, and the stored payload carries the raw id verbatim.
    async fn record_absorbed_reply(
        &self,
        site: InstanceId,
        envelope: &Envelope,
        raw_operation_id: Option<&str>,
        now: OffsetDateTime,
    ) -> Result<(), TrackingErrorOf<Store, Inbox>> {
        let operation_id =
            raw_operation_id.map_or_else(OperationId::generate, absorbed_receipt_operation_id);
        self.record_reply(site, envelope, operation_id, now).await
    }

    /// Persists the reply envelope as the operation's inbox receipt and
    /// sets the receipt's phase to mirror the reply.
    ///
    /// The insert and the phase advance are one write-gate transaction
    /// (P3-9): the receipt row is created at the phase the reply dictates
    /// — `Accepted` for an acceptance or progress, `Rejected` for a
    /// refusal, `Completed` for a terminal report — so a fresh receipt
    /// costs one write instead of two or three. The merge is sound because
    /// the phase is a fact of the reply being recorded, not a separate
    /// step: the old two-write path's transient `Received` row was never
    /// observable, and a crash between the two writes could even have
    /// stranded the receipt one phase behind the reply.
    ///
    /// The advance path survives for a duplicate receipt, where the stored
    /// row already exists: the phase leads mirror the reply against
    /// whatever the row carries, best-effort, exactly as before — an
    /// advance the stored phase refuses (a re-delivered older reply) is
    /// logged and heals on the next reply.
    async fn log_reply(
        &self,
        site: InstanceId,
        envelope: &Envelope,
        operation_id: OperationId,
        message: Option<&EnvelopeMessage>,
        now: OffsetDateTime,
    ) -> Result<(), TrackingErrorOf<Store, Inbox>> {
        let payload_json =
            serde_json::to_string(envelope).map_err(CenterOperationTrackingError::Payload)?;
        let phase = reply_events(message)
            .last()
            .map_or(InboxEntryState::Received, |event| event.to_state());
        let entry = InboxEntry::from_parts(
            InboxEntryId::generate(),
            operation_id,
            site,
            payload_json,
            phase,
            now,
            now,
        );
        let outcome = self
            .inbox
            .insert(&entry)
            .await
            .map_err(CenterOperationTrackingError::Inbox)?;
        if outcome == InboxInsertOutcome::Created {
            // The fresh row was born at the reply's phase: the insert
            // carried the phase the old code applied through a separate
            // advance write.
            return Ok(());
        }
        // A duplicate receipt: the stored row already exists, so the phase
        // leads mirror the reply against it, best-effort — an advance the
        // stored phase refuses (a re-delivered older reply) is logged and
        // heals on the next reply.
        for event in reply_events(message) {
            match self.inbox.advance(operation_id, *event).await {
                Ok(()) => {}
                Err(source) => {
                    tracing::warn!(
                        "site {site}: the receipt of operation {operation_id} did not advance to \
                         {event}: {source}"
                    );
                    break;
                }
            }
        }
        Ok(())
    }
}

/// The operation id of one reply message.
fn reply_operation_id(message: Option<&EnvelopeMessage>) -> Option<OperationId> {
    raw_reply_operation_id(message).and_then(|raw| raw.parse().ok())
}

/// The raw operation id string of one reply message — the verbatim wire
/// value, without parsing (R6-E-08): the absorbing receipt of a corrupt id
/// must preserve the raw string, and the payload stores the envelope
/// verbatim around it.
fn raw_reply_operation_id(message: Option<&EnvelopeMessage>) -> Option<&str> {
    let Some(
        EnvelopeMessage::OperationAccepted(OperationAccepted { operation_id, .. })
        | EnvelopeMessage::OperationRejected(OperationRejected { operation_id, .. })
        | EnvelopeMessage::OperationProgress(OperationProgress { operation_id, .. })
        | EnvelopeMessage::OperationCompleted(OperationCompleted { operation_id, .. }),
    ) = message
    else {
        return None;
    };
    Some(operation_id)
}

/// The receipt key of a reply whose wire operation id is not a valid
/// `OperationId` (R6-E-08): a corrupt id cannot key a `center_inbox`
/// receipt directly, so the key is the deterministic UUID v5 of the raw
/// string — the same raw id always yields the same key, and the receipt
/// payload carries the raw id verbatim, so the trace survives both the
/// re-delivery and the audit read.
fn absorbed_receipt_operation_id(raw: &str) -> OperationId {
    OperationId::from_uuid(uuid::Uuid::new_v5(
        &uuid::Uuid::NAMESPACE_OID,
        raw.as_bytes(),
    ))
}

/// The `OperationCompleted` summary vocabulary of the E3-4 refusal
/// classification: a `Failed` operation whose persisted §13.7 failure kind
/// is `capability-unsupported` is summarized as `failed-unsupported` by the
/// site (`CenterSync::completed_summary` in `application/src/center_sync.rs`;
/// the `OperationCompleted.summary` contract in
/// `center-protocol/proto/rutilus/center/v1/center.proto`), so the center's
/// receipt can recognize the endpoint-side limitation instead of letting the
/// unparseable summary fall through to the plain failure. The recognition is
/// a value addition to the existing summary field, never a wire change.
///
/// The recognition is boundary-checked (see [`is_unsupported_summary`]): the
/// exact vocabulary value, or the value followed by the `:` detail
/// delimiter, is the classification; a longer word that merely shares the
/// prefix — a malformed or unrelated summary — is not, so a truncated or
/// extended spelling can never misclassify an ordinary failure as
/// unsupported.
///
/// The console tracking response cannot surface the classification yet:
/// `CenterOperationResponse` has no unsupported phase in its state
/// vocabulary and no classification field, and the wire is fixed, so the
/// tracking view keeps reporting the plain `failed` phase — the vocabulary
/// addition is tracked by the existing TODO(W3C-3) at
/// `web/src/lib.rs:4084`. Within the center's domain layer the
/// classification survives on the tracking record (the §13.7 failure kind
/// the receipt path records) and in the durable receipt payload.
const UNSUPPORTED_SUMMARY_PREFIX: &str = "failed-unsupported";

/// Whether one `OperationCompleted` summary carries the E3-4 refusal
/// classification: the exact [`UNSUPPORTED_SUMMARY_PREFIX`] value, or the
/// value followed by the `:` delimiter of a detail suffix. Anything else —
/// a longer word that merely shares the prefix without the delimiter — is
/// not the classification.
fn is_unsupported_summary(summary: &str) -> bool {
    summary
        .strip_prefix(UNSUPPORTED_SUMMARY_PREFIX)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with(':'))
}

/// The tracking target of one reply message.
fn reply_target(message: Option<&EnvelopeMessage>) -> Option<ReplyTarget> {
    match message {
        Some(EnvelopeMessage::OperationAccepted(_)) => Some(ReplyTarget::Running),
        Some(EnvelopeMessage::OperationProgress(progress)) => {
            // R6-E-06: the progress frame carries the site's real operation
            // state (§15.6 `OperationProgress.state` — the domain state
            // code, §13.2): an asynchronous task the site is monitoring
            // tracks as `WaitingRemote` with the remote-task lead-in,
            // every other progress state stays on the plain running path.
            match progress.state.parse::<OperationState>() {
                Ok(OperationState::WaitingRemote) => Some(ReplyTarget::WaitingRemote),
                _ => Some(ReplyTarget::Running),
            }
        }
        Some(EnvelopeMessage::OperationRejected(_)) => Some(ReplyTarget::Failed),
        Some(EnvelopeMessage::OperationCompleted(completed)) => {
            if completed.succeeded {
                Some(ReplyTarget::Succeeded)
            } else {
                // The wire contract distinguishes the terminal outcomes
                // within the existing fields: the site reports its stable
                // operation state code in the summary, so the receipt must
                // not collapse `Unknown` and `Cancelled` into `Failed`.
                // The E3-4 refusal vocabulary is recognized before the
                // stable-state parse — a summary in the `failed-unsupported`
                // vocabulary is the capability classification (see
                // [`is_unsupported_summary`]) — and a summary that names no
                // stable state is a plain failure.
                if is_unsupported_summary(&completed.summary) {
                    Some(ReplyTarget::Unsupported)
                } else {
                    match completed.summary.parse::<OperationState>() {
                        Ok(OperationState::Cancelled) => Some(ReplyTarget::Cancelled),
                        Ok(OperationState::Unknown) => Some(ReplyTarget::Unknown),
                        _ => Some(ReplyTarget::Failed),
                    }
                }
            }
        }
        _ => None,
    }
}

/// The receipt-phase advances of one reply (§17.5 vocabulary: a receipt is
/// `received` on the first reply, `accepted`/`rejected` on the decision,
/// `completed` on the terminal report).
fn reply_events(message: Option<&EnvelopeMessage>) -> &'static [InboxEvent] {
    match message {
        Some(EnvelopeMessage::OperationAccepted(_) | EnvelopeMessage::OperationProgress(_)) => {
            &[InboxEvent::Accepted]
        }
        Some(EnvelopeMessage::OperationRejected(_)) => &[InboxEvent::Rejected],
        Some(EnvelopeMessage::OperationCompleted(_)) => {
            &[InboxEvent::Accepted, InboxEvent::Completed]
        }
        _ => &[],
    }
}

/// The frame processor: the engine's [`crate::center::session::CenterFrameConsumer`]
/// composing the §15.5 projection and the §15.6 reply tracking.
///
/// `Projection` is the content boundary ([`CenterContentConsumer`], the
/// concrete [`CenterProjection`]) and `Tracking` the reply boundary
/// ([`CenterReplyConsumer`], the concrete [`CenterOperationTracking`]).
pub struct CenterFrameProcessor<Projection, Tracking> {
    projection: Projection,
    tracking: Tracking,
}

impl<Projection, Tracking> CenterFrameProcessor<Projection, Tracking> {
    #[must_use]
    pub const fn new(projection: Projection, tracking: Tracking) -> Self {
        Self {
            projection,
            tracking,
        }
    }
}

/// A controlled failure of one processor step.
#[derive(Debug, Error)]
pub enum CenterFrameProcessorError<ProjectionError, TrackingError>
where
    ProjectionError: Error + 'static,
    TrackingError: Error + 'static,
{
    /// The projection failed; carries its own error.
    #[error("the projection failed: {0}")]
    Projection(#[source] ProjectionError),
    /// The reply tracking failed; carries its own error.
    #[error("the reply tracking failed: {0}")]
    Tracking(#[source] TrackingError),
}

impl<Projection, Tracking> crate::center::session::CenterFrameConsumer
    for CenterFrameProcessor<Projection, Tracking>
where
    Projection: CenterContentConsumer,
    Tracking: CenterReplyConsumer,
{
    type Error = CenterFrameProcessorError<Projection::Error, Tracking::Error>;

    fn on_frame<'a>(
        &'a self,
        site: &'a ResolvedSite,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            match envelope.message.as_ref() {
                Some(
                    EnvelopeMessage::OperationAccepted(_)
                    | EnvelopeMessage::OperationRejected(_)
                    | EnvelopeMessage::OperationProgress(_)
                    | EnvelopeMessage::OperationCompleted(_),
                ) => self
                    .tracking
                    .on_reply(site.instance_id(), envelope, now)
                    .await
                    .map_err(CenterFrameProcessorError::Tracking),
                Some(message) => self
                    .projection
                    .on_frame(site, envelope.sequence, message, now)
                    .await
                    .map_err(CenterFrameProcessorError::Projection),
                None => Ok(()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use rutilus_center_protocol::{
        EndpointSnapshot, Envelope, EnvelopeMessage, OperationAccepted, OperationCompleted,
        OperationOffer, OperationProgress, OperationRejected, TlsTrust,
    };
    use rutilus_domain::{
        Artifact, ArtifactId, ArtifactState, BatchOperation, BatchOperationId, CenterBindingId,
        CertificateFingerprint, EndpointId, Event, FailureKind, InboxEntry, InboxEntryState,
        InboxEvent, InstanceId, Operation, OperationId, OperationSource, OperationState,
        OutboxEntry, OutboxEntryId, OutboxEntryState, PrincipalId, RedfishCommand, ResetType,
        ResourceODataId, Role, RoleAssignment, SyncCursor, SyncCursorId, SyncStream, SystemCommand,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild, OperationStore,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::{
        ArtifactRepository, CenterInbox, CenterOutbox, InboxInsertOutcome,
        center::projection::{
            CenterEndpointProjection, CenterProjection, EndpointProjectionWrite,
            ProjectionWriteOutcome, ResourceProjectionWrite,
        },
        center::session::{CenterFrameConsumer, ResolvedSite},
    };

    /// A store error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock store never fails")]
    struct MockStoreError;

    /// The shared state of the mock dispatch store: the operation records
    /// and the projection reads the dispatch routing validates against.
    #[derive(Clone)]
    struct MockDispatchState {
        operations: Arc<Mutex<HashMap<OperationId, Operation>>>,
        // The persisted §13.7 failure-kind code string, mirroring the
        // `operations.failure_kind` column of the real store.
        failure_kinds: Arc<Mutex<HashMap<OperationId, String>>>,
        endpoint: Arc<Mutex<Option<(EndpointId, InstanceId)>>>,
        endpoints: Arc<Mutex<Vec<EndpointProjectionWrite>>>,
        resources: Arc<Mutex<Vec<(EndpointId, String)>>>,
        inbox_entries: Arc<Mutex<Vec<InboxEntry>>>,
        offers: Arc<Mutex<Vec<OperationOffer>>>,
        entries: Arc<Mutex<Vec<OutboxEntry>>>,
        roles: Arc<Mutex<Option<RoleAssignment>>>,
        enqueue_failures: Arc<Mutex<u64>>,
    }

    impl MockDispatchState {
        fn new() -> Self {
            Self {
                operations: Arc::new(Mutex::new(HashMap::new())),
                failure_kinds: Arc::new(Mutex::new(HashMap::new())),
                endpoint: Arc::new(Mutex::new(None)),
                endpoints: Arc::new(Mutex::new(Vec::new())),
                resources: Arc::new(Mutex::new(Vec::new())),
                inbox_entries: Arc::new(Mutex::new(Vec::new())),
                offers: Arc::new(Mutex::new(Vec::new())),
                entries: Arc::new(Mutex::new(Vec::new())),
                roles: Arc::new(Mutex::new(None)),
                enqueue_failures: Arc::new(Mutex::new(0)),
            }
        }

        /// Scripts the next `count` enqueue attempts to fail — the failed
        /// first attempt of the stranded-offer retry test.
        fn fail_enqueues(&self, count: u64) -> Result<(), MockStoreError> {
            *self.enqueue_failures.lock().map_err(|_| MockStoreError)? = count;
            Ok(())
        }

        fn entries_owned(&self) -> Vec<OutboxEntry> {
            self.entries
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn find_operation_owned(&self, operation_id: OperationId) -> Option<Operation> {
            self.operations
                .lock()
                .map(|rows| rows.get(&operation_id).cloned())
                .unwrap_or_default()
        }

        fn endpoints_owned(&self) -> Vec<EndpointProjectionWrite> {
            self.endpoints
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn offers_owned(&self) -> Vec<OperationOffer> {
            self.offers
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn inbox_entries_owned(&self) -> Vec<InboxEntry> {
            self.inbox_entries
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }
    }

    #[derive(Clone)]
    struct MockDispatchStore {
        state: MockDispatchState,
    }

    impl MockDispatchStore {
        fn new() -> (Self, MockDispatchState) {
            let state = MockDispatchState::new();
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl CenterProjectionRepository for MockDispatchStore {
        type Error = MockStoreError;

        fn upsert_endpoint<'a>(
            &'a self,
            projection: &'a EndpointProjectionWrite,
            _site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move {
                self.state
                    .endpoints
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(projection.clone());
                Ok(ProjectionWriteOutcome::Applied)
            })
        }

        fn delete_endpoint(
            &self,
            _endpoint_id: EndpointId,
            _site: InstanceId,
        ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move { Ok(ProjectionWriteOutcome::Applied) })
        }

        fn upsert_resource<'a>(
            &'a self,
            _projection: &'a ResourceProjectionWrite,
            _site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move { Ok(ProjectionWriteOutcome::Applied) })
        }

        fn delete_resource(
            &self,
            _endpoint_id: EndpointId,
            _odata_id: &str,
            _site: InstanceId,
        ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move { Ok(ProjectionWriteOutcome::Applied) })
        }

        fn upsert_event<'a>(
            &'a self,
            _event: &'a Event,
            _site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn declare_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
            _site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_artifact_site(
            &self,
            _artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<InstanceId>, Self::Error>> {
            Box::pin(async move { Ok(None) })
        }

        fn find_endpoint_projection(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<CenterEndpointProjection>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .endpoint
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .as_ref()
                    .filter(|(stored, _)| *stored == endpoint_id)
                    .map(|(stored, site)| CenterEndpointProjection::new(*stored, Some(*site))))
            })
        }

        fn has_resource(
            &self,
            endpoint_id: EndpointId,
            odata_id: &str,
        ) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
            let odata_id = odata_id.to_owned();
            Box::pin(async move {
                Ok(self
                    .state
                    .resources
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .any(|(stored, known)| *stored == endpoint_id && known == &odata_id))
            })
        }
    }

    impl ArtifactRepository for MockDispatchStore {
        type Error = MockStoreError;

        fn create_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_artifact(
            &self,
            _artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
            Box::pin(async move { Ok(None) })
        }

        fn list_artifacts_by_state(
            &self,
            _state: ArtifactState,
        ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn update_artifact(
            &self,
            _artifact_id: ArtifactId,
            _uploaded_bytes: u64,
            _state: ArtifactState,
            _occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn artifact_file_path(&self, _artifact_id: ArtifactId) -> PathBuf {
            PathBuf::new()
        }
    }

    impl OperationStore for MockDispatchStore {
        type Error = MockStoreError;

        fn create_operation<'a>(
            &'a self,
            operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.state
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(operation.id(), operation.clone());
                Ok(())
            })
        }

        fn find_operation(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn apply_transition(
            &self,
            operation_id: OperationId,
            new_state: OperationState,
            occurred_at: OffsetDateTime,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.state.operations.lock().map_err(|_| MockStoreError)?;
                let row = rows.get(&operation_id).ok_or(MockStoreError)?.clone();
                if row.is_terminal() {
                    return Err(MockStoreError);
                }
                let updated = Operation::try_from_parts(
                    row.id(),
                    row.source(),
                    row.targets().to_vec(),
                    row.command(),
                    new_state,
                    row.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockStoreError)?;
                rows.insert(operation_id, updated);
                Ok(())
            })
        }

        fn apply_transition_if_current(
            &self,
            operation_id: OperationId,
            expected_state: OperationState,
            new_state: OperationState,
            occurred_at: OffsetDateTime,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.state.operations.lock().map_err(|_| MockStoreError)?;
                let row = rows.get(&operation_id).ok_or(MockStoreError)?.clone();
                if row.state() != expected_state {
                    return Err(MockStoreError);
                }
                let updated = Operation::try_from_parts(
                    row.id(),
                    row.source(),
                    row.targets().to_vec(),
                    row.command(),
                    new_state,
                    row.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockStoreError)?;
                rows.insert(operation_id, updated);
                Ok(())
            })
        }

        fn record_failure_kind(
            &self,
            operation_id: OperationId,
            kind: FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                // The persistence store refuses an unknown id (`NotFound`);
                // the mock mirrors the contract.
                if !self
                    .state
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .contains_key(&operation_id)
                {
                    return Err(MockStoreError);
                }
                self.state
                    .failure_kinds
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(operation_id, kind.as_str().to_owned());
                Ok(())
            })
        }

        fn find_failure_kind(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<FailureKind>, Self::Error>> {
            Box::pin(async move {
                // A stored code this build cannot classify is a corrupt
                // row, exactly like the persistence store's read.
                self.state
                    .failure_kinds
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&operation_id)
                    .map(|code| code.parse::<FailureKind>())
                    .transpose()
                    .map_err(|_| MockStoreError)
            })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                if let Some(state) = state {
                    rows.retain(|operation| operation.state() == state);
                }
                Ok(rows)
            })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_batch(
            &self,
            _batch_id: BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
            Box::pin(async move { Ok(None) })
        }

        fn list_batches(
            &self,
        ) -> OperationBoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_batch_children(
            &self,
            _batch_id: BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl CenterRoleRepository for MockDispatchStore {
        type Error = MockStoreError;

        fn find_role_assignment(
            &self,
            _principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>> {
            Box::pin(
                async move { Ok(self.state.roles.lock().map_err(|_| MockStoreError)?.clone()) },
            )
        }
    }

    impl CenterOutbox for MockDispatchStore {
        type Error = MockStoreError;

        fn enqueue<'a>(
            &'a self,
            instance_id: InstanceId,
            message: &'a EnvelopeMessage,
            created_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
            Box::pin(async move {
                let mut failures = self
                    .state
                    .enqueue_failures
                    .lock()
                    .map_err(|_| MockStoreError)?;
                if *failures > 0 {
                    *failures -= 1;
                    return Err(MockStoreError);
                }
                let mut entries = self.state.entries.lock().map_err(|_| MockStoreError)?;
                let sequence = i64::try_from(entries.len())
                    .unwrap_or(i64::MAX)
                    .saturating_add(1);
                let envelope = Envelope {
                    sequence: u64::try_from(sequence).unwrap_or(u64::MAX),
                    acked_sequence: 0,
                    message: Some(message.clone()),
                };
                let payload_json = serde_json::to_string(&envelope).map_err(|_| MockStoreError)?;
                let entry = OutboxEntry::new(
                    OutboxEntryId::generate(),
                    instance_id,
                    sequence,
                    payload_json,
                    created_at,
                );
                if let EnvelopeMessage::OperationOffer(offer) = message {
                    self.state
                        .offers
                        .lock()
                        .map_err(|_| MockStoreError)?
                        .push(offer.clone());
                }
                entries.push(entry.clone());
                Ok(entry)
            })
        }

        fn list_pending(
            &self,
            instance_id: InstanceId,
            limit: u64,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .filter(|entry| {
                        entry.instance_id() == instance_id
                            && entry.state() == OutboxEntryState::Pending
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                rows.sort_by_key(OutboxEntry::sequence);
                rows.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
                Ok(rows)
            })
        }

        fn list_offers(
            &self,
            instance_id: InstanceId,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .filter(|entry| entry.instance_id() == instance_id)
                    .cloned()
                    .collect::<Vec<_>>();
                rows.sort_by_key(OutboxEntry::sequence);
                Ok(rows)
            })
        }

        fn acknowledge(
            &self,
            entry_id: OutboxEntryId,
            acked_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.state.entries.lock().map_err(|_| MockStoreError)?;
                for row in &mut *rows {
                    if row.id() == entry_id && row.state() == OutboxEntryState::Pending {
                        let _ = row.ack(acked_at);
                    }
                }
                Ok(())
            })
        }
    }

    impl CenterInbox for MockDispatchStore {
        type Error = MockStoreError;

        fn insert<'a>(
            &'a self,
            entry: &'a InboxEntry,
        ) -> BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .inbox_entries
                    .lock()
                    .map_err(|_| MockStoreError)?;
                if rows
                    .iter()
                    .any(|row| row.operation_id() == entry.operation_id())
                {
                    return Ok(InboxInsertOutcome::DuplicateInProgress);
                }
                rows.push(entry.clone());
                Ok(InboxInsertOutcome::Created)
            })
        }

        fn find_by_operation(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .inbox_entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .find(|entry| entry.operation_id() == operation_id)
                    .cloned())
            })
        }

        fn advance(
            &self,
            operation_id: OperationId,
            event: InboxEvent,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .inbox_entries
                    .lock()
                    .map_err(|_| MockStoreError)?;
                let entry = rows
                    .iter_mut()
                    .find(|entry| entry.operation_id() == operation_id)
                    .ok_or(MockStoreError)?;
                // The trait contract of `CenterInbox::advance`: an entry
                // that already carries the target state is a successful
                // no-op, exactly like the persistence implementation's
                // `AlreadyInState` outcome.
                if entry.state() == event.to_state() {
                    return Ok(());
                }
                entry.apply(event).map_err(|_| MockStoreError)
            })
        }
    }

    fn base_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    fn request(
        site: InstanceId,
        endpoint_id: EndpointId,
        target: &str,
        actor: PrincipalId,
    ) -> Result<CenterOperationRequest, Box<dyn Error>> {
        Ok(CenterOperationRequest::new(
            site,
            endpoint_id,
            ResourceODataId::parse(target)?,
            RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown)),
            actor,
        ))
    }

    /// The dispatch setup shared by the retry tests: the endpoint projected
    /// for the site, the offered resource, and the administrator role.
    fn seed_dispatch_route(
        state: &MockDispatchState,
        site: InstanceId,
        endpoint_id: EndpointId,
        actor: PrincipalId,
        now: OffsetDateTime,
    ) -> Result<(), MockStoreError> {
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        Ok(())
    }

    /// Sends one `OperationAccepted` reply for the operation.
    async fn accept_reply(
        tracking: &CenterOperationTracking<MockDispatchStore, MockDispatchStore>,
        site: InstanceId,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> Result<(), Box<dyn Error>> {
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now,
            )
            .await?;
        Ok(())
    }

    /// Sends one unsuccessful `OperationCompleted` reply for the operation,
    /// carrying the given summary — the site's stable state code (§15.6).
    async fn complete_reply(
        tracking: &CenterOperationTracking<MockDispatchStore, MockDispatchStore>,
        site: InstanceId,
        operation_id: OperationId,
        summary: &str,
        now: OffsetDateTime,
    ) -> Result<(), Box<dyn Error>> {
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationCompleted(OperationCompleted {
                        operation_id: operation_id.to_string(),
                        succeeded: false,
                        summary: summary.to_owned(),
                    })),
                },
                now,
            )
            .await?;
        Ok(())
    }

    #[test]
    fn allows_dispatch_applies_the_role_and_site_scope_rules() {
        let site = InstanceId::generate();
        let other = InstanceId::generate();
        // The Administrator is global, scoped or not.
        assert!(allows_dispatch(Role::Administrator, None, site));
        assert!(allows_dispatch(Role::Administrator, Some(other), site));
        // The Operator dispatches globally when unscoped, and only to the
        // assigned site when scoped (D3).
        assert!(allows_dispatch(Role::Operator, None, site));
        assert!(allows_dispatch(Role::Operator, Some(site), site));
        assert!(!allows_dispatch(Role::Operator, Some(other), site));
        // The Viewer never dispatches.
        assert!(!allows_dispatch(Role::Viewer, None, site));
        assert!(!allows_dispatch(Role::Viewer, Some(site), site));
    }

    #[tokio::test]
    async fn dispatch_records_the_operation_and_enqueues_the_s15_6_offer_wire_shape()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store, outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));

        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        assert_eq!(dispatched.expires_at(), now + CENTER_OFFER_TTL);

        // The tracking record exists with the offer's operation id.
        let operation = state
            .find_operation_owned(dispatched.operation_id())
            .ok_or("the tracking record is missing")?;
        assert_eq!(operation.source(), OperationSource::Center);
        assert_eq!(operation.state(), OperationState::Queued);
        assert_eq!(operation.targets().len(), 1);
        assert_eq!(operation.targets()[0].endpoint_id(), endpoint_id);

        // The offer carries exactly the §15.6 set: the typed command, the
        // target, the stable ids, the expiry, and the actor context — and
        // nothing else (no URL, no method, no headers, no body).
        let offers = state.offers_owned();
        assert_eq!(offers.len(), 1);
        let offer = &offers[0];
        assert_eq!(offer.operation_id, dispatched.operation_id().to_string());
        assert_eq!(offer.endpoint_id, endpoint_id.to_string());
        assert_eq!(offer.site_id, site.to_string());
        assert_eq!(offer.target, "/redfish/v1/Systems/1");
        assert_eq!(
            offer.expires_at_unix,
            dispatched.expires_at().unix_timestamp()
        );
        assert_eq!(offer.actor_context, actor.to_string());
        let decoded: RedfishCommand = serde_json::from_slice(&offer.command_json)?;
        assert_eq!(
            decoded,
            RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown))
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_refuses_without_authorization_and_outside_the_site_scope()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store, outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let other = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));

        // No assignment at all is refused.
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::NotAuthorized)
        ));
        // A Viewer assignment is read-only.
        *state.roles.lock().map_err(|_| MockStoreError)? =
            Some(RoleAssignment::new(actor, Role::Viewer, None, now, None));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::NotAuthorized)
        ));
        // A site-scoped Operator cannot dispatch to another site (D3).
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Operator,
            None,
            now,
            Some(other),
        ));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::NotAuthorized)
        ));
        // The same scoped Operator dispatches to the assigned site.
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Operator,
            None,
            now,
            Some(site),
        ));
        assert!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_refuses_unknown_endpoints_targets_and_cross_site_routes()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store, outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let other = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));

        // An endpoint outside the projection is refused.
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::UnknownEndpoint { .. })
        ));
        // An endpoint projected for another site is refused — the offer
        // would be dropped by the addressed site (§15.6 routing).
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, other));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::EndpointNotInSite { .. })
        ));
        // A target outside the endpoint's projection is refused.
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::UnknownTarget { .. })
        ));
        Ok(())
    }

    // Every reply phase and its duplicate absorption is spelled out as its
    // own assertion so a failure pinpoints the exact transition, which
    // exceeds the pedantic line budget (the persistence tests allow the
    // same lint on their exhaustive assertion tests).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn replies_advance_the_tracking_state_machine_idempotently() -> Result<(), Box<dyn Error>>
    {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store.clone(), outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let operation_id = dispatched.operation_id();
        let tracking = CenterOperationTracking::new(store.clone(), store);

        // The accepted reply moves the record to Running.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );

        // A duplicate accepted reply is absorbed, not applied twice.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::seconds(2),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );

        // The completed reply reports the terminal outcome.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 3,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationCompleted(OperationCompleted {
                        operation_id: operation_id.to_string(),
                        succeeded: true,
                        summary: String::from("reset verified"),
                    })),
                },
                now + Duration::seconds(3),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Succeeded
        );
        // A reply after the terminal outcome is absorbed.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 4,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationProgress(OperationProgress {
                        operation_id: operation_id.to_string(),
                        state: String::from("running"),
                        detail: String::new(),
                    })),
                },
                now + Duration::seconds(4),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Succeeded
        );
        // The reply receipts were logged under the operation id.
        let receipts = state.inbox_entries_owned();
        assert!(
            receipts
                .iter()
                .all(|entry| entry.operation_id() == operation_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rejected_reply_marks_the_operation_failed_and_unknown_replies_are_absorbed()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store.clone(), outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let operation_id = dispatched.operation_id();
        let tracking = CenterOperationTracking::new(store.clone(), store);

        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationRejected(OperationRejected {
                        operation_id: operation_id.to_string(),
                        reason: rutilus_center_protocol::OperationRejectedReason::Expired as i32,
                        detail: String::from("the offer expired"),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );

        // A reply for an unknown operation id is absorbed, never an error.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: OperationId::generate().to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::seconds(2),
            )
            .await?;
        Ok(())
    }

    /// An in-memory cursor store behind the processor test.
    #[derive(Clone)]
    struct MockCursor {
        cursors: Arc<Mutex<HashMap<SyncStream, u64>>>,
    }

    impl MockCursor {
        fn new() -> Self {
            Self {
                cursors: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl crate::CenterCursor for MockCursor {
        type Error = MockStoreError;

        fn get(
            &self,
            _instance_id: InstanceId,
            stream: SyncStream,
        ) -> BoundaryFuture<'_, Result<Option<SyncCursor>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&stream)
                    .map(|sequence| {
                        SyncCursor::new(
                            SyncCursorId::generate(),
                            InstanceId::generate(),
                            stream,
                            sequence.to_string(),
                            OffsetDateTime::UNIX_EPOCH,
                        )
                    }))
            })
        }

        fn set<'a>(
            &'a self,
            cursor: &'a SyncCursor,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let sequence = cursor
                    .cursor_value()
                    .parse::<u64>()
                    .map_err(|_| MockStoreError)?;
                self.cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(cursor.stream(), sequence);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn the_processor_routes_content_and_replies_to_the_right_consumers()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store.clone(), cursor);
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        let processor = CenterFrameProcessor::new(projection, tracking);
        let site = ResolvedSite::new(
            InstanceId::generate(),
            CenterBindingId::generate(),
            CertificateFingerprint::from_bytes([0x42; 32]),
        );
        let now = base_time();
        let endpoint_id = EndpointId::generate();

        // A dispatched offer gives the reply routing a record to advance.
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? =
            Some((endpoint_id, site.instance_id()));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let dispatched = dispatch
            .dispatch(
                &request(
                    site.instance_id(),
                    endpoint_id,
                    "/redfish/v1/Systems/1",
                    actor,
                )?,
                now,
            )
            .await?;

        // A content frame reaches the projection...
        let content = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
                endpoint_id: endpoint_id.to_string(),
                display_name: String::from("Rack A PDU"),
                address: String::from("https://192.0.2.10"),
                trust: TlsTrust::SystemCa as i32,
                refresh_generation: 1,
                resources: Vec::new(),
                health: String::from("ok"),
            })),
        };
        processor.on_frame(&site, &content, now).await?;
        assert_eq!(state.endpoints_owned().len(), 1);

        // ...and a reply frame reaches the tracking: the record advances.
        let reply = Envelope {
            sequence: 2,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                operation_id: dispatched.operation_id().to_string(),
                accepted_at_unix: now.unix_timestamp(),
            })),
        };
        processor
            .on_frame(&site, &reply, now + Duration::SECOND)
            .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_of_an_undecided_dispatch_returns_the_existing_operation()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The retry of the same undecided dispatch returns the same
        // operation: one tracking record and one offer, no second execution
        // (§17.5 idempotency), and the original offer's expiry is reported.
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(retry.operation_id(), first.operation_id());
        assert_eq!(retry.expires_at(), first.expires_at());
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            1
        );
        assert_eq!(state.offers_owned().len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_after_an_enqueue_failure_delivers_the_stranded_offer()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        state.fail_enqueues(1)?;

        // The first attempt records the operation and fails at the queue
        // write, stranding the record `Queued` without an offer.
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::Outbox(_))
        ));
        assert_eq!(state.offers_owned().len(), 0);
        let stranded = state
            .operations
            .lock()
            .map_err(|_| MockStoreError)?
            .values()
            .next()
            .cloned()
            .ok_or("the stranded operation is missing")?;

        // The retry returns the same operation and delivers its offer: no
        // orphaned second `Queued` record.
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(retry.operation_id(), stranded.id());
        let offers = state.offers_owned();
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0].operation_id, stranded.id().to_string());
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            1
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_revives_an_offer_past_its_ttl_under_the_same_id() -> Result<(), Box<dyn Error>>
    {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The retry after the offer's §15.6 TTL: the stale offer row is
        // retired and a fresh offer is delivered under the same operation
        // id — the same §17.5 key, so the site can never execute it twice.
        let retry_at = now + CENTER_OFFER_TTL + Duration::SECOND;
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                retry_at,
            )
            .await?;
        assert_eq!(retry.operation_id(), first.operation_id());
        assert_eq!(retry.expires_at(), retry_at + CENTER_OFFER_TTL);
        let entries = state.entries_owned();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Acked)
                .count(),
            1,
            "the stale offer row must be retired"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Pending)
                .count(),
            1,
            "exactly one live offer row must remain"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_ignores_an_acknowledged_offer_as_delivered_history()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The site processed the offer: the outbox row is acknowledged
        // (§15.4), but no reply has landed yet — the operation is still
        // undecided. The idempotency scan reads only pending offers, so
        // the acked row is delivered history and is never decrypted for a
        // retry; the history read resolves the single candidate exactly
        // like the multi-candidate path (W3F-5): the offer is still
        // actionable, so the retry returns the operation in flight with
        // its original expiry — nothing is re-sent under the id the site
        // already processed (§17.5 idempotency).
        let entries = state.entries_owned();
        assert_eq!(entries.len(), 1);
        store
            .acknowledge(entries[0].id(), now + Duration::SECOND)
            .await?;
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(2),
            )
            .await?;
        assert_eq!(retry.operation_id(), first.operation_id());
        assert_eq!(retry.expires_at(), first.expires_at());
        let entries = state.entries_owned();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Acked)
                .count(),
            1,
            "the acknowledged offer row stays retired history"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Pending)
                .count(),
            0,
            "an in-flight offer is returned in flight, never re-delivered"
        );
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            1,
            "no second tracking record is created"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_multi_candidate_retry_reuses_the_acked_operations_id() -> Result<(), Box<dyn Error>>
    {
        // F1: with several undecided operations on the same endpoint and
        // command, a retry of the one whose offer was acknowledged — the
        // site processed it, but the reply receipt never landed — must
        // reuse its id. The pending-only scan cannot see the acknowledged
        // row, so without the fall-through history read the retry would
        // mint a fresh id and the site would execute the same dispatch
        // twice (§17.5: the operation id is the idempotency key).
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Chassis/1")));

        // A: the /Systems/1 dispatch, whose offer the site later
        // acknowledges without ever answering.
        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // B: a second undecided operation on the same endpoint and
        // command (another target), still pending — the multi-candidate
        // working set the retry scan must not confuse.
        let second = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                now + Duration::SECOND,
            )
            .await?;
        assert_ne!(second.operation_id(), first.operation_id());
        let entries = state.entries_owned();
        assert_eq!(entries.len(), 2);
        // The site processes A's offer and acknowledges the frame; the
        // `OperationAccepted` reply is lost in transit. The rows sit in
        // enqueue order, so A's is the first.
        store
            .acknowledge(entries[0].id(), now + Duration::seconds(2))
            .await?;

        // The retry of A: the same operation id comes back — in flight
        // with the original expiry — and no second tracking record or
        // offer is created.
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(3),
            )
            .await?;
        assert_eq!(retry.operation_id(), first.operation_id());
        assert_eq!(retry.expires_at(), first.expires_at());
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            2,
            "no third tracking record is created"
        );
        assert_eq!(state.offers_owned().len(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_multi_candidate_retry_revives_an_expired_acked_offer_under_the_same_id()
    -> Result<(), Box<dyn Error>> {
        // The retired flavor of the F1 scenario: A's acknowledged offer
        // is past its §15.6 TTL — the acknowledged state is exactly what
        // the flush's TTL retirement leaves behind — and B's offer for a
        // different target is still pending. The retry of A re-delivers
        // under A's id with a fresh expiry, the same §17.5 key, never a
        // second identity.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Chassis/1")));

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let second = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                now + Duration::SECOND,
            )
            .await?;
        assert_ne!(second.operation_id(), first.operation_id());
        // The site processes A's offer and acknowledges the frame; the
        // reply is lost, and the retry comes only after the offer's TTL
        // passed.
        let entries = state.entries_owned();
        store
            .acknowledge(entries[0].id(), now + Duration::SECOND)
            .await?;
        let retry_at = now + CENTER_OFFER_TTL + Duration::SECOND;
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                retry_at,
            )
            .await?;
        assert_eq!(retry.operation_id(), first.operation_id());
        assert_eq!(retry.expires_at(), retry_at + CENTER_OFFER_TTL);
        let entries = state.entries_owned();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Acked)
                .count(),
            1,
            "A's stale offer row stays retired history"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Pending)
                .count(),
            2,
            "the retry delivers one fresh offer under A's id beside B's"
        );
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            2,
            "no third tracking record is created"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_single_candidate_repair_never_merges_a_different_target_dispatch()
    -> Result<(), Box<dyn Error>> {
        // W3F-1: A(X) is in flight — its offer was acknowledged by the
        // site with the reply lost — when Y, the same endpoint and command
        // with a different target, is dispatched. The single-candidate
        // repair must verify the candidate's target against the offer
        // history before reusing its id: Y is a different operation
        // (§17.5 keys the target), so it starts fresh instead of being
        // silently merged into X's id — a merged offer would never execute
        // (the site answers the duplicate X under its recorded state).
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Chassis/1")));

        // A(X): the /Systems/1 dispatch, whose offer the site acknowledges
        // without ever answering — the in-flight, reply-lost scenario.
        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let entries = state.entries_owned();
        assert_eq!(entries.len(), 1);
        store
            .acknowledge(entries[0].id(), now + Duration::SECOND)
            .await?;

        // Y: the same endpoint and command with another target. The retry
        // must not merge Y into X's id: a fresh id is minted, its own
        // offer is delivered, and X's tracking record stays untouched.
        let second = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                now + Duration::seconds(2),
            )
            .await?;
        assert_ne!(second.operation_id(), first.operation_id());
        let offers = state.offers_owned();
        assert_eq!(offers.len(), 2);
        assert_eq!(offers[1].target, "/redfish/v1/Chassis/1");
        assert_eq!(offers[1].operation_id, second.operation_id().to_string());
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            2,
            "the different-target dispatch is its own tracking record"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_single_candidate_repair_revives_an_expired_acked_offer_under_the_same_id()
    -> Result<(), Box<dyn Error>> {
        // W3F-5: the single-candidate repair resolves against the full
        // offer history like a multi-candidate retry — an acknowledged
        // offer past its §15.6 TTL is retired and re-delivered under the
        // same id, the same §17.5 key, never a second identity.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The site processed the offer and acknowledged the frame; the
        // reply is lost, and the retry comes only after the offer's TTL
        // passed.
        let entries = state.entries_owned();
        assert_eq!(entries.len(), 1);
        store
            .acknowledge(entries[0].id(), now + Duration::SECOND)
            .await?;
        let retry_at = now + CENTER_OFFER_TTL + Duration::SECOND;
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                retry_at,
            )
            .await?;
        assert_eq!(retry.operation_id(), first.operation_id());
        assert_eq!(retry.expires_at(), retry_at + CENTER_OFFER_TTL);
        let entries = state.entries_owned();
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Acked)
                .count(),
            1,
            "the stale offer row stays retired history"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Pending)
                .count(),
            1,
            "the retry delivers one fresh offer under the same id"
        );
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            1,
            "no second tracking record is created"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_fresh_receipt_is_born_at_the_phase_the_reply_dictates() -> Result<(), Box<dyn Error>>
    {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let operation_id = dispatched.operation_id();
        let tracking = CenterOperationTracking::new(store.clone(), store);

        // P3-9: the first receipt is inserted at the phase the reply
        // dictates — one write, not the insert plus a separate advance.
        accept_reply(&tracking, site, operation_id, now + Duration::SECOND).await?;
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].state(), InboxEntryState::Accepted);

        // A duplicate reply is absorbed without a second row or a phase
        // change.
        accept_reply(&tracking, site, operation_id, now + Duration::seconds(2)).await?;
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].state(), InboxEntryState::Accepted);

        // The terminal report lands the receipt at the terminal phase.
        complete_reply(
            &tracking,
            site,
            operation_id,
            "failed",
            now + Duration::seconds(3),
        )
        .await?;
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].state(), InboxEntryState::Completed);
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_after_a_terminal_outcome_starts_a_fresh_operation()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The site refuses the offer; the operation is terminal.
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationRejected(OperationRejected {
                        operation_id: first.operation_id().to_string(),
                        reason: rutilus_center_protocol::OperationRejectedReason::Expired as i32,
                        detail: String::from("the offer expired"),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(first.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );

        // A retry of a terminal operation is a fresh attempt: a new
        // identity, a new offer, no reuse of the finished operation.
        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(2),
            )
            .await?;
        assert_ne!(retry.operation_id(), first.operation_id());
        assert_eq!(state.offers_owned().len(), 2);
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_dispatch_of_a_different_target_starts_a_fresh_operation()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Chassis/1")));

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The same endpoint and command with another target is not the same
        // dispatch: the idempotency key includes the target (§17.5).
        let second = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                now + Duration::SECOND,
            )
            .await?;
        assert_ne!(second.operation_id(), first.operation_id());
        let offers = state.offers_owned();
        assert_eq!(offers.len(), 2);
        assert_eq!(offers[1].target, "/redfish/v1/Chassis/1");
        Ok(())
    }

    #[tokio::test]
    async fn a_reply_from_another_site_is_refused_and_recorded_but_never_credited()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let other_site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());

        // A reply arriving over another site's connection is refused: the
        // operation state must not advance.
        tracking
            .on_reply(
                other_site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: dispatched.operation_id().to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Queued
        );
        // The refusal is recorded truthfully: the receipt names the
        // replying site and its phase stays untouched.
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].instance_id(), other_site);
        assert_eq!(receipts[0].state(), InboxEntryState::Received);

        // The addressed site's own reply still advances the record.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: dispatched.operation_id().to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::seconds(2),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_terminal_reply_still_credits_after_the_endpoint_projection_is_deleted()
    -> Result<(), Box<dyn Error>> {
        // V5E-1: the site completes the operation, and the endpoint's
        // projection is then deleted (the §21 endpoint-level delete the
        // site reports after the work is done). The terminal reply arrives
        // with the projection gone — the projection lookup alone would
        // refuse it and leave the operation non-terminal forever — so the
        // expected site is rebuilt from the operation's recorded offer
        // facts: the replying site's durable outbox history holds the offer
        // the center addressed to it, and the reply credits normally.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Chassis/1")));
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());

        let failed = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        // The succeeded report heals the same way from a record that missed
        // the acceptance: the offer facts carry the credit. The second
        // dispatch is a different §17.5 key (another target), so it is its
        // own operation.
        let succeeded = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                now + Duration::SECOND,
            )
            .await?;
        assert_ne!(succeeded.operation_id(), failed.operation_id());
        // The endpoint projection goes away before the site's terminal
        // reports arrive.
        *state.endpoint.lock().map_err(|_| MockStoreError)? = None;
        complete_reply(
            &tracking,
            site,
            failed.operation_id(),
            "failed",
            now + Duration::seconds(2),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(failed.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed,
            "a terminal reply must still credit after the endpoint's projection is deleted"
        );

        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationCompleted(OperationCompleted {
                        operation_id: succeeded.operation_id().to_string(),
                        succeeded: true,
                        summary: String::from("reset verified"),
                    })),
                },
                now + Duration::seconds(3),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(succeeded.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Succeeded
        );
        // Both credits were logged as durable receipts.
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 2);
        assert!(
            receipts
                .iter()
                .all(|entry| entry.operation_id() == failed.operation_id()
                    || entry.operation_id() == succeeded.operation_id())
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_foreign_site_reply_is_refused_after_the_endpoint_projection_is_deleted()
    -> Result<(), Box<dyn Error>> {
        // V5E-1: the offer-facts fallback must not weaken the site check —
        // a reply routed through another site's connection is still refused
        // when the projection is gone, because the foreign site's own outbox
        // history does not carry the operation's offer.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let other_site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;

        *state.endpoint.lock().map_err(|_| MockStoreError)? = None;
        accept_reply(
            &tracking,
            other_site,
            dispatched.operation_id(),
            now + Duration::SECOND,
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Queued,
            "the foreign site's reply must stay refused with the projection gone"
        );
        // The refusal is recorded truthfully, naming the replying site.
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].instance_id(), other_site);
        assert_eq!(receipts[0].state(), InboxEntryState::Received);

        // The addressed site's own reply still credits through the fallback.
        accept_reply(
            &tracking,
            site,
            dispatched.operation_id(),
            now + Duration::seconds(2),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_reply_is_recorded_but_never_credited_when_the_offer_history_is_gone_too()
    -> Result<(), Box<dyn Error>> {
        // V5E-1: when the projection AND the operation's offer facts are
        // both missing — the outbox rows a manual DB change or a restore
        // that predates the offer removed — the reply is unverifiable and
        // refused (fail closed): the receipt is recorded durably with the
        // replying site, the phase stays untouched, and the frame is
        // consumed so the site's connection never wedges on the anomaly.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;

        *state.endpoint.lock().map_err(|_| MockStoreError)? = None;
        *state.entries.lock().map_err(|_| MockStoreError)? = Vec::new();
        accept_reply(
            &tracking,
            site,
            dispatched.operation_id(),
            now + Duration::SECOND,
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Queued,
            "an unverifiable reply is never credited"
        );
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].instance_id(), site);
        assert_eq!(receipts[0].state(), InboxEntryState::Received);
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn completed_replies_distinguish_failed_unknown_and_cancelled_outcomes()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());

        // The summary carries the site's stable terminal state code; the
        // tracking record must not collapse `Cancelled` and `Unknown` into
        // `Failed`.
        let cancelled = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        accept_reply(
            &tracking,
            site,
            cancelled.operation_id(),
            now + Duration::SECOND,
        )
        .await?;
        complete_reply(
            &tracking,
            site,
            cancelled.operation_id(),
            "cancelled",
            now + Duration::seconds(2),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(cancelled.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Cancelled
        );

        // The plain failure dispatch runs before the unknown one — R6-E-01:
        // a terminal `Unknown` outcome blocks a same-key re-dispatch (the
        // write may have landed), so the unknown receipt is the last of the
        // three dispatches.
        let failed = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(3),
            )
            .await?;
        accept_reply(
            &tracking,
            site,
            failed.operation_id(),
            now + Duration::seconds(4),
        )
        .await?;
        complete_reply(
            &tracking,
            site,
            failed.operation_id(),
            "failed",
            now + Duration::seconds(5),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(failed.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );

        let unknown = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(6),
            )
            .await?;
        accept_reply(
            &tracking,
            site,
            unknown.operation_id(),
            now + Duration::seconds(7),
        )
        .await?;
        complete_reply(
            &tracking,
            site,
            unknown.operation_id(),
            "unknown",
            now + Duration::seconds(8),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(unknown.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Unknown
        );
        Ok(())
    }

    #[test]
    fn reply_target_recognizes_the_unsupported_summary_prefix() {
        let completed = |summary: &str, succeeded: bool| {
            Some(EnvelopeMessage::OperationCompleted(OperationCompleted {
                operation_id: String::new(),
                succeeded,
                summary: summary.to_owned(),
            }))
        };
        // E3-4: the `failed-unsupported` summary vocabulary is the
        // capability classification — recognized exactly, and with the `:`
        // detail-suffix delimiter.
        assert_eq!(
            reply_target(completed("failed-unsupported", false).as_ref()),
            Some(ReplyTarget::Unsupported)
        );
        assert_eq!(
            reply_target(completed("failed-unsupported: reset is not supported", false).as_ref()),
            Some(ReplyTarget::Unsupported)
        );
        // The recognition is boundary-checked: a longer word that merely
        // shares the prefix without the delimiter is a malformed or
        // unrelated summary, and must not misclassify an ordinary failure
        // as unsupported.
        assert_eq!(
            reply_target(completed("failed-unsupported-extra", false).as_ref()),
            Some(ReplyTarget::Failed)
        );
        assert_eq!(
            reply_target(completed("failed-unsupportedness", false).as_ref()),
            Some(ReplyTarget::Failed)
        );
        // The stable-state codes keep their own classifications, and a
        // summary naming no stable state is a plain failure.
        assert_eq!(
            reply_target(completed("failed", false).as_ref()),
            Some(ReplyTarget::Failed)
        );
        assert_eq!(
            reply_target(completed("cancelled", false).as_ref()),
            Some(ReplyTarget::Cancelled)
        );
        assert_eq!(
            reply_target(completed("unknown", false).as_ref()),
            Some(ReplyTarget::Unknown)
        );
        // The unsupported vocabulary never overrides a successful outcome.
        assert_eq!(
            reply_target(completed("failed-unsupported", true).as_ref()),
            Some(ReplyTarget::Succeeded)
        );
    }

    #[tokio::test]
    async fn an_unsupported_receipt_tracks_distinct_from_a_plain_failure()
    -> Result<(), Box<dyn Error>> {
        // E3-4/W3C-3: the site's `failed-unsupported` summary is a `Failed`
        // operation whose persisted §13.7 failure kind is
        // `capability-unsupported`. The center's receipt must not collapse
        // it into an ordinary failure: the tracking record lands in the
        // honest terminal `Failed` (the domain state machine has no
        // unsupported state) and carries the classification as its failure
        // kind, where a plain failure stays unclassified.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());

        // The unsupported report arrives with the accepted reply lost (the
        // §15.6 heal path): the terminal report still lands, healing the
        // lagging record, and the receipt row is born at the `Completed`
        // phase carrying the report's envelope verbatim.
        let unsupported = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        complete_reply(
            &tracking,
            site,
            unsupported.operation_id(),
            "failed-unsupported",
            now + Duration::SECOND,
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(unsupported.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );
        assert_eq!(
            store.find_failure_kind(unsupported.operation_id()).await?,
            Some(FailureKind::CapabilityUnsupported)
        );

        // The plain failure lands in the same honest terminal state without
        // any classification.
        let plain = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(2),
            )
            .await?;
        accept_reply(
            &tracking,
            site,
            plain.operation_id(),
            now + Duration::seconds(3),
        )
        .await?;
        complete_reply(
            &tracking,
            site,
            plain.operation_id(),
            "failed",
            now + Duration::seconds(4),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(plain.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );
        assert_eq!(store.find_failure_kind(plain.operation_id()).await?, None);

        // The durable receipts keep the distinction legible in the audit
        // trail: the unsupported receipt is born at the `Completed` phase
        // with the report's envelope (the `failed-unsupported` vocabulary),
        // while the plain receipt's payload is the acceptance that led it —
        // neither carries the refusal vocabulary.
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 2);
        let unsupported_receipt = receipts
            .iter()
            .find(|entry| entry.operation_id() == unsupported.operation_id())
            .ok_or("the unsupported receipt is missing")?;
        let plain_receipt = receipts
            .iter()
            .find(|entry| entry.operation_id() == plain.operation_id())
            .ok_or("the plain receipt is missing")?;
        assert_eq!(unsupported_receipt.state(), InboxEntryState::Completed);
        assert_eq!(plain_receipt.state(), InboxEntryState::Completed);
        assert!(
            unsupported_receipt
                .payload_json()
                .contains("failed-unsupported")
        );
        assert!(!plain_receipt.payload_json().contains("failed-unsupported"));

        // A re-delivered unsupported receipt is absorbed: the record stays
        // terminal and the classification is re-recorded idempotently.
        complete_reply(
            &tracking,
            site,
            unsupported.operation_id(),
            "failed-unsupported",
            now + Duration::seconds(5),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(unsupported.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );
        assert_eq!(
            store.find_failure_kind(unsupported.operation_id()).await?,
            Some(FailureKind::CapabilityUnsupported)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_retry_after_an_unknown_outcome_is_refused_with_the_existing_operation_id()
    -> Result<(), Box<dyn Error>> {
        // R6-E-01 (§13.5): an `Unknown` outcome means the site cannot prove
        // whether the write landed, so a same-key dispatch must be refused
        // with the existing operation id — never minted afresh, never
        // double-executed. The refusal is stable: every retry names the
        // same id.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());

        let first = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        complete_reply(
            &tracking,
            site,
            first.operation_id(),
            "unknown",
            now + Duration::SECOND,
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(first.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Unknown
        );

        let retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(2),
            )
            .await;
        assert!(
            matches!(
                retry,
                Err(CenterDispatchError::UnknownOutcomePending { operation_id })
                    if operation_id == first.operation_id()
            ),
            "the retry must be refused with the existing operation id"
        );
        // The refusal is stable: a second retry names the same id.
        let second_retry = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(3),
            )
            .await;
        assert!(matches!(
            second_retry,
            Err(CenterDispatchError::UnknownOutcomePending { operation_id })
                if operation_id == first.operation_id()
        ));
        assert_eq!(
            state.operations.lock().map_err(|_| MockStoreError)?.len(),
            1,
            "no second tracking record is created"
        );
        assert_eq!(state.offers_owned().len(), 1, "no second offer is enqueued");
        Ok(())
    }

    #[tokio::test]
    async fn a_reply_from_the_original_site_credits_after_the_endpoint_was_re_homed()
    -> Result<(), Box<dyn Error>> {
        // R6-E-03: the endpoint's projection moves to another site after
        // the dispatch (the site re-homed the endpoint), and the reply
        // arrives over the *original* site's connection — the projection
        // alone would refuse it and leave the operation non-terminal
        // forever. The offer facts arbitrate: the replying site's own queue
        // holds the offer the center addressed to it, so the reply credits.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let other_site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;

        // The endpoint's projection moves to the other site before the
        // reply arrives.
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, other_site));
        accept_reply(
            &tracking,
            site,
            dispatched.operation_id(),
            now + Duration::SECOND,
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running,
            "the original site's reply must credit through the offer facts"
        );
        // The durable receipt records the credited reply.
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].instance_id(), site);
        Ok(())
    }

    #[tokio::test]
    async fn a_waiting_remote_progress_reply_tracks_the_remote_task_state()
    -> Result<(), Box<dyn Error>> {
        // R6-E-06: the progress frame carries the site's real operation
        // state (§15.6 `OperationProgress.state`), so an asynchronous task
        // the site is monitoring tracks as `WaitingRemote` — with the
        // remote-task lead-in — instead of being folded into the plain
        // running path.
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let operation_id = dispatched.operation_id();

        // A plain running progress report stays on the running path.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationProgress(OperationProgress {
                        operation_id: operation_id.to_string(),
                        state: String::from("running"),
                        detail: String::from("executing"),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );

        // The site reports the asynchronous task: the record leads into the
        // remote-task tracking.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationProgress(OperationProgress {
                        operation_id: operation_id.to_string(),
                        state: String::from("waiting-remote"),
                        detail: String::from("monitoring the BMC task"),
                    })),
                },
                now + Duration::seconds(2),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::WaitingRemote
        );

        // A re-delivered older progress report is absorbed: the record
        // stays on the remote-task path.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 3,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationProgress(OperationProgress {
                        operation_id: operation_id.to_string(),
                        state: String::from("running"),
                        detail: String::new(),
                    })),
                },
                now + Duration::seconds(3),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::WaitingRemote
        );
        Ok(())
    }

    #[tokio::test]
    async fn absorbed_replies_for_unknown_operations_leave_a_durable_receipt()
    -> Result<(), Box<dyn Error>> {
        // R6-E-08: a reply the tracking cannot credit — an operation the
        // center has no record of, or an operation id that does not parse —
        // is recorded as an absorbing receipt (the phase stays `Received`
        // and the envelope is stored verbatim) before the warn, so nothing
        // the site said vanishes without a trace.
        let (store, state) = MockDispatchStore::new();
        let tracking = CenterOperationTracking::new(store.clone(), store);
        let now = base_time();
        let site = InstanceId::generate();

        // A reply for an unknown-but-parseable operation id.
        let unknown_id = OperationId::generate();
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: unknown_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now,
            )
            .await?;
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].operation_id(), unknown_id);
        assert_eq!(receipts[0].state(), InboxEntryState::Received);
        assert!(
            receipts[0].payload_json().contains(&unknown_id.to_string()),
            "the receipt payload must carry the envelope verbatim"
        );

        // A reply whose operation id does not parse: the receipt key is the
        // deterministic derivation of the raw id, and the payload carries
        // the raw id verbatim.
        let corrupt_id = String::from("not-a-uuid");
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: corrupt_id.clone(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now,
            )
            .await?;
        let receipts = state.inbox_entries_owned();
        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[1].state(), InboxEntryState::Received);
        assert!(
            receipts[1].payload_json().contains(&corrupt_id),
            "the receipt payload must carry the corrupt id verbatim"
        );

        // Re-delivering the same corrupt id lands on the same deterministic
        // key: the receipt is absorbed as a duplicate, never a second row.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 3,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: corrupt_id,
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now,
            )
            .await?;
        let receipts = state.inbox_entries_owned();
        assert_eq!(
            receipts.len(),
            2,
            "the corrupt id must map to one receipt key"
        );
        Ok(())
    }

    #[test]
    fn reply_target_parses_the_wire_progress_state() {
        let progress = |state: &str| {
            Some(EnvelopeMessage::OperationProgress(OperationProgress {
                operation_id: String::new(),
                state: state.to_owned(),
                detail: String::new(),
            }))
        };
        // R6-E-06: the wire `OperationProgress.state` is the site's real
        // operation state; the remote-task state tracks as `WaitingRemote`
        // and every other (or unparseable) state stays on the running path.
        assert_eq!(
            reply_target(progress("waiting-remote").as_ref()),
            Some(ReplyTarget::WaitingRemote)
        );
        assert_eq!(
            reply_target(progress("running").as_ref()),
            Some(ReplyTarget::Running)
        );
        assert_eq!(
            reply_target(progress("queued").as_ref()),
            Some(ReplyTarget::Running)
        );
        assert_eq!(
            reply_target(progress("not-a-state").as_ref()),
            Some(ReplyTarget::Running)
        );
    }

    #[tokio::test]
    async fn a_terminal_completed_reply_heals_a_record_that_missed_the_acceptance()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        seed_dispatch_route(&state, site, endpoint_id, actor, now)?;
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());

        // A summary that names no stable state is a plain failure. The
        // failure dispatch runs first — R6-E-01: a terminal `Unknown`
        // outcome blocks a same-key re-dispatch (the write may have
        // landed), so the unknown report is the last receipt of the test.
        let failed = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        complete_reply(
            &tracking,
            site,
            failed.operation_id(),
            "the recorded outcome is unavailable",
            now + Duration::SECOND,
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(failed.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );

        // The record is `Queued` when the terminal report arrives (the
        // accepted reply was lost): the unknown-outcome report still lands,
        // healing the lagging record like the succeeded path does.
        let unknown = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now + Duration::seconds(2),
            )
            .await?;
        complete_reply(
            &tracking,
            site,
            unknown.operation_id(),
            "unknown",
            now + Duration::seconds(3),
        )
        .await?;
        assert_eq!(
            state
                .find_operation_owned(unknown.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Unknown
        );
        Ok(())
    }
}
