//! The site-side center synchronization engine (design §15, 0.7.0 S4).
//!
//! [`CenterSync`] runs the site's half of the site-to-center protocol over
//! the [`crate::CenterTransport`] boundary. The engine owns everything the
//! connection layer deliberately does not: the §15.4 reconnect backoff, the
//! §15.3 negotiation-failure handling, the heartbeat timing, the durable
//! outbox resume from the last acknowledged sequence, the §15.6 operation
//! offers, and the incremental endpoint, event, and artifact reporting of
//! the §21 0.7.0 checklist.
//!
//! # Local autonomy (§4.2, §15.3)
//!
//! The engine is a background loop with exactly one contract: never take
//! the site down. A rejected negotiation (no common protocol version), an
//! unreachable center, and a dropped connection all log the reason and
//! schedule the next attempt after the §15.4 backoff, while every local
//! feature — endpoint refresh, operations, the local GUI — keeps running
//! unchanged. The durable outbox is the queue that makes this safe: content
//! enqueued while disconnected stays in the database and the flush resumes
//! from the last acknowledged sequence when the connection returns (§15.4
//! at-least-once delivery).
//!
//! # Shutdown
//!
//! `run` observes a stop signal at every await point and exits promptly;
//! an in-flight send or receive is simply dropped. The outbox rows are the
//! durable state — a stop mid-flush abandons only the wire position, which
//! the next connection resumes from the last acknowledgment, so no shutdown
//! sequence needs to complete a half-sent batch.

use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    error::Error,
    future::Future,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use rutilus_center_protocol::{
    ArtifactChunk, ArtifactManifest, EndpointSnapshot, Envelope, EnvelopeMessage, EventBatch,
    EventRecord, EventSeverity as WireEventSeverity, Heartbeat, OperationOffer,
    OperationRejectedReason, ResourceDelta, ResourceDeltaOp, ResourceSummary,
    SITE_HEARTBEAT_INTERVAL, SITE_RECONNECT_AFTER, TlsTrust as WireTlsTrust,
};
use rutilus_domain::{
    ArtifactId, ArtifactState, CapabilityState, EndpointId, Event, EventId, EventSeverity,
    FailureKind, InboxEntry, InboxEntryId, InboxEntryState, InboxEvent, InstanceId, Operation,
    OperationId, OperationSource, OperationState, OperationTarget, OutboxEntry, OutboxEntryId,
    RedfishCommand, RefreshGeneration, Sha256Hex, SyncCursor, SyncCursorId, SyncStream, TargetId,
    TlsTrust,
};
use rutilus_operation_engine::OperationStore;
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    ArtifactRepository, BoundaryFuture, CapabilityQueryRepository, Clock,
    CredentialInventoryRepository, EndpointCapabilityQuery, EndpointCapabilityQueryError,
    EndpointInventoryItem, EndpointInventoryQuery, EndpointInventoryQueryError,
    EndpointInventoryRepository, EndpointRefreshRepository,
    artifact_store::ARTIFACT_MAX_SIZE_BYTES,
    center_transport::{CenterSession, CenterTransport},
    operation_executor::{required_capability, required_capability_state},
};

/// The chunk size of one center artifact transfer: 1 MiB of payload per
/// [`ArtifactChunk`] frame, far below the protocol frame limit
/// ([`rutilus_center_protocol::MAX_FRAME_BYTES`]) with room for the envelope
/// overhead, so a chunk never risks an `EncodeLimit` refusal.
pub const CENTER_ARTIFACT_CHUNK_BYTES: usize = 1024 * 1024;

/// The §13.6 in-flight states of the reconnect report's discovery scan
/// (audit follow-up P3-10).
///
/// An operation with an open inbox entry is either in-flight (progress to
/// report) or terminal with its completion not yet delivered, so the
/// in-flight and terminal state sets partition the report's work exactly;
/// the scan queries each state through the store's state filter instead of
/// listing the whole table.
const CENTER_REPORT_IN_FLIGHT_STATES: [OperationState; 5] = [
    OperationState::Queued,
    OperationState::Validating,
    OperationState::Running,
    OperationState::WaitingRemote,
    OperationState::Verifying,
];

/// The terminal states of the reconnect report's discovery scan (audit
/// follow-up P3-10): an operation that finished since the last report
/// still carries an open inbox entry until its `OperationCompleted` is
/// delivered, so the scan must see terminal rows too.
const CENTER_REPORT_TERMINAL_STATES: [OperationState; 4] = [
    OperationState::Succeeded,
    OperationState::Failed,
    OperationState::Unknown,
    OperationState::Cancelled,
];

/// The durable outbox boundary of the site-to-center synchronization
/// (design §17 D4, §15.4).
///
/// The outbox is the site's queue to the center: every content message is
/// enqueued as one durable row carrying the next per-instance sequence, the
/// flush sends the pending rows in sequence order, and the center's `Ack`
/// moves one row to the acknowledged state. Because the queue is the
/// database, a disconnected site keeps enqueuing (the offline queue of
/// §21 0.7.0) and a reconnect resumes from the last acknowledged sequence.
pub trait CenterOutbox: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Allocates the next per-instance sequence and persists the message as
    /// one atomic write, returning the queued entry with its sequence.
    fn enqueue<'a>(
        &'a self,
        instance_id: InstanceId,
        message: &'a EnvelopeMessage,
        created_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>>;

    /// Lists the oldest pending entries of one instance in sequence order,
    /// bounded by `limit`. This is the delivery scan of the flush.
    fn list_pending(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>>;

    /// Lists every outbox entry of one instance, oldest first — the
    /// center's §15.6 offer scan. The center's durable outbox holds exactly
    /// the operation offers, acknowledged or not, so the scan rebuilds the
    /// offer facts — the target site, the target, and the offer expiry —
    /// that the tracking operation record does not persist. The dispatch
    /// retry uses it as its fall-through repair read: the retry's primary
    /// scan is the bounded pending listing, and a retry the pending scan
    /// cannot resolve — an acknowledged offer whose reply receipt was
    /// lost, an offer beyond the scan's limit, a record whose enqueue
    /// failed — is disambiguated from this full history, so the retry
    /// never mints a fresh id for a delivered operation (§17.5: one
    /// operation id, one execution).
    fn list_offers(
        &self,
        instance_id: InstanceId,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>>;

    /// Lists the newest outbox entries of one instance, newest first,
    /// bounded by `limit` — the bounded twin of [`Self::list_offers`]
    /// (V4P-3).
    ///
    /// The default implementation reads through [`Self::list_offers`] and
    /// truncates to the newest `limit` entries in memory: it bounds the
    /// caller's working set on every store, while the decryption surface is
    /// reduced only by a store-level override that pushes the limit into
    /// the query (the production repository exposes that read as
    /// `SqliteStore::list_outbox_entries_bounded`). The window holds the
    /// newest `limit` entries of the underlying read in their original
    /// order, so it holds the offers a repair most likely needs — the
    /// newest offer per dispatched operation.
    fn list_offers_bounded(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
        Box::pin(async move {
            let mut rows = self.list_offers(instance_id).await?;
            let bound = usize::try_from(limit).unwrap_or(usize::MAX);
            if rows.len() > bound {
                rows.drain(..rows.len() - bound);
            }
            Ok(rows)
        })
    }

    /// Finds the newest durable outbox row of one operation — the directed
    /// repair read of the dispatch retry's fall-through and the V5E-1
    /// reply-site fallback (R6-E-04).
    ///
    /// The center's durable outbox holds exactly the §15.6 offers, and the
    /// ack-time pruning keeps at most the newest acknowledged row per
    /// operation beside its pending row, so the newest row of the operation
    /// carries the offer facts — the target, the expiry, and the addressed
    /// site — the repair reads need, and no read has to decrypt the site's
    /// whole queue to find it.
    ///
    /// The default implementation reads through [`Self::list_offers`] and
    /// keeps the newest matching row — correct on every store — while the
    /// production repository overrides it with a directed read over the
    /// plaintext `operation_id` column (the pre-migration rows are
    /// backfilled lazily by that read).
    fn find_offer_by_operation(
        &self,
        instance_id: InstanceId,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<OutboxEntry>, Self::Error>> {
        Box::pin(async move {
            let mut rows = self.list_offers(instance_id).await?;
            rows.retain(|entry| {
                let Ok(envelope) = serde_json::from_str::<Envelope>(entry.payload_json()) else {
                    return false;
                };
                matches!(
                    envelope.message.as_ref(),
                    Some(EnvelopeMessage::OperationOffer(offer))
                        if offer.operation_id == operation_id.to_string()
                )
            });
            Ok(rows.into_iter().max_by_key(OutboxEntry::sequence))
        })
    }

    /// Finds the newest durable outbox row of one operation across every
    /// instance — the cross-instance confirmation read of the R6-E-01
    /// dispatch refusal (W7-E-3).
    ///
    /// The R6-E-01 unknown-outcome refusal confirms an `Unknown`
    /// operation's offer before refusing a same-key dispatch. An endpoint
    /// can be re-homed while the outcome is unresolved, and the offer that
    /// may have executed the write lives in the *original* site's queue —
    /// so the confirmation must address any instance, or the re-home
    /// silently unblocks the retry and the same physical write executes
    /// twice.
    ///
    /// `instance_id` is the dispatch's addressed site: the default
    /// implementation resolves the cross-instance question through that
    /// site's queue — the per-site semantics of the R6-E-01 confirmation
    /// before the W7-E-3 fix, correct on every store without instance
    /// enumeration — while the production center outbox overrides it with
    /// the true cross-instance read (the pre-migration rows are backfilled
    /// lazily by that read, exactly like [`Self::find_offer_by_operation`]).
    fn find_offer_by_operation_across_instances(
        &self,
        instance_id: InstanceId,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<OutboxEntry>, Self::Error>> {
        Box::pin(async move {
            self.find_offer_by_operation(instance_id, operation_id)
                .await
        })
    }

    /// Marks one entry acknowledged. The write is idempotent: a repeated
    /// acknowledgement (the center may deliver its `Ack` more than once) is
    /// a successful no-op.
    ///
    /// Acknowledging a content row (an entry without an `operation_id` — the
    /// site-side queue) is terminal delivery, and the production repository
    /// deletes the row instead of keeping an acknowledged row the pruning
    /// never touches (W11-S-1); the retire path relies on the same
    /// semantics to clean up a retired half-set instead of leaving acked
    /// rows behind. Offer rows keep their acknowledged history (R6-E-04).
    fn acknowledge(
        &self,
        entry_id: OutboxEntryId,
        acked_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

impl<Outbox> CenterOutbox for &Outbox
where
    Outbox: CenterOutbox + ?Sized,
{
    type Error = Outbox::Error;

    fn enqueue<'a>(
        &'a self,
        instance_id: InstanceId,
        message: &'a EnvelopeMessage,
        created_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
        Outbox::enqueue(*self, instance_id, message, created_at)
    }

    fn list_pending(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
        Outbox::list_pending(*self, instance_id, limit)
    }

    fn list_offers(
        &self,
        instance_id: InstanceId,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
        Outbox::list_offers(*self, instance_id)
    }

    fn list_offers_bounded(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
        Outbox::list_offers_bounded(*self, instance_id, limit)
    }

    fn find_offer_by_operation(
        &self,
        instance_id: InstanceId,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<OutboxEntry>, Self::Error>> {
        Outbox::find_offer_by_operation(*self, instance_id, operation_id)
    }

    fn find_offer_by_operation_across_instances(
        &self,
        instance_id: InstanceId,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<OutboxEntry>, Self::Error>> {
        Outbox::find_offer_by_operation_across_instances(*self, instance_id, operation_id)
    }

    fn acknowledge(
        &self,
        entry_id: OutboxEntryId,
        acked_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Outbox::acknowledge(*self, entry_id, acked_at)
    }
}

/// The outcome of one idempotent inbox insertion (§15.4).
///
/// Mirrors the domain's [`rutilus_domain::decide_inbox_duplicate`] decision
/// at the persistence boundary, so the engine can answer a re-delivered
/// offer with the recorded state instead of a second execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxInsertOutcome {
    /// The envelope was stored as a new entry, carrying the phase of the
    /// inserted row: `Received` for a fresh §15.6 offer, or the reply's
    /// phase when the receipt insert is born at the phase the reply
    /// dictates (P3-9).
    Created,
    /// A stored entry with the same operation id is still being processed.
    DuplicateInProgress,
    /// A stored entry with the same operation id already finished; the
    /// duplicate is answered with the recorded outcome.
    DuplicateResolved(InboxEntryState),
}

/// The durable inbox boundary of the site-to-center synchronization
/// (design §17 D4, §15.4, §15.6).
///
/// The inbox records every operation offer received from the center under
/// the §17.5 idempotency rule: the operation id is the key, so a
/// re-delivered offer is answered with the recorded state and never
/// executes twice. The state machine is the domain's `InboxEntry` — the
/// boundary only persists and advances it.
pub trait CenterInbox: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists one received envelope under the idempotency rule, returning
    /// the duplicate decision of §15.4.
    fn insert<'a>(
        &'a self,
        entry: &'a InboxEntry,
    ) -> BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>>;

    /// Reads the entry of one operation id — the idempotency lookup.
    fn find_by_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>>;

    /// Applies one inbox state-machine event. The write is idempotent: an
    /// entry that already carries the target state is a successful no-op.
    fn advance(
        &self,
        operation_id: OperationId,
        event: InboxEvent,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

impl<Inbox> CenterInbox for &Inbox
where
    Inbox: CenterInbox + ?Sized,
{
    type Error = Inbox::Error;

    fn insert<'a>(
        &'a self,
        entry: &'a InboxEntry,
    ) -> BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>> {
        Inbox::insert(*self, entry)
    }

    fn find_by_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>> {
        Inbox::find_by_operation(*self, operation_id)
    }

    fn advance(
        &self,
        operation_id: OperationId,
        event: InboxEvent,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Inbox::advance(*self, operation_id, event)
    }
}

/// The per-stream sync cursor boundary of the site-to-center
/// synchronization (design §17).
///
/// Each §17 stream (`endpoint`, `health`, `event`, `artifact`) carries one
/// monotonic cursor per instance, so a reconnect resumes reporting where the
/// last batch ended — the §21 0.7.0 incremental sync.
pub trait CenterCursor: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Reads the cursor of one stream; `None` when the stream was never
    /// reported.
    fn get(
        &self,
        instance_id: InstanceId,
        stream: SyncStream,
    ) -> BoundaryFuture<'_, Result<Option<SyncCursor>, Self::Error>>;

    /// Stores the cursor of one stream (insert or replace).
    fn set<'a>(&'a self, cursor: &'a SyncCursor) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

impl<Cursor> CenterCursor for &Cursor
where
    Cursor: CenterCursor + ?Sized,
{
    type Error = Cursor::Error;

    fn get(
        &self,
        instance_id: InstanceId,
        stream: SyncStream,
    ) -> BoundaryFuture<'_, Result<Option<SyncCursor>, Self::Error>> {
        Cursor::get(*self, instance_id, stream)
    }

    fn set<'a>(&'a self, cursor: &'a SyncCursor) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Cursor::set(*self, cursor)
    }
}

/// The bounded event tail boundary of the §21 0.7.0 event reporting.
///
/// `list_recent` is the first sync (the newest bounded tail, §14.4 bounded
/// history); `list_after` is the incremental resume — the events strictly
/// after the cursor, oldest first, so a batch is contiguous and no event is
/// skipped or reported twice.
pub trait CenterEventTail: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// The newest events first, bounded by `limit`.
    fn list_recent(&self, limit: u64) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>>;

    /// The events strictly after `after`, oldest first, bounded by `limit`.
    fn list_after(
        &self,
        after: EventId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>>;

    /// Reports whether one event id is still stored — the §17 resume-anchor
    /// validity check. The bounded history can evict the anchor (§14.4) and
    /// a manual DB change can remove it; the engine resets such a stream to
    /// the bounded tail instead of failing the connection on every attempt.
    fn contains(&self, event_id: EventId) -> BoundaryFuture<'_, Result<bool, Self::Error>>;
}

impl<EventTail> CenterEventTail for &EventTail
where
    EventTail: CenterEventTail + ?Sized,
{
    type Error = EventTail::Error;

    fn list_recent(&self, limit: u64) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        EventTail::list_recent(*self, limit)
    }

    fn list_after(
        &self,
        after: EventId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        EventTail::list_after(*self, after, limit)
    }

    fn contains(&self, event_id: EventId) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
        EventTail::contains(*self, event_id)
    }
}

/// The decision of the §15.6 rechecks for one operation offer.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OfferDecision {
    /// Every recheck passed; the operation may be accepted. The parsed
    /// command rides along so the acceptance never re-parses it.
    Accept { command: RedfishCommand },
    /// The named recheck failed; the offer is refused with the stable
    /// reason code and a human-readable detail.
    Reject {
        reason: OperationRejectedReason,
        detail: String,
    },
}

/// The outcome of handling one received operation offer.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OfferOutcome {
    /// The offer was accepted: the operation is persisted and the
    /// `OperationAccepted` reply is queued.
    Accepted,
    /// The offer was refused: the `OperationRejected` reply is queued with
    /// the stable reason code.
    Rejected {
        reason: OperationRejectedReason,
        detail: String,
    },
    /// The offer duplicates one already being processed; the current state
    /// reply is queued and nothing executes a second time.
    DuplicateProgress,
    /// The offer is not for this site or carries unparseable stable ids; it
    /// was logged and dropped.
    Dropped,
}

/// The timing bounds of the site-to-center synchronization engine.
///
/// The defaults are the protocol constants of `rutilus-center-protocol`:
/// one [`Heartbeat`] every [`SITE_HEARTBEAT_INTERVAL`] (30 seconds) and the
/// §15.4 reconnect backoff [`SITE_RECONNECT_AFTER`] (120 seconds). Tests use
/// short bounds instead of the production ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterSyncOptions {
    /// How often the engine sends a [`Heartbeat`] while connected (§15.2).
    pub heartbeat_interval: Duration,
    /// How long the engine waits after a failed connect or a dropped
    /// connection before the next attempt (§15.4).
    pub reconnect_after: Duration,
    /// How many pending outbox entries one flush sends before the next
    /// acknowledgement is needed. Bounds one burst on the wire.
    pub flush_limit: u64,
    /// The bounded event batch of one §21 0.7.0 event report.
    pub event_batch_limit: u64,
    /// The chunk size of one center artifact transfer.
    pub artifact_chunk_bytes: usize,
    /// How many consecutive `not-bound` connect refusals end the engine
    /// (audit follow-up F4).
    ///
    /// The center answers the `Hello` of a site whose binding is not in
    /// force with the `not-bound` reason; after this many consecutive such
    /// refusals the engine returns [`CenterSyncError::NotBound`] and the
    /// runtime converges the site's local binding. `None` disables the
    /// convergence (the engine retries forever, the historical behavior).
    pub not_bound_abort_after: Option<u64>,
    /// How many consecutive `identity-mismatch` connect refusals end the
    /// engine (audit follow-up E3-2, C5-10).
    ///
    /// The center answers the `Hello` of a site whose declared instance
    /// identity disagrees with its certificate's binding record with the
    /// `identity-mismatch` reason; after this many consecutive such
    /// refusals the engine returns [`CenterSyncError::IdentityMismatch`]
    /// and the runtime stops it with a diagnostic. Unlike `not-bound`, the
    /// local binding is NOT converged — the mismatch means the binding is
    /// in force on both sides, and only a re-bind heals it. `None` keeps
    /// the historical behavior (the engine retries forever).
    pub identity_mismatch_abort_after: Option<u64>,
}

impl Default for CenterSyncOptions {
    fn default() -> Self {
        Self {
            heartbeat_interval: SITE_HEARTBEAT_INTERVAL,
            reconnect_after: SITE_RECONNECT_AFTER,
            flush_limit: 64,
            event_batch_limit: 256,
            artifact_chunk_bytes: CENTER_ARTIFACT_CHUNK_BYTES,
            // Three consecutive refusals: one transient drop is absorbed by
            // the backoff, two still fit a flaky transport, three mean the
            // center consistently says the site is not bound.
            not_bound_abort_after: Some(3),
            // The same consecutive-refusal verdict: the declared identity
            // cannot drift transiently, so three refusals mean the
            // certificate and the binding record genuinely disagree.
            identity_mismatch_abort_after: Some(3),
        }
    }
}

/// The site-side center synchronization engine.
///
/// `Transport` is the [`CenterTransport`] boundary (the app crate's
/// `CenterClient` in the runtime slice), `Outbox` the durable §15.4 queue
/// boundary, and `Time` the caller's monotonic clock, supplied at the
/// boundary exactly like every other use case.
pub struct CenterSync<Transport, Store, Outbox, Inbox, Cursor, EventTail, Time> {
    transport: Transport,
    store: Store,
    outbox: Outbox,
    inbox: Inbox,
    cursor: Cursor,
    events: EventTail,
    clock: Time,
    instance_id: InstanceId,
    options: CenterSyncOptions,
    /// The last-reported `OperationProgress` state of every center-sourced
    /// operation with an open inbox entry, keyed by operation id (audit
    /// follow-up P3-10).
    ///
    /// `None` marks an accepted operation whose first progress has not been
    /// reported yet. The map is the reconnect report's working set: it
    /// bounds every later connection to the operations that still need
    /// reporting, so a reconnect never scans the operations table. It is
    /// deliberately in-memory — a restart re-reports the current states,
    /// which the center's idempotent receipt absorbs (at-least-once).
    last_progress: Mutex<HashMap<OperationId, Option<OperationState>>>,
    /// The outbox entry ids enqueued by the current artifact distribution
    /// (W11-F-2, W11-C-2, W11-C-3).
    ///
    /// `distribute_artifact` clears the ledger at the start and appends
    /// every entry it enqueues. A failed distribution retires exactly these
    /// ids — the fresh partial set — instead of scanning the pending queue,
    /// so the retire reaches the set even when the queue's oldest window is
    /// full of unrelated entries (the W11-F-2 window breakthrough), and a
    /// distribution that failed before enqueueing anything has an empty
    /// ledger and retires nothing (W11-C-3: the zero-enqueue path skips the
    /// scan). The engine drives the report sequentially, so the ledger never
    /// races two distributions.
    distribution_entries: Mutex<Vec<OutboxEntryId>>,
    /// Whether the state-indexed discovery scan of
    /// [`Self::report_center_operations`] has completed at least once in
    /// this process run.
    ///
    /// The first report scans the in-flight and terminal state sets to
    /// rediscover operations whose inbox entries a previous process run
    /// left open; every later report is driven by `last_progress` alone.
    discovery_done: AtomicBool,
}

impl<Transport, Store, Outbox, Inbox, Cursor, EventTail, Time>
    CenterSync<Transport, Store, Outbox, Inbox, Cursor, EventTail, Time>
where
    Transport: CenterTransport,
    Store: OperationStore
        + EndpointRefreshRepository
        + CapabilityQueryRepository
        + CredentialInventoryRepository
        + EndpointInventoryRepository
        + ArtifactRepository,
    Outbox: CenterOutbox,
    Inbox: CenterInbox,
    Cursor: CenterCursor,
    EventTail: CenterEventTail,
    Time: Clock,
{
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transport: Transport,
        store: Store,
        outbox: Outbox,
        inbox: Inbox,
        cursor: Cursor,
        events: EventTail,
        clock: Time,
        instance_id: InstanceId,
        options: CenterSyncOptions,
    ) -> Self {
        Self {
            transport,
            store,
            outbox,
            inbox,
            cursor,
            events,
            clock,
            instance_id,
            options,
            last_progress: Mutex::new(HashMap::new()),
            distribution_entries: Mutex::new(Vec::new()),
            discovery_done: AtomicBool::new(false),
        }
    }

    /// Enqueues one message into the durable outbox (§15.4): allocates the
    /// next per-instance sequence and persists the envelope. The database is
    /// the queue, so this is safe while the engine is disconnected — the
    /// offline queue of §21 0.7.0 — and the flush resumes from the last
    /// acknowledged sequence when the connection returns.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSyncError::Outbox`] when the queue write fails.
    pub async fn enqueue_outbox_entry(
        &self,
        message: EnvelopeMessage,
    ) -> Result<OutboxEntry, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    {
        self.outbox
            .enqueue(self.instance_id, &message, self.clock.now())
            .await
            .map_err(CenterSyncError::Outbox)
    }

    /// Runs the engine until `stop` resolves: the connect loop with the
    /// §15.4 backoff, the heartbeat and frame exchange of one connection,
    /// and the reconnect loop after every disconnect.
    ///
    /// The engine never returns an error for a failed connection: every
    /// transport failure is logged and the loop schedules the next attempt,
    /// so `Ok` on a stopped signal is the only return path.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSyncError::Transport`] or [`CenterSyncError::Outbox`]
    /// when a boundary fails inside one connection step — the loop then
    /// waits out the backoff and reconnects.
    pub async fn run<Stop>(
        &self,
        stop: Stop,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    where
        Stop: Future<Output = ()> + Send,
    {
        self.connect_loop(stop).await
    }

    /// The outer connect loop (§15.1, §15.3, §15.4): connect, run the
    /// connection, and on every failure or disconnect wait out the backoff
    /// and try again, until `stop` resolves.
    async fn connect_loop<Stop>(
        &self,
        stop: Stop,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    where
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        // The `not-bound` refusal count (audit follow-up F4): a
        // successful connection or a different verdict resets it, and a
        // generic failure — an unreachable center, a dropped handshake —
        // carries no verdict about the binding and no longer resets it
        // (W3N-5): the convergence verdict is the center consistently
        // saying the site is not bound, and a flaky transport must not
        // postpone that verdict forever.
        let mut consecutive_not_bound: u64 = 0;
        // The `identity-mismatch` refusal count (audit follow-up E3-2,
        // C5-10): the same verdict-accumulation semantics as `not-bound`,
        // kept separate because the two refusals mean different things —
        // one
        // says the binding is not in force (the runtime converges), the
        // other says the declared identity disagrees with the binding (the
        // runtime stops without touching the binding).
        let mut consecutive_identity_mismatch: u64 = 0;
        loop {
            let session = tokio::select! {
                () = stop.as_mut() => return Ok(()),
                result = self.transport.connect() => match result {
                    Ok(session) => {
                        consecutive_not_bound = 0;
                        consecutive_identity_mismatch = 0;
                        session
                    }
                    Err(error) => {
                        if self.transport.is_not_bound(&error) {
                            consecutive_not_bound += 1;
                            consecutive_identity_mismatch = 0;
                            if let Some(limit) = self.options.not_bound_abort_after
                                && consecutive_not_bound >= limit
                            {
                                // The center consistently refuses the site
                                // as not bound: its binding is not in force
                                // on the center (revoked or re-bound), so
                                // retrying is futile. The runtime converges
                                // the local binding on this return.
                                tracing::error!(
                                    "the center refused the connection {consecutive_not_bound} \
                                     times as not bound; the site's binding is not in force"
                                );
                                return Err(CenterSyncError::NotBound);
                            }
                        } else if self.transport.is_identity_mismatch(&error) {
                            consecutive_identity_mismatch += 1;
                            consecutive_not_bound = 0;
                            if let Some(limit) = self.options.identity_mismatch_abort_after
                                && consecutive_identity_mismatch >= limit
                            {
                                // The center consistently refuses the site
                                // as an identity mismatch: the declared
                                // instance identity disagrees with the
                                // binding record its certificate resolves
                                // to. The binding is in force, so retrying
                                // is futile and the local row must NOT be
                                // converged — the runtime logs the repair
                                // path (re-bind the site) on this return.
                                tracing::error!(
                                    "the center refused the connection \
                                     {consecutive_identity_mismatch} times as an identity \
                                     mismatch; the site's instance identity does not match the \
                                     center's binding for its certificate"
                                );
                                return Err(CenterSyncError::IdentityMismatch);
                            }
                        } else {
                            // A generic failure carries no verdict about
                            // the binding: the counters answer what the
                            // center says, and an unreachable center or a
                            // dropped handshake says nothing (W3N-5). Not
                            // resetting keeps a flaky transport from
                            // postponing the convergence forever — the
                            // trade-off is that the count is no longer
                            // strictly consecutive in wall-clock terms: it
                            // counts the same-verdict refusals since the
                            // last successful connection or the last
                            // different verdict, ignoring the noise in
                            // between. A successful connection still
                            // resets both, because the center accepted the
                            // site and the binding is in force.
                        }
                        // §15.3: a center without a common protocol version
                        // rejects the negotiation, and an unreachable center
                        // fails the attempt — either way the site keeps
                        // running locally and retries after the backoff.
                        tracing::warn!(
                            "center connection failed: {error}; keeping the site local and \
                             retrying in {:?}",
                            self.options.reconnect_after
                        );
                        tokio::select! {
                            () = stop.as_mut() => return Ok(()),
                            () = tokio::time::sleep(self.options.reconnect_after) => {}
                        }
                        continue;
                    }
                },
            };
            let outcome = self.connected_loop(session, stop.as_mut()).await;
            match outcome {
                Ok(()) => return Ok(()),
                Err(error) => {
                    tracing::warn!(
                        "center connection ended: {error}; reconnecting in {:?}",
                        self.options.reconnect_after
                    );
                    tokio::select! {
                        () = stop.as_mut() => return Ok(()),
                        () = tokio::time::sleep(self.options.reconnect_after) => {}
                    }
                }
            }
        }
    }

    /// One established connection: the initial outbox flush (§15.4 resume
    /// from the last acknowledged sequence), then the heartbeat loop and the
    /// inbound frame dispatch, until the peer closes the connection, the
    /// transport fails, or `stop` resolves.
    async fn connected_loop<Session, Stop>(
        &self,
        mut session: Session,
        stop: Stop,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    where
        Session: CenterSession<Error = Transport::Error>,
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + self.options.heartbeat_interval,
            self.options.heartbeat_interval,
        );
        // The highest center sequence accepted on this connection; every
        // outbound frame piggybacks it (§15.4). Heartbeats carry `sequence:
        // 0` — a liveness frame, not an outbox message.
        let mut peer_acked: u64 = 0;
        // The durable entries sent on this connection, in send order: the
        // center's acknowledgements pop the head. The list resets on every
        // connection; unacknowledged entries stay pending and the reconnect
        // flush re-sends them from the last acknowledgement (§15.4).
        let mut sent: VecDeque<(OutboxEntryId, i64)> = VecDeque::new();
        // The operation results and the incremental data reporting enqueue
        // before the flush, so one batch carries them all.
        self.report_center_operations().await?;
        let artifact_outcome = self.report_incremental_sync().await?;
        self.flush_outbox(&mut session, &mut sent, peer_acked)
            .await?;
        // W11-P-1: an absorbed artifact failure leaves the stream stalled —
        // the report only runs once per connection, the absorption keeps the
        // connection alive (the flush and the receive loop keep running), and
        // the heartbeat outlives every idle timeout, so without a timer the
        // retry never arrives on a stable network. The stall timer ends this
        // connection one reconnect period after the absorption; the connect
        // loop's own backoff then schedules the next attempt, which re-runs
        // the report and retries the artifact (the W10-D-1 self-healing, now
        // on a bounded schedule instead of the old never).
        let stalled_artifact = match artifact_outcome {
            ArtifactStreamOutcome::Complete => None,
            ArtifactStreamOutcome::Stalled { artifact_id } => {
                tracing::error!(
                    "site {}: the artifact stream is stalled before artifact {}; the \
                     connection ends after {:?} so the report retries it",
                    self.instance_id,
                    artifact_id,
                    self.options.reconnect_after
                );
                Some(artifact_id)
            }
        };
        let stall = tokio::time::sleep(self.options.reconnect_after);
        tokio::pin!(stall);
        loop {
            tokio::select! {
                () = stop.as_mut() => return Ok(()),
                _ = heartbeat.tick() => {
                    session
                        .send(Envelope {
                            sequence: 0,
                            acked_sequence: peer_acked,
                            message: Some(EnvelopeMessage::Heartbeat(Heartbeat {
                                sent_at_unix: self.clock.now().unix_timestamp(),
                            })),
                        })
                        .await
                        .map_err(CenterSyncError::Transport)?;
                }
                () = &mut stall, if stalled_artifact.is_some() => {
                    // The guard makes the None branch unreachable; the
                    // reference bind keeps the extraction expect-free and
                    // avoids moving out of the guard-borrowed option.
                    let Some(artifact_id) = stalled_artifact.as_ref() else {
                        continue;
                    };
                    return Err(CenterSyncError::ArtifactStreamStalled {
                        artifact_id: *artifact_id,
                    });
                }
                frame = session.receive() => {
                    let Some(envelope) = frame.map_err(CenterSyncError::Transport)? else {
                        return Err(CenterSyncError::Closed);
                    };
                    peer_acked = peer_acked.max(envelope.sequence);
                    match envelope.message.as_ref() {
                        Some(EnvelopeMessage::Ack(ack)) => {
                            self.ack_outbox(ack.sequence, &mut sent).await?;
                            // An acknowledgement frees the next batch: the
                            // flush continues until the queue is empty.
                            self.flush_outbox(&mut session, &mut sent, peer_acked).await?;
                        }
                        Some(EnvelopeMessage::OperationOffer(offer)) => {
                            self.handle_offer(offer, &envelope).await?;
                            // The reply is durable before the flush, so one
                            // burst carries it: a handled offer must reach
                            // the center without waiting for an
                            // acknowledgement that may never come (§15.6 —
                            // the center waits for the reply to its offer,
                            // and an idle site has nothing to acknowledge).
                            self.flush_outbox(&mut session, &mut sent, peer_acked)
                                .await?;
                        }
                        _ => self.dispatch_inbound(envelope),
                    }
                }
            }
        }
    }

    /// Sends the oldest pending outbox entries in sequence order, up to the
    /// flush limit, and records them as sent on this connection.
    ///
    /// Every frame carries its durable sequence — the resume point of §15.4 —
    /// with the current acknowledgement watermark piggybacked. A transport
    /// failure mid-flush abandons only the wire position: the unacknowledged
    /// entries stay pending and the next connection re-sends them
    /// (at-least-once delivery; the center deduplicates by sequence).
    async fn flush_outbox<Session>(
        &self,
        session: &mut Session,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
        peer_acked: u64,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    where
        Session: CenterSession<Error = Transport::Error>,
    {
        let pending = self
            .outbox
            .list_pending(self.instance_id, self.options.flush_limit)
            .await
            .map_err(CenterSyncError::Outbox)?;
        for entry in pending {
            // An entry already delivered on this connection is not sent
            // again: the acknowledgement retires it, and a dropped
            // connection re-sends it from the pending scan (§15.4
            // at-least-once). The skip keeps a mid-burst flush — the
            // offer-reply flush of the inbound loop — from duplicating an
            // unacknowledged burst on the wire.
            if sent.iter().any(|(sent_id, _)| *sent_id == entry.id()) {
                continue;
            }
            // The payload is the §9.4 typed serialization of the envelope;
            // the row's sequence column is authoritative, and the stored
            // acknowledgement watermark is the enqueue-time value, so the
            // frame is rebuilt with both patched to the send-time truth.
            let mut envelope: Envelope = match serde_json::from_str(entry.payload_json()) {
                Ok(envelope) => envelope,
                Err(source) => {
                    // Ciphertext rows are authenticated by the list scan:
                    // a tampered payload fails the whole `list_pending`
                    // read as Corrupt before this loop runs, so a flush
                    // never sends on top of a tampered queue (fail closed,
                    // deliberate). The per-row skip here survives only for
                    // legacy plaintext rows whose JSON no longer parses:
                    // log it, skip it, and deliver the rest of the queue.
                    // The row has no durable failure state, so it stays
                    // pending and every flush re-logs it until an operator
                    // repairs or clears it (a future migration could add a
                    // failed state).
                    tracing::error!(
                        "site {}: skipping outbox entry {} with a corrupt payload: {source}",
                        self.instance_id,
                        entry.id()
                    );
                    continue;
                }
            };
            let Ok(wire_sequence) = u64::try_from(entry.sequence()) else {
                tracing::error!(
                    "site {}: skipping outbox entry {} with an unwireable sequence {}",
                    self.instance_id,
                    entry.id(),
                    entry.sequence()
                );
                continue;
            };
            envelope.sequence = wire_sequence;
            envelope.acked_sequence = peer_acked;
            session
                .send(envelope)
                .await
                .map_err(CenterSyncError::Transport)?;
            sent.push_back((entry.id(), entry.sequence()));
        }
        Ok(())
    }

    /// Applies one center acknowledgement: every entry sent on this
    /// connection whose sequence is at most the acknowledged sequence leaves
    /// the delivery queue. Frames on one connection are ordered, so the
    /// center's acknowledgements are monotonic and the head of the sent
    /// list is the only candidate.
    async fn ack_outbox(
        &self,
        acked_sequence: u64,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let now = self.clock.now();
        while let Some(&(entry_id, sequence)) = sent.front() {
            let wire_sequence = u64::try_from(sequence)
                .map_err(|_| CenterSyncError::SequenceOverflow { sequence })?;
            if wire_sequence > acked_sequence {
                break;
            }
            sent.pop_front();
            self.outbox
                .acknowledge(entry_id, now)
                .await
                .map_err(CenterSyncError::Outbox)?;
        }
        Ok(())
    }

    /// Handles one §15.6 operation offer: the idempotent inbox insertion,
    /// the five rechecks, and the durable reply.
    ///
    /// The offer's `operation_id` is the §17.5 idempotency key: a stored
    /// entry with the same id is answered with its recorded state instead of
    /// a second execution. A fresh offer runs the §15.6 rechecks — endpoint
    /// existence, capability presence, credential validity, target-state
    /// applicability, and expiry — and only an `Accept` persists the
    /// operation (with the offer's own id, `OperationSource::Center`) and
    /// advances the inbox. Every reply travels through the durable outbox,
    /// so an accepted or rejected offer survives a disconnect (§15.4).
    async fn handle_offer(
        &self,
        offer: &OperationOffer,
        received: &Envelope,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    {
        // The wire contract says these fields carry stable product codes; an
        // offer addressed to another site or carrying unparseable ids cannot
        // be recorded and is dropped with a log instead of being guessed at.
        if offer.site_id != self.instance_id.to_string() {
            tracing::warn!(
                "site {}: dropping an operation offer for site {}",
                self.instance_id,
                offer.site_id
            );
            return Ok(OfferOutcome::Dropped);
        }
        let Ok(operation_id) = offer.operation_id.parse::<OperationId>() else {
            tracing::warn!(
                "site {}: dropping an offer with an unparseable operation id",
                self.instance_id
            );
            return Ok(OfferOutcome::Dropped);
        };
        let Ok(endpoint_id) = offer.endpoint_id.parse::<EndpointId>() else {
            tracing::warn!(
                "site {}: dropping an offer with an unparseable endpoint id",
                self.instance_id
            );
            return Ok(OfferOutcome::Dropped);
        };
        let now = self.clock.now();
        // The payload record is the received envelope itself: the §9.4
        // typed payload of the inbox row.
        let payload_json = serde_json::to_string(received).map_err(CenterSyncError::Payload)?;
        // Fail closed: an offer whose expiry cannot be parsed is pinned one
        // second before the receipt, so the domain's `is_expired` judgment
        // refuses it like any other expired offer (§15.6) — an unreadable
        // TTL must never extend an offer's life.
        let expires_at = OffsetDateTime::from_unix_timestamp(offer.expires_at_unix)
            .unwrap_or(now - time::Duration::SECOND);
        let entry = InboxEntry::new(
            InboxEntryId::generate(),
            operation_id,
            self.instance_id,
            payload_json,
            expires_at,
            now,
        );
        match self
            .inbox
            .insert(&entry)
            .await
            .map_err(CenterSyncError::Inbox)?
        {
            InboxInsertOutcome::Created => {
                self.decide_and_record(offer, &entry, endpoint_id, now)
                    .await
            }
            InboxInsertOutcome::DuplicateInProgress => {
                self.reply_to_in_progress_duplicate(offer, &entry, endpoint_id, now)
                    .await
            }
            InboxInsertOutcome::DuplicateResolved(state) => {
                self.reply_to_resolved_duplicate(offer, &entry, endpoint_id, state, now)
                    .await
            }
        }
    }

    /// Applies the §15.6 rechecks to a fresh offer and records the decision:
    /// `Accept` persists the operation and advances the inbox to `Accepted`;
    /// `Reject` queues the `OperationRejected` reply and advances the inbox
    /// to `Rejected`. Only the site's explicit acceptance transfers
    /// execution responsibility (§15.6).
    async fn decide_and_record(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    {
        let operation_id = entry.operation_id();
        match self.decide_offer(offer, entry, endpoint_id, now).await? {
            OfferDecision::Accept { command } => {
                // The offer's stable operation id becomes the persisted
                // operation's id: the §17.5 key must name the operation so a
                // re-delivered offer resolves to the recorded outcome. The
                // engine's create path cannot be used — it generates fresh
                // ids — so the operation is persisted directly through the
                // store boundary, with the target validation already done by
                // the rechecks.
                let operation = Operation::new(
                    operation_id,
                    OperationSource::Center,
                    vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
                    command,
                    now,
                );
                self.store
                    .create_operation(&operation)
                    .await
                    .map_err(CenterSyncError::Operation)?;
                // The accepted operation joins the reconnect report's
                // working set before the first progress can be reported
                // (audit follow-up P3-10): `None` marks it as accepted but
                // never reported, so the next connection reports its state
                // instead of a reconnect scan re-finding it.
                self.last_progress
                    .lock()
                    .map_err(|_| CenterSyncError::ProgressTracking)?
                    .insert(operation_id, None);
                self.enqueue_outbox_entry(EnvelopeMessage::OperationAccepted(
                    rutilus_center_protocol::OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    },
                ))
                .await?;
                self.inbox
                    .advance(operation_id, InboxEvent::Accepted)
                    .await
                    .map_err(CenterSyncError::Inbox)?;
                Ok(OfferOutcome::Accepted)
            }
            OfferDecision::Reject { reason, detail } => {
                self.enqueue_outbox_entry(EnvelopeMessage::OperationRejected(
                    rutilus_center_protocol::OperationRejected {
                        operation_id: operation_id.to_string(),
                        reason: reason as i32,
                        detail: detail.clone(),
                    },
                ))
                .await?;
                self.inbox
                    .advance(operation_id, InboxEvent::Rejected)
                    .await
                    .map_err(CenterSyncError::Inbox)?;
                Ok(OfferOutcome::Rejected { reason, detail })
            }
        }
    }

    /// The §15.6 rechecks, in the design's order: the endpoint must still
    /// exist, its capability must still be usable, its credential must still
    /// be stored, the offer's target must still be part of the last-known
    /// projection, and the operation must not have expired (the domain TTL
    /// judgment on the stored entry).
    async fn decide_offer(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<OfferDecision, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    {
        let Some(endpoint) = self
            .store
            .find_endpoint(endpoint_id)
            .await
            .map_err(CenterSyncError::Endpoint)?
        else {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::EndpointMissing,
                detail: String::from("the endpoint is no longer managed"),
            });
        };
        let command = match Self::parse_command(offer) {
            Ok(command) => command,
            Err(decision) => return Ok(decision),
        };
        let required = required_capability(&command);
        let entries = EndpointCapabilityQuery::new(&self.store, endpoint_id)
            .execute()
            .await
            .map_err(CenterSyncError::Capability)?;
        let state = entries
            .as_deref()
            .and_then(|entries| required_capability_state(required, entries));
        if state != Some(CapabilityState::Supported) {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::CapabilityMissing,
                detail: format!("the {required} capability is not usable"),
            });
        }
        let credentials = self
            .store
            .list_credentials()
            .await
            .map_err(CenterSyncError::Credential)?;
        if !credentials
            .iter()
            .any(|credential| credential.id() == endpoint.credential_id())
        {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::CredentialInvalid,
                detail: String::from("the endpoint credential is no longer stored"),
            });
        }
        let items = EndpointInventoryQuery::new(&self.store)
            .execute()
            .await
            .map_err(CenterSyncError::Inventory)?;
        let target_known = items.iter().any(|item| {
            item.endpoint().id() == endpoint_id
                && item.resources().iter().any(|resource| {
                    let odata_id = resource.odata_id().as_str();
                    offer.target == odata_id || offer.target.starts_with(&format!("{odata_id}/"))
                })
        });
        if !target_known {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::TargetStateChanged,
                detail: String::from("the target is not in the endpoint's last-known projection"),
            });
        }
        if entry.is_expired(now) {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::Expired,
                detail: String::from("the offer expired before it could be applied"),
            });
        }
        Ok(OfferDecision::Accept { command })
    }

    /// Decodes the offer's typed command payload; an undecodable command is
    /// the `InvalidCommand` rejection.
    fn parse_command(offer: &OperationOffer) -> Result<RedfishCommand, OfferDecision> {
        serde_json::from_slice(&offer.command_json).map_err(|_| OfferDecision::Reject {
            reason: OperationRejectedReason::InvalidCommand,
            detail: String::from("the command payload is not a valid RedfishCommand"),
        })
    }

    /// Answers a duplicate offer whose stored entry is still being
    /// processed: the persisted operation (created with the offer's id)
    /// carries the current state. When no operation exists, the acceptance
    /// never happened — the crash window between the inbox insert and the
    /// operation create — and the rechecks run again.
    ///
    /// Both answer paths keep the entry's phase truthful about the
    /// operation's facts: a `Received` entry with an existing operation is
    /// the crash window between the operation create and the entry advance,
    /// repaired to the in-flight phase (W3N-2) — so a re-delivered offer's
    /// later `Accepted` is always legal and the site's tracking reflects
    /// the execution — and the in-progress reply records the reported
    /// state in the progress map (W3N-3), so the next connection does not
    /// re-send the same progress.
    async fn reply_to_in_progress_duplicate(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    {
        let operation_id = entry.operation_id();
        let Some(operation) = self
            .store
            .find_operation(operation_id)
            .await
            .map_err(CenterSyncError::Operation)?
        else {
            return self.decide_and_record(offer, entry, endpoint_id, now).await;
        };
        if operation.state().is_terminal() {
            self.enqueue_outbox_entry(EnvelopeMessage::OperationCompleted(
                rutilus_center_protocol::OperationCompleted {
                    operation_id: operation_id.to_string(),
                    succeeded: operation.state() == OperationState::Succeeded,
                    summary: self.completed_summary(&operation).await?,
                },
            ))
            .await?;
            // The terminal report closes the inbox lifecycle; a `Received`
            // entry (the crash window) advances through `Accepted` first.
            self.inbox
                .advance(operation_id, InboxEvent::Accepted)
                .await
                .map_err(CenterSyncError::Inbox)?;
            self.inbox
                .advance(operation_id, InboxEvent::Completed)
                .await
                .map_err(CenterSyncError::Inbox)?;
            self.forget_progress(operation_id)?;
        } else {
            self.enqueue_outbox_entry(EnvelopeMessage::OperationProgress(
                rutilus_center_protocol::OperationProgress {
                    operation_id: operation_id.to_string(),
                    state: operation.state().as_str().to_owned(),
                    detail: String::from("duplicate offer; the operation is already in progress"),
                },
            ))
            .await?;
            // W3N-2: the operation exists, so the offer was accepted — the
            // entry's phase must say so. The crash window (the operation
            // created before the entry advanced) leaves the entry
            // `Received`; advancing it to the in-flight phase here keeps
            // the site's tracking truthful about the execution facts and
            // makes every later re-delivery's `Accepted` legal. The advance
            // is an idempotent no-op for an entry already accepted.
            self.inbox
                .advance(operation_id, InboxEvent::Accepted)
                .await
                .map_err(CenterSyncError::Inbox)?;
            // W3N-3: the reply is recorded in the progress map after a
            // successful enqueue — a failed queue write leaves the state
            // unreported for the next connection, exactly like the
            // reconnect report's map write — so the next connection does
            // not re-send the progress the center just received.
            self.last_progress
                .lock()
                .map_err(|_| CenterSyncError::ProgressTracking)?
                .insert(operation_id, Some(operation.state()));
        }
        Ok(OfferOutcome::DuplicateProgress)
    }

    /// Answers a duplicate offer whose stored entry already finished. The
    /// original rejection reason is not persisted, so a rejected duplicate
    /// re-runs the rechecks for a current reason and falls back to a generic
    /// refusal when the situation changed; a completed duplicate is answered
    /// from the persisted operation's outcome.
    async fn reply_to_resolved_duplicate(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        state: InboxEntryState,
        now: OffsetDateTime,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>>
    {
        let operation_id = entry.operation_id();
        match state {
            InboxEntryState::Rejected => {
                let (reason, detail) =
                    match self.decide_offer(offer, entry, endpoint_id, now).await? {
                        OfferDecision::Accept { .. } => (
                            OperationRejectedReason::Unspecified,
                            String::from("the offer was already rejected and cannot be revived"),
                        ),
                        OfferDecision::Reject { reason, detail } => (reason, detail),
                    };
                self.enqueue_outbox_entry(EnvelopeMessage::OperationRejected(
                    rutilus_center_protocol::OperationRejected {
                        operation_id: operation_id.to_string(),
                        reason: reason as i32,
                        detail: detail.clone(),
                    },
                ))
                .await?;
                Ok(OfferOutcome::Rejected { reason, detail })
            }
            InboxEntryState::Completed => {
                let operation = self
                    .store
                    .find_operation(operation_id)
                    .await
                    .map_err(CenterSyncError::Operation)?;
                let (succeeded, summary) = match operation {
                    Some(operation) => (
                        operation.state() == OperationState::Succeeded,
                        self.completed_summary(&operation).await?,
                    ),
                    None => (false, String::from("the recorded outcome is unavailable")),
                };
                self.enqueue_outbox_entry(EnvelopeMessage::OperationCompleted(
                    rutilus_center_protocol::OperationCompleted {
                        operation_id: operation_id.to_string(),
                        succeeded,
                        summary,
                    },
                ))
                .await?;
                Ok(OfferOutcome::DuplicateProgress)
            }
            // The domain maps in-progress states to `DuplicateInProgress`,
            // so these arms are the defensive floor for a corrupt repository.
            InboxEntryState::Received | InboxEntryState::Accepted => {
                self.reply_to_in_progress_duplicate(offer, entry, endpoint_id, now)
                    .await
            }
        }
    }

    /// Reports the state of every center-sourced operation to the center:
    /// an active operation queues an `OperationProgress` frame, a terminal
    /// one queues `OperationCompleted` and closes the inbox lifecycle. The
    /// inbox state machine makes the report idempotent — terminal entries
    /// are skipped on the next connection.
    ///
    /// The report never scans the operations table (audit follow-up
    /// P3-10): the first report of the process run rediscovers every
    /// center-sourced operation with an open inbox entry through the
    /// state-indexed queries over the in-flight and terminal state sets —
    /// the only states such an operation can be in — and every later
    /// report is driven by the in-memory progress map, which bounds the
    /// work to the operations that still need reporting. Progress is
    /// enqueued only when the reported state changed, so a reconnect does
    /// not replay states the center already knows.
    async fn report_center_operations(
        &self,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        if !self.discovery_done.load(Ordering::Acquire) {
            // The state-indexed discovery scan: an operation with an open
            // inbox entry is either in-flight (progress to report) or
            // terminal with its completion not yet delivered — the crash
            // window a previous process run left behind — so the in-flight
            // and terminal state sets partition the report's work exactly.
            // The scan runs once per process run; after it completes, the
            // progress map knows every open entry.
            for state in CENTER_REPORT_IN_FLIGHT_STATES
                .into_iter()
                .chain(CENTER_REPORT_TERMINAL_STATES)
            {
                let operations = self
                    .store
                    .list_operations(Some(state))
                    .await
                    .map_err(CenterSyncError::Operation)?;
                for operation in operations {
                    if operation.source() != OperationSource::Center {
                        continue;
                    }
                    self.report_open_entry(&operation).await?;
                }
            }
            self.discovery_done.store(true, Ordering::Release);
            return Ok(());
        }
        // The bounded map-driven pass: every center-sourced operation with
        // an open entry is known to the progress map, so the report
        // re-reads exactly those rows by id — a reconnect never scans the
        // table. Entries closed since the last report (a duplicate-offer
        // reply) are dropped from the map; terminal operations are
        // reported once and closed.
        let known = self
            .last_progress
            .lock()
            .map_err(|_| CenterSyncError::ProgressTracking)?
            .keys()
            .copied()
            .collect::<Vec<_>>();
        for operation_id in known {
            let Some(entry) = self
                .inbox
                .find_by_operation(operation_id)
                .await
                .map_err(CenterSyncError::Inbox)?
            else {
                self.forget_progress(operation_id)?;
                continue;
            };
            if entry.state().is_terminal() {
                self.forget_progress(operation_id)?;
                continue;
            }
            let Some(operation) = self
                .store
                .find_operation(operation_id)
                .await
                .map_err(CenterSyncError::Operation)?
            else {
                self.forget_progress(operation_id)?;
                continue;
            };
            self.report_open_entry(&operation).await?;
        }
        Ok(())
    }

    /// Reports one center-sourced operation with an open inbox entry: an
    /// active operation queues an `OperationProgress` — only when the
    /// reported state changed (audit follow-up P3-10) — and a terminal one
    /// queues `OperationCompleted` and closes the entry.
    async fn report_open_entry(
        &self,
        operation: &Operation,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let operation_id = operation.id();
        let Some(entry) = self
            .inbox
            .find_by_operation(operation_id)
            .await
            .map_err(CenterSyncError::Inbox)?
        else {
            return Ok(());
        };
        if entry.state().is_terminal() {
            return Ok(());
        }
        if entry.state() == InboxEntryState::Received {
            // The operation exists, so the offer was accepted before a
            // crash interrupted the record; repair it and report.
            self.inbox
                .advance(operation_id, InboxEvent::Accepted)
                .await
                .map_err(CenterSyncError::Inbox)?;
        }
        if operation.state().is_terminal() {
            self.enqueue_outbox_entry(EnvelopeMessage::OperationCompleted(
                rutilus_center_protocol::OperationCompleted {
                    operation_id: operation_id.to_string(),
                    succeeded: operation.state() == OperationState::Succeeded,
                    summary: self.completed_summary(operation).await?,
                },
            ))
            .await?;
            self.inbox
                .advance(operation_id, InboxEvent::Completed)
                .await
                .map_err(CenterSyncError::Inbox)?;
            self.forget_progress(operation_id)?;
        } else {
            // The map records the last state the center acknowledged
            // learning about; an identical state queues nothing, so a
            // reconnect does not replay it. The enqueue happens before the
            // map update, so a failed queue write leaves the operation
            // unreported for the next connection.
            let already_reported = self
                .last_progress
                .lock()
                .map_err(|_| CenterSyncError::ProgressTracking)?
                .get(&operation_id)
                .copied()
                .flatten()
                == Some(operation.state());
            if already_reported {
                return Ok(());
            }
            self.enqueue_outbox_entry(EnvelopeMessage::OperationProgress(
                rutilus_center_protocol::OperationProgress {
                    operation_id: operation_id.to_string(),
                    state: operation.state().as_str().to_owned(),
                    detail: String::new(),
                },
            ))
            .await?;
            self.last_progress
                .lock()
                .map_err(|_| CenterSyncError::ProgressTracking)?
                .insert(operation_id, Some(operation.state()));
        }
        Ok(())
    }

    /// The `OperationCompleted` summary of one terminal operation: the
    /// stable state code, extended with the provable refusal classification
    /// (audit follow-up E3-4) — a `Failed` operation whose persisted
    /// failure kind is `capability-unsupported` is summarized as
    /// `failed-unsupported`, so the center can distinguish the
    /// endpoint-side limitation from an ordinary failure. The wire contract
    /// is the field, not the value: the center's receipt parses the summary
    /// as a stable state code and treats a summary naming no stable state
    /// as a plain `Failed` outcome, so the extension never distorts the
    /// tracking.
    async fn completed_summary(
        &self,
        operation: &Operation,
    ) -> Result<String, CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        if operation.state() != OperationState::Failed {
            return Ok(operation.state().as_str().to_owned());
        }
        let kind = self
            .store
            .find_failure_kind(operation.id())
            .await
            .map_err(CenterSyncError::Operation)?;
        Ok(match kind {
            Some(FailureKind::CapabilityUnsupported) => String::from("failed-unsupported"),
            _ => operation.state().as_str().to_owned(),
        })
    }

    /// Drops one operation from the progress map after its lifecycle
    /// closed (the entry reached a terminal state or the row vanished).
    ///
    /// # Errors
    ///
    /// Returns [`CenterSyncError::ProgressTracking`] when the map is
    /// poisoned.
    fn forget_progress(
        &self,
        operation_id: OperationId,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        self.last_progress
            .lock()
            .map_err(|_| CenterSyncError::ProgressTracking)?
            .remove(&operation_id);
        Ok(())
    }

    /// Reports the §21 0.7.0 incremental data to the center: the endpoint
    /// projections whose refresh generation advanced, the bounded event
    /// tail, and the ready artifacts. Every report is cursor-gated — the
    /// §17 per-stream cursors advance as the content is enqueued, and the
    /// durable outbox guarantees delivery — so a reconnect reports exactly
    /// what the center has not seen yet.
    ///
    /// Returns the artifact stream's outcome so the connection can arm the
    /// W11-P-1 stall timer when a persistent failure stopped the stream.
    async fn report_incremental_sync(
        &self,
    ) -> Result<
        ArtifactStreamOutcome,
        CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>,
    > {
        self.report_endpoint_projection().await?;
        self.report_event_batch().await?;
        self.report_artifacts().await
    }

    /// Reports every endpoint whose refresh generation advanced past the
    /// `endpoint` stream cursor: one [`EndpointSnapshot`] with the full
    /// projection and one [`ResourceDelta`] per resource of the new
    /// generation. The cursor is the `endpoint-id:generation` watermark of
    /// every endpoint, so an unchanged generation reports nothing.
    async fn report_endpoint_projection(
        &self,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let cursor = self
            .cursor
            .get(self.instance_id, SyncStream::Endpoint)
            .await
            .map_err(CenterSyncError::Cursor)?;
        let mut watermark = match cursor.as_ref() {
            Some(cursor) => match parse_endpoint_cursor(cursor.cursor_value()) {
                Ok(watermark) => watermark,
                Err(source) => {
                    // A stored cursor a manual DB change or a partial
                    // restore left unparseable must not wedge the sync loop:
                    // log it and re-report the current projections. The
                    // report's cursor write at the end heals the row.
                    tracing::warn!(
                        "site {}: resetting the {} stream cursor: {source}",
                        self.instance_id,
                        SyncStream::Endpoint
                    );
                    BTreeMap::new()
                }
            },
            None => BTreeMap::new(),
        };
        let items = EndpointInventoryQuery::new(&self.store)
            .execute()
            .await
            .map_err(CenterSyncError::Inventory)?;
        let mut changed = false;
        for item in &items {
            let endpoint_id = item.endpoint().id();
            let generation = item.generation().map_or(0, RefreshGeneration::get);
            let reported = watermark.get(&endpoint_id).copied();
            if reported.is_none() || reported < Some(generation) {
                changed = true;
                self.enqueue_endpoint_snapshot(item, generation).await?;
                for resource in item.resources() {
                    self.enqueue_resource_delta(item, resource, generation)
                        .await?;
                }
                watermark.insert(endpoint_id, generation);
            }
        }
        // §21 deletion convergence: an endpoint that was reported but is no
        // longer in the inventory (a manual DB change, a partial restore, or
        // a future deletion use case) must drop from the center projection.
        // The site no longer has the deleted endpoint's resources, so the
        // delete is endpoint-level — one `ResourceDelta` with `resource:
        // None` — and the watermark forgets the endpoint, so a re-created
        // endpoint reports a fresh upsert.
        let deleted = watermark
            .keys()
            .filter(|endpoint_id| {
                !items
                    .iter()
                    .any(|item| item.endpoint().id() == **endpoint_id)
            })
            .copied()
            .collect::<Vec<_>>();
        for endpoint_id in deleted {
            changed = true;
            self.enqueue_outbox_entry(EnvelopeMessage::ResourceDelta(ResourceDelta {
                endpoint_id: endpoint_id.to_string(),
                op: ResourceDeltaOp::Delete as i32,
                resource: None,
                payload_json: Vec::new(),
                observed_at_unix: self.clock.now().unix_timestamp(),
            }))
            .await?;
            watermark.remove(&endpoint_id);
        }
        if changed {
            let now = self.clock.now();
            let value = format_endpoint_cursor(&watermark);
            self.cursor
                .set(&SyncCursor::new(
                    SyncCursorId::generate(),
                    self.instance_id,
                    SyncStream::Endpoint,
                    value,
                    now,
                ))
                .await
                .map_err(CenterSyncError::Cursor)?;
        }
        Ok(())
    }

    /// Enqueues one [`EndpointSnapshot`]: the site-side projection of the
    /// endpoint (§15.5 — the center never sees credentials or sessions).
    /// The health field is the first cut of the vocabulary: `ok` after the
    /// first completed refresh, `unknown` before it.
    async fn enqueue_endpoint_snapshot(
        &self,
        item: &EndpointInventoryItem,
        generation: u64,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let endpoint = item.endpoint();
        let resources = item
            .resources()
            .iter()
            .map(|resource| ResourceSummary {
                feature: resource.feature().as_str().to_owned(),
                odata_id: resource.odata_id().as_str().to_owned(),
                odata_type: resource
                    .odata_type()
                    .map_or_else(String::new, |odata_type| odata_type.as_str().to_owned()),
                etag: resource
                    .etag()
                    .map_or_else(String::new, |etag| etag.as_str().to_owned()),
                generation,
            })
            .collect();
        let trust = match endpoint.trust() {
            TlsTrust::SystemCa { .. } => WireTlsTrust::SystemCa,
            TlsTrust::PinnedCertificate { .. } => WireTlsTrust::PinnedCertificate,
        };
        self.enqueue_outbox_entry(EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
            endpoint_id: endpoint.id().to_string(),
            display_name: endpoint.display_name().as_str().to_owned(),
            address: endpoint.address().as_url().to_string(),
            trust: trust as i32,
            refresh_generation: generation,
            resources,
            health: if generation == 0 {
                String::from("unknown")
            } else {
                String::from("ok")
            },
        }))
        .await
        .map(|_| ())
    }

    /// Enqueues one [`ResourceDelta`] upsert for a resource of the new
    /// generation, carrying the raw decoded resource document.
    async fn enqueue_resource_delta(
        &self,
        item: &EndpointInventoryItem,
        resource: &rutilus_domain::ResourceSnapshot,
        generation: u64,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        self.enqueue_outbox_entry(EnvelopeMessage::ResourceDelta(ResourceDelta {
            endpoint_id: item.endpoint().id().to_string(),
            op: ResourceDeltaOp::Upsert as i32,
            resource: Some(ResourceSummary {
                feature: resource.feature().as_str().to_owned(),
                odata_id: resource.odata_id().as_str().to_owned(),
                odata_type: resource
                    .odata_type()
                    .map_or_else(String::new, |odata_type| odata_type.as_str().to_owned()),
                etag: resource
                    .etag()
                    .map_or_else(String::new, |etag| etag.as_str().to_owned()),
                generation,
            }),
            payload_json: resource.payload().as_str().as_bytes().to_vec(),
            observed_at_unix: resource.observed_at().unix_timestamp(),
        }))
        .await
        .map(|_| ())
    }

    /// Reports the bounded event tail: the newest events on the first sync,
    /// then everything after the `event` stream cursor. The cursor advances
    /// to the newest reported event, so the next batch is exactly the events
    /// in between. The domain event model does not persist the Redfish
    /// target or the raw event document, so those wire fields stay empty in
    /// this cut.
    async fn report_event_batch(
        &self,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let cursor = self
            .cursor
            .get(self.instance_id, SyncStream::Event)
            .await
            .map_err(CenterSyncError::Cursor)?;
        let cursor_anchor = if let Some(cursor) = cursor.as_ref() {
            if let Ok(anchor) = cursor.cursor_value().parse::<EventId>() {
                Some(anchor)
            } else {
                // A stored cursor a manual DB change or a partial restore
                // left unparseable must not wedge the sync loop: log it and
                // re-report the bounded tail. The report's cursor write at
                // the end heals the row.
                tracing::warn!(
                    "site {}: resetting the event stream cursor: the stored value is not an event id",
                    self.instance_id
                );
                None
            }
        } else {
            None
        };
        let (events, newest_id) = if let Some(anchor) = cursor_anchor {
            if self
                .events
                .contains(anchor)
                .await
                .map_err(CenterSyncError::Events)?
            {
                let events = self
                    .events
                    .list_after(anchor, self.options.event_batch_limit)
                    .await
                    .map_err(CenterSyncError::Events)?;
                let newest_id = events.last().map(Event::id);
                (events, newest_id)
            } else {
                // The bounded history evicted the anchor (§14.4) or a manual
                // DB change removed it: reset the stream to the bounded tail
                // instead of failing the connection on every attempt.
                tracing::warn!(
                    "site {}: resetting the event stream cursor: the anchor {} is no longer stored",
                    self.instance_id,
                    anchor
                );
                let events = self
                    .events
                    .list_recent(self.options.event_batch_limit)
                    .await
                    .map_err(CenterSyncError::Events)?;
                let newest_id = events.first().map(Event::id);
                (events, newest_id)
            }
        } else {
            let events = self
                .events
                .list_recent(self.options.event_batch_limit)
                .await
                .map_err(CenterSyncError::Events)?;
            let newest_id = events.first().map(Event::id);
            (events, newest_id)
        };
        if events.is_empty() {
            return Ok(());
        }
        let records = events
            .iter()
            .map(|event| EventRecord {
                event_id: event.id().to_string(),
                message_id: event.message_id().as_str().to_owned(),
                severity: match event.severity() {
                    EventSeverity::Ok => WireEventSeverity::Ok,
                    EventSeverity::Warning => WireEventSeverity::Warning,
                    EventSeverity::Critical => WireEventSeverity::Critical,
                } as i32,
                target: String::new(),
                occurred_at_unix: event.event_timestamp().unix_timestamp(),
                payload_json: Vec::new(),
                endpoint_id: event.endpoint_id().to_string(),
            })
            .collect();
        self.enqueue_outbox_entry(EnvelopeMessage::EventBatch(EventBatch { events: records }))
            .await?;
        let now = self.clock.now();
        self.cursor
            .set(&SyncCursor::new(
                SyncCursorId::generate(),
                self.instance_id,
                SyncStream::Event,
                newest_id.map(|event_id| event_id.to_string()).ok_or(
                    CenterSyncError::InvalidCursor {
                        stream: SyncStream::Event,
                        source: StoredCursorError::InvalidId,
                    },
                )?,
                now,
            ))
            .await
            .map_err(CenterSyncError::Cursor)?;
        Ok(())
    }

    /// Reports every ready artifact past the `artifact` stream cursor, in
    /// declaration order: one [`ArtifactManifest`] followed by the
    /// [`ArtifactChunk`] frames of the artifact bytes, chunked at
    /// [`CENTER_ARTIFACT_CHUNK_BYTES`], enqueued before the flush sends
    /// them. The cursor is the last distributed artifact id.
    ///
    /// A persistent distribution failure — a missing file (W10-D-1), a byte
    /// count that contradicts the manifest (W10-D-2), a same-size file whose
    /// bytes disagree with the declared digest (W11-D-3), or an unreadable
    /// file (W11-F-1) — is absorbed here: the failure cannot heal within
    /// this round, so propagating it would only take the whole connection
    /// down with it (the flush and the receive loop never run, and every
    /// reconnect fails at the same artifact — the W10-D-1 storm). The
    /// artifact stream stops at the artifact and the cursor stays before
    /// it, so the next round retries it — the distribution heals on its own
    /// once the file is restored, and skipping the artifact (advancing the
    /// cursor past it) would leave the center without it permanently
    /// (W9-S-2). The absorbed round reports the stall to the connection
    /// (W11-P-1): the connection ends itself after the reconnect period so
    /// the retry arrives on a bounded schedule instead of waiting for a
    /// disconnect that never comes. Transient failures keep the historical
    /// contract: the round aborts and the reconnect retries.
    async fn report_artifacts(
        &self,
    ) -> Result<
        ArtifactStreamOutcome,
        CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>,
    > {
        let cursor = self
            .cursor
            .get(self.instance_id, SyncStream::Artifact)
            .await
            .map_err(CenterSyncError::Cursor)?;
        let anchor = if let Some(cursor) = cursor.as_ref() {
            if let Ok(anchor) = cursor.cursor_value().parse::<ArtifactId>() {
                Some(anchor)
            } else {
                // A stored cursor a manual DB change or a partial restore
                // left unparseable must not wedge the sync loop: log it and
                // re-distribute the ready set. The report's cursor write at
                // the end heals the row.
                tracing::warn!(
                    "site {}: resetting the artifact stream cursor: the stored value is not an artifact id",
                    self.instance_id
                );
                None
            }
        } else {
            None
        };
        let anchor_created_at = if let Some(anchor_id) = anchor {
            if let Some(artifact) = self
                .store
                .find_artifact(anchor_id)
                .await
                .map_err(CenterSyncError::Artifact)?
            {
                Some(artifact.created_at())
            } else {
                // The anchor artifact is gone (a manual DB change or a
                // partial restore): reset the stream and re-distribute the
                // ready set; the report's cursor write heals the row.
                tracing::warn!(
                    "site {}: resetting the artifact stream cursor: the anchor artifact is no longer stored",
                    self.instance_id
                );
                None
            }
        } else {
            None
        };
        let ready = self
            .store
            .list_artifacts_by_state(ArtifactState::Ready)
            .await
            .map_err(CenterSyncError::Artifact)?;
        let mut newest_distributed = None;
        for artifact in ready {
            let after_anchor = match (anchor_created_at, anchor) {
                (Some(anchor_created_at), Some(anchor_id)) => {
                    artifact.created_at() > anchor_created_at
                        || (artifact.created_at() == anchor_created_at && artifact.id() > anchor_id)
                }
                _ => true,
            };
            if !after_anchor {
                continue;
            }
            if let Err(error) = self.distribute_artifact(&artifact).await {
                match &error {
                    // The persistent failure shapes (W10-D-1, W10-D-2,
                    // W11-D-3, W11-F-1): the artifact's file is missing,
                    // its byte count contradicts the manifest, its bytes
                    // disagree with the declared digest, or the file is
                    // unreadable — so no retry within this round can
                    // succeed, and propagating the error would take the
                    // whole connection down with it: the flush and the
                    // receive loop never run (W10-E-2), and every reconnect
                    // fails at the same artifact forever (the W10-D-1
                    // storm). The failure is absorbed instead: the repair
                    // path is logged, the artifact stream stops here, and
                    // the cursor stays before the artifact — the next round
                    // retries it, so it heals automatically once the
                    // operator restores the file. Skipping the artifact
                    // would leave the center without it permanently while
                    // the row stays `Ready` (the W9-S-2 inconsistency), and
                    // the domain lifecycle refuses a `Failed` verdict for a
                    // `Ready` row, so the retry is the honest state. The
                    // returned stall arms the connection's W11-P-1 timer so
                    // the retry actually arrives.
                    CenterSyncError::ArtifactFileMissing { .. }
                    | CenterSyncError::ArtifactSizeMismatch { .. }
                    | CenterSyncError::ArtifactDigestMismatch { .. }
                    | CenterSyncError::ArtifactFileUnreadable { .. } => {
                        tracing::error!(
                            "site {}: the artifact stream stops before artifact {}: {error}",
                            self.instance_id,
                            artifact.id()
                        );
                        return Ok(ArtifactStreamOutcome::Stalled {
                            artifact_id: artifact.id(),
                        });
                    }
                    // A transient read error or a boundary failure keeps the
                    // historical contract: the round aborts and the
                    // reconnect retries the artifact (its half-set was
                    // already retired by the distribution).
                    _ => return Err(error),
                }
            }
            newest_distributed = Some(artifact.id());
        }
        if let Some(newest) = newest_distributed {
            let now = self.clock.now();
            self.cursor
                .set(&SyncCursor::new(
                    SyncCursorId::generate(),
                    self.instance_id,
                    SyncStream::Artifact,
                    newest.to_string(),
                    now,
                ))
                .await
                .map_err(CenterSyncError::Cursor)?;
        }
        Ok(ArtifactStreamOutcome::Complete)
    }

    /// Enqueues the manifest and the chunk frames of one ready artifact.
    ///
    /// The artifact bytes stream from disk chunk by chunk (W9-S-3) instead
    /// of being read whole into memory: the blocking reader task (design
    /// §7.8) reads one chunk at a time into a bounded channel, and each
    /// chunk is enqueued into the durable outbox as it arrives and
    /// released — the peak memory is one chunk plus the outbox entry,
    /// never the whole artifact (the pre-fix `fs::read` peaked at roughly
    /// twice the artifact size). The manifest is enqueued only after the
    /// first chunk was read, so a missing file aborts the distribution
    /// before anything is enqueued — the same property as the old
    /// whole-file read.
    ///
    /// The reader refuses a file whose byte count contradicts the manifest
    /// twice over: the metadata length pre-check (W11-F-3) fails fast
    /// before a byte is read — an empty, truncated, or oversized file
    /// never pays for a full read and never enqueues anything — and the
    /// streamed byte count at EOF remains the authority for a file that
    /// changed size between the pre-check and the read (the TOCTOU
    /// window), both classified as [`CenterSyncError::ArtifactSizeMismatch`]
    /// with the observed and declared counts. The reader also accumulates
    /// the SHA-256 of the streamed bytes at zero extra I/O (W11-D-3) and
    /// compares it with the declared digest at EOF: a same-size file whose
    /// bytes disagree is refused as [`CenterSyncError::ArtifactDigestMismatch`]
    /// instead of being silently distributed once — the pre-fix shape that
    /// left the center holding bad content and the site row `Ready`
    /// forever.
    ///
    /// The distribution begins by retiring the artifact's stale outbox
    /// entries ([`Self::retire_pending_artifact_entries`]): a half-set a
    /// cancelled round (W11-F-4) or a failed retire (W11-C-2) left pending
    /// must not be delivered by the flush alongside the fresh set — or on
    /// its own when the file is gone again. On any failure of this round,
    /// the manifest and the chunks this round enqueued are retired by
    /// their recorded entry ids (W11-F-2): the retire reaches the fresh
    /// partial set even when the queue's oldest window is full of
    /// unrelated entries, and a distribution that failed before enqueueing
    /// anything (the W11-C-3 zero-enqueue path) retires nothing. A failed
    /// retire is never swallowed (W11-C-2): it escalates into the round's
    /// error, so the connection ends before the flush — the residual
    /// half-set is never sent, and the reconnect retries the distribution,
    /// whose pre-clean re-runs the retire.
    // The distribution is one sequential procedure — ledger clear, chunk
    // enqueue, and the retire on failure share a single narrative;
    // splitting it would fragment the W11-C-2/C-3 invariant story.
    #[allow(clippy::too_many_lines)]
    async fn distribute_artifact(
        &self,
        artifact: &rutilus_domain::Artifact,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let path = self.store.artifact_file_path(artifact.id());
        let chunk_bytes = self.options.artifact_chunk_bytes;
        let declared_bytes = artifact.size_bytes();
        let expected_digest: [u8; 32] = artifact.sha256().into_bytes();
        self.distribution_entries
            .lock()
            .map_err(|_| CenterSyncError::ProgressTracking)?
            .clear();
        // W11-F-2 / W11-F-4 / W11-C-2: the stale-set cleanup before the
        // fresh set enters the queue — a residual half-set of this artifact
        // from a cancelled round or a failed retire must not ride the flush.
        self.retire_pending_artifact_entries(artifact.id()).await?;
        // A bounded channel carries the chunks from the blocking reader to
        // the async enqueue side; capacity 1 caps the buffered bytes at one
        // chunk, and the reader's `blocking_send` applies backpressure to
        // the disk reads.
        let (chunk_sender, mut chunk_receiver) = tokio::sync::mpsc::channel::<Vec<u8>>(1);
        let reader = tokio::task::spawn_blocking(move || -> Result<(), ArtifactReadFailure> {
            use std::io::Read as _;
            let mut file = std::fs::File::open(&path).map_err(ArtifactReadFailure::Io)?;
            // W11-F-3: the metadata length pre-check. A file whose length
            // already disagrees with the manifest fails before a byte is
            // read or enqueued — the fast-fail keeps an oversized or
            // truncated error from paying for a full read and a full outbox
            // write before the EOF check discovers it. The streamed count
            // below remains authoritative: a file that changes size between
            // the pre-check and the read is caught at EOF.
            let actual_len = file.metadata().map_err(ArtifactReadFailure::Io)?.len();
            if actual_len != declared_bytes {
                return Err(ArtifactReadFailure::SizeMismatch {
                    read_bytes: actual_len,
                    declared_bytes,
                });
            }
            let mut hasher = Sha256::new();
            let mut chunk = vec![0_u8; chunk_bytes];
            let mut total_read: u64 = 0;
            loop {
                let mut filled = 0_usize;
                while filled < chunk_bytes {
                    match file.read(&mut chunk[filled..]) {
                        Ok(0) => break,
                        Ok(read) => {
                            filled += read;
                            total_read += read as u64;
                        }
                        Err(source) => return Err(ArtifactReadFailure::Io(source)),
                    }
                }
                if filled == 0 {
                    // EOF exactly at a chunk boundary: the stream is done.
                    break;
                }
                // The digest accumulates on the streamed bytes (W11-D-3):
                // one extra pass over bytes already in memory, zero extra
                // I/O.
                hasher.update(&chunk[..filled]);
                let last = filled < chunk_bytes;
                chunk.truncate(filled);
                chunk_sender.blocking_send(chunk).map_err(|_| {
                    ArtifactReadFailure::Io(std::io::Error::other(
                        "the artifact reader was cancelled",
                    ))
                })?;
                if last {
                    break;
                }
                chunk = vec![0_u8; chunk_bytes];
            }
            // The file's byte count must match the declared size (W10-D-2):
            // a shorter file is empty or truncated — distributing it would
            // strand the center's upload on a partial set — and a longer
            // file carries bytes the manifest never declared. Either way
            // the artifact is corrupted, and the distribution is refused
            // with the observed count in the diagnosis.
            if total_read != declared_bytes {
                return Err(ArtifactReadFailure::SizeMismatch {
                    read_bytes: total_read,
                    declared_bytes,
                });
            }
            // W11-D-3: the declared digest must match the streamed bytes.
            // The size check alone let a same-size file with wrong content
            // through — the center would silently hold bad bytes while the
            // site row stays `Ready`, and the two would diverge forever.
            // The digest is a persistent corruption signature, so the
            // failure is classified in the same absorbed family as a size
            // mismatch, with both digests in the diagnosis.
            let actual_digest: [u8; 32] = hasher.finalize().into();
            if actual_digest != expected_digest {
                return Err(ArtifactReadFailure::DigestMismatch {
                    expected: Sha256Hex::from_bytes(expected_digest).as_str().to_owned(),
                    actual: Sha256Hex::from_bytes(actual_digest).as_str().to_owned(),
                });
            }
            Ok(())
        });
        let outcome = async {
            // The manifest is enqueued only after the first chunk was read: a
            // missing file (the W9-S-2 restore-crash signature) surfaces its
            // classified error here, before anything entered the outbox.
            let Some(first_chunk) = chunk_receiver.recv().await else {
                return reader
                    .await
                    .map_err(|source| CenterSyncError::ArtifactRead {
                        artifact_id: artifact.id(),
                        source: std::io::Error::other(source.to_string()),
                    })?
                    .map_err(|source| Self::map_artifact_read_failure(artifact.id(), source));
            };
            let manifest = self
                .enqueue_outbox_entry(EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                    artifact_id: artifact.id().to_string(),
                    name: artifact.name().as_str().to_owned(),
                    total_bytes: artifact.size_bytes(),
                    sha256: artifact.sha256().into_bytes().to_vec(),
                }))
                .await?;
            self.distribution_entries
                .lock()
                .map_err(|_| CenterSyncError::ProgressTracking)?
                .push(manifest.id());
            let mut index = 0_usize;
            let mut chunk = first_chunk;
            loop {
                let entry = self
                    .enqueue_outbox_entry(EnvelopeMessage::ArtifactChunk(ArtifactChunk {
                        artifact_id: artifact.id().to_string(),
                        index: u32::try_from(index).map_err(|_| {
                            CenterSyncError::SequenceOverflow {
                                sequence: i64::try_from(index).unwrap_or(i64::MAX),
                            }
                        })?,
                        data: chunk,
                    }))
                    .await?;
                self.distribution_entries
                    .lock()
                    .map_err(|_| CenterSyncError::ProgressTracking)?
                    .push(entry.id());
                index += 1;
                let Some(next) = chunk_receiver.recv().await else {
                    break;
                };
                chunk = next;
            }
            reader
                .await
                .map_err(|source| CenterSyncError::ArtifactRead {
                    artifact_id: artifact.id(),
                    source: std::io::Error::other(source.to_string()),
                })?
                .map_err(|source| Self::map_artifact_read_failure(artifact.id(), source))
        }
        .await;
        if outcome.is_err() {
            // The entries this round enqueued must not linger in the outbox:
            // the flush would deliver the half-set to the center, and the
            // next round would enqueue another set on top of it. The retire
            // addresses the recorded entry ids directly (W11-F-2): no scan,
            // no window, so a queue whose oldest window is full of unrelated
            // entries cannot hide the fresh partial set. A distribution that
            // failed before enqueueing anything has an empty ledger and
            // retires nothing (W11-C-3). The cleanup is not best-effort
            // (W11-C-2): a failing retire escalates into the round's error,
            // so the connection ends before the flush and the residual
            // half-set is never delivered — the reconnect retries the
            // distribution, whose pre-clean re-runs the retire.
            let enqueued = self
                .distribution_entries
                .lock()
                .map_err(|_| CenterSyncError::ProgressTracking)?
                .drain(..)
                .collect::<Vec<_>>();
            if !enqueued.is_empty() {
                let now = self.clock.now();
                for entry_id in enqueued {
                    self.outbox
                        .acknowledge(entry_id, now)
                        .await
                        .map_err(CenterSyncError::Outbox)?;
                }
            }
        }
        outcome
    }

    /// Retires every pending outbox entry of one artifact's distribution —
    /// its manifest and chunk frames — without sending it.
    ///
    /// This is the *stale-set* cleanup of [`Self::distribute_artifact`]:
    /// it scans the pending queue for entries of the artifact that earlier
    /// rounds left behind (a cancelled distribution, W11-F-4; a failed
    /// retire, W11-C-2). The fresh partial set of the current round is
    /// retired by its recorded entry ids instead (W11-F-2), because this
    /// scan reads the *oldest* pending window: with the window full of
    /// unrelated entries, the artifact's own entries — enqueued more
    /// recently — are beyond it. The stale set is always older than the
    /// fresh window's tail, so the scan reaches the residue within the
    /// window; a deeper residue stays for a later round, exactly like the
    /// dispatch settle scan's bounded queue (W9-C-2), and the flush
    /// delivers at most an idempotently-absorbed duplicate, never a
    /// half-set on its own.
    ///
    /// The scan repeats until a pass retires nothing or sees fewer pending
    /// entries than its bound, so one artifact's full set (whose size is
    /// bounded by the declared-size cap over the chunk size) is always
    /// within reach.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSyncError::Outbox`] when the queue scan or an
    /// acknowledgement fails.
    async fn retire_pending_artifact_entries(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail>> {
        let now = self.clock.now();
        let bound = artifact_set_size_bound(self.options.artifact_chunk_bytes);
        loop {
            let pending = self
                .outbox
                .list_pending(self.instance_id, bound)
                .await
                .map_err(CenterSyncError::Outbox)?;
            let mut retired_any = false;
            for entry in &pending {
                if entry_carries_artifact(entry, artifact_id) {
                    self.outbox
                        .acknowledge(entry.id(), now)
                        .await
                        .map_err(CenterSyncError::Outbox)?;
                    retired_any = true;
                }
            }
            if !retired_any || pending.len() < usize::try_from(bound).unwrap_or(usize::MAX) {
                break;
            }
        }
        Ok(())
    }

    /// Maps one failure of the distribution reader: a byte-count mismatch
    /// against the declared manifest is the W10-D-2 corruption signature —
    /// [`CenterSyncError::ArtifactSizeMismatch`], carrying the observed and
    /// declared counts — and a same-size digest mismatch is the W11-D-3
    /// corruption signature, [`CenterSyncError::ArtifactDigestMismatch`]
    /// with both digests. Every I/O failure keeps the existing
    /// classification (a missing file is the W9-S-2 signature,
    /// [`CenterSyncError::ArtifactFileMissing`]; anything else goes
    /// through [`Self::classify_artifact_read_error`]).
    fn map_artifact_read_failure(
        artifact_id: ArtifactId,
        failure: ArtifactReadFailure,
    ) -> CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail> {
        match failure {
            ArtifactReadFailure::SizeMismatch {
                read_bytes,
                declared_bytes,
            } => CenterSyncError::ArtifactSizeMismatch {
                artifact_id,
                read_bytes,
                declared_bytes,
            },
            ArtifactReadFailure::DigestMismatch { expected, actual } => {
                CenterSyncError::ArtifactDigestMismatch {
                    artifact_id,
                    expected,
                    actual,
                }
            }
            ArtifactReadFailure::Io(source) => {
                Self::classify_artifact_read_error(artifact_id, source)
            }
        }
    }

    /// Maps one artifact-file read error of the distribution reader: a
    /// missing file is the W9-S-2 signature — a `Ready` row whose artifact
    /// file is not on disk — classified as
    /// [`CenterSyncError::ArtifactFileMissing`] so the run loop's warning
    /// names the repair path; a file the process cannot open because of its
    /// permissions or its path shape — [`ErrorKind::PermissionDenied`] and
    /// [`ErrorKind::IsADirectory`] (W11-F-1) — is a persistent condition
    /// the operator must resolve (fix the file's ownership or replace the
    /// directory placeholder), classified as
    /// [`CenterSyncError::ArtifactFileUnreadable`] and absorbed like the
    /// other persistent shapes instead of storming the reconnect loop. The
    /// genuinely transient kinds — resource exhaustion (EMFILE/ENFILE),
    /// interruption, would-block — stay [`CenterSyncError::ArtifactRead`]:
    /// they can clear within the round, so the historical contract of
    /// propagating and retrying keeps them moving.
    fn classify_artifact_read_error(
        artifact_id: ArtifactId,
        source: std::io::Error,
    ) -> CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail> {
        match source.kind() {
            std::io::ErrorKind::NotFound => CenterSyncError::ArtifactFileMissing { artifact_id },
            std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::IsADirectory => {
                CenterSyncError::ArtifactFileUnreadable {
                    artifact_id,
                    source,
                }
            }
            _ => CenterSyncError::ArtifactRead {
                artifact_id,
                source,
            },
        }
    }

    /// Handles one inbound envelope from the center. The reliable outbox
    /// (acknowledgements) and the operation offers arrive in later slices;
    /// every other message — and every message this build does not act on —
    /// is logged and absorbed so a future protocol message never kills the
    /// connection.
    fn dispatch_inbound(&self, envelope: Envelope) {
        match envelope.message {
            Some(EnvelopeMessage::Heartbeat(_)) => {}
            Some(message) => {
                tracing::warn!(
                    "site {}: center frame {} carries an unhandled message: {message:?}",
                    self.instance_id,
                    envelope.sequence
                );
            }
            None => {
                tracing::warn!(
                    "site {}: center frame {} carries no message",
                    self.instance_id,
                    envelope.sequence
                );
            }
        }
    }
}

/// One failure of the blocking artifact-distribution reader (W10-D-2,
/// W11-D-3).
///
/// The reader distinguishes an I/O failure — classified like every other
/// file error by [`CenterSync::classify_artifact_read_error`] — from a
/// byte-count mismatch against the declared manifest, the
/// empty/truncated-file corruption shape the pre-fix reader silently
/// distributed or silently skipped, and a same-size digest mismatch, the
/// wrong-content corruption shape the size check alone let through.
enum ArtifactReadFailure {
    /// The file could not be opened or read.
    Io(std::io::Error),
    /// The file's byte count is different from the declared size.
    SizeMismatch {
        read_bytes: u64,
        declared_bytes: u64,
    },
    /// The streamed bytes do not hash to the declared digest.
    DigestMismatch { expected: String, actual: String },
}

/// The outcome of one artifact stream report (W11-P-1).
///
/// The report returns the outcome so the connection can arm the stall
/// timer: an absorbed persistent failure stops the stream, and the timer
/// ends the connection after the reconnect period so the retry actually
/// arrives on a stable network.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ArtifactStreamOutcome {
    /// The stream distributed every ready artifact past the cursor.
    Complete,
    /// The stream stopped at the persistent failure of `artifact_id`: the
    /// cursor stays before it, and the connection ends itself after the
    /// reconnect period so the next connection retries the artifact.
    Stalled { artifact_id: ArtifactId },
}

/// The upper bound of one artifact's distribution set: at most
/// `size / chunk` chunk frames plus the manifest, so a retire scan bounded
/// by `ceil(max size / chunk) + 1` always sees one artifact's full set.
fn artifact_set_size_bound(chunk_bytes: usize) -> u64 {
    let chunk_bytes = u64::try_from(chunk_bytes).unwrap_or(1);
    ARTIFACT_MAX_SIZE_BYTES.div_ceil(chunk_bytes) + 1
}

/// Decodes one outbox entry and reports whether it belongs to the given
/// artifact's distribution — its manifest or one of its chunk frames. A
/// corrupt payload row is skipped exactly like the flush skips it; the
/// flush already owns the per-row corruption warning.
fn entry_carries_artifact(entry: &OutboxEntry, artifact_id: ArtifactId) -> bool {
    let Ok(envelope) = serde_json::from_str::<Envelope>(entry.payload_json()) else {
        return false;
    };
    let Some(message) = envelope.message else {
        return false;
    };
    match message {
        EnvelopeMessage::ArtifactManifest(manifest) => {
            manifest.artifact_id == artifact_id.to_string()
        }
        EnvelopeMessage::ArtifactChunk(chunk) => chunk.artifact_id == artifact_id.to_string(),
        _ => false,
    }
}

/// A controlled failure of one step of the site-to-center synchronization.
///
/// The engine's `run` loop absorbs every variant — the connection is
/// retried after the §15.4 backoff — so this error type is the surface of
/// the engine's internal steps and of the runtime's final log line, not a
/// reason to stop the site.
#[derive(Debug, Error)]
pub enum CenterSyncError<
    TransportError,
    OperationStoreError,
    EndpointError,
    CapabilityError,
    CredentialError,
    InventoryError,
    ArtifactError,
    OutboxError,
    InboxError,
    CursorError,
    EventTailError,
> where
    TransportError: Error + 'static,
    OperationStoreError: Error + 'static,
    EndpointError: Error + 'static,
    CapabilityError: Error + 'static,
    CredentialError: Error + 'static,
    InventoryError: Error + 'static,
    ArtifactError: Error + 'static,
    OutboxError: Error + 'static,
    InboxError: Error + 'static,
    CursorError: Error + 'static,
    EventTailError: Error + 'static,
{
    /// The transport boundary failed; carries the transport's own error.
    #[error("the center transport failed: {0}")]
    Transport(#[source] TransportError),
    /// The operation store boundary failed; carries the repository's own
    /// error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationStoreError),
    /// The endpoint lookup boundary failed; carries the repository's own
    /// error.
    #[error("the endpoint lookup failed: {0}")]
    Endpoint(#[source] EndpointError),
    /// The capability pre-check (§15.6) could not be evaluated; carries the
    /// query's own error.
    #[error("the capability query failed: {0}")]
    Capability(#[source] EndpointCapabilityQueryError<CapabilityError>),
    /// The credential inventory boundary failed; carries the repository's
    /// own error.
    #[error("the credential inventory failed: {0}")]
    Credential(#[source] CredentialError),
    /// The target-state pre-check (§15.6) could not be evaluated; carries
    /// the query's own error.
    #[error("the endpoint inventory failed: {0}")]
    Inventory(#[source] EndpointInventoryQueryError<InventoryError>),
    /// The artifact store boundary failed; carries the repository's own
    /// error.
    #[error("the artifact store failed: {0}")]
    Artifact(#[source] ArtifactError),
    /// The durable outbox boundary failed; carries the repository's own
    /// error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
    /// The durable inbox boundary failed; carries the repository's own
    /// error.
    #[error("the center inbox failed: {0}")]
    Inbox(#[source] InboxError),
    /// The sync cursor boundary failed; carries the repository's own error.
    #[error("the sync cursor failed: {0}")]
    Cursor(#[source] CursorError),
    /// The event tail boundary failed; carries the repository's own error.
    #[error("the event tail failed: {0}")]
    Events(#[source] EventTailError),
    /// A stored sync cursor value is not parseable.
    #[error("the stored {stream} cursor value is invalid: {source}")]
    InvalidCursor {
        stream: SyncStream,
        #[source]
        source: StoredCursorError,
    },
    /// A wire message could not be serialized into its §9.4 payload record.
    #[error("the message could not be serialized into its payload record: {0}")]
    Payload(#[source] serde_json::Error),
    /// The center closed the connection.
    #[error("the center closed the connection")]
    Closed,
    /// A stored outbox payload is not the §9.4 typed serialization of an
    /// envelope; the row is corrupt. The flush isolates such rows (log and
    /// skip) instead of failing the connection, so this variant documents
    /// the corruption shape the engine detects rather than a return path.
    #[error("stored outbox entry {entry_id} is not a valid envelope payload: {source}")]
    InvalidOutboxPayload {
        entry_id: OutboxEntryId,
        #[source]
        source: serde_json::Error,
    },
    /// A stored sequence cannot be represented on the wire; the flush
    /// isolates such rows (log and skip) like corrupt payloads.
    #[error("outbox sequence {sequence} cannot be represented on the wire")]
    SequenceOverflow { sequence: i64 },
    /// An artifact's bytes could not be read for the center distribution.
    #[error("artifact {artifact_id} could not be read: {source}")]
    ArtifactRead {
        artifact_id: ArtifactId,
        #[source]
        source: std::io::Error,
    },
    /// A `Ready` artifact's file is missing on disk (W9-S-2): the §20.2
    /// restore-crash signature — a new database whose `Ready` rows have no
    /// artifact files. The failure is persistent, so `report_artifacts`
    /// absorbs it: the artifact stream stops at the artifact and the cursor
    /// never advances past it (skipping the artifact would leave the
    /// center without it permanently while the site row stays `Ready`),
    /// and the next round retries it — the distribution heals on its own
    /// once the operator re-restores from a backup taken with the artifact
    /// files in place, or deletes and re-uploads the artifact.
    #[error(
        "artifact {artifact_id} is ready but its file is missing on disk; the artifact stream \
         stops before it: re-restore from a backup taken with the artifact files in place, or \
         delete and re-upload the artifact"
    )]
    ArtifactFileMissing { artifact_id: ArtifactId },
    /// A `Ready` artifact's file does not hold the declared byte count
    /// (W10-D-2): the file is empty or truncated, so distributing it would
    /// either silently lose the artifact (an empty file enqueues nothing)
    /// or strand the center's upload on a partial set, or the file is
    /// longer than the manifest declares. The mismatch is persistent —
    /// only a re-restore or a re-upload heals it — so `report_artifacts`
    /// absorbs it (no reconnect storm), stops the artifact stream, and
    /// keeps the cursor before the artifact, and the distribution retires
    /// the partial outbox set it may have left behind.
    #[error(
        "artifact {artifact_id} is ready but its file holds {read_bytes} bytes, not the \
         declared {declared_bytes}; the artifact stream stops before it: re-restore from a \
         backup taken with the artifact files in place, or delete and re-upload the artifact"
    )]
    ArtifactSizeMismatch {
        artifact_id: ArtifactId,
        read_bytes: u64,
        declared_bytes: u64,
    },
    /// A `Ready` artifact's file holds the declared byte count but its
    /// bytes do not hash to the declared digest (W11-D-3): the size check
    /// alone would have distributed the bad content once and left the
    /// center and the site row permanently divergent. The mismatch is
    /// persistent — only a re-restore or a re-upload heals it — so
    /// `report_artifacts` absorbs it exactly like the size mismatch (no
    /// reconnect storm), stops the artifact stream, and keeps the cursor
    /// before the artifact.
    #[error(
        "artifact {artifact_id} is ready but its bytes hash to {actual}, not the declared \
         {expected}; the artifact stream stops before it: re-restore from a backup taken with \
         the artifact files in place, or delete and re-upload the artifact"
    )]
    ArtifactDigestMismatch {
        artifact_id: ArtifactId,
        expected: String,
        actual: String,
    },
    /// A `Ready` artifact's file is not readable — the process lacks the
    /// permission, or the path is a directory placeholder (W11-F-1). The
    /// condition is persistent until an operator fixes the file system, so
    /// `report_artifacts` absorbs it exactly like the missing-file shape
    /// (no reconnect storm), stops the artifact stream, and keeps the
    /// cursor before the artifact.
    #[error(
        "artifact {artifact_id} is ready but its file is not readable: {source}; the artifact \
         stream stops before it: fix the file's permissions or replace the path, or delete and \
         re-upload the artifact"
    )]
    ArtifactFileUnreadable {
        artifact_id: ArtifactId,
        #[source]
        source: std::io::Error,
    },
    /// The artifact stream stopped at a persistent failure and the W11-P-1
    /// stall timer ended the connection: the reconnect retries the
    /// artifact, so the distribution heals on its own once the operator
    /// fixes the file.
    #[error(
        "the artifact stream is stalled before artifact {artifact_id}; the connection ends \
         so the next one retries it"
    )]
    ArtifactStreamStalled { artifact_id: ArtifactId },
    /// The center refused the connection as `not-bound` the configured
    /// number of consecutive times (audit follow-up F4): the site's binding
    /// is not in force on the center, so the engine stops instead of
    /// retrying forever, and the runtime converges the site's local binding
    /// on this return.
    #[error("the center refused the connection as not bound")]
    NotBound,
    /// The center refused the connection as `identity-mismatch` the
    /// configured number of consecutive times (audit follow-up E3-2,
    /// C5-10): the `Hello`'s declared instance identity disagrees with the
    /// binding record its certificate resolves to. The binding is in force
    /// on both sides, so the engine stops instead of retrying forever and
    /// the runtime must NOT converge the local binding — only a re-bind
    /// heals the mismatch.
    #[error(
        "the center refused the connection as an identity mismatch: the site's instance \
         identity does not match the center's binding for its certificate"
    )]
    IdentityMismatch,
    /// The engine's in-memory progress tracking could not be locked; the
    /// tracking is the reconnect report's working set, so the engine treats
    /// a poisoned lock like any other internal break and the run loop
    /// reconnects.
    #[error("the engine's progress tracking is poisoned")]
    ProgressTracking,
}

/// Why a stored sync cursor value cannot be interpreted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StoredCursorError {
    /// The endpoint watermark pair is not `id:generation`.
    #[error("endpoint cursor pair is not endpoint-id:generation")]
    InvalidEndpointPair,
    /// A stored stream code is unknown.
    #[error("the cursor stream code is unknown")]
    UnknownStream,
    /// A cursor value carries an unparseable stable id.
    #[error("the cursor value is not a stable id")]
    InvalidId,
}

/// The concrete failure type of one engine step: every boundary error, in
/// [`CenterSyncError`] variant order.
type CenterSyncErrorOf<Transport, Store, Outbox, Inbox, Cursor, EventTail> = CenterSyncError<
    <Transport as CenterTransport>::Error,
    <Store as OperationStore>::Error,
    <Store as EndpointRefreshRepository>::Error,
    <Store as CapabilityQueryRepository>::Error,
    <Store as CredentialInventoryRepository>::Error,
    <Store as EndpointInventoryRepository>::Error,
    <Store as ArtifactRepository>::Error,
    <Outbox as CenterOutbox>::Error,
    <Inbox as CenterInbox>::Error,
    <Cursor as CenterCursor>::Error,
    <EventTail as CenterEventTail>::Error,
>;

/// Parses the `endpoint` stream cursor: the sorted `endpoint-id:generation`
/// pairs joined by commas (a UUID never contains a colon).
fn parse_endpoint_cursor(value: &str) -> Result<BTreeMap<EndpointId, u64>, StoredCursorError> {
    let mut watermark = BTreeMap::new();
    if value.is_empty() {
        return Ok(watermark);
    }
    for pair in value.split(',') {
        let Some((id, generation)) = pair.split_once(':') else {
            return Err(StoredCursorError::InvalidEndpointPair);
        };
        let endpoint_id = id
            .parse::<EndpointId>()
            .map_err(|_| StoredCursorError::InvalidId)?;
        let generation = generation
            .parse::<u64>()
            .map_err(|_| StoredCursorError::InvalidEndpointPair)?;
        watermark.insert(endpoint_id, generation);
    }
    Ok(watermark)
}

/// Serializes the `endpoint` stream cursor: the sorted
/// `endpoint-id:generation` pairs joined by commas.
fn format_endpoint_cursor(watermark: &BTreeMap<EndpointId, u64>) -> String {
    watermark
        .iter()
        .map(|(endpoint_id, generation)| format!("{endpoint_id}:{generation}"))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rutilus_center_protocol::{Ack, EnvelopeMessage, OperationOffer, OperationRejectedReason};
    use rutilus_domain::{
        BatchOperation, BatchOperationId, Credential, CredentialId, CredentialName,
        CredentialUsername, CredentialVersionId, Endpoint, EndpointAddress, EndpointCapability,
        EndpointDisplayName, EndpointId, Event, EventId, EventSeverity, InboxEntryState, MessageId,
        Operation, OperationId, OperationState, OutboxEntryState, RedfishCommand,
        RefreshGeneration, ResetType, ResourceFeature, ResourceId, ResourceODataId,
        ResourceSnapshot, ResourceSnapshotPayload, SyncStream, SystemCommand, TlsCertificate,
        TlsTrust, decide_inbox_duplicate,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild, OperationStore,
    };
    use time::OffsetDateTime;
    use tokio::sync::mpsc;
    use tokio::task::JoinSet;

    use super::*;
    use crate::{
        CapabilityQueryRepository, CredentialInventoryRepository, EndpointInventoryItem,
        EndpointInventoryRepository, EndpointRefreshRepository, StoredCapability,
        center_transport::test_support::{ChannelSession, ChannelTransport, MockCenterError},
    };
    /// The test-side wire ends of one scripted session: the frames the
    /// engine sent and the feed that delivers the frames the engine
    /// receives.
    #[derive(Debug)]
    struct Wire {
        outbound: mpsc::UnboundedReceiver<Envelope>,
        inbound: mpsc::UnboundedSender<Envelope>,
    }

    /// The shared script state of a [`ScriptedTransport`]: the engine owns
    /// the transport, so the test keeps a clone of this state to observe the
    /// connect attempts.
    struct ScriptedState {
        attempts: AtomicUsize,
        fail_until: usize,
    }

    impl ScriptedState {
        fn new(fail_until: usize) -> Self {
            Self {
                attempts: AtomicUsize::new(0),
                fail_until,
            }
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    /// A transport whose connect attempts fail on script and whose sessions
    /// hand their wire ends to the test. The engine takes it by value, so
    /// the test observes the shared state.
    struct ScriptedTransport {
        state: Arc<ScriptedState>,
        wires: mpsc::UnboundedSender<Wire>,
    }

    impl ScriptedTransport {
        fn new(fail_until: usize) -> (Self, Arc<ScriptedState>, mpsc::UnboundedReceiver<Wire>) {
            let state = Arc::new(ScriptedState::new(fail_until));
            let (wires, receiver) = mpsc::unbounded_channel();
            (
                Self {
                    state: Arc::clone(&state),
                    wires,
                },
                state,
                receiver,
            )
        }
    }

    impl CenterTransport for ScriptedTransport {
        type Session = ChannelSession;
        type Error = MockCenterError;

        fn connect(&self) -> crate::BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
            Box::pin(async move {
                let attempt = self.state.attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt <= self.state.fail_until {
                    return Err(MockCenterError);
                }
                let (session, outbound, inbound) = ChannelSession::channel();
                let _ = self.wires.send(Wire { outbound, inbound });
                Ok(session)
            })
        }
    }

    /// A mock store error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock store never fails")]
    struct MockStoreError;

    /// An in-memory store behind the engine's persistence boundaries:
    /// operations, endpoint lookup, capabilities, credentials, endpoint
    /// inventory, and artifacts. Every operation succeeds.
    struct MockEngineStore {
        operations: Mutex<HashMap<OperationId, Operation>>,
        endpoints: Mutex<HashMap<EndpointId, Endpoint>>,
        capabilities: Mutex<HashMap<EndpointId, Vec<StoredCapability>>>,
        credentials: Mutex<Vec<Credential>>,
        inventory: Mutex<Vec<EndpointInventoryItem>>,
        artifacts: Mutex<Vec<rutilus_domain::Artifact>>,
        artifact_dir: Mutex<Option<tempfile::TempDir>>,
        // The kind mirrors the persistence column, which stores a code
        // value (not a boolean): the value is semantically significant and
        // future `FailureKind` variants will make it non-zero-sized.
        #[allow(clippy::zero_sized_map_values)]
        failure_kinds: Mutex<HashMap<OperationId, FailureKind>>,
    }

    impl MockEngineStore {
        fn new() -> Self {
            Self {
                operations: Mutex::new(HashMap::new()),
                endpoints: Mutex::new(HashMap::new()),
                capabilities: Mutex::new(HashMap::new()),
                credentials: Mutex::new(Vec::new()),
                inventory: Mutex::new(Vec::new()),
                artifacts: Mutex::new(Vec::new()),
                artifact_dir: Mutex::new(None),
                #[allow(clippy::zero_sized_map_values)]
                failure_kinds: Mutex::new(HashMap::new()),
            }
        }

        fn set_failure_kind(
            &self,
            operation_id: OperationId,
            kind: FailureKind,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.failure_kinds
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .insert(operation_id, kind);
            Ok(())
        }

        fn set_endpoint(&self, endpoint: Endpoint) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.endpoints
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .insert(endpoint.id(), endpoint);
            Ok(())
        }

        fn set_capability(
            &self,
            endpoint_id: EndpointId,
            observation: rutilus_domain::EndpointCapabilityObservation,
            observed_at: OffsetDateTime,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.capabilities
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .entry(endpoint_id)
                .or_default()
                .push(StoredCapability::new(observation, observed_at));
            Ok(())
        }

        fn set_credential(
            &self,
            credential: Credential,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.credentials
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .push(credential);
            Ok(())
        }

        fn set_inventory(
            &self,
            item: EndpointInventoryItem,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.inventory
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .push(item);
            Ok(())
        }

        fn artifact_state(
            &self,
            artifact_id: rutilus_domain::ArtifactId,
        ) -> Result<Option<ArtifactState>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .artifacts
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .iter()
                .find(|artifact| artifact.id() == artifact_id)
                .map(rutilus_domain::Artifact::state))
        }

        fn set_artifact(
            &self,
            artifact: &rutilus_domain::Artifact,
            bytes: Vec<u8>,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.artifacts
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .push(artifact.clone());
            // The engine reads the artifact bytes from the store's
            // deterministic path, so the mock materializes the file.
            let mut dir_guard = self
                .artifact_dir
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?;
            if dir_guard.is_none() {
                *dir_guard = Some(tempfile::tempdir()?);
            }
            let directory = dir_guard
                .as_ref()
                .ok_or_else(|| std::io::Error::other("the mock artifact directory is missing"))?;
            std::fs::write(directory.path().join(artifact.id().to_string()), bytes)?;
            Ok(())
        }

        fn find_operation_owned(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<Operation>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .operations
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .get(&operation_id)
                .cloned())
        }

        fn operations_owned(&self) -> Result<Vec<Operation>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .operations
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .values()
                .cloned()
                .collect())
        }
    }

    impl OperationStore for MockEngineStore {
        type Error = MockStoreError;

        fn create_operation<'a>(
            &'a self,
            operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.operations
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
                let mut rows = self.operations.lock().map_err(|_| MockStoreError)?;
                let row = rows.get(&operation_id).ok_or(MockStoreError)?.clone();
                if row.is_terminal() {
                    return Err(MockStoreError);
                }
                rows.insert(
                    operation_id,
                    Operation::try_from_parts(
                        row.id(),
                        row.source(),
                        row.targets().to_vec(),
                        row.command(),
                        new_state,
                        row.created_at(),
                        occurred_at,
                    )
                    .map_err(|_| MockStoreError)?,
                );
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
                let mut rows = self.operations.lock().map_err(|_| MockStoreError)?;
                let row = rows.get(&operation_id).ok_or(MockStoreError)?.clone();
                if row.state() != expected_state {
                    return Err(MockStoreError);
                }
                rows.insert(
                    operation_id,
                    Operation::try_from_parts(
                        row.id(),
                        row.source(),
                        row.targets().to_vec(),
                        row.command(),
                        new_state,
                        row.created_at(),
                        occurred_at,
                    )
                    .map_err(|_| MockStoreError)?,
                );
                Ok(())
            })
        }

        fn record_failure_kind(
            &self,
            operation_id: OperationId,
            kind: rutilus_domain::FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.failure_kinds
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(operation_id, kind);
                Ok(())
            })
        }

        fn find_failure_kind(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<FailureKind>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .failure_kinds
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&operation_id)
                    .copied())
            })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .values()
                    .filter(|operation| state.is_none_or(|state| operation.state() == state))
                    .cloned()
                    .collect())
            })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The center-sync engine never creates batches; unreachable.
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

    impl EndpointRefreshRepository for MockEngineStore {
        type Error = MockStoreError;

        fn find_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> crate::BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .endpoints
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&endpoint_id)
                    .cloned())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [crate::ResourceObservation],
            _decode_failures: &'a [crate::ResourceDecodeFailure],
            _observed_at: OffsetDateTime,
        ) -> crate::BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl CapabilityQueryRepository for MockEngineStore {
        type Error = MockStoreError;

        fn find_endpoint_capabilities(
            &self,
            endpoint_id: EndpointId,
        ) -> crate::BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .capabilities
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&endpoint_id)
                    .cloned())
            })
        }
    }

    impl CredentialInventoryRepository for MockEngineStore {
        type Error = MockStoreError;

        fn list_credentials(
            &self,
        ) -> crate::BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
            Box::pin(
                async move { Ok(self.credentials.lock().map_err(|_| MockStoreError)?.clone()) },
            )
        }
    }

    impl EndpointInventoryRepository for MockEngineStore {
        type Error = MockStoreError;

        fn list_endpoint_inventory(
            &self,
        ) -> crate::BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async move { Ok(self.inventory.lock().map_err(|_| MockStoreError)?.clone()) })
        }
    }

    impl ArtifactRepository for MockEngineStore {
        type Error = MockStoreError;

        fn create_artifact<'a>(
            &'a self,
            _artifact: &'a rutilus_domain::Artifact,
        ) -> crate::BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_artifact(
            &self,
            artifact_id: rutilus_domain::ArtifactId,
        ) -> crate::BoundaryFuture<'_, Result<Option<rutilus_domain::Artifact>, Self::Error>>
        {
            Box::pin(async move {
                Ok(self
                    .artifacts
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .find(|artifact| artifact.id() == artifact_id)
                    .cloned())
            })
        }

        fn list_artifacts_by_state(
            &self,
            state: ArtifactState,
        ) -> crate::BoundaryFuture<'_, Result<Vec<rutilus_domain::Artifact>, Self::Error>> {
            Box::pin(async move {
                let mut artifacts = self
                    .artifacts
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .filter(|artifact| artifact.state() == state)
                    .cloned()
                    .collect::<Vec<_>>();
                artifacts.sort_by_key(|artifact| (artifact.created_at(), artifact.id()));
                Ok(artifacts)
            })
        }

        fn update_artifact(
            &self,
            _artifact_id: rutilus_domain::ArtifactId,
            _uploaded_bytes: u64,
            _state: ArtifactState,
            _occurred_at: OffsetDateTime,
        ) -> crate::BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn artifact_file_path(
            &self,
            artifact_id: rutilus_domain::ArtifactId,
        ) -> std::path::PathBuf {
            self.artifact_dir
                .lock()
                .ok()
                .and_then(|guard| {
                    guard
                        .as_ref()
                        .map(|directory| directory.path().join(artifact_id.to_string()))
                })
                .unwrap_or_else(|| std::path::PathBuf::from(format!("mock-artifact-{artifact_id}")))
        }
    }

    /// An in-memory [`CenterInbox`] mirroring the persistence contract: the
    /// operation id is the idempotency key and the state machine is the
    /// domain `InboxEntry`. Every operation succeeds.
    struct MockInbox {
        entries: Mutex<HashMap<OperationId, InboxEntry>>,
    }

    impl MockInbox {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }

        fn entry_state(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<InboxEntryState>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .entries
                .lock()
                .map_err(|_| std::io::Error::other("the mock inbox lock was poisoned"))?
                .get(&operation_id)
                .map(InboxEntry::state))
        }
    }

    impl CenterInbox for MockInbox {
        type Error = MockStoreError;

        fn insert<'a>(
            &'a self,
            entry: &'a InboxEntry,
        ) -> crate::BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockStoreError)?;
                let existing = entries.get(&entry.operation_id()).map(InboxEntry::state);
                match decide_inbox_duplicate(existing) {
                    rutilus_domain::IdempotencyDecision::Proceed => {
                        entries.insert(entry.operation_id(), entry.clone());
                        Ok(InboxInsertOutcome::Created)
                    }
                    rutilus_domain::IdempotencyDecision::InProgress => {
                        Ok(InboxInsertOutcome::DuplicateInProgress)
                    }
                    rutilus_domain::IdempotencyDecision::AlreadyResolved(state) => {
                        Ok(InboxInsertOutcome::DuplicateResolved(state))
                    }
                }
            })
        }

        fn find_by_operation(
            &self,
            operation_id: OperationId,
        ) -> crate::BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn advance(
            &self,
            operation_id: OperationId,
            event: InboxEvent,
        ) -> crate::BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockStoreError)?;
                if let Some(entry) = entries.get_mut(&operation_id) {
                    let _ = entry.apply(event);
                }
                Ok(())
            })
        }
    }

    /// An in-memory [`CenterCursor`]: one cursor per (instance, stream),
    /// exactly like the persistence contract. Every operation succeeds.
    struct MockCursor {
        cursors: Mutex<HashMap<(InstanceId, SyncStream), SyncCursor>>,
    }

    impl MockCursor {
        fn new() -> Self {
            Self {
                cursors: Mutex::new(HashMap::new()),
            }
        }

        fn cursor_value(
            &self,
            instance_id: InstanceId,
            stream: SyncStream,
        ) -> Result<Option<String>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .cursors
                .lock()
                .map_err(|_| std::io::Error::other("the mock cursor lock was poisoned"))?
                .get(&(instance_id, stream))
                .map(|cursor| cursor.cursor_value().to_owned()))
        }
    }

    impl CenterCursor for MockCursor {
        type Error = MockStoreError;

        fn get(
            &self,
            instance_id: InstanceId,
            stream: SyncStream,
        ) -> crate::BoundaryFuture<'_, Result<Option<SyncCursor>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&(instance_id, stream))
                    .cloned())
            })
        }

        fn set<'a>(
            &'a self,
            cursor: &'a SyncCursor,
        ) -> crate::BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert((cursor.instance_id(), cursor.stream()), cursor.clone());
                Ok(())
            })
        }
    }

    /// An in-memory [`CenterEventTail`]: the first sync returns the newest
    /// events, the resume returns everything after the anchor in
    /// `(observed_at, id)` order.
    struct MockEventTail {
        events: Mutex<Vec<Event>>,
    }

    impl MockEventTail {
        fn new(events: Vec<Event>) -> Self {
            Self {
                events: Mutex::new(events),
            }
        }
    }

    impl CenterEventTail for MockEventTail {
        type Error = MockStoreError;

        fn list_recent(
            &self,
            limit: u64,
        ) -> crate::BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
            Box::pin(async move {
                let mut events = self.events.lock().map_err(|_| MockStoreError)?.clone();
                events.sort_by(|left, right| {
                    right
                        .observed_at()
                        .cmp(&left.observed_at())
                        .then_with(|| right.id().cmp(&left.id()))
                });
                events.truncate(usize::try_from(limit).map_err(|_| MockStoreError)?);
                Ok(events)
            })
        }

        fn list_after(
            &self,
            after: EventId,
            limit: u64,
        ) -> crate::BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
            Box::pin(async move {
                let events = self.events.lock().map_err(|_| MockStoreError)?;
                let anchor = events
                    .iter()
                    .find(|event| event.id() == after)
                    .ok_or(MockStoreError)?;
                let mut after_anchor = events
                    .iter()
                    .filter(|event| {
                        event.observed_at() > anchor.observed_at()
                            || (event.observed_at() == anchor.observed_at()
                                && event.id() > anchor.id())
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                after_anchor.sort_by(|left, right| {
                    left.observed_at()
                        .cmp(&right.observed_at())
                        .then_with(|| left.id().cmp(&right.id()))
                });
                after_anchor.truncate(usize::try_from(limit).map_err(|_| MockStoreError)?);
                Ok(after_anchor)
            })
        }

        fn contains(
            &self,
            event_id: EventId,
        ) -> crate::BoundaryFuture<'_, Result<bool, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .events
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .any(|event| event.id() == event_id))
            })
        }
    }

    /// A fixed clock for the engine tests.
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn engine_options() -> CenterSyncOptions {
        CenterSyncOptions {
            heartbeat_interval: Duration::from_millis(20),
            reconnect_after: Duration::from_millis(20),
            flush_limit: 64,
            event_batch_limit: 256,
            artifact_chunk_bytes: CENTER_ARTIFACT_CHUNK_BYTES,
            not_bound_abort_after: None,
            identity_mismatch_abort_after: None,
        }
    }

    /// A mock outbox error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock outbox never fails")]
    struct MockOutboxError;

    /// An in-memory [`CenterOutbox`] mirroring the persistence contract:
    /// sequences allocated as max plus one, pending listing in sequence
    /// order, and idempotent acknowledgements. The mock never fails unless
    /// the acknowledge failure is armed (W11-C-2: the retire-failure
    /// escalation test needs an outbox whose acknowledgements fail while
    /// its listings still work).
    struct MockOutbox {
        entries: Arc<Mutex<Vec<OutboxEntry>>>,
        instance_id: InstanceId,
        fail_acknowledge: AtomicBool,
    }

    impl MockOutbox {
        fn new(instance_id: InstanceId) -> Self {
            Self {
                entries: Arc::new(Mutex::new(Vec::new())),
                instance_id,
                fail_acknowledge: AtomicBool::new(false),
            }
        }

        /// Arms the mock so every acknowledgement fails — the outbox shape
        /// whose listing works but whose write path does not.
        fn set_fail_acknowledge(&self, fail: bool) {
            self.fail_acknowledge.store(fail, Ordering::SeqCst);
        }

        /// Enqueues `count` heartbeat messages with sent-at times 1..=count,
        /// the same shape the flush tests assert on the wire.
        fn enqueue_heartbeats(
            &self,
            count: u64,
            now: OffsetDateTime,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            for index in 1..=count {
                let sent_at_unix = i64::try_from(index)
                    .map_err(|_| std::io::Error::other("the mock heartbeat time overflowed"))?;
                push_heartbeat_entry(&self.entries, self.instance_id, sent_at_unix, now)?;
            }
            Ok(())
        }

        /// Enqueues one entry whose payload is not the §9.4 typed
        /// serialization of an envelope — the corrupt-row shape a manual DB
        /// change can produce.
        fn enqueue_corrupt_payload(
            &self,
            now: OffsetDateTime,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            let mut entries = self
                .entries
                .lock()
                .map_err(|_| std::io::Error::other("the mock outbox lock was poisoned"))?;
            let next = entries.iter().map(OutboxEntry::sequence).max().unwrap_or(0) + 1;
            entries.push(OutboxEntry::new(
                OutboxEntryId::generate(),
                self.instance_id,
                next,
                String::from("{not a serialized envelope"),
                now,
            ));
            Ok(())
        }

        /// The pending messages, in sequence order, decoded from their §9.4
        /// payload records.
        fn pending_messages(&self) -> Result<Vec<EnvelopeMessage>, Box<dyn Error + Send + Sync>> {
            pending_messages_from(&self.entries)
        }
    }

    impl CenterOutbox for MockOutbox {
        type Error = MockOutboxError;

        fn enqueue<'a>(
            &'a self,
            instance_id: InstanceId,
            message: &'a EnvelopeMessage,
            created_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockOutboxError)?;
                let next = entries.iter().map(OutboxEntry::sequence).max().unwrap_or(0) + 1;
                let envelope = Envelope {
                    sequence: u64::try_from(next).map_err(|_| MockOutboxError)?,
                    acked_sequence: 0,
                    message: Some(message.clone()),
                };
                let entry = OutboxEntry::new(
                    OutboxEntryId::generate(),
                    instance_id,
                    next,
                    serde_json::to_string(&envelope).map_err(|_| MockOutboxError)?,
                    created_at,
                );
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
                let entries = self.entries.lock().map_err(|_| MockOutboxError)?;
                let mut pending = entries
                    .iter()
                    .filter(|entry| {
                        entry.instance_id() == instance_id
                            && entry.state() == OutboxEntryState::Pending
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                pending.sort_by_key(OutboxEntry::sequence);
                pending.truncate(usize::try_from(limit).map_err(|_| MockOutboxError)?);
                Ok(pending)
            })
        }

        fn list_offers(
            &self,
            instance_id: InstanceId,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .entries
                    .lock()
                    .map_err(|_| MockOutboxError)?
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
                if self.fail_acknowledge.load(Ordering::SeqCst) {
                    return Err(MockOutboxError);
                }
                let mut entries = self.entries.lock().map_err(|_| MockOutboxError)?;
                for entry in &mut *entries {
                    if entry.id() == entry_id && entry.state() == OutboxEntryState::Pending {
                        let _ = entry.ack(acked_at);
                    }
                }
                Ok(())
            })
        }
    }

    /// Appends one heartbeat entry to the shared entries vector of a
    /// [`MockOutbox`] — the offline-queue writer of the reconnect storm
    /// tests: local producers keep enqueuing into the durable outbox while
    /// the engine is disconnected (§21 0.7.0), and the flush drains the same
    /// rows on the next connection.
    fn push_heartbeat_entry(
        entries: &Arc<Mutex<Vec<OutboxEntry>>>,
        instance_id: InstanceId,
        sent_at_unix: i64,
        now: OffsetDateTime,
    ) -> Result<(), Box<dyn Error + Send + Sync>> {
        let mut rows = entries
            .lock()
            .map_err(|_| std::io::Error::other("the mock outbox lock was poisoned"))?;
        let next = rows.iter().map(OutboxEntry::sequence).max().unwrap_or(0) + 1;
        let envelope = Envelope {
            sequence: u64::try_from(next)
                .map_err(|_| std::io::Error::other("the mock outbox sequence overflowed"))?,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix })),
        };
        rows.push(OutboxEntry::new(
            OutboxEntryId::generate(),
            instance_id,
            next,
            serde_json::to_string(&envelope)?,
            now,
        ));
        Ok(())
    }

    /// The pending messages of the shared entries vector, in sequence order,
    /// decoded from their §9.4 payload records — the reader counterpart of
    /// [`push_heartbeat_entry`]: a storm test observes the outbox through
    /// the shared vector while the engine owns the mock.
    fn pending_messages_from(
        entries: &Arc<Mutex<Vec<OutboxEntry>>>,
    ) -> Result<Vec<EnvelopeMessage>, Box<dyn Error + Send + Sync>> {
        let rows = entries
            .lock()
            .map_err(|_| std::io::Error::other("the mock outbox lock was poisoned"))?;
        let mut pending = rows
            .iter()
            .filter(|entry| entry.state() == OutboxEntryState::Pending)
            .cloned()
            .collect::<Vec<_>>();
        pending.sort_by_key(OutboxEntry::sequence);
        let mut messages = Vec::with_capacity(pending.len());
        for entry in pending {
            let envelope: Envelope = serde_json::from_str(entry.payload_json())?;
            if let Some(message) = envelope.message {
                messages.push(message);
            }
        }
        Ok(messages)
    }

    /// Awaits the wire ends of the next established session.
    async fn next_wire(wires: &mut mpsc::UnboundedReceiver<Wire>) -> Result<Wire, Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(5), wires.recv())
            .await
            .map_err(|_| std::io::Error::other("no session was established"))?
            .ok_or_else(|| std::io::Error::other("the scripted transport ended").into())
    }

    /// Awaits the next frame the engine sent on the session.
    async fn next_frame(wire: &mut Wire) -> Result<Envelope, Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(5), wire.outbound.recv())
            .await
            .map_err(|_| std::io::Error::other("no frame arrived in time"))?
            .ok_or_else(|| std::io::Error::other("the session ended early").into())
    }

    /// Awaits the next outbox content frame, skipping liveness heartbeats.
    async fn next_outbox_frame(wire: &mut Wire) -> Result<Envelope, Box<dyn Error>> {
        loop {
            let envelope = next_frame(wire).await?;
            if envelope.sequence != 0 {
                return Ok(envelope);
            }
        }
    }

    #[tokio::test]
    async fn heartbeats_are_sent_while_connected_and_stop_exits_promptly()
    -> Result<(), Box<dyn Error>> {
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
                InstanceId::generate(),
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;

        // Heartbeats arrive roughly every 20 ms; each carries sequence 0
        // (a liveness frame, never an outbox message).
        let mut heartbeats_seen = 0;
        while heartbeats_seen < 2 {
            let envelope = next_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, 0);
            match envelope.message {
                Some(EnvelopeMessage::Heartbeat(_)) => heartbeats_seen += 1,
                Some(other) => {
                    return Err(std::io::Error::other(format!(
                        "expected a Heartbeat, got {other:?}"
                    ))
                    .into());
                }
                None => {
                    return Err(
                        std::io::Error::other("the heartbeat frame carried no message").into(),
                    );
                }
            }
        }

        // The stop signal drains the engine promptly, mid-connection.
        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_connects_keep_the_site_local_and_the_loop_alive() -> Result<(), Box<dyn Error>>
    {
        // The first three attempts fail — a scripted stand-in for a center
        // that rejects the §15.3 negotiation or is unreachable.
        let (transport, state, mut wires) = ScriptedTransport::new(3);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
                InstanceId::generate(),
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        // The fourth attempt succeeds; until then the loop kept retrying
        // with the backoff instead of exiting.
        let wire = next_wire(&mut wires).await?;
        assert_eq!(state.attempts(), 4);
        drop(wire);

        // The engine still answers the stop signal after the connection
        // ended and the loop moved back into the backoff.
        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_closed_connection_reconnects_after_the_backoff() -> Result<(), Box<dyn Error>> {
        let (transport, state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
                InstanceId::generate(),
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let first = next_wire(&mut wires).await?;
        // Closing the first session (the center disconnected) must lead to a
        // second connect after the backoff.
        let Wire { outbound, inbound } = first;
        drop(outbound);
        drop(inbound);

        let _second = next_wire(&mut wires).await?;
        assert_eq!(state.attempts(), 2);

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_flush_sends_pending_entries_in_sequence_order() -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // The offline queue: three messages enqueued while the site has
            // no connection. The flush must deliver them in sequence order.
            outbox.enqueue_heartbeats(3, now)?;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        let mut messages = Vec::new();
        for _ in 0..3 {
            let envelope = next_outbox_frame(&mut wire).await?;
            messages.push(envelope.sequence);
            let Some(EnvelopeMessage::Heartbeat(heartbeat)) = envelope.message else {
                return Err(std::io::Error::other(
                    "the flushed frame was not the enqueued message",
                )
                .into());
            };
            assert_eq!(
                heartbeat.sent_at_unix,
                i64::try_from(envelope.sequence)
                    .map_err(|_| std::io::Error::other("the wire sequence overflowed"))?
            );
        }
        assert_eq!(messages, vec![1, 2, 3]);

        // The flush acknowledged nothing yet: after a reconnect, the same
        // three entries are re-sent (at-least-once delivery).
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);
        let mut second = next_wire(&mut wires).await?;
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut second).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn acks_advance_the_outbox_and_the_resume_starts_after_them() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            outbox.enqueue_heartbeats(3, now)?;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        // The center acknowledges only the first sequence. After a
        // disconnect, the flush must resume from the last acknowledgement
        // (§15.4): only sequences 2 and 3 are re-sent.
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 1 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        let mut second = next_wire(&mut wires).await?;
        for sequence in [2, 3] {
            let envelope = next_outbox_frame(&mut second).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    /// Builds one endpoint bound to the given credential.
    fn managed_endpoint(
        credential_id: CredentialId,
        now: OffsetDateTime,
    ) -> Result<Endpoint, Box<dyn Error + Send + Sync>> {
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Rack A BMC")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"offer test certificate".to_vec())?,
                trusted_at: now,
            },
            credential_id,
            now,
            now,
        )?)
    }

    /// Builds one stored credential.
    fn managed_credential(now: OffsetDateTime) -> Result<Credential, Box<dyn Error + Send + Sync>> {
        Ok(Credential::try_new(
            CredentialId::generate(),
            CredentialName::parse("admin")?,
            CredentialUsername::parse("root")?,
            CredentialVersionId::generate(),
            now,
            now,
        )?)
    }

    /// Builds a one-generation endpoint inventory whose projection contains
    /// the offer target `/redfish/v1/Systems/1`.
    fn inventory_with_target(
        endpoint: &Endpoint,
        now: OffsetDateTime,
    ) -> Result<EndpointInventoryItem, Box<dyn Error + Send + Sync>> {
        let generation = RefreshGeneration::new(1)?;
        let service_root = ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            ResourceODataId::parse("/redfish/v1")?,
            ResourceSnapshotPayload::parse(r#"{"@odata.id":"/redfish/v1"}"#)?,
            now,
            generation,
        );
        let system = ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint.id(),
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(r#"{"@odata.id":"/redfish/v1/Systems/1"}"#)?,
            now,
            generation,
        );
        Ok(EndpointInventoryItem::try_new(
            endpoint.clone(),
            vec![service_root, system],
        )?)
    }

    /// Builds one operation offer for this site and the received envelope
    /// that carried it.
    fn offer_for(
        instance_id: InstanceId,
        endpoint_id: EndpointId,
        expires_at_unix: i64,
    ) -> Result<(OperationOffer, Envelope), Box<dyn Error + Send + Sync>> {
        let offer = OperationOffer {
            operation_id: OperationId::generate().to_string(),
            endpoint_id: endpoint_id.to_string(),
            site_id: instance_id.to_string(),
            command_json: serde_json::to_vec(&RedfishCommand::System(SystemCommand::Reset(
                ResetType::PowerCycle,
            )))?,
            target: String::from("/redfish/v1/Systems/1"),
            expires_at_unix,
            actor_context: String::from("principal-7"),
        };
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer.clone())),
        };
        Ok((offer, received))
    }

    /// The full §15.6 setup: a managed endpoint with a stored credential, a
    /// `Supported` capability observation, and an inventory containing the
    /// offer target.
    fn fully_prepared_store(
        now: OffsetDateTime,
    ) -> Result<(MockEngineStore, Endpoint), Box<dyn Error + Send + Sync>> {
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        store.set_credential(credential)?;
        store.set_inventory(inventory_with_target(&endpoint, now)?)?;
        Ok((store, endpoint))
    }

    /// Constructs the engine over the mocks, all borrowed so the test keeps
    /// inspecting them.
    fn engine_over<'a>(
        store: &'a MockEngineStore,
        outbox: &'a MockOutbox,
        inbox: &'a MockInbox,
        cursor: &'a MockCursor,
        events: &'a MockEventTail,
        instance_id: InstanceId,
        now: OffsetDateTime,
    ) -> CenterSync<
        &'a ChannelTransport,
        &'a MockEngineStore,
        &'a MockOutbox,
        &'a MockInbox,
        &'a MockCursor,
        &'a MockEventTail,
        FixedClock,
    > {
        static TRANSPORT: ChannelTransport = ChannelTransport;
        CenterSync::new(
            &TRANSPORT,
            store,
            outbox,
            inbox,
            cursor,
            events,
            FixedClock(now),
            instance_id,
            engine_options(),
        )
    }

    /// Handles one offer against a prepared store and returns the outcome
    /// with the outbox and inbox the engine wrote.
    async fn handle_offer_with(
        store: &MockEngineStore,
        instance_id: InstanceId,
        endpoint_id: EndpointId,
        expires_at_unix: i64,
        now: OffsetDateTime,
    ) -> Result<(OfferOutcome, MockOutbox, MockInbox), Box<dyn Error + Send + Sync>> {
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint_id, expires_at_unix)?;
        let outcome = engine.handle_offer(&offer, &received).await?;
        Ok((outcome, outbox, inbox))
    }

    #[tokio::test]
    async fn an_offer_passing_every_recheck_is_accepted_once()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;

        let outcome = engine.handle_offer(&offer, &received).await?;
        assert_eq!(outcome, OfferOutcome::Accepted);

        // The operation is persisted with the offer's stable id, the Center
        // source, and the offer's endpoint as its target.
        let operation_id: OperationId = offer.operation_id.parse()?;
        let operation = store
            .find_operation_owned(operation_id)?
            .ok_or_else(|| std::io::Error::other("the accepted operation is missing"))?;
        assert_eq!(operation.source(), OperationSource::Center);
        assert_eq!(operation.targets().len(), 1);
        assert_eq!(operation.targets()[0].endpoint_id(), endpoint.id());
        assert_eq!(operation.state(), OperationState::Queued);

        // The durable reply is queued and the inbox advanced.
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 1);
        let Some(EnvelopeMessage::OperationAccepted(accepted)) = messages.first() else {
            return Err(std::io::Error::other("the reply was not an OperationAccepted").into());
        };
        assert_eq!(accepted.operation_id, offer.operation_id);
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Accepted)
        );

        // A re-delivered offer is answered with the existing state and never
        // creates a second operation (§15.4 idempotency).
        let duplicate = engine.handle_offer(&offer, &received).await?;
        assert_eq!(duplicate, OfferOutcome::DuplicateProgress);
        assert_eq!(store.operations_owned()?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_endpoint_rejects_with_endpoint_missing()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let (outcome, outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            EndpointId::generate(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::EndpointMissing,
                detail: String::from("the endpoint is no longer managed"),
            }
        );
        let messages = outbox.pending_messages()?;
        let Some(EnvelopeMessage::OperationRejected(rejected)) = messages.first() else {
            return Err(std::io::Error::other("the reply was not an OperationRejected").into());
        };
        assert_eq!(
            rejected.reason,
            OperationRejectedReason::EndpointMissing as i32
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_capability_rejects_with_capability_missing()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        // The endpoint exists but its capability ledger has no observation.
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::CapabilityMissing,
                detail: format!(
                    "the {} capability is not usable",
                    EndpointCapability::Systems
                ),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_credential_rejects_with_credential_invalid()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        // The credential row is gone.
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::CredentialInvalid,
                detail: String::from("the endpoint credential is no longer stored"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_changed_target_rejects_with_target_state_changed()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        store.set_credential(credential)?;
        // The inventory exists but never contained the offer's target.
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::TargetStateChanged,
                detail: String::from("the target is not in the endpoint's last-known projection"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_expired_offer_rejects_with_expired() -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        // The offer expired one second before it was handled (§15.6 TTL).
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() - 1,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::Expired,
                detail: String::from("the offer expired before it could be applied"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_offer_with_an_unparseable_expiry_is_refused_as_expired()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        // A timestamp outside the parseable range: the wire field is a
        // signed 64-bit integer, the `time` crate spans only ±9999 years.
        let (offer, received) = offer_for(instance_id, endpoint.id(), i64::MAX)?;

        let outcome = engine.handle_offer(&offer, &received).await?;
        // Fail closed: the unparseable expiry is treated as already past,
        // exactly like the domain's `is_expired` judgment would refuse it.
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::Expired,
                detail: String::from("the offer expired before it could be applied"),
            }
        );
        // The refusal is durable: the reply is queued, the inbox records
        // it, and the stored entry is pinned before the receipt so a
        // re-delivered offer stays refused.
        let messages = outbox.pending_messages()?;
        let Some(EnvelopeMessage::OperationRejected(rejected)) = messages.first() else {
            return Err(std::io::Error::other("the reply was not an OperationRejected").into());
        };
        assert_eq!(rejected.reason, OperationRejectedReason::Expired as i32);
        let operation_id: OperationId = offer.operation_id.parse()?;
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Rejected)
        );
        let entry = CenterInbox::find_by_operation(&inbox, operation_id)
            .await?
            .ok_or_else(|| std::io::Error::other("the inbox entry is missing"))?;
        assert!(
            entry.expires_at() < now,
            "an unparseable expiry must pin the entry before the receipt"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_undecodable_command_rejects_with_invalid_command()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (mut offer, _received) =
            offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        offer.command_json = b"not a redfish command".to_vec();
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer.clone())),
        };
        let outcome = engine.handle_offer(&offer, &received).await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::InvalidCommand,
                detail: String::from("the command payload is not a valid RedfishCommand"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_offer_for_another_site_is_dropped() -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (mut offer, _received) =
            offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        offer.site_id = InstanceId::generate().to_string();
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer.clone())),
        };
        let outcome = engine.handle_offer(&offer, &received).await?;
        assert_eq!(outcome, OfferOutcome::Dropped);
        assert_eq!(outbox.pending_messages()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicate_of_a_rejected_offer_stays_rejected()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        // The store starts without the endpoint: the first delivery is
        // rejected with `EndpointMissing` and the inbox records it.
        let store = MockEngineStore::new();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        let first = engine.handle_offer(&offer, &received).await?;
        assert!(matches!(first, OfferOutcome::Rejected { .. }));
        let operation_id: OperationId = offer.operation_id.parse()?;
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Rejected)
        );

        // The endpoint appears before the re-delivery; the re-run now passes
        // every recheck, so the duplicate is answered with the generic
        // refusal — the recorded outcome stands and nothing executes.
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        store.set_credential(credential)?;
        store.set_inventory(inventory_with_target(&endpoint, now)?)?;
        let second = engine.handle_offer(&offer, &received).await?;
        assert_eq!(
            second,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::Unspecified,
                detail: String::from("the offer was already rejected and cannot be revived"),
            }
        );
        assert_eq!(store.operations_owned()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicate_of_a_completed_offer_returns_the_recorded_outcome()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::Accepted
        );
        let operation_id: OperationId = offer.operation_id.parse()?;

        // The operation runs to a terminal outcome.
        store
            .apply_transition(
                operation_id,
                OperationState::Succeeded,
                now + time::Duration::SECOND,
            )
            .await?;

        // The result reporting closes the inbox lifecycle.
        engine.report_center_operations().await?;
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Completed)
        );
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        let Some(EnvelopeMessage::OperationCompleted(completed)) = messages.get(1) else {
            return Err(std::io::Error::other("the report was not an OperationCompleted").into());
        };
        assert!(completed.succeeded);

        // A re-delivered offer is answered with the recorded outcome, and
        // the report never repeats itself.
        let duplicate = engine.handle_offer(&offer, &received).await?;
        assert_eq!(duplicate, OfferOutcome::DuplicateProgress);
        engine.report_center_operations().await?;
        assert_eq!(outbox.pending_messages()?.len(), 3);
        Ok(())
    }

    /// The duplicate-offer progress reply is recorded in the progress map
    /// (audit follow-up W3N-3): a re-delivered offer answers with the
    /// operation's current state, and the next connection's report must not
    /// re-send the same progress — the center just received it.
    #[tokio::test]
    async fn a_duplicate_offer_progress_is_not_replayed_after_a_reconnect()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::Accepted
        );
        // The redelivered offer (the center's TTL retirement) arrives
        // before the state was ever reported: the duplicate answer queues
        // the progress and records it as reported.
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::DuplicateProgress
        );
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        assert!(matches!(
            messages.get(1),
            Some(EnvelopeMessage::OperationProgress(progress))
                if progress.operation_id == offer.operation_id
        ));
        // The reconnect report re-reads the unchanged operation: the
        // recorded state was already reported, so nothing is re-sent.
        engine.report_center_operations().await?;
        assert_eq!(
            outbox.pending_messages()?.len(),
            2,
            "the duplicate-offer progress must not be replayed"
        );
        Ok(())
    }

    /// The TTL retirement race (audit follow-up W3N-2): the center
    /// re-delivers an offer under the same id while the site's reply for
    /// the first delivery is in flight. When the redelivery lands while
    /// the entry is still in the crash-window `Received` phase, the
    /// duplicate answer repairs the entry to the in-flight phase — the
    /// operation exists, so it was accepted — and the final adjudication
    /// stays correct: one execution, the terminal report delivered exactly
    /// once, the entry closed, and every later re-delivery answered from
    /// the recorded outcome.
    #[tokio::test]
    async fn a_redelivered_offer_after_ttl_retirement_adjudicates_the_operation_cleanly()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        let operation_id: OperationId = offer.operation_id.parse()?;
        // The previous run's crash window: the operation was accepted and
        // persisted, but the entry never advanced past `Received` — the
        // redelivery lands with the reply for the first delivery in
        // flight.
        store
            .create_operation(&Operation::new(
                operation_id,
                OperationSource::Center,
                vec![OperationTarget::new(TargetId::generate(), endpoint.id())],
                RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
                now,
            ))
            .await
            .map_err(std::io::Error::other)?;
        CenterInbox::insert(
            &inbox,
            &InboxEntry::new(
                InboxEntryId::generate(),
                operation_id,
                instance_id,
                serde_json::to_string(&received).map_err(std::io::Error::other)?,
                now + time::Duration::seconds(3600),
                now,
            ),
        )
        .await
        .map_err(std::io::Error::other)?;

        // The redelivered offer is answered with the recorded state, and
        // the crash-window entry repairs to the in-flight phase: the
        // site's tracking reflects that the operation was accepted.
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::DuplicateProgress
        );
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Accepted),
            "the duplicate answer must repair the crash-window entry phase"
        );
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.first(),
            Some(EnvelopeMessage::OperationProgress(progress))
                if progress.operation_id == offer.operation_id
        ));

        // The operation completes locally; the report delivers the
        // terminal outcome exactly once and closes the entry — no
        // transition conflict, the adjudication is final.
        store
            .apply_transition(
                operation_id,
                OperationState::Succeeded,
                now + time::Duration::SECOND,
            )
            .await
            .map_err(std::io::Error::other)?;
        engine.report_center_operations().await?;
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Completed)
        );
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        assert!(matches!(
            messages.get(1),
            Some(EnvelopeMessage::OperationCompleted(completed))
                if completed.succeeded && completed.operation_id == offer.operation_id
        ));

        // A further re-delivery is answered from the recorded outcome and
        // nothing executes a second time.
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::DuplicateProgress
        );
        assert_eq!(store.operations_owned()?.len(), 1);
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 3);
        assert!(matches!(
            messages.get(2),
            Some(EnvelopeMessage::OperationCompleted(completed))
                if completed.succeeded && completed.operation_id == offer.operation_id
        ));
        Ok(())
    }

    #[tokio::test]
    async fn result_reporting_reports_active_operations_as_progress()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::Accepted
        );

        // The still-queued operation reports progress, never completion.
        engine.report_center_operations().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        let Some(EnvelopeMessage::OperationProgress(progress)) = messages.get(1) else {
            return Err(std::io::Error::other("the report was not an OperationProgress").into());
        };
        assert_eq!(progress.state, OperationState::Queued.as_str());
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_projections_are_reported_once_per_generation()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        // First report: the snapshot plus one delta per resource.
        engine.report_endpoint_projection().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 3);
        let Some(EnvelopeMessage::EndpointSnapshot(snapshot)) = messages.first() else {
            return Err(std::io::Error::other("the first message was not a snapshot").into());
        };
        assert_eq!(snapshot.endpoint_id, endpoint.id().to_string());
        assert_eq!(snapshot.refresh_generation, 1);
        assert_eq!(snapshot.resources.len(), 2);
        assert_eq!(snapshot.health, "ok");
        assert!(matches!(
            messages.get(1),
            Some(EnvelopeMessage::ResourceDelta(delta)) if delta.op == ResourceDeltaOp::Upsert as i32
        ));
        // The cursor advanced to the reported generation.
        let value = cursor
            .cursor_value(instance_id, SyncStream::Endpoint)?
            .ok_or_else(|| std::io::Error::other("the endpoint cursor is missing"))?;
        assert_eq!(value, format!("{}:1", endpoint.id()));

        // A second report with an unchanged generation reports nothing.
        engine.report_endpoint_projection().await?;
        assert_eq!(outbox.pending_messages()?.len(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn event_batches_advance_the_cursor_without_skipping()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        // Two events observed at different instants.
        let first = Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse("ResourceEvent.1.0.ResourceUpdated")?,
            EventSeverity::Warning,
            Some(String::from("rebooted")),
            now,
            now,
        )?;
        let second = Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse("ResourceEvent.1.0.ResourceUpdated")?,
            EventSeverity::Critical,
            Some(String::from("thermal trip")),
            now + time::Duration::MINUTE,
            now + time::Duration::MINUTE,
        )?;
        let events = MockEventTail::new(vec![first.clone(), second.clone()]);
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        // First sync: the newest tail, and the cursor lands on its newest.
        engine.report_event_batch().await?;
        let messages = outbox.pending_messages()?;
        let Some(EnvelopeMessage::EventBatch(batch)) = messages.first() else {
            return Err(std::io::Error::other("the report was not an EventBatch").into());
        };
        assert_eq!(batch.events.len(), 2);
        let event_cursor = cursor
            .cursor_value(instance_id, SyncStream::Event)?
            .ok_or_else(|| std::io::Error::other("the event cursor is missing"))?;
        assert_eq!(event_cursor, second.id().to_string());

        // The resume after the cursor reports nothing new.
        engine.report_event_batch().await?;
        assert_eq!(outbox.pending_messages()?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn ready_artifacts_are_distributed_as_manifest_and_chunks()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        // W11-D-3: the digest check verifies the streamed bytes against
        // the declared digest, so the stored bytes must hash to it.
        let artifact_bytes = vec![0x01, 0x02, 0x03];
        let digest = rutilus_domain::Sha256Hex::from_bytes(Sha256::digest(&artifact_bytes).into());
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            digest,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        store.set_artifact(&artifact, artifact_bytes)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());

        // The chunk size is set to one byte so the three-byte artifact
        // produces exactly three chunk frames after the manifest.
        let mut options = engine_options();
        options.artifact_chunk_bytes = 1;
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            options,
        );
        engine.report_artifacts().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 4);
        let Some(EnvelopeMessage::ArtifactManifest(manifest)) = messages.first() else {
            return Err(std::io::Error::other("the first message was not a manifest").into());
        };
        assert_eq!(manifest.total_bytes, 3);
        assert_eq!(manifest.sha256.len(), 32);
        for (index, message) in messages.iter().enumerate().skip(1) {
            let EnvelopeMessage::ArtifactChunk(chunk) = message else {
                return Err(std::io::Error::other("the chunk frame was missing").into());
            };
            assert_eq!(chunk.index as usize, index - 1);
            assert_eq!(
                chunk.data,
                vec![u8::try_from(index).map_err(|_| std::io::Error::other("chunk index"))?]
            );
        }
        // The cursor advanced to the distributed artifact.
        let artifact_cursor = cursor
            .cursor_value(instance_id, SyncStream::Artifact)?
            .ok_or_else(|| std::io::Error::other("the artifact cursor is missing"))?;
        assert_eq!(artifact_cursor, artifact.id().to_string());

        // A second report distributes nothing.
        engine.report_artifacts().await?;
        assert_eq!(outbox.pending_messages()?.len(), 4);
        Ok(())
    }

    #[tokio::test]
    async fn a_ready_artifact_without_its_file_is_absorbed_without_a_storm()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W9-S-2 / W10-D-1: the §20.2 restore-crash window leaves a
        // `Ready` artifact row without its file on disk. The distribution
        // classifies the missing file explicitly (instead of a generic read
        // error) so the log names the repair path, and the failure is
        // absorbed by the report: propagating it would take the whole
        // connection down and fail at the same artifact on every reconnect
        // forever (the W10-D-1 storm). The artifact stream stops before the
        // artifact and the cursor does not advance — skipping it would
        // leave the center without the artifact permanently while the row
        // stays `Ready`.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            rutilus_domain::Sha256Hex::parse(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )?,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        // The row exists but its file does not: remove the materialized
        // file right after `set_artifact` to simulate the restore-crash
        // window.
        store.set_artifact(&artifact, vec![0x01, 0x02, 0x03])?;
        std::fs::remove_file(store.artifact_file_path(artifact.id()))?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            engine_options(),
        );
        // The report absorbs the failure: it returns cleanly, so the flush
        // and the receive loop of the connection still run — the offer
        // channel stays alive.
        engine.report_artifacts().await?;
        // Nothing was enqueued for the missing artifact (the manifest
        // enters the outbox only after the first chunk was read), the
        // cursor did not advance, and the row kept its honest `Ready`
        // state — the artifact is visible in the inventory.
        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "a missing file must abort the distribution before the manifest enters the outbox"
        );
        assert!(
            cursor
                .cursor_value(instance_id, SyncStream::Artifact)?
                .is_none(),
            "the cursor must not advance past the missing artifact"
        );
        assert_eq!(
            store.artifact_state(artifact.id())?,
            Some(ArtifactState::Ready),
            "the row must stay Ready: the artifact is not abandoned, it is retried"
        );
        // A second report behaves identically: no error, no growth — the
        // per-cycle retry is cheap and bounded, not a storm.
        engine.report_artifacts().await?;
        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "the retried report must not accumulate anything"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_empty_artifact_file_is_absorbed_and_never_silently_skipped()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W10-D-2: an empty artifact file must not silently "distribute"
        // nothing and advance the cursor — the pre-fix reader treated EOF
        // as success, so the artifact was lost forever with no log line.
        // The byte-count check classifies it as a size mismatch, the report
        // absorbs it, and the cursor stays put.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            rutilus_domain::Sha256Hex::parse(
                "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )?,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        store.set_artifact(&artifact, Vec::new())?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            engine_options(),
        );

        engine.report_artifacts().await?;

        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "an empty file must enqueue nothing"
        );
        assert!(
            cursor
                .cursor_value(instance_id, SyncStream::Artifact)?
                .is_none(),
            "the cursor must not advance past the empty artifact"
        );
        assert_eq!(
            store.artifact_state(artifact.id())?,
            Some(ArtifactState::Ready),
            "the row must stay Ready so the next round retries it"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_truncated_artifact_file_leaves_no_half_set_and_heals()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W10-D-2 / W10-E-2: a file shorter than the declared size is
        // classified as a size mismatch. The manifest and the chunks read
        // before EOF were already enqueued; they must be retired again, or
        // the flush would deliver a partial artifact and every round would
        // pile up another half-set. The cursor stays put, and once the file
        // holds its declared bytes again the next round distributes the
        // artifact and advances the cursor.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        // The digest must match the healed bytes the repair writes back
        // (W11-D-3): the truncated interim state never reaches the digest
        // check, but the healed file does.
        let healed_bytes = vec![0x01, 0x02, 0x03];
        let digest = rutilus_domain::Sha256Hex::from_bytes(Sha256::digest(&healed_bytes).into());
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            digest,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        // Two bytes for a declared three, with one-byte chunks: the reader
        // streams both chunks, then EOF reveals the shortfall.
        store.set_artifact(&artifact, vec![0x01, 0x02])?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let mut options = engine_options();
        options.artifact_chunk_bytes = 1;
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            options,
        );

        engine.report_artifacts().await?;
        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "the enqueued half-set must be retired: no manifest and no partial chunk may linger"
        );
        assert!(
            cursor
                .cursor_value(instance_id, SyncStream::Artifact)?
                .is_none(),
            "the cursor must not advance past the truncated artifact"
        );

        // The repair path heals automatically: the operator re-restores the
        // file, and the next round distributes it and advances the cursor.
        std::fs::write(store.artifact_file_path(artifact.id()), &healed_bytes)?;
        engine.report_artifacts().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(
            messages.len(),
            4,
            "the healed artifact distributes its manifest and three chunks"
        );
        let healed = cursor
            .cursor_value(instance_id, SyncStream::Artifact)?
            .ok_or_else(|| std::io::Error::other("the artifact cursor is missing"))?;
        assert_eq!(healed, artifact.id().to_string());
        Ok(())
    }

    #[tokio::test]
    async fn a_stale_half_set_of_a_failed_artifact_is_retired_from_the_outbox()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W10-E-2: a half-set a previous cycle left behind (the pre-fix
        // flush never ran after a failed distribution) must be retired when
        // the artifact fails again — the queue converges back to nothing
        // instead of accumulating one set per cycle.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            rutilus_domain::Sha256Hex::parse(
                "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            )?,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        store.set_artifact(&artifact, vec![0x01, 0x02])?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let mut options = engine_options();
        options.artifact_chunk_bytes = 1;
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            options,
        );
        // Seed the stale set the pre-fix behavior left pending: one manifest
        // and one chunk of the artifact, never sent, never acknowledged.
        engine
            .enqueue_outbox_entry(EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                artifact_id: artifact.id().to_string(),
                name: artifact.name().as_str().to_owned(),
                total_bytes: artifact.size_bytes(),
                sha256: artifact.sha256().into_bytes().to_vec(),
            }))
            .await?;
        engine
            .enqueue_outbox_entry(EnvelopeMessage::ArtifactChunk(ArtifactChunk {
                artifact_id: artifact.id().to_string(),
                index: 0,
                data: vec![0x01],
            }))
            .await?;

        engine.report_artifacts().await?;

        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "the stale half-set and the fresh one must both be retired"
        );
        assert!(
            cursor
                .cursor_value(instance_id, SyncStream::Artifact)?
                .is_none(),
            "the cursor must not advance past the truncated artifact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_retire_escalates_into_the_round_error()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W11-C-2: a failed retire is never swallowed — the pre-clean
        // retire runs before the fresh distribution, and its acknowledge
        // failure must end the round so the residual half-set never rides
        // the flush on this connection.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        // The stored bytes hash to the declared digest even though the
        // armed retire fails before the digest check runs — the invariant
        // holds regardless of the failure order.
        let artifact_bytes = vec![0x01, 0x02, 0x03];
        let digest = rutilus_domain::Sha256Hex::from_bytes(Sha256::digest(&artifact_bytes).into());
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            digest,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        store.set_artifact(&artifact, artifact_bytes)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let mut options = engine_options();
        options.artifact_chunk_bytes = 1;
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            options,
        );
        // A residual half-set of the artifact, the shape the pre-clean
        // retire would acknowledge; the armed outbox turns that retire
        // into the escalated failure under test.
        engine
            .enqueue_outbox_entry(EnvelopeMessage::ArtifactManifest(ArtifactManifest {
                artifact_id: artifact.id().to_string(),
                name: artifact.name().as_str().to_owned(),
                total_bytes: artifact.size_bytes(),
                sha256: artifact.sha256().into_bytes().to_vec(),
            }))
            .await?;
        outbox.set_fail_acknowledge(true);

        match engine.report_artifacts().await {
            Err(CenterSyncError::Outbox(_)) => {}
            other => {
                return Err(std::io::Error::other(format!(
                    "the failed retire must escalate the round error, got: {other:?}"
                ))
                .into());
            }
        }
        assert_eq!(
            outbox.pending_messages()?.len(),
            1,
            "the half-set must survive the failed retire, not be dropped or acknowledged"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_directory_blocking_the_artifact_path_is_absorbed_without_a_storm()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W11-F-1: a directory placeholder on the artifact path is a
        // persistent condition — opening it fails with `PermissionDenied`
        // (Windows) or `IsADirectory` (Unix), and only an operator fixing
        // the file system heals it. The pre-fix code classified it as a
        // generic read error and propagated it: the round aborted, the
        // reconnect failed at the same artifact, and the 120-second storm
        // ran until an operator intervened (the W10-D-1 pathology for a
        // shape that cannot clear on its own). Both kinds are now absorbed
        // like the missing-file shape: the report returns cleanly, nothing
        // is enqueued, the cursor stays put, and the row stays `Ready`.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            rutilus_domain::Sha256Hex::parse(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            )?,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        store.set_artifact(&artifact, vec![0x01, 0x02, 0x03])?;
        // A directory now blocks the artifact path: opening it fails with
        // `PermissionDenied` or `IsADirectory`, never `NotFound`.
        std::fs::remove_file(store.artifact_file_path(artifact.id()))?;
        std::fs::create_dir(store.artifact_file_path(artifact.id()))?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            engine_options(),
        );

        // The report absorbs the failure: it returns cleanly, so the flush
        // and the receive loop of the connection still run.
        let outcome = match engine.report_artifacts().await {
            Ok(outcome) => outcome,
            Err(e) => {
                return Err(std::io::Error::other(format!(
                    "the directory placeholder must be absorbed, got: {e}"
                ))
                .into());
            }
        };
        assert_eq!(
            outcome,
            ArtifactStreamOutcome::Stalled {
                artifact_id: artifact.id()
            },
            "the absorbed failure must arm the stall timer"
        );
        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "the failed distribution must not leave a half-set behind"
        );
        assert!(
            cursor
                .cursor_value(instance_id, SyncStream::Artifact)?
                .is_none(),
            "the cursor must not advance past the failed artifact"
        );
        assert_eq!(
            store.artifact_state(artifact.id())?,
            Some(ArtifactState::Ready),
            "the row must stay Ready: the condition is retried, not abandoned"
        );
        // A second report behaves identically: no error, no growth — the
        // per-cycle retry is cheap and bounded, not a storm.
        let again = engine.report_artifacts().await;
        assert!(
            again.is_ok(),
            "the retried report must absorb the same condition, got: {again:?}"
        );
        assert_eq!(outbox.pending_messages()?.len(), 0);
        Ok(())
    }

    /// The classification seam under test: one read error mapped through the
    /// engine's concrete error type and reduced to its absorbed-family shape.
    fn classify_read_error_shape(
        source: std::io::Error,
    ) -> Result<&'static str, Box<dyn Error + Send + Sync>> {
        let artifact_id = rutilus_domain::ArtifactId::generate();
        Ok(
            match CenterSync::<
                ChannelTransport,
                MockEngineStore,
                MockOutbox,
                MockInbox,
                MockCursor,
                MockEventTail,
                FixedClock,
            >::classify_artifact_read_error(artifact_id, source)
            {
                CenterSyncError::ArtifactFileMissing { .. } => "missing",
                CenterSyncError::ArtifactFileUnreadable { .. } => "unreadable",
                CenterSyncError::ArtifactRead { .. } => "read",
                other => {
                    return Err(std::io::Error::other(format!(
                        "unexpected classification: {other:?}"
                    ))
                    .into());
                }
            },
        )
    }

    #[tokio::test]
    async fn the_read_error_classification_separates_persistent_and_transient_kinds()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W11-F-1: the classification is the contract's seam — the
        // persistent kinds (missing, permission-denied, directory) map to
        // the absorbed family, and the genuinely transient kinds keep
        // propagating as `ArtifactRead` so the reconnect retry can clear
        // them (EMFILE/ENFILE, interruption, would-block). The direct test
        // pins the seam without needing the platform to produce each kind.
        assert_eq!(
            classify_read_error_shape(std::io::Error::from(std::io::ErrorKind::NotFound))?,
            "missing",
            "a missing file must classify as the missing-file shape"
        );
        assert_eq!(
            classify_read_error_shape(std::io::Error::from(std::io::ErrorKind::PermissionDenied))?,
            "unreadable",
            "a permission denial must classify as the unreadable shape"
        );
        assert_eq!(
            classify_read_error_shape(std::io::Error::from(std::io::ErrorKind::IsADirectory))?,
            "unreadable",
            "a directory path must classify as the unreadable shape"
        );
        for transient in [
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::WouldBlock,
            std::io::ErrorKind::Other,
        ] {
            assert_eq!(
                classify_read_error_shape(std::io::Error::from(transient))?,
                "read",
                "a transient kind ({transient:?}) must keep propagating as ArtifactRead"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn later_ready_artifacts_wait_for_the_broken_artifact()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        // W10-D-1: a persistent failure stops the artifact stream at the
        // broken artifact — a later ready artifact is not distributed past
        // it, because advancing the cursor over it would skip the broken
        // one forever (W9-S-2). Once the broken artifact heals, both
        // distribute in declaration order and the cursor lands on the
        // newest.
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        // W11-D-3: both artifacts' digests must match their stored bytes —
        // the healed `broken` distribution reaches the digest check.
        let broken_bytes = vec![0x01, 0x02, 0x03];
        let later_bytes = vec![0x03, 0x02, 0x01];
        let mut broken = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("broken")?,
            3,
            rutilus_domain::Sha256Hex::from_bytes(Sha256::digest(&broken_bytes).into()),
            now,
        );
        broken.record_bytes_received(3)?;
        broken.mark_ready()?;
        store.set_artifact(&broken, broken_bytes)?;
        std::fs::remove_file(store.artifact_file_path(broken.id()))?;
        let mut later = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("later")?,
            3,
            rutilus_domain::Sha256Hex::from_bytes(Sha256::digest(&later_bytes).into()),
            now + time::Duration::SECOND,
        );
        later.record_bytes_received(3)?;
        later.mark_ready()?;
        store.set_artifact(&later, later_bytes)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = CenterSync::new(
            &ChannelTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            engine_options(),
        );

        engine.report_artifacts().await?;
        assert_eq!(
            outbox.pending_messages()?.len(),
            0,
            "the later artifact must wait: distributing it would advance the cursor over the broken one"
        );
        assert!(
            cursor
                .cursor_value(instance_id, SyncStream::Artifact)?
                .is_none(),
            "the cursor must not advance past the broken artifact"
        );

        // Heal the broken artifact: both distribute now, and the cursor
        // lands on the later one.
        std::fs::write(store.artifact_file_path(broken.id()), [0x01, 0x02, 0x03])?;
        engine.report_artifacts().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(
            messages.len(),
            4,
            "both artifacts distribute: one manifest and one chunk each"
        );
        let healed = cursor
            .cursor_value(instance_id, SyncStream::Artifact)?
            .ok_or_else(|| std::io::Error::other("the artifact cursor is missing"))?;
        assert_eq!(healed, later.id().to_string());
        Ok(())
    }

    // The heal scenario is one contiguous script — absorb, phase-1
    // heartbeats, restore, phase-2 reconnect; splitting it would break
    // the single-scenario assertion continuity.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn an_absorbed_artifact_stall_reconnects_and_heals_after_the_file_restore()
    -> Result<(), Box<dyn Error>> {
        // W11-P-1, the full healing sequence end to end: a ready artifact's
        // file is missing. The pre-fix round aborted with the classified
        // error and stormed on every reconnect; the W10-D-1 fix absorbed
        // the failure, but the report only runs once per connection — the
        // absorption kept the connection alive, and with the heartbeat
        // outliving every idle timeout the retry never arrived on a stable
        // network. Now the absorption arms the stall timer: the connection
        // stays up (heartbeats flow, the flush and the receive loop keep
        // running) for one reconnect period, then ends itself; the connect
        // loop's backoff schedules the next attempt, and the reconnect
        // re-runs the report. The operator restores the file before the
        // stall fires, so the reconnect distributes the artifact and
        // advances the cursor — the healing sequence, no manual second
        // call.
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        // The restore signal: the test tells the run task to materialize
        // the artifact file again while the engine is stalled on it.
        let (restore_tx, restore_rx) = tokio::sync::oneshot::channel::<()>();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let mut artifact = rutilus_domain::Artifact::new(
                rutilus_domain::ArtifactId::generate(),
                rutilus_domain::ArtifactName::parse("backup")?,
                3,
                rutilus_domain::Sha256Hex::parse(
                    "039058c6f2c0cb492c533b0a4d14ef77cc0f78abccced5287d84a1a2011cfb81",
                )?,
                now,
            );
            artifact.record_bytes_received(3)?;
            artifact.mark_ready()?;
            store.set_artifact(&artifact, vec![0x01, 0x02, 0x03])?;
            std::fs::remove_file(store.artifact_file_path(artifact.id()))?;
            // The operator's restore: a helper task that writes the file
            // back when the test signals it.
            let artifact_path = store.artifact_file_path(artifact.id());
            let restore = tokio::spawn(async move {
                let _ = restore_rx.await;
                std::fs::write(&artifact_path, [0x01, 0x02, 0x03])?;
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let mut options = engine_options();
            // One reconnect period of 120 ms: the stall timer and the
            // backoff both use it, so the reconnect lands around 240 ms
            // after the absorption — the margins keep the phase-1 and
            // phase-2 assertions deterministic.
            options.reconnect_after = Duration::from_millis(120);
            options.artifact_chunk_bytes = 1;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                options,
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            restore.abort();
            cursor.cursor_value(instance_id, SyncStream::Artifact)
        });

        // Phase 1: the absorbed failure left the connection alive — the
        // heartbeats keep flowing on the first wire.
        let mut wire = next_wire(&mut wires).await?;
        let mut heartbeats_seen = 0;
        while heartbeats_seen < 2 {
            let envelope = next_frame(&mut wire).await?;
            assert_eq!(
                envelope.sequence, 0,
                "the broken artifact must not enqueue anything to flush"
            );
            if matches!(envelope.message, Some(EnvelopeMessage::Heartbeat(_))) {
                heartbeats_seen += 1;
            }
        }
        // The operator restores the file before the stall fires.
        restore_tx
            .send(())
            .map_err(|()| std::io::Error::other("the restore signal failed"))?;
        // No early reconnect: the stall period has not elapsed yet.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            wires.try_recv().is_err(),
            "the connection must stay up for the stall period, not reconnect immediately"
        );
        // Phase 2: the stall timer fires, the backoff elapses, and the
        // reconnect re-runs the report — the restored file distributes.
        let mut healed = next_wire(&mut wires).await?;
        let manifest = next_outbox_frame(&mut healed).await?;
        let Some(EnvelopeMessage::ArtifactManifest(manifest)) = manifest.message else {
            return Err(std::io::Error::other("the healed wire must open with a manifest").into());
        };
        assert_eq!(manifest.total_bytes, 3);
        for _ in 0..3 {
            let envelope = next_outbox_frame(&mut healed).await?;
            let Some(EnvelopeMessage::ArtifactChunk(_)) = envelope.message else {
                return Err(std::io::Error::other("the healed wire must carry the chunks").into());
            };
        }
        // The healed report advanced the artifact cursor.
        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let cursor_value = match tokio::time::timeout(Duration::from_secs(5), run).await {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => {
                return Err(std::io::Error::other(format!(
                    "the engine failed after the stall stop: {e}"
                ))
                .into());
            }
            Ok(Err(join_err)) => {
                return Err(std::io::Error::other(format!(
                    "the engine task joined with an error: {join_err}"
                ))
                .into());
            }
            Err(_) => {
                return Err(std::io::Error::other("the engine did not stop in time").into());
            }
        };
        assert_eq!(
            cursor_value.as_deref(),
            Some(manifest.artifact_id.as_str()),
            "the healed report must advance the artifact cursor"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_partial_batch_flushes_again_after_each_acknowledgement() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // Five entries, a flush limit of two: the first connection sends
            // one batch of two, and every acknowledgement frees the next.
            outbox.enqueue_heartbeats(5, now)?;
            let mut options = engine_options();
            options.flush_limit = 2;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                options,
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // Without an acknowledgement the flush holds: the next frames can
        // only be heartbeats.
        for _ in 0..3 {
            let envelope = next_frame(&mut wire).await?;
            assert_eq!(
                envelope.sequence, 0,
                "the flush must wait for an acknowledgement"
            );
        }
        // One acknowledgement frees exactly the next batch.
        wire.inbound
            .send(Envelope {
                sequence: 20,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 2 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        for sequence in [3, 4] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // Acknowledging the last sent sequence frees the final entry.
        wire.inbound
            .send(Envelope {
                sequence: 21,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 4 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut wire).await?;
        assert_eq!(envelope.sequence, 5);
        // Acknowledging the tail drains the queue: no further outbox frames.
        wire.inbound
            .send(Envelope {
                sequence: 22,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 5 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_offer_reply_is_flushed_without_waiting_for_an_acknowledgement()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        // The `?` operator cannot widen the mock helper's
        // `Box<dyn Error + Send + Sync>` into the test's `Box<dyn Error>`,
        // so the two `Send + Sync`-typed sites convert explicitly.
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let instance_id = InstanceId::generate();
        let endpoint_id = endpoint.id();
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let outbox = MockOutbox::new(instance_id);
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        // The connect reports the prepared projection first: one snapshot and
        // two upserts (§21 0.7.0 incremental sync).
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        // The center sends one operation offer and never acknowledges
        // anything. The §15.6 reply must still reach it: the engine flushes
        // immediately after handling the offer, and the flush never re-sends
        // the already-delivered burst.
        let (offer, received) = offer_for(instance_id, endpoint_id, now.unix_timestamp() + 3600)
            .map_err(std::io::Error::other)?;
        wire.inbound
            .send(received.clone())
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut wire).await?;
        assert_eq!(
            envelope.sequence, 4,
            "the reply must be the next frame, not a re-send of the burst"
        );
        let Some(EnvelopeMessage::OperationAccepted(accepted)) = envelope.message else {
            return Err(std::io::Error::other("the reply was not an OperationAccepted").into());
        };
        assert_eq!(accepted.operation_id, offer.operation_id);

        // A re-delivered offer is answered from the recorded state, and that
        // reply is flushed the same way.
        wire.inbound
            .send(received)
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut wire).await?;
        assert_eq!(envelope.sequence, 5);
        let Some(EnvelopeMessage::OperationProgress(progress)) = envelope.message else {
            return Err(
                std::io::Error::other("the duplicate reply was not an OperationProgress").into(),
            );
        };
        assert_eq!(progress.operation_id, offer.operation_id);
        assert_eq!(progress.state, OperationState::Queued.as_str());

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_endpoint_cursor_resets_and_re_reports()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        // The stored cursor a manual DB change left unparseable.
        cursor
            .set(&SyncCursor::new(
                SyncCursorId::generate(),
                instance_id,
                SyncStream::Endpoint,
                String::from("not-an-endpoint-cursor"),
                now,
            ))
            .await?;
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        // The reset re-reports the whole current projection instead of
        // failing the connection...
        engine.report_endpoint_projection().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 3);
        assert!(matches!(
            messages.first(),
            Some(EnvelopeMessage::EndpointSnapshot(_))
        ));
        // ... and the report healed the cursor row.
        let value = cursor
            .cursor_value(instance_id, SyncStream::Endpoint)?
            .ok_or_else(|| std::io::Error::other("the endpoint cursor is missing"))?;
        assert_eq!(value, format!("{}:1", endpoint.id()));
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_event_cursor_resets_to_the_bounded_tail()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let first = Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse("ResourceEvent.1.0.ResourceUpdated")?,
            EventSeverity::Warning,
            Some(String::from("rebooted")),
            now,
            now,
        )?;
        let second = Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse("ResourceEvent.1.0.ResourceUpdated")?,
            EventSeverity::Critical,
            Some(String::from("thermal trip")),
            now + time::Duration::MINUTE,
            now + time::Duration::MINUTE,
        )?;
        let events = MockEventTail::new(vec![first, second.clone()]);
        cursor
            .set(&SyncCursor::new(
                SyncCursorId::generate(),
                instance_id,
                SyncStream::Event,
                String::from("not-an-event-id"),
                now,
            ))
            .await?;
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        engine.report_event_batch().await?;
        let messages = outbox.pending_messages()?;
        let Some(EnvelopeMessage::EventBatch(batch)) = messages.first() else {
            return Err(std::io::Error::other("the report was not an EventBatch").into());
        };
        assert_eq!(
            batch.events.len(),
            2,
            "the bounded tail must be re-reported"
        );
        let healed = cursor
            .cursor_value(instance_id, SyncStream::Event)?
            .ok_or_else(|| std::io::Error::other("the event cursor is missing"))?;
        assert_eq!(healed, second.id().to_string());
        Ok(())
    }

    #[tokio::test]
    async fn an_evicted_event_anchor_resets_to_the_bounded_tail()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let event = Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse("ResourceEvent.1.0.ResourceUpdated")?,
            EventSeverity::Warning,
            Some(String::from("rebooted")),
            now,
            now,
        )?;
        let events = MockEventTail::new(vec![event.clone()]);
        // The cursor points at an event the bounded history already evicted
        // (§14.4): a valid-format id that is no longer stored.
        cursor
            .set(&SyncCursor::new(
                SyncCursorId::generate(),
                instance_id,
                SyncStream::Event,
                EventId::generate().to_string(),
                now,
            ))
            .await?;
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        engine.report_event_batch().await?;
        let messages = outbox.pending_messages()?;
        let Some(EnvelopeMessage::EventBatch(batch)) = messages.first() else {
            return Err(std::io::Error::other("the report was not an EventBatch").into());
        };
        assert_eq!(
            batch.events.len(),
            1,
            "the bounded tail must be re-reported"
        );
        let healed = cursor
            .cursor_value(instance_id, SyncStream::Event)?
            .ok_or_else(|| std::io::Error::other("the event cursor is missing"))?;
        assert_eq!(healed, event.id().to_string());
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_artifact_cursor_resets_and_redistributes()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        // W11-D-3: the redistributed bytes must hash to the declared digest.
        let artifact_bytes = vec![0x01, 0x02, 0x03];
        let digest = rutilus_domain::Sha256Hex::from_bytes(Sha256::digest(&artifact_bytes).into());
        let mut artifact = rutilus_domain::Artifact::new(
            rutilus_domain::ArtifactId::generate(),
            rutilus_domain::ArtifactName::parse("backup")?,
            3,
            digest,
            now,
        );
        artifact.record_bytes_received(3)?;
        artifact.mark_ready()?;
        store.set_artifact(&artifact, artifact_bytes)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        cursor
            .set(&SyncCursor::new(
                SyncCursorId::generate(),
                instance_id,
                SyncStream::Artifact,
                String::from("not-an-artifact-id"),
                now,
            ))
            .await?;
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        engine.report_artifacts().await?;
        // The default chunk size carries the three bytes in one chunk: the
        // manifest plus the chunk are re-distributed after the reset.
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        assert!(matches!(
            messages.first(),
            Some(EnvelopeMessage::ArtifactManifest(_))
        ));
        let healed = cursor
            .cursor_value(instance_id, SyncStream::Artifact)?
            .ok_or_else(|| std::io::Error::other("the artifact cursor is missing"))?;
        assert_eq!(healed, artifact.id().to_string());
        Ok(())
    }

    #[tokio::test]
    async fn a_corrupt_outbox_row_is_skipped_and_the_rest_still_flushes()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // The queue holds one corrupt row between two valid rows: the
            // flush must skip it, deliver the rest, and stay connected.
            outbox.enqueue_heartbeats(1, now)?;
            outbox.enqueue_corrupt_payload(now)?;
            outbox.enqueue_heartbeats(1, now)?;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // The connection survived the corrupt row: the engine never
        // reconnected (a wedge would have restarted after the backoff).
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(state.attempts(), 1);

        // The loop is still responsive: the center can acknowledge the
        // delivered frames, and the engine keeps answering the stop signal.
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 3 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_deleted_endpoint_is_reported_as_an_endpoint_level_delete_delta()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);

        // First report: the snapshot plus one upsert per resource.
        engine.report_endpoint_projection().await?;
        assert_eq!(outbox.pending_messages()?.len(), 3);

        // The endpoint disappears from the inventory.
        store
            .inventory
            .lock()
            .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
            .clear();

        // The next report emits one endpoint-level delete delta and forgets
        // the endpoint in the watermark.
        engine.report_endpoint_projection().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 4);
        let Some(EnvelopeMessage::ResourceDelta(delta)) = messages.last() else {
            return Err(std::io::Error::other("the delete was not a ResourceDelta").into());
        };
        assert_eq!(delta.endpoint_id, endpoint.id().to_string());
        assert_eq!(delta.op, ResourceDeltaOp::Delete as i32);
        assert_eq!(delta.resource, None);
        assert!(delta.payload_json.is_empty());
        let value = cursor
            .cursor_value(instance_id, SyncStream::Endpoint)?
            .ok_or_else(|| std::io::Error::other("the endpoint cursor is missing"))?;
        assert_eq!(value, "", "the watermark must forget the deleted endpoint");

        // A third report stays quiet: the deletion was already reported.
        engine.report_endpoint_projection().await?;
        assert_eq!(outbox.pending_messages()?.len(), 4);
        Ok(())
    }

    #[tokio::test]
    async fn a_deleted_endpoint_reaches_the_center_as_a_delete_delta() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let endpoint_id = EndpointId::generate();
        let instance_id = InstanceId::generate();
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            // The watermark remembers the endpoint from before its deletion;
            // the inventory no longer has it.
            cursor
                .set(&SyncCursor::new(
                    SyncCursorId::generate(),
                    instance_id,
                    SyncStream::Endpoint,
                    format!("{endpoint_id}:1"),
                    now,
                ))
                .await?;
            let outbox = MockOutbox::new(instance_id);
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        let envelope = next_outbox_frame(&mut wire).await?;
        assert_eq!(envelope.sequence, 1);
        let Some(EnvelopeMessage::ResourceDelta(delta)) = envelope.message else {
            return Err(std::io::Error::other("the delete was not a ResourceDelta").into());
        };
        assert_eq!(delta.endpoint_id, endpoint_id.to_string());
        assert_eq!(delta.op, ResourceDeltaOp::Delete as i32);
        assert_eq!(delta.resource, None);
        assert!(delta.payload_json.is_empty());

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    /// The §0.9.0 reconnect storm: several independent site loops — each
    /// with its own per-instance durable outbox — lose their connections at
    /// the same instant and reconnect concurrently. Every flush resumes from
    /// that instance's last acknowledged sequence: nothing lost, nothing
    /// already acknowledged re-sent (§15.4 at-least-once delivery).
    #[tokio::test]
    async fn a_concurrent_reconnect_storm_resumes_every_outbox_from_its_last_ack()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        // Four concurrent site loops share one center-side storm; each
        // acknowledges a different prefix of its five-message queue so every
        // resume point is distinct — the acknowledgement watermark is per
        // instance.
        let acked_by = [1u64, 3, 2, 4];
        let mut runs = JoinSet::new();
        let mut stops = Vec::new();
        let mut states = Vec::new();
        let mut wires = Vec::new();
        for _ in acked_by {
            let (transport, state, receiver) = ScriptedTransport::new(0);
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
            let instance_id = InstanceId::generate();
            runs.spawn(async move {
                let store = MockEngineStore::new();
                let inbox = MockInbox::new();
                let cursor = MockCursor::new();
                let events = MockEventTail::new(Vec::new());
                let outbox = MockOutbox::new(instance_id);
                // The offline queue: five messages queued before the first
                // connection, the same shape the flush tests assert on the
                // wire.
                outbox.enqueue_heartbeats(5, now)?;
                let engine = CenterSync::new(
                    transport,
                    &store,
                    outbox,
                    &inbox,
                    &cursor,
                    &events,
                    FixedClock(now),
                    instance_id,
                    engine_options(),
                );
                engine
                    .run(async move {
                        let _ = stop_rx.await;
                    })
                    .await?;
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
            stops.push(stop_tx);
            states.push(state);
            wires.push(receiver);
        }

        // Every loop established its first connection and delivered the
        // whole queue in sequence order.
        let mut connected = Vec::new();
        for receiver in &mut wires {
            let mut wire = next_wire(receiver).await?;
            for sequence in 1..=5 {
                let envelope = next_outbox_frame(&mut wire).await?;
                assert_eq!(envelope.sequence, sequence);
            }
            connected.push(wire);
        }
        // Each loop acknowledges its own prefix, then every connection drops
        // at the same instant — one synchronous step, so no loop can make
        // progress past its drop point before the storm is complete.
        for (wire, acked) in connected.iter_mut().zip(acked_by) {
            wire.inbound
                .send(Envelope {
                    sequence: 10,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::Ack(Ack { sequence: acked })),
                })
                .map_err(|_| std::io::Error::other("the center feed closed"))?;
        }
        for wire in connected {
            let Wire { outbound, inbound } = wire;
            drop(outbound);
            drop(inbound);
        }

        // All loops reconnect concurrently (each waits out the same backoff);
        // every flush resumes exactly after its own last acknowledgement —
        // the acked prefix is never re-sent and the rest is never lost.
        for (receiver, acked) in wires.iter_mut().zip(acked_by) {
            let mut wire = next_wire(receiver).await?;
            for sequence in acked + 1..=5 {
                let envelope = next_outbox_frame(&mut wire).await?;
                assert_eq!(envelope.sequence, sequence);
            }
        }
        for (state, acked) in states.iter().zip(acked_by) {
            assert_eq!(
                state.attempts(),
                2,
                "loop {acked}: the storm must reconnect exactly once"
            );
        }

        for stop_tx in stops {
            let _ = stop_tx.send(());
        }
        while let Some(join) = tokio::time::timeout(Duration::from_secs(5), runs.join_next())
            .await
            .map_err(|_| std::io::Error::other("the engines did not stop in time"))?
        {
            join?.map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        Ok(())
    }

    /// The duplicate burst arriving at the reconnect instant: the center
    /// re-delivers outbox messages (the at-least-once re-send of the pending
    /// rows), repeats acknowledgements of the same sequence, and re-offers
    /// an operation whose acceptance is already recorded. Every duplicate
    /// must be a successful no-op and the business effect must happen
    /// exactly once (§15.4, §15.6).
    // The storm test spells out the full concurrent driver script in one
    // place; splitting it would break the single-scenario assertion
    // continuity (the persistence stress tests allow the same lint on
    // their exhaustive storm tests).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn a_reconnect_duplicate_burst_is_idempotent_and_effects_each_operation_once()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let instance_id = InstanceId::generate();
        let endpoint_id = endpoint.id();
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        // The task returns the store and the inbox so the test can assert
        // the recorded state after the storm; the outbox stays observable
        // through its shared entries vector.
        let outbox = MockOutbox::new(instance_id);
        let outbox_entries = Arc::clone(&outbox.entries);
        let run = tokio::spawn(async move {
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((store, inbox))
        });

        let mut wire = next_wire(&mut wires).await?;
        // The first connection delivers the projection: one snapshot and
        // two upserts.
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // The center acknowledges only the first message, then the storm
        // drops the connection.
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 1 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        // The reconnect flushes the pending rows again — the duplicate
        // outbox entries of at-least-once delivery, each sent exactly once
        // on this connection.
        let mut second = next_wire(&mut wires).await?;
        for sequence in [2, 3] {
            let envelope = next_outbox_frame(&mut second).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        // The duplicate burst: an acknowledgement of the already-retired
        // message, an acknowledgement covering the whole re-sent batch, and
        // the same acknowledgement repeated.
        for sequence in [20u64, 21, 22] {
            second
                .inbound
                .send(Envelope {
                    sequence,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::Ack(Ack {
                        sequence: if sequence >= 21 { 3 } else { 1 },
                    })),
                })
                .map_err(|_| std::io::Error::other("the center feed closed"))?;
        }

        // The duplicate offer, re-delivered at the reconnect instant:
        // accepted against the recorded state, never executed a second time.
        let (offer, received) = offer_for(instance_id, endpoint_id, now.unix_timestamp() + 3600)
            .map_err(std::io::Error::other)?;
        second
            .inbound
            .send(received.clone())
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut second).await?;
        assert_eq!(
            envelope.sequence, 4,
            "the reply must be the next frame, not a re-send of the burst"
        );
        let Some(EnvelopeMessage::OperationAccepted(accepted)) = envelope.message else {
            return Err(std::io::Error::other("the reply was not an OperationAccepted").into());
        };
        assert_eq!(accepted.operation_id, offer.operation_id);
        second
            .inbound
            .send(received)
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut second).await?;
        assert_eq!(envelope.sequence, 5);
        let Some(EnvelopeMessage::OperationProgress(progress)) = envelope.message else {
            return Err(
                std::io::Error::other("the duplicate reply was not an OperationProgress").into(),
            );
        };
        assert_eq!(progress.operation_id, offer.operation_id);
        assert_eq!(progress.state, OperationState::Queued.as_str());

        // The burst did not disturb the connection, and the recorded state
        // is exactly one operation: the duplicate offer never executed a
        // second time (§15.4 exactly-once business effect).
        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        // The task handle unwraps in two layers — the timeout's Elapsed and
        // the task's JoinError — before the recorded state.
        let state = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        let (store, inbox) = state.map_err(|error| std::io::Error::other(error.to_string()))?;
        let operations = store.operations_owned().map_err(std::io::Error::other)?;
        assert_eq!(
            operations.len(),
            1,
            "the duplicate offer must not create a second operation"
        );
        assert_eq!(operations[0].id().to_string(), offer.operation_id);
        assert_eq!(operations[0].source(), OperationSource::Center);
        let operation_id: OperationId = offer.operation_id.parse()?;
        assert_eq!(
            inbox
                .entry_state(operation_id)
                .map_err(std::io::Error::other)?,
            Some(InboxEntryState::Accepted)
        );
        // The durable replies: exactly one acceptance and one progress reply.
        // The re-sent projection rows left the queue under the repeated
        // acknowledgements.
        let messages = pending_messages_from(&outbox_entries).map_err(std::io::Error::other)?;
        assert_eq!(messages.len(), 2);
        assert!(matches!(
            messages.first(),
            Some(EnvelopeMessage::OperationAccepted(_))
        ));
        assert!(matches!(
            messages.get(1),
            Some(EnvelopeMessage::OperationProgress(_))
        ));
        Ok(())
    }

    /// The reconnect report pin (audit A2, tightened by P3-10):
    /// `report_center_operations` runs at the start of every established
    /// connection, so a reconnect reports every state change of a
    /// still-active center operation as `OperationProgress` — an unchanged
    /// state is not replayed — while a completed operation is reported
    /// exactly once: its terminal inbox entry makes every later
    /// connection's report skip it (§15.4 at-least-once, §15.6 idempotent
    /// reporting).
    // The reconnect script is one continuous scenario — three connections
    // with the local completion in between — so it stays in one test (the
    // persistence stress tests allow the same lint on their exhaustive
    // storm tests).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn reconnect_resends_progress_for_active_operations_and_skips_completed_ones()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let instance_id = InstanceId::generate();
        let endpoint_id = endpoint.id();
        // The store is shared with the engine so the test can complete one
        // operation while the loop is connected; the outbox entries are
        // shared for the final pending-message assertion, and the task
        // returns the inbox for the recorded-state assertions.
        let store = Arc::new(store);
        let store_for_engine = Arc::clone(&store);
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let outbox = MockOutbox::new(instance_id);
        let outbox_entries = Arc::clone(&outbox.entries);
        let run = tokio::spawn(async move {
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let engine = CenterSync::new(
                transport,
                store_for_engine.as_ref(),
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(inbox)
        });

        // The first connection flushes the endpoint projection; the report
        // ran before any operation existed, so no progress frame is among
        // them.
        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        // Two center operations are offered and accepted; both stay active
        // (`Queued`).
        let (offer_a, received_a) =
            offer_for(instance_id, endpoint_id, now.unix_timestamp() + 3600)
                .map_err(std::io::Error::other)?;
        let (offer_b, received_b) =
            offer_for(instance_id, endpoint_id, now.unix_timestamp() + 3600)
                .map_err(std::io::Error::other)?;
        for received in [&received_a, &received_b] {
            wire.inbound
                .send((*received).clone())
                .map_err(|_| std::io::Error::other("the center feed closed"))?;
            let envelope = next_outbox_frame(&mut wire).await?;
            assert!(matches!(
                envelope.message,
                Some(EnvelopeMessage::OperationAccepted(_))
            ));
        }
        // The whole first connection is acknowledged, so the reconnect
        // flushes nothing but the fresh report rows.
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 5 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;

        // Between the connections, operation B completes locally.
        let operation_b: OperationId = offer_b.operation_id.parse()?;
        store
            .apply_transition(
                operation_b,
                OperationState::Succeeded,
                now + time::Duration::SECOND,
            )
            .await
            .map_err(std::io::Error::other)?;
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        // The reconnect reports both operations: the still-active one as
        // `OperationProgress`, the completed one as its single
        // `OperationCompleted` (the inbox entry closes in the same report).
        let mut second = next_wire(&mut wires).await?;
        let mut progress_for_a = false;
        let mut completed_for_b = false;
        for _ in 0..2 {
            let envelope = next_outbox_frame(&mut second).await?;
            let Some(message) = envelope.message else {
                return Err(
                    std::io::Error::other("the reconnect report carried no message").into(),
                );
            };
            match message {
                EnvelopeMessage::OperationProgress(progress)
                    if progress.operation_id == offer_a.operation_id =>
                {
                    assert_eq!(progress.state, OperationState::Queued.as_str());
                    progress_for_a = true;
                }
                EnvelopeMessage::OperationCompleted(completed)
                    if completed.operation_id == offer_b.operation_id =>
                {
                    assert!(completed.succeeded);
                    completed_for_b = true;
                }
                other => {
                    return Err(std::io::Error::other(format!(
                        "unexpected reconnect frame: {other:?}"
                    ))
                    .into());
                }
            }
        }
        assert!(
            progress_for_a,
            "the reconnect must re-report the active operation as progress"
        );
        assert!(
            completed_for_b,
            "the reconnect must report the completed operation exactly once"
        );
        // The flush delivered exactly the two report frames: the next
        // frame is a heartbeat.
        let envelope = next_frame(&mut second).await?;
        assert_eq!(envelope.sequence, 0);
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::Heartbeat(_))
        ));
        second
            .inbound
            .send(Envelope {
                sequence: 20,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 7 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire {
            outbound: outbound_second,
            inbound: inbound_second,
        } = second;
        drop(outbound_second);
        drop(inbound_second);

        // Between the second and third connections, operation A advances
        // to `Running` locally: the reconnect reports the state change and
        // nothing for the completed one — its terminal inbox entry makes
        // the report skip it, so no duplicate completion can reach the
        // center. An unchanged state is not replayed (audit follow-up
        // P3-10): only the state change queues a fresh progress frame.
        let operation_a: OperationId = offer_a.operation_id.parse()?;
        store
            .apply_transition(
                operation_a,
                OperationState::Running,
                now + time::Duration::seconds(2),
            )
            .await
            .map_err(std::io::Error::other)?;
        let mut third = next_wire(&mut wires).await?;
        let envelope = next_outbox_frame(&mut third).await?;
        let Some(EnvelopeMessage::OperationProgress(progress)) = envelope.message else {
            return Err(
                std::io::Error::other("the re-sent report was not an OperationProgress").into(),
            );
        };
        assert_eq!(progress.operation_id, offer_a.operation_id);
        assert_eq!(progress.state, OperationState::Running.as_str());
        // The flush delivered exactly that one frame: the next frame is a
        // heartbeat, never a duplicate completion.
        let envelope = next_frame(&mut third).await?;
        assert_eq!(envelope.sequence, 0);
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::Heartbeat(_))
        ));

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        let inbox = stopped.map_err(|error| std::io::Error::other(error.to_string()))?;
        // The recorded lifecycle: A stays accepted and active, B closed.
        assert_eq!(
            inbox
                .entry_state(operation_a)
                .map_err(std::io::Error::other)?,
            Some(InboxEntryState::Accepted)
        );
        assert_eq!(
            inbox
                .entry_state(operation_b)
                .map_err(std::io::Error::other)?,
            Some(InboxEntryState::Completed)
        );
        // The durable outbox: exactly one pending progress row for the
        // active operation; B's completion was acknowledged and retired.
        let messages = pending_messages_from(&outbox_entries).map_err(std::io::Error::other)?;
        assert_eq!(messages.len(), 1);
        assert!(matches!(
            messages.first(),
            Some(EnvelopeMessage::OperationProgress(progress))
                if progress.operation_id == offer_a.operation_id
        ));
        Ok(())
    }

    /// The reconnect report does not replay a state the center already
    /// knows (audit follow-up P3-10): an operation whose state did not
    /// change between two connections queues no new `OperationProgress`,
    /// so a reconnect never replays the whole active set.
    #[tokio::test]
    // The no-replay scenario is one continuous three-connection script;
    // splitting it would break the single-scenario assertion continuity
    // (the reconnect tests allow the same lint for the same reason).
    #[allow(clippy::too_many_lines)]
    async fn reconnect_does_not_replay_an_unchanged_operation_state() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let instance_id = InstanceId::generate();
        let endpoint_id = endpoint.id();
        let store = Arc::new(store);
        let store_for_engine = Arc::clone(&store);
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let outbox = MockOutbox::new(instance_id);
        let outbox_entries = Arc::clone(&outbox.entries);
        let run = tokio::spawn(async move {
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let engine = CenterSync::new(
                transport,
                store_for_engine.as_ref(),
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(inbox)
        });

        // The first connection flushes the endpoint projection; the report
        // ran before any operation existed.
        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // One operation is offered and accepted; it stays `Queued`.
        let (offer_a, received_a) =
            offer_for(instance_id, endpoint_id, now.unix_timestamp() + 3600)
                .map_err(std::io::Error::other)?;
        wire.inbound
            .send(received_a)
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut wire).await?;
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::OperationAccepted(_))
        ));
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 4 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        // The reconnect reports the operation's first progress — the
        // accepted-but-never-reported state is new to the center.
        let mut second = next_wire(&mut wires).await?;
        let envelope = next_outbox_frame(&mut second).await?;
        let Some(EnvelopeMessage::OperationProgress(progress)) = envelope.message else {
            return Err(
                std::io::Error::other("the reconnect report was not an OperationProgress").into(),
            );
        };
        assert_eq!(progress.operation_id, offer_a.operation_id);
        assert_eq!(progress.state, OperationState::Queued.as_str());
        second
            .inbound
            .send(Envelope {
                sequence: 20,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 5 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire {
            outbound: outbound_second,
            inbound: inbound_second,
        } = second;
        drop(outbound_second);
        drop(inbound_second);

        // The second reconnect reports nothing for the unchanged
        // operation: the flush delivers no report frame, and the next
        // frame on the wire is the liveness heartbeat.
        let mut third = next_wire(&mut wires).await?;
        let envelope = next_frame(&mut third).await?;
        assert_eq!(envelope.sequence, 0);
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::Heartbeat(_))
        ));

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        let inbox = stopped.map_err(|error| std::io::Error::other(error.to_string()))?;
        let operation_a: OperationId = offer_a.operation_id.parse()?;
        assert_eq!(
            inbox
                .entry_state(operation_a)
                .map_err(std::io::Error::other)?,
            Some(InboxEntryState::Accepted)
        );
        // The durable outbox: the progress row was acknowledged and
        // retired; nothing was re-enqueued for the unchanged state.
        let messages = pending_messages_from(&outbox_entries).map_err(std::io::Error::other)?;
        assert!(
            messages.is_empty(),
            "an unchanged state must not be replayed: {messages:?}"
        );
        Ok(())
    }

    /// The first report of a process run rediscovers every open entry
    /// through the state-indexed discovery scan (audit follow-up P3-10):
    /// an operation a previous process run left completed with an open
    /// inbox entry is reported exactly once, and its entry closes.
    #[tokio::test]
    // The restart script is one continuous scenario — the stranded entry,
    // the discovery report, and the skip on the next connection — so it
    // stays in one test (the same lint allowance as the storm tests).
    #[allow(clippy::too_many_lines)]
    async fn the_first_report_discovers_entries_a_previous_run_left_open()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let instance_id = InstanceId::generate();
        let endpoint_id = endpoint.id();
        // The previous run's debris: a center-sourced operation that
        // completed, whose inbox entry never closed (the crash window).
        let operation_id = OperationId::generate();
        let operation = Operation::new(
            operation_id,
            OperationSource::Center,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            now,
        );
        store
            .create_operation(&operation)
            .await
            .map_err(std::io::Error::other)?;
        store
            .apply_transition(
                operation_id,
                OperationState::Succeeded,
                now + time::Duration::SECOND,
            )
            .await
            .map_err(std::io::Error::other)?;
        let store = Arc::new(store);
        let store_for_engine = Arc::clone(&store);
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let outbox = MockOutbox::new(instance_id);
        let outbox_entries = Arc::clone(&outbox.entries);
        let run = tokio::spawn(async move {
            // The open entry the previous run left behind, rehydrated in
            // its `Accepted` state.
            let inbox = MockInbox::new();
            let received = Envelope {
                sequence: 1,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::OperationOffer(OperationOffer {
                    operation_id: operation_id.to_string(),
                    endpoint_id: endpoint_id.to_string(),
                    site_id: instance_id.to_string(),
                    command_json: serde_json::to_vec(&RedfishCommand::System(
                        SystemCommand::Reset(ResetType::PowerCycle),
                    ))?,
                    target: String::from("/redfish/v1/Systems/1"),
                    expires_at_unix: now.unix_timestamp() + 3600,
                    actor_context: String::from("principal-7"),
                })),
            };
            let entry = InboxEntry::from_parts(
                InboxEntryId::generate(),
                operation_id,
                instance_id,
                serde_json::to_string(&received)?,
                InboxEntryState::Accepted,
                now + time::Duration::seconds(3600),
                now,
            );
            let _ = CenterInbox::insert(&inbox, &entry).await;
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let engine = CenterSync::new(
                transport,
                store_for_engine.as_ref(),
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(inbox)
        });

        // The first connection reports the stranded completion before the
        // projection: the discovery scan found the terminal operation with
        // its open entry.
        let mut wire = next_wire(&mut wires).await?;
        let envelope = next_outbox_frame(&mut wire).await?;
        let Some(EnvelopeMessage::OperationCompleted(completed)) = envelope.message else {
            return Err(
                std::io::Error::other("the first report was not an OperationCompleted").into(),
            );
        };
        assert_eq!(completed.operation_id, operation_id.to_string());
        assert!(completed.succeeded);
        assert_eq!(completed.summary, OperationState::Succeeded.as_str());
        for sequence in [2, 3, 4] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 4 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        // The second connection reports nothing for the closed entry: the
        // next frame is a heartbeat, never a duplicate completion.
        let mut second = next_wire(&mut wires).await?;
        let envelope = next_frame(&mut second).await?;
        assert_eq!(envelope.sequence, 0);
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::Heartbeat(_))
        ));

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        let inbox = stopped.map_err(|error| std::io::Error::other(error.to_string()))?;
        assert_eq!(
            inbox
                .entry_state(operation_id)
                .map_err(std::io::Error::other)?,
            Some(InboxEntryState::Completed)
        );
        let messages = pending_messages_from(&outbox_entries).map_err(std::io::Error::other)?;
        assert!(
            messages.is_empty(),
            "the closed entry must not be reported again: {messages:?}"
        );
        Ok(())
    }

    /// A transport whose connect always fails with the `identity-mismatch`
    /// classification, exactly like the app transport reports for the
    /// wire reason code.
    struct IdentityMismatchTransport;

    impl CenterTransport for IdentityMismatchTransport {
        type Session = ChannelSession;
        type Error = MockCenterError;

        fn connect(&self) -> crate::BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
            Box::pin(async move { Err(MockCenterError) })
        }

        fn is_identity_mismatch(&self, _error: &Self::Error) -> bool {
            true
        }
    }

    /// Consecutive `identity-mismatch` refusals stop the engine (audit
    /// follow-up E3-2): the mismatch is a configuration error no retry can
    /// heal, so the engine returns [`CenterSyncError::IdentityMismatch`]
    /// instead of alerting every backoff forever — and, unlike `not-bound`,
    /// nothing about the binding is touched by the engine itself.
    #[tokio::test]
    async fn consecutive_identity_mismatch_refusals_stop_the_engine() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let store = MockEngineStore::new();
        let instance_id = InstanceId::generate();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = CenterSync::new(
            IdentityMismatchTransport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(now),
            instance_id,
            CenterSyncOptions {
                identity_mismatch_abort_after: Some(2),
                ..engine_options()
            },
        );
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let outcome = engine
            .run(async move {
                let _ = stop_rx.await;
            })
            .await;
        assert!(matches!(outcome, Err(CenterSyncError::IdentityMismatch)));
        Ok(())
    }

    /// The connect-verdict of one scripted attempt: a classified refusal
    /// (`not-bound` or `identity-mismatch`) or a generic failure that
    /// carries no verdict about the binding.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ConnectVerdict {
        NotBound,
        Generic,
        IdentityMismatch,
    }

    /// A transport whose connect fails with a scripted verdict sequence,
    /// so a test can mix classified refusals with generic failures — the
    /// classification the engine reads is the verdict of the last attempt.
    struct ScriptedVerdictTransport {
        verdicts: Mutex<std::collections::VecDeque<ConnectVerdict>>,
        last: Arc<Mutex<ConnectVerdict>>,
    }

    impl ScriptedVerdictTransport {
        fn new(verdicts: Vec<ConnectVerdict>) -> Self {
            Self {
                verdicts: Mutex::new(verdicts.into()),
                last: Arc::new(Mutex::new(ConnectVerdict::Generic)),
            }
        }
    }

    impl CenterTransport for ScriptedVerdictTransport {
        type Session = ChannelSession;
        type Error = MockCenterError;

        fn connect(&self) -> crate::BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
            Box::pin(async move {
                let verdict = self
                    .verdicts
                    .lock()
                    .map_err(|_| MockCenterError)?
                    .pop_front()
                    .unwrap_or(ConnectVerdict::Generic);
                *self.last.lock().map_err(|_| MockCenterError)? = verdict;
                Err(MockCenterError)
            })
        }

        fn is_not_bound(&self, _error: &Self::Error) -> bool {
            self.last
                .lock()
                .is_ok_and(|verdict| *verdict == ConnectVerdict::NotBound)
        }

        fn is_identity_mismatch(&self, _error: &Self::Error) -> bool {
            self.last
                .lock()
                .is_ok_and(|verdict| *verdict == ConnectVerdict::IdentityMismatch)
        }
    }

    /// A generic failure does not reset the `not-bound` convergence count
    /// (audit follow-up W3N-5): the counters answer what the center says
    /// about the binding, and an unreachable center or a dropped handshake
    /// says nothing — resetting on it would let a flaky transport postpone
    /// the convergence forever. The script: two `not-bound` refusals, a
    /// generic failure, one more `not-bound` — the third reachable verdict
    /// is the third `not-bound`, so the engine converges.
    #[tokio::test]
    async fn generic_failures_do_not_reset_the_not_bound_convergence_count()
    -> Result<(), Box<dyn Error>> {
        let transport = ScriptedVerdictTransport::new(vec![
            ConnectVerdict::NotBound,
            ConnectVerdict::NotBound,
            ConnectVerdict::Generic,
            ConnectVerdict::NotBound,
        ]);
        let store = MockEngineStore::new();
        let instance_id = InstanceId::generate();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = CenterSync::new(
            transport,
            &store,
            &outbox,
            &inbox,
            &cursor,
            &events,
            FixedClock(OffsetDateTime::UNIX_EPOCH),
            instance_id,
            CenterSyncOptions {
                not_bound_abort_after: Some(3),
                ..engine_options()
            },
        );
        let (_stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        // The timeout bounds the run: without the fix the generic failure
        // resets the count and the engine retries forever, which must fail
        // the test instead of hanging the suite.
        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            engine.run(async move {
                let _ = stop_rx.await;
            }),
        )
        .await
        .map_err(|_| std::io::Error::other("the engine never converged"))?;
        assert!(matches!(outcome, Err(CenterSyncError::NotBound)));
        Ok(())
    }

    /// The `OperationCompleted` summary carries the provable refusal
    /// classification (audit follow-up E3-4): a `Failed` operation whose
    /// persisted failure kind is `capability-unsupported` is summarized as
    /// `failed-unsupported`, while an unclassified failure keeps the plain
    /// state code.
    #[tokio::test]
    async fn unsupported_failures_carry_the_classification_in_the_completed_summary()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let endpoint_id = endpoint.id();
        let operation_id = OperationId::generate();
        let operation = Operation::new(
            operation_id,
            OperationSource::Center,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            now,
        );
        store
            .create_operation(&operation)
            .await
            .map_err(std::io::Error::other)?;
        store
            .apply_transition(
                operation_id,
                OperationState::Failed,
                now + time::Duration::SECOND,
            )
            .await
            .map_err(std::io::Error::other)?;
        store
            .set_failure_kind(operation_id, FailureKind::CapabilityUnsupported)
            .map_err(std::io::Error::other)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(OperationOffer {
                operation_id: operation_id.to_string(),
                endpoint_id: endpoint_id.to_string(),
                site_id: instance_id.to_string(),
                command_json: serde_json::to_vec(&RedfishCommand::System(SystemCommand::Reset(
                    ResetType::PowerCycle,
                )))?,
                target: String::from("/redfish/v1/Systems/1"),
                expires_at_unix: now.unix_timestamp() + 3600,
                actor_context: String::from("principal-7"),
            })),
        };
        let entry = InboxEntry::from_parts(
            InboxEntryId::generate(),
            operation_id,
            instance_id,
            serde_json::to_string(&received)?,
            InboxEntryState::Accepted,
            now + time::Duration::seconds(3600),
            now,
        );
        let _ = CenterInbox::insert(&inbox, &entry).await;
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        engine
            .report_center_operations()
            .await
            .map_err(std::io::Error::other)?;

        let messages = outbox.pending_messages().map_err(std::io::Error::other)?;
        assert_eq!(messages.len(), 1);
        let Some(EnvelopeMessage::OperationCompleted(completed)) = messages.first() else {
            return Err(std::io::Error::other("the report was not an OperationCompleted").into());
        };
        assert_eq!(completed.operation_id, operation_id.to_string());
        assert!(!completed.succeeded);
        assert_eq!(
            completed.summary, "failed-unsupported",
            "the summary must carry the provable refusal classification"
        );
        assert_eq!(
            inbox
                .entry_state(operation_id)
                .map_err(std::io::Error::other)?,
            Some(InboxEntryState::Completed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_unclassified_failure_keeps_the_plain_state_summary() -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now).map_err(std::io::Error::other)?;
        let endpoint_id = endpoint.id();
        let operation_id = OperationId::generate();
        let operation = Operation::new(
            operation_id,
            OperationSource::Center,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            now,
        );
        store
            .create_operation(&operation)
            .await
            .map_err(std::io::Error::other)?;
        store
            .apply_transition(
                operation_id,
                OperationState::Failed,
                now + time::Duration::SECOND,
            )
            .await
            .map_err(std::io::Error::other)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(OperationOffer {
                operation_id: operation_id.to_string(),
                endpoint_id: endpoint_id.to_string(),
                site_id: instance_id.to_string(),
                command_json: serde_json::to_vec(&RedfishCommand::System(SystemCommand::Reset(
                    ResetType::PowerCycle,
                )))?,
                target: String::from("/redfish/v1/Systems/1"),
                expires_at_unix: now.unix_timestamp() + 3600,
                actor_context: String::from("principal-7"),
            })),
        };
        let entry = InboxEntry::from_parts(
            InboxEntryId::generate(),
            operation_id,
            instance_id,
            serde_json::to_string(&received)?,
            InboxEntryState::Accepted,
            now + time::Duration::seconds(3600),
            now,
        );
        let _ = CenterInbox::insert(&inbox, &entry).await;
        let cursor = MockCursor::new();
        let events = MockEventTail::new(Vec::new());
        let engine = engine_over(&store, &outbox, &inbox, &cursor, &events, instance_id, now);
        engine
            .report_center_operations()
            .await
            .map_err(std::io::Error::other)?;

        let messages = outbox.pending_messages().map_err(std::io::Error::other)?;
        assert_eq!(messages.len(), 1);
        let Some(EnvelopeMessage::OperationCompleted(completed)) = messages.first() else {
            return Err(std::io::Error::other("the report was not an OperationCompleted").into());
        };
        assert_eq!(completed.summary, OperationState::Failed.as_str());
        Ok(())
    }

    /// The storm interleaves heartbeats and reconnects: while two loops
    /// lose their connections, a third stays connected and keeps
    /// heartbeating, and the reconnecting loops resume on their fresh
    /// connections — no loop's heartbeat loop disturbs another's reconnect,
    /// and vice versa (§15.2, §15.4).
    // The storm test spells out the full concurrent driver script in one
    // place; splitting it would break the single-scenario assertion
    // continuity (the persistence stress tests allow the same lint on
    // their exhaustive storm tests). The `_a`/`_b`/`_c` suffixes name the
    // three concurrent loops, so the a/b/c naming is the test semantics
    // itself and the similar-names lint is scoped off here as well.
    #[allow(clippy::too_many_lines, clippy::similar_names)]
    #[tokio::test]
    async fn heartbeats_and_reconnects_interleave_without_interference()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport_a, state_a, mut wires_a) = ScriptedTransport::new(0);
        let (transport_b, state_b, mut wires_b) = ScriptedTransport::new(0);
        let (transport_c, state_c, mut wires_c) = ScriptedTransport::new(0);
        let (stop_a_tx, stop_a_rx) = tokio::sync::oneshot::channel();
        let (stop_b_tx, stop_b_rx) = tokio::sync::oneshot::channel();
        let (stop_c_tx, stop_c_rx) = tokio::sync::oneshot::channel();
        let mut runs = JoinSet::new();
        for (transport, stop_rx) in [transport_a, transport_b, transport_c]
            .into_iter()
            .zip([stop_a_rx, stop_b_rx, stop_c_rx])
        {
            let instance_id = InstanceId::generate();
            runs.spawn(async move {
                let store = MockEngineStore::new();
                let inbox = MockInbox::new();
                let cursor = MockCursor::new();
                let events = MockEventTail::new(Vec::new());
                let outbox = MockOutbox::new(instance_id);
                outbox.enqueue_heartbeats(2, now)?;
                let engine = CenterSync::new(
                    transport,
                    &store,
                    outbox,
                    &inbox,
                    &cursor,
                    &events,
                    FixedClock(now),
                    instance_id,
                    engine_options(),
                );
                engine
                    .run(async move {
                        let _ = stop_rx.await;
                    })
                    .await?;
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            });
        }

        // All three loops connect and deliver their two queued messages;
        // each acknowledges the pair and keeps heartbeating.
        let mut wire_a = next_wire(&mut wires_a).await?;
        let mut wire_b = next_wire(&mut wires_b).await?;
        let mut wire_c = next_wire(&mut wires_c).await?;
        for wire in [&mut wire_a, &mut wire_b, &mut wire_c] {
            for sequence in [1, 2] {
                let envelope = next_outbox_frame(wire).await?;
                assert_eq!(envelope.sequence, sequence);
            }
            wire.inbound
                .send(Envelope {
                    sequence: 10,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::Ack(Ack { sequence: 2 })),
                })
                .map_err(|_| std::io::Error::other("the center feed closed"))?;
            let envelope = next_frame(wire).await?;
            assert_eq!(envelope.sequence, 0);
            assert!(matches!(
                envelope.message,
                Some(EnvelopeMessage::Heartbeat(_))
            ));
        }

        // The storm drops B's and C's connections while A stays connected.
        let Wire {
            outbound: outbound_b,
            inbound: inbound_b,
        } = wire_b;
        drop(outbound_b);
        drop(inbound_b);
        let Wire {
            outbound: outbound_c,
            inbound: inbound_c,
        } = wire_c;
        drop(outbound_c);
        drop(inbound_c);

        // While B and C wait out the backoff and reconnect, A's connection
        // never noticed the storm: its heartbeats keep flowing.
        let envelope = next_frame(&mut wire_a).await?;
        assert_eq!(envelope.sequence, 0);
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::Heartbeat(_))
        ));

        // B and C reconnect concurrently, and every loop's fresh connection
        // is liveness-clean: the queue was drained, so only heartbeats
        // arrive — and A's heartbeat loop stays undisturbed throughout.
        let (second_b, second_c) = tokio::join!(next_wire(&mut wires_b), next_wire(&mut wires_c),);
        let mut second_b = second_b?;
        let mut second_c = second_c?;
        assert_eq!(state_b.attempts(), 2);
        assert_eq!(state_c.attempts(), 2);
        assert_eq!(
            state_a.attempts(),
            1,
            "A never reconnected during the storm"
        );
        for wire in [&mut second_b, &mut second_c, &mut wire_a] {
            let envelope = next_frame(wire).await?;
            assert_eq!(envelope.sequence, 0);
            assert!(matches!(
                envelope.message,
                Some(EnvelopeMessage::Heartbeat(_))
            ));
        }

        let _ = stop_a_tx.send(());
        let _ = stop_b_tx.send(());
        let _ = stop_c_tx.send(());
        while let Some(join) = tokio::time::timeout(Duration::from_secs(5), runs.join_next())
            .await
            .map_err(|_| std::io::Error::other("the engines did not stop in time"))?
        {
            join?.map_err(|error| std::io::Error::other(error.to_string()))?;
        }
        Ok(())
    }

    /// The storm never touches the site's local state: while the loop sits
    /// in the reconnect backoff, local producers keep enqueuing into the
    /// durable outbox (the offline queue of §21 0.7.0), and the reconnect
    /// flushes the whole accumulated queue in one burst, in sequence order —
    /// nothing lost, nothing duplicated (§15.4 local autonomy).
    #[tokio::test]
    async fn the_local_queue_keeps_accumulating_while_disconnected_and_drains_in_order_on_reconnect()
    -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let outbox = MockOutbox::new(instance_id);
        // The offline queue holds two messages before the first connection.
        outbox
            .enqueue_heartbeats(2, now)
            .map_err(std::io::Error::other)?;
        // The test keeps the shared entries vector so it can keep writing
        // the queue while the engine is disconnected.
        let entries = Arc::clone(&outbox.entries);
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let cursor = MockCursor::new();
            let events = MockEventTail::new(Vec::new());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                &cursor,
                &events,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 1 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        // The storm drops the connection; the site stays local.
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        // While the loop waits out the backoff, local producers keep
        // enqueuing: the queue accumulates messages 3, 4, and 5 offline.
        push_heartbeat_entry(&entries, instance_id, 3, now).map_err(std::io::Error::other)?;
        push_heartbeat_entry(&entries, instance_id, 4, now).map_err(std::io::Error::other)?;
        push_heartbeat_entry(&entries, instance_id, 5, now).map_err(std::io::Error::other)?;

        // The reconnect drains the whole accumulated queue in one burst, in
        // sequence order: the unacknowledged message 2 first, then the
        // offline accumulation.
        let mut second = next_wire(&mut wires).await?;
        for sequence in [2, 3, 4, 5] {
            let envelope = next_outbox_frame(&mut second).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // The burst drained the queue: only liveness heartbeats follow, and
        // the loop answers the stop signal.
        let envelope = next_frame(&mut second).await?;
        assert_eq!(envelope.sequence, 0);
        assert!(matches!(
            envelope.message,
            Some(EnvelopeMessage::Heartbeat(_))
        ));

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }
}
