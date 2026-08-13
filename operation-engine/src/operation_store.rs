use std::{error::Error, future::Future, pin::Pin};

use rutilus_domain::{
    BatchOperation, BatchOperationId, FailureKind, Operation, OperationId, OperationState,
};
use time::OffsetDateTime;

/// A boxed future returned by boundary traits so implementers stay `dyn`-safe.
pub type BoundaryFuture<'a, Output> = Pin<Box<dyn Future<Output = Output> + Send + 'a>>;

/// One batch child paired with its persisted failure classification (§13.7).
///
/// The kind is `None` for every child that is not a classified failure;
/// reporting reads the pair to bucket a `Failed` child as `unsupported`
/// instead of an ordinary failure.
pub type ClassifiedBatchChild = (Operation, Option<FailureKind>);

/// The persistence boundary for the Operation lifecycle.
///
/// # Why this boundary exists
///
/// Design section 13.1 turns every write into a persisted `Operation` and
/// section 13.3 persists each state step, so unfinished work can be recovered
/// after a process restart (design section 13.6). The engine deliberately does
/// not know `SQLite` or `SeaORM` (design section 7.3), so persistence is injected
/// through this trait: `rutilus-persistence` provides the production
/// implementation, tests provide an in-memory fake, and `rutilus-web`/`app`
/// never see either.
///
/// # Concurrency contract
///
/// All methods must be safe to call concurrently. Implementations do not
/// need an internal queue: each method documents the exact atomicity it
/// requires.
pub trait OperationStore: Send + Sync {
    /// The persistence layer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists a new operation.
    ///
    /// # Idempotency (design section 15.4)
    ///
    /// Delivery is at-least-once, so the same `OperationId` may be delivered
    /// again (for example a Center re-sending a stable operation id over the
    /// reconnected site link). A second call with the same id MUST return
    /// `Ok(())` without touching the stored row: "already exists -> return the
    /// existing state -> never re-execute" (single business effect per
    /// operation). The persisted row is always authoritative; callers that
    /// need it re-read through [`Self::find_operation`].
    fn create_operation<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Reads one operation by id; `None` when the id is unknown.
    fn find_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>>;

    /// Persists one state step of an operation (design section 13.3).
    ///
    /// # Optimistic concurrency
    ///
    /// `occurred_at` is recorded as the time this state was observed to take
    /// effect. The stored state only ever moves forward through the domain
    /// state machine, so implementations MUST return a conflict-style error
    /// instead of writing when the operation id is unknown OR when the
    /// currently persisted state is terminal (`Succeeded`/`Failed`/`Cancelled`/
    /// `Unknown`): a finished operation can never be resurrected, which is what
    /// protects a restart recovery sweep racing an in-flight execution from
    /// overwriting an already-final result. Non-terminal state steps overwrite
    /// freely; per-step recovery of a crashed write is the engine's concern.
    ///
    /// This signature intentionally does not carry the expected previous
    /// state; a driver that must not overwrite a state it no longer observed
    /// uses the compare-and-set step [`Self::apply_transition_if_current`]
    /// instead.
    fn apply_transition(
        &self,
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Persists one state step only while the persisted state still equals
    /// `expected_state` — the compare-and-set step of [`Self::apply_transition`].
    ///
    /// The check and the write are one atomic store operation: a driver that
    /// observed the operation in `expected_state` and whose step is legal from
    /// that state gets its write; a driver whose observation went stale (a
    /// second driver advanced the operation in the meantime) gets a
    /// conflict-style error and nothing is written. This is what closes the
    /// two-read race window of a re-read-then-step guard: the state is
    /// re-verified at write time, inside the same transaction as the write.
    ///
    /// # Optimistic concurrency
    ///
    /// `occurred_at` and `new_state` are recorded exactly like
    /// [`Self::apply_transition`]. Implementations MUST return a
    /// conflict-style error instead of writing when the operation id is
    /// unknown OR when the persisted state differs from `expected_state` —
    /// including a terminal state, which can never equal a driver's expected
    /// in-flight state and can never be overwritten. The conflict error MAY
    /// carry the observed state so the caller can classify the race honestly.
    /// A returned error must never have written anything.
    fn apply_transition_if_current(
        &self,
        operation_id: OperationId,
        expected_state: OperationState,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Persists the failure classification of one operation (design section
    /// 13.7 batch reporting).
    ///
    /// The kind is a fact of a provable failure's *reason*, written by the
    /// refusal path BEFORE the `Failed` transition, so a crash between the
    /// two writes leaves either an unclassified failure (the ordinary case)
    /// or an orphaned kind on a non-terminal row — both harmless, because
    /// reporting reads the kind only to bucket a `Failed` child, and the
    /// domain state machine never treats the column as a state. The write
    /// does not touch `updated_at` (the timeline records state transitions).
    ///
    /// # Errors
    ///
    /// Returns a conflict-style error for an unknown operation id, exactly
    /// like [`Self::apply_transition`].
    fn record_failure_kind(
        &self,
        operation_id: OperationId,
        kind: FailureKind,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    /// Reads the persisted failure classification of one operation (audit
    /// follow-up E3-4: the site's `OperationCompleted` summary carries the
    /// classification so the center can distinguish a provably unsupported
    /// write from an ordinary failure).
    ///
    /// `None` for every operation that is not a classified failure and for
    /// an unknown operation id — the kind is an optional fact of a `Failed`
    /// row, never a state. The default implementation reports no
    /// classification, so a store that does not read the column keeps the
    /// historical summary semantics; the production store overrides it.
    ///
    /// # Errors
    ///
    /// Returns a boundary error when the classification cannot be read (a
    /// stored code this build cannot classify is a corrupt row, exactly
    /// like the batch-children listing).
    fn find_failure_kind(
        &self,
        _operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<FailureKind>, Self::Error>> {
        Box::pin(async move { Ok(None) })
    }

    /// Lists operations, optionally filtered by exact state.
    ///
    /// A `None` filter returns every operation; a `Some` filter returns only
    /// operations currently in that state. Design section 13.6 uses this to
    /// scan for recoverable work after a restart; batch reporting (design
    /// section 13.7) uses it to summarize per-target outcomes.
    fn list_operations(
        &self,
        state: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>>;

    /// Atomically persists one batch parent and every child operation
    /// (design section 13.7).
    ///
    /// A batch is one `batch_operations` parent plus one ordinary
    /// single-target child operation per submitted endpoint; the parent and
    /// all children commit in one transaction, so a child can never be
    /// persisted without its batch (or half a batch without the rest).
    ///
    /// # Idempotency (design section 15.4)
    ///
    /// Delivery is at-least-once, exactly like [`Self::create_operation`]: a
    /// second call with the same `BatchOperationId` MUST return `Ok(())`
    /// without touching any stored row — the persisted batch is authoritative
    /// and a re-delivered batch must never re-insert its children (single
    /// business effect per batch). The persisted rows are always
    /// authoritative; callers that need them re-read through
    /// [`Self::find_batch`] and [`Self::list_batch_children`].
    fn create_batch<'a>(
        &'a self,
        batch: &'a BatchOperation,
        children: &'a [Operation],
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Reads one batch parent by id; `None` when the id is unknown.
    fn find_batch(
        &self,
        batch_id: BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>>;

    /// Lists every batch parent in acceptance order (creation time, then
    /// identity), so batch reporting (design section 13.7) replays the same
    /// deterministic order as the operation listing.
    fn list_batches(&self) -> BoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>>;

    /// Lists one batch's child operations in target order, paired with each
    /// child's persisted failure classification (design section 13.7).
    ///
    /// Each child carries exactly one target, so target order is a total
    /// order over the batch; reporting (design section 13.7) reads the
    /// children in this deterministic order to pair each endpoint with its
    /// child outcome and to bucket classified failures. The kind is `None`
    /// for every child that is not a classified failure — the kind is only
    /// ever written for the capability pre-flight refusal path, so most rows
    /// carry `None`. An unknown batch id returns an empty list (the parent
    /// existence is a separate [`Self::find_batch`] read).
    fn list_batch_children(
        &self,
        batch_id: BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>>;
}

impl<Store> OperationStore for &Store
where
    Store: OperationStore + ?Sized,
{
    type Error = Store::Error;

    fn create_operation<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Store::create_operation(*self, operation)
    }

    fn find_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
        Store::find_operation(*self, operation_id)
    }

    fn apply_transition(
        &self,
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Store::apply_transition(*self, operation_id, new_state, occurred_at)
    }

    fn apply_transition_if_current(
        &self,
        operation_id: OperationId,
        expected_state: OperationState,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Store::apply_transition_if_current(
            *self,
            operation_id,
            expected_state,
            new_state,
            occurred_at,
        )
    }

    fn record_failure_kind(
        &self,
        operation_id: OperationId,
        kind: FailureKind,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Store::record_failure_kind(*self, operation_id, kind)
    }

    fn find_failure_kind(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<FailureKind>, Self::Error>> {
        Store::find_failure_kind(*self, operation_id)
    }

    fn list_operations(
        &self,
        state: Option<OperationState>,
    ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Store::list_operations(*self, state)
    }

    fn create_batch<'a>(
        &'a self,
        batch: &'a BatchOperation,
        children: &'a [Operation],
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Store::create_batch(*self, batch, children)
    }

    fn find_batch(
        &self,
        batch_id: BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
        Store::find_batch(*self, batch_id)
    }

    fn list_batches(&self) -> BoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
        Store::list_batches(*self)
    }

    fn list_batch_children(
        &self,
        batch_id: BatchOperationId,
    ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
        Store::list_batch_children(*self, batch_id)
    }
}
