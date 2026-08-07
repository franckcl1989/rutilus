use std::error::Error;

use rutilus_domain::{
    BatchOperation, BatchOperationId, InvalidTransition, Operation, OperationEvent, OperationId,
    OperationSource, OperationState, OperationTarget, RedfishCommand,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::OperationStore;

/// States that may still hold unfinished work after a process restart.
///
/// # Why exactly these four
///
/// Design section 13.6 scans `WaitingRemote` after a restart, but a crash can
/// interrupt work at any non-terminal step, so the recovery set covers the
/// whole in-flight span:
///
/// - `Validating` — capability/permission/parameter checks were in flight; the
///   BMC write has not been issued yet (design section 13.3 steps 1-5), so
///   resuming the validation is always safe.
/// - `Running` — the BMC call was in flight; its outcome is unknown (design
///   section 13.5). Recovery must re-check the target instead of blindly
///   re-executing, which is exactly what the upper layer schedules from the
///   recovered list.
/// - `WaitingRemote` — an asynchronous Task was accepted and its progress is
///   only observable by resuming Task polling (design section 13.6).
/// - `Verifying` — the write has already landed (design section 13.3 steps
///   9-10) and only the target re-read and expected-result check were in
///   flight. The outcome is unknown, so recovery applies the same §13.5
///   re-read-and-decide pattern: re-read the target, then record `Succeeded`,
///   `Failed`, or `Unknown`. A `Verifying` operation can no longer be
///   cancelled (the write completed), so leaving it out of the recovery set
///   would strand it in flight forever.
///
/// `Queued` is deliberately excluded: it has never started, so it is the
/// normal scheduler's job, not a recovery concern. Terminal states
/// (`Succeeded`/`Failed`/`Cancelled`/`Unknown`) are final by definition and
/// must never be re-executed.
pub const RECOVERABLE_STATES: [OperationState; 4] = [
    OperationState::Validating,
    OperationState::Running,
    OperationState::WaitingRemote,
    OperationState::Verifying,
];

/// The supported upper bound of one batch's target count (design §13.7).
///
/// # Why 128
///
/// A batch commits one parent and all its children in a single transaction
/// and one batch report pairs every child with its outcome, so the bound
/// keeps one batch's transaction and projection bounded while staying far
/// above any realistic managed-endpoint sweep. It is a product limit, not a
/// storage limit: the database imposes none, and callers surface the limit
/// as a clean rejection instead of an unbounded write.
pub const MAX_BATCH_TARGETS: usize = 128;

/// Drives the persisted Operation lifecycle (design section 13).
///
/// Every write the product performs is first persisted here as a `Queued`
/// operation, then advanced step by step through the domain state machine,
/// with each step persisted before it is acted on (design section 13.3). The
/// store is injected so the engine stays free of SQLite/SeaORM; the execution
/// of BMC actions is not part of this crate (that lands with the scheduler in
/// a later iteration).
pub struct OperationEngine<Store> {
    store: Store,
}

impl<Store> OperationEngine<Store>
where
    Store: OperationStore,
{
    /// Wraps a store implementation.
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    /// Constructs a `Queued` operation, persists it, and returns it.
    ///
    /// # Why the callers pass `now`
    ///
    /// Timestamps are injected exactly like the application layer's `Clock` so
    /// tests stay deterministic; the engine never reads the wall clock.
    /// Callers must supply a monotonic clock: the domain trusts `now` without
    /// re-checking (`Operation::apply` sets `updated_at` from it), so moving
    /// the clock backwards would corrupt the operation timeline.
    ///
    /// `targets` must contain at least one target: a zero-target operation
    /// could never execute (a batch, design section 13.7, is a list of
    /// targets, not an empty one). The domain constructor documents this
    /// contract; the engine enforces it before persisting anything.
    ///
    /// # Why the command is persisted with the operation
    ///
    /// The record must stand alone: the future execution scheduler reads the
    /// operation back and dispatches the exact typed `nv-redfish` method from
    /// `command` (design section 13.3 step 7), and the design section 13.6
    /// restart recovery scans the same records to resume unfinished work. The
    /// command is a fact of the operation, not a session detail, so it is
    /// persisted from the first step and never recomputed by the caller.
    ///
    /// The operation id is generated fresh here, so two calls never produce
    /// the same record. [`OperationStore::create_operation`] is still
    /// idempotent on the id (design section 15.4) as the guard for the future
    /// stable-id injection path (Center dispatch re-delivering one
    /// `OperationId`): a re-delivered id must never re-execute.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyTargets`] when `targets` is empty, and
    /// [`EngineError::Store`] when the persistence boundary rejects the write.
    pub async fn create(
        &self,
        source: OperationSource,
        targets: Vec<OperationTarget>,
        command: RedfishCommand,
        now: OffsetDateTime,
    ) -> Result<Operation, EngineError<Store::Error>> {
        if targets.is_empty() {
            return Err(EngineError::EmptyTargets);
        }
        let operation = Operation::new(OperationId::generate(), source, targets, command, now);
        self.store
            .create_operation(&operation)
            .await
            .map_err(EngineError::Store)?;
        Ok(operation)
    }

    /// Advances one operation through the domain state machine and persists
    /// the resulting state.
    ///
    /// The engine reads the current aggregate, lets the domain decide the next
    /// state for `event` (domain `Operation::apply`), persists that step with
    /// `now` as the occurrence time (design section 13.3), and returns the
    /// advanced aggregate. The returned aggregate is the domain-mutated copy,
    /// whose state and `updated_at` are exactly what `apply_transition`
    /// records, so no fabricated value ever leaves the engine.
    ///
    /// Concurrency: the store contract rejects any write onto a terminal
    /// state, so a recovery sweep can never resurrect a finished operation.
    /// Two writers racing on a non-terminal step may both succeed — the last
    /// write wins and the next read surfaces the persisted truth; a full
    /// compare-and-set would need the expected state as an additional store
    /// parameter and is a later iteration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::NotFound`] when the id is unknown,
    /// [`EngineError::InvalidTransition`] when the domain state machine
    /// rejects `event` for the current state, and [`EngineError::Store`] when
    /// the persistence boundary fails — including the store's conflict error
    /// when a concurrent writer has already moved the operation into a
    /// terminal state.
    pub async fn apply(
        &self,
        operation_id: OperationId,
        event: OperationEvent,
        now: OffsetDateTime,
    ) -> Result<Operation, EngineError<Store::Error>> {
        let mut current = self
            .store
            .find_operation(operation_id)
            .await
            .map_err(EngineError::Store)?
            .ok_or(EngineError::NotFound(operation_id))?;
        current
            .apply(event, now)
            .map_err(|source| EngineError::InvalidTransition {
                operation_id,
                source,
            })?;
        self.store
            .apply_transition(operation_id, current.state(), now)
            .await
            .map_err(EngineError::Store)?;
        Ok(current)
    }

    /// Lists persisted operations, optionally filtered by exact state.
    ///
    /// The optional filter is forwarded unchanged to the store; `None` lists
    /// every operation. Batch reporting (design section 13.7) filters per
    /// state to summarize outcomes.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] when the persistence boundary fails.
    pub async fn list(
        &self,
        state: Option<OperationState>,
    ) -> Result<Vec<Operation>, EngineError<Store::Error>> {
        self.store
            .list_operations(state)
            .await
            .map_err(EngineError::Store)
    }

    /// Constructs one batch parent and its single-target child operations,
    /// persists them atomically, and returns the parent with its children.
    ///
    /// # Why every child is an ordinary operation
    ///
    /// Design section 13.7 turns a multi-endpoint submission into one batch
    /// parent plus one ordinary single-target `Operation` per submitted
    /// endpoint — the same §13.2 state machine, the same scheduler, the same
    /// recovery. The executor, scheduler, Task monitor, recovery, and audit
    /// paths never see the batch; only the parent record links the children.
    ///
    /// `targets` must contain at least one target (a batch is a list of
    /// targets, not an empty one, exactly like [`Self::create`]) and at most
    /// [`MAX_BATCH_TARGETS`] targets. The batch id and every child's
    /// `OperationId` are generated fresh here, so two calls never produce the
    /// same records; [`OperationStore::create_batch`] is still idempotent on
    /// the batch id (design §15.4) as the guard for re-delivery, which must
    /// never re-insert the children.
    ///
    /// `now` is the caller-supplied creation time with the same monotonic
    /// contract as [`Self::create`]: the domain trusts it without re-checking.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::EmptyTargets`] when `targets` is empty,
    /// [`EngineError::TooManyTargets`] when it exceeds [`MAX_BATCH_TARGETS`],
    /// and [`EngineError::Store`] when the persistence boundary rejects the
    /// write.
    pub async fn create_batch(
        &self,
        source: OperationSource,
        targets: Vec<OperationTarget>,
        command: RedfishCommand,
        now: OffsetDateTime,
    ) -> Result<(BatchOperation, Vec<Operation>), EngineError<Store::Error>> {
        if targets.is_empty() {
            return Err(EngineError::EmptyTargets);
        }
        if targets.len() > MAX_BATCH_TARGETS {
            return Err(EngineError::TooManyTargets {
                limit: MAX_BATCH_TARGETS,
            });
        }
        let batch = BatchOperation::new(BatchOperationId::generate(), source, command, now);
        let children = targets
            .into_iter()
            .map(|target| {
                Operation::new(
                    OperationId::generate(),
                    source,
                    vec![target],
                    batch.command(),
                    now,
                )
            })
            .collect::<Vec<_>>();
        self.store
            .create_batch(&batch, &children)
            .await
            .map_err(EngineError::Store)?;
        Ok((batch, children))
    }

    /// Lists operations in [`RECOVERABLE_STATES`] after a restart.
    ///
    /// This first version only reports the candidates; the upper layer (the
    /// future scheduler in `application`) decides per operation whether to
    /// re-validate, re-check the target, resume Task polling, or mark the
    /// outcome unknown (design sections 13.5 and 13.6). Executing BMC actions
    /// here is deliberately out of scope for this iteration.
    ///
    /// # Errors
    ///
    /// Returns [`EngineError::Store`] when the persistence boundary fails.
    pub async fn recover_pending(&self) -> Result<Vec<Operation>, EngineError<Store::Error>> {
        let operations = self
            .store
            .list_operations(None)
            .await
            .map_err(EngineError::Store)?;
        Ok(operations
            .into_iter()
            .filter(|operation| RECOVERABLE_STATES.contains(&operation.state()))
            .collect())
    }
}

/// A controlled failure while driving the Operation lifecycle.
///
/// The single generic parameter is the injected store's error type, so every
/// persistence failure stays reachable as the source of an error chain and
/// callers never lose the store's own context.
#[derive(Debug, Error)]
pub enum EngineError<StoreError>
where
    StoreError: Error + 'static,
{
    /// The operation id is not known to the store.
    #[error("operation {0} was not found")]
    NotFound(OperationId),
    /// The operation would have no target and could never execute.
    #[error("operation must target at least one object")]
    EmptyTargets,
    /// The batch would exceed the supported target limit (§13.7).
    ///
    /// A batch commits its parent and every child in one transaction and one
    /// report pairs each child with its outcome, so the supported bound keeps
    /// one batch bounded; the caller should split the submission.
    #[error("a batch may target at most {limit} endpoints")]
    TooManyTargets { limit: usize },
    /// The domain state machine rejected the event for the current state.
    #[error("operation {operation_id} rejected transition: {source}")]
    InvalidTransition {
        operation_id: OperationId,
        #[source]
        source: InvalidTransition,
    },
    /// The persistence boundary failed; carries the store's own error.
    #[error("operation store failed: {0}")]
    Store(#[source] StoreError),
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, io, sync::Mutex};

    use rutilus_domain::{
        BatchOperation, BatchOperationId, EndpointId, OperationId, OperationState, OperationTarget,
        ResetType, SystemCommand, TargetId,
    };
    use thiserror::Error;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::{
        BoundaryFuture, ClassifiedBatchChild, RemoteTask, RemoteTaskState, RemoteTaskStore, TaskUri,
    };

    /// One recorded store call, in order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Create(OperationId),
        Find(OperationId),
        ApplyTransition(OperationId, OperationState),
        RecordFailureKind(OperationId),
        List(Option<OperationState>),
        SaveRemoteTask(OperationId),
        FindRemoteTask(OperationId),
        ListRemoteTasks(RemoteTaskState),
        CreateBatch(BatchOperationId),
        FindBatch(BatchOperationId),
        ListBatches,
        ListBatchChildren(BatchOperationId),
    }

    /// A recorded state step, with the exact timestamp the engine supplied.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TransitionStep {
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    }

    /// The fake's controlled failure modes, exercised per test.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
    enum FakeStoreError {
        #[error("simulated store conflict: operation already moved on")]
        Conflict,
        #[error("simulated store failure")]
        Failure,
    }

    /// In-memory fake store that records the exact call sequence.
    ///
    /// `apply_transition` models the trait contract from `operation_store.rs`:
    /// it rejects unknown ids and any write onto a terminal state with
    /// [`FakeStoreError::Conflict`], so tests can verify the engine propagates
    /// store conflicts unchanged. The fake also implements
    /// [`RemoteTaskStore`] on separate rows, exactly like the production
    /// `SqliteStore`, so the §13.6 Task flow can be driven through one test
    /// object.
    struct FakeStore {
        rows: Mutex<HashMap<OperationId, Operation>>,
        remote_rows: Mutex<HashMap<OperationId, RemoteTask>>,
        batch_rows: Mutex<HashMap<BatchOperationId, BatchOperation>>,
        batch_children: Mutex<HashMap<BatchOperationId, Vec<Operation>>>,
        calls: Mutex<Vec<Call>>,
        steps: Mutex<Vec<TransitionStep>>,
        fail_next_write: Mutex<bool>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                remote_rows: Mutex::new(HashMap::new()),
                batch_rows: Mutex::new(HashMap::new()),
                batch_children: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                steps: Mutex::new(Vec::new()),
                fail_next_write: Mutex::new(false),
            }
        }

        fn find_batch_owned(
            &self,
            batch_id: BatchOperationId,
        ) -> Result<Option<BatchOperation>, FakeStoreError> {
            self.batch_rows
                .lock()
                .map_err(|_| FakeStoreError::Failure)
                .map(|rows| rows.get(&batch_id).cloned())
        }

        fn list_batch_children_owned(
            &self,
            batch_id: BatchOperationId,
        ) -> Result<Vec<Operation>, FakeStoreError> {
            let mut children = self
                .batch_children
                .lock()
                .map_err(|_| FakeStoreError::Failure)?
                .get(&batch_id)
                .cloned()
                .unwrap_or_default();
            // Target order (§13.7): each child carries exactly one target, so
            // ordering by that target's identity is a total order; a corrupt
            // zero-target row (impossible through the engine) sorts first by
            // `None` instead of panicking.
            children.sort_by_key(|child| child.targets().first().map(|target| target.target_id()));
            Ok(children)
        }

        fn arm_write_failure(&self) -> Result<(), FakeStoreError> {
            *self
                .fail_next_write
                .lock()
                .map_err(|_| FakeStoreError::Failure)? = true;
            Ok(())
        }

        fn calls(&self) -> Result<Vec<Call>, FakeStoreError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| FakeStoreError::Failure)
        }

        fn steps(&self) -> Result<Vec<TransitionStep>, FakeStoreError> {
            self.steps
                .lock()
                .map(|steps| steps.clone())
                .map_err(|_| FakeStoreError::Failure)
        }

        fn find_owned(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<Operation>, FakeStoreError> {
            self.rows
                .lock()
                .map_err(|_| FakeStoreError::Failure)
                .map(|rows| rows.get(&operation_id).cloned())
        }
    }

    impl OperationStore for FakeStore {
        type Error = FakeStoreError;

        fn create_operation<'a>(
            &'a self,
            operation: &'a Operation,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::Create(operation.id()));
                let mut rows = self.rows.lock().map_err(|_| FakeStoreError::Failure)?;
                rows.entry(operation.id())
                    .or_insert_with(|| operation.clone());
                Ok(())
            })
        }

        fn find_operation(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::Find(operation_id));
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn apply_transition(
            &self,
            operation_id: OperationId,
            new_state: OperationState,
            occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::ApplyTransition(operation_id, new_state));
                if *self
                    .fail_next_write
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                {
                    return Err(FakeStoreError::Conflict);
                }
                let mut rows = self.rows.lock().map_err(|_| FakeStoreError::Failure)?;
                let row = rows.get(&operation_id).ok_or(FakeStoreError::Conflict)?;
                if row.is_terminal() {
                    return Err(FakeStoreError::Conflict);
                }
                let row = rows
                    .get_mut(&operation_id)
                    .ok_or(FakeStoreError::Conflict)?;
                *row = Operation::try_from_parts(
                    row.id(),
                    row.source(),
                    row.targets().to_vec(),
                    row.command(),
                    new_state,
                    row.created_at(),
                    occurred_at,
                )
                .map_err(|_| FakeStoreError::Failure)?;
                self.steps
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(TransitionStep {
                        operation_id,
                        new_state,
                        occurred_at,
                    });
                Ok(())
            })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::List(state));
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .values()
                    .filter(|operation| state.is_none_or(|state| operation.state() == state))
                    .cloned()
                    .collect())
            })
        }

        fn create_batch<'a>(
            &'a self,
            batch: &'a BatchOperation,
            children: &'a [Operation],
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::CreateBatch(batch.id()));
                // At-least-once delivery (§15.4): a re-delivered batch id is
                // a no-op that never re-inserts the children, mirroring the
                // production repository's "already exists -> return" rule.
                let mut batch_rows = self
                    .batch_rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?;
                if batch_rows.contains_key(&batch.id()) {
                    return Ok(());
                }
                batch_rows.insert(batch.id(), batch.clone());
                self.batch_children
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .insert(batch.id(), children.to_vec());
                Ok(())
            })
        }

        fn find_batch(
            &self,
            batch_id: BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::FindBatch(batch_id));
                self.find_batch_owned(batch_id)
            })
        }

        fn list_batches(&self) -> BoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::ListBatches);
                let mut batches = self
                    .batch_rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                // Acceptance order: creation time, then identity, mirroring
                // the production listing.
                batches.sort_by_key(|batch| (batch.created_at(), batch.id()));
                Ok(batches)
            })
        }

        fn record_failure_kind(
            &self,
            operation_id: OperationId,
            _kind: rutilus_domain::FailureKind,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::RecordFailureKind(operation_id));
                Ok(())
            })
        }

        fn list_batch_children(
            &self,
            batch_id: BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::ListBatchChildren(batch_id));
                // The engine never writes failure kinds, so every child reads
                // back unclassified.
                Ok(self
                    .list_batch_children_owned(batch_id)?
                    .into_iter()
                    .map(|child| (child, None))
                    .collect())
            })
        }
    }

    impl RemoteTaskStore for FakeStore {
        type Error = FakeStoreError;

        fn save_remote_task<'a>(
            &'a self,
            task: &'a RemoteTask,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::SaveRemoteTask(task.operation_id()));
                self.remote_rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .insert(task.operation_id(), task.clone());
                Ok(())
            })
        }

        fn find_remote_task(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<RemoteTask>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::FindRemoteTask(operation_id));
                Ok(self
                    .remote_rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn list_remote_tasks_by_state(
            &self,
            state: RemoteTaskState,
        ) -> BoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::ListRemoteTasks(state));
                Ok(self
                    .remote_rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .values()
                    .filter(|task| task.last_state() == state)
                    .cloned()
                    .collect())
            })
        }
    }

    /// The recoverable set is exactly the in-flight span.
    #[test]
    fn recoverable_states_cover_the_in_flight_span() {
        assert_eq!(
            RECOVERABLE_STATES,
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::WaitingRemote,
                OperationState::Verifying,
            ]
        );
    }

    #[tokio::test]
    async fn create_rejects_empty_targets_without_touching_the_store() -> Result<(), Box<dyn Error>>
    {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();

        let error = engine
            .create(OperationSource::Standalone, Vec::new(), one_command(), now)
            .await
            .err()
            .ok_or_else(|| io::Error::other("empty-target create must fail"))?;
        assert_eq!(
            error.to_string(),
            "operation must target at least one object"
        );
        assert!(matches!(error, EngineError::EmptyTargets));
        // The store is never contacted for an operation that cannot execute.
        assert_eq!(store.calls()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn create_persists_a_queued_operation() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();

        let operation = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                now,
            )
            .await?;

        assert_eq!(operation.state(), OperationState::Queued);
        assert_eq!(operation.updated_at(), now);
        let stored = store
            .find_owned(operation.id())?
            .ok_or_else(|| io::Error::other("created operation must be stored"))?;
        assert_eq!(stored, operation);
        assert_eq!(store.calls()?, vec![Call::Create(operation.id())]);
        Ok(())
    }

    #[tokio::test]
    async fn create_persists_the_operation_together_with_its_command() -> Result<(), Box<dyn Error>>
    {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();

        let operation = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                now,
            )
            .await?;

        // The command is part of the persisted record from the first step:
        // the scheduler reads it back to dispatch the typed Redfish method
        // (design section 13.3 step 7) and restart recovery resumes the same
        // command (design section 13.6), so the read-back must be identical.
        assert_eq!(operation.command(), one_command());
        let stored = store
            .find_owned(operation.id())?
            .ok_or_else(|| io::Error::other("created operation must be stored"))?;
        assert_eq!(stored.command(), one_command());
        assert_eq!(stored, operation);
        assert_eq!(store.calls()?, vec![Call::Create(operation.id())]);
        Ok(())
    }

    #[tokio::test]
    async fn apply_runs_find_transition_write_round_trip() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();
        let created = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                now,
            )
            .await?;

        let later = now + Duration::SECOND;
        let updated = engine
            .apply(created.id(), OperationEvent::ValidationStarted, later)
            .await?;

        // The returned aggregate carries the domain-mutated state and the
        // exact occurrence time the store recorded.
        assert_eq!(updated.state(), OperationState::Validating);
        assert_eq!(updated.updated_at(), later);
        // The command survives the find-transition-write round trip: the
        // transitioned record is rehydrated from the stored row, so a step
        // must never lose what the operation is supposed to execute.
        assert_eq!(updated.command(), one_command());
        assert_eq!(
            store.calls()?,
            vec![
                Call::Create(created.id()),
                Call::Find(created.id()),
                Call::ApplyTransition(created.id(), OperationState::Validating),
            ]
        );
        assert_eq!(
            store.steps()?,
            vec![TransitionStep {
                operation_id: created.id(),
                new_state: OperationState::Validating,
                occurred_at: later,
            }]
        );
        Ok(())
    }

    #[tokio::test]
    async fn apply_reports_unknown_operations_as_not_found() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let unknown = OperationId::generate();

        let error = engine
            .apply(
                unknown,
                OperationEvent::ValidationStarted,
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| io::Error::other("apply on an unknown id must fail"))?;
        assert!(matches!(error, EngineError::NotFound(id) if id == unknown));
        assert_eq!(store.calls()?, vec![Call::Find(unknown)]);
        Ok(())
    }

    #[tokio::test]
    async fn apply_propagates_the_domains_invalid_transition_verdict() -> Result<(), Box<dyn Error>>
    {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();
        let created = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                now,
            )
            .await?;
        let validating = engine
            .apply(
                created.id(),
                OperationEvent::ValidationStarted,
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(validating.state(), OperationState::Validating);
        let failed = engine
            .apply(
                created.id(),
                OperationEvent::Failed,
                now + Duration::SECOND * 2,
            )
            .await?;
        assert_eq!(failed.state(), OperationState::Failed);

        let error = engine
            .apply(
                created.id(),
                OperationEvent::ValidationStarted,
                now + Duration::SECOND * 3,
            )
            .await
            .err()
            .ok_or_else(|| io::Error::other("transition out of a terminal state must fail"))?;

        let EngineError::InvalidTransition {
            operation_id,
            source,
        } = &error
        else {
            return Err(io::Error::other("expected an invalid-transition verdict").into());
        };
        assert_eq!(*operation_id, created.id());
        assert_eq!(
            source.to_string(),
            "event validation-started cannot occur in operation state failed"
        );
        // The domain verdict is the exact source of the engine error chain.
        let chain_source = std::error::Error::source(&error)
            .ok_or_else(|| io::Error::other("engine error must expose its source"))?;
        assert_eq!(chain_source.to_string(), source.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn store_conflicts_propagate_unchanged_through_the_source_chain()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();
        let created = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                now,
            )
            .await?;
        store.arm_write_failure()?;

        let error = engine
            .apply(
                created.id(),
                OperationEvent::ValidationStarted,
                now + Duration::SECOND,
            )
            .await
            .err()
            .ok_or_else(|| io::Error::other("conflicted apply must fail"))?;

        let EngineError::Store(store_error) = &error else {
            return Err(io::Error::other("expected a store boundary error").into());
        };
        assert_eq!(*store_error, FakeStoreError::Conflict);
        let chain_source = std::error::Error::source(&error)
            .ok_or_else(|| io::Error::other("engine error must expose its source"))?;
        assert_eq!(
            chain_source.to_string(),
            FakeStoreError::Conflict.to_string()
        );
        Ok(())
    }

    #[tokio::test]
    async fn recover_pending_lists_only_the_recoverable_states() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();

        // `running` ends in Running: the BMC write was in flight, recoverable.
        let running = advance_to(
            &engine,
            now,
            &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
            ],
        )
        .await?;
        // `validating` stays Validating: in flight, recoverable.
        let validating = advance_to(&engine, now, &[OperationEvent::ValidationStarted]).await?;
        // `verifying` ends in Verifying: the write landed and only the final
        // re-read was in flight; recovery re-reads and decides (§13.5).
        let verifying = advance_to(
            &engine,
            now,
            &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
                OperationEvent::ExecutionAccepted,
            ],
        )
        .await?;
        // `failed` ends in Failed: terminal, excluded from recovery.
        let failed = advance_to(
            &engine,
            now,
            &[OperationEvent::ValidationStarted, OperationEvent::Failed],
        )
        .await?;
        // `queued` never started: excluded from recovery (normal scheduling).
        let queued = advance_to(&engine, now, &[]).await?;

        assert_eq!(running.state(), OperationState::Running);
        assert_eq!(validating.state(), OperationState::Validating);
        assert_eq!(verifying.state(), OperationState::Verifying);
        assert_eq!(failed.state(), OperationState::Failed);
        assert_eq!(queued.state(), OperationState::Queued);

        let mut recovered_ids: Vec<_> = engine
            .recover_pending()
            .await?
            .into_iter()
            .map(|operation| operation.id())
            .collect();
        recovered_ids.sort();

        let mut expected = vec![running.id(), validating.id(), verifying.id()];
        expected.sort();
        assert_eq!(recovered_ids, expected);
        Ok(())
    }

    #[tokio::test]
    async fn waiting_remote_flow_persists_observations_and_resumes_verification()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();
        let created = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                now,
            )
            .await?;
        let endpoint_id = created.targets()[0].endpoint_id();
        let task_uri = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;
        let monitor_uri = TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/42")?;
        let mut occurred_at = now;

        // Queued → Validating → Running → WaitingRemote (§13.3 steps 6-8):
        // the 202 acceptance path of the operation state machine, driven by
        // the existing engine API.
        for event in [
            OperationEvent::ValidationStarted,
            OperationEvent::ValidationPassed,
            OperationEvent::RemoteTaskStarted,
        ] {
            occurred_at += Duration::SECOND;
            engine.apply(created.id(), event, occurred_at).await?;
        }
        let waiting = store
            .find_owned(created.id())?
            .ok_or_else(|| io::Error::other("the operation must be stored"))?;
        assert_eq!(waiting.state(), OperationState::WaitingRemote);

        // The acceptance observation is persisted right after the event, so
        // a crash before the first poll still leaves the URIs (§13.6).
        let accepted_at = occurred_at + Duration::SECOND;
        let acceptance = RemoteTask::new(
            created.id(),
            endpoint_id,
            task_uri.clone(),
            Some(monitor_uri.clone()),
            accepted_at,
        );
        store.save_remote_task(&acceptance).await?;
        assert_eq!(
            store.find_remote_task(created.id()).await?,
            Some(acceptance)
        );

        // §13.6 recovery: after a restart the scan reports the operation,
        // and its observation row is re-readable for the URIs.
        let recovered = engine.recover_pending().await?;
        assert_eq!(recovered, [waiting]);

        // The poll observed the terminal state; the newest observation is
        // saved, then the event drives WaitingRemote → Verifying.
        let polled_at = accepted_at + Duration::SECOND;
        let observed = RemoteTask::try_from_parts(
            created.id(),
            endpoint_id,
            task_uri,
            Some(monitor_uri),
            RemoteTaskState::Completed,
            Some("the power cycle completed".to_owned()),
            Some(100),
            polled_at,
        )?;
        store.save_remote_task(&observed).await?;
        assert_eq!(store.find_remote_task(created.id()).await?, Some(observed));

        // WaitingRemote → Verifying → Succeeded through the engine.
        occurred_at = polled_at;
        for event in [
            OperationEvent::RemoteTaskCompleted,
            OperationEvent::VerificationPassed,
        ] {
            occurred_at += Duration::SECOND;
            engine.apply(created.id(), event, occurred_at).await?;
        }
        let finished = store
            .find_owned(created.id())?
            .ok_or_else(|| io::Error::other("the operation must be stored"))?;
        assert_eq!(finished.state(), OperationState::Succeeded);
        assert!(finished.is_terminal());

        // The full call order: operation steps interleave with observation
        // saves and reads exactly as the §13.6 flow prescribes.
        assert_eq!(
            store.calls()?,
            [
                Call::Create(created.id()),
                Call::Find(created.id()),
                Call::ApplyTransition(created.id(), OperationState::Validating),
                Call::Find(created.id()),
                Call::ApplyTransition(created.id(), OperationState::Running),
                Call::Find(created.id()),
                Call::ApplyTransition(created.id(), OperationState::WaitingRemote),
                Call::SaveRemoteTask(created.id()),
                Call::FindRemoteTask(created.id()),
                Call::List(None),
                Call::SaveRemoteTask(created.id()),
                Call::FindRemoteTask(created.id()),
                Call::Find(created.id()),
                Call::ApplyTransition(created.id(), OperationState::Verifying),
                Call::Find(created.id()),
                Call::ApplyTransition(created.id(), OperationState::Succeeded),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_batch_persists_one_parent_and_single_target_children_in_one_call()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();
        let targets = [one_target(), one_target(), one_target()];

        let (batch, children) = engine
            .create_batch(OperationSource::Site, targets.to_vec(), one_command(), now)
            .await?;

        assert_eq!(batch.source(), OperationSource::Site);
        assert_eq!(batch.command(), one_command());
        assert_eq!(batch.created_at(), now);
        assert_eq!(children.len(), 3);
        // Every child is an ordinary single-target queued operation.
        for (child, target) in children.iter().zip(targets) {
            assert_eq!(child.state(), OperationState::Queued);
            assert_eq!(child.targets(), &[target]);
            assert_eq!(child.command(), one_command());
            assert_eq!(child.created_at(), now);
            assert_eq!(child.source(), OperationSource::Site);
        }
        // The children are distinct ordinary operations, exactly like any
        // other submitted operation, and the parent + all children landed in
        // one atomic store call (§13.7).
        let stored = store
            .find_batch_owned(batch.id())?
            .ok_or_else(|| io::Error::other("created batch must be stored"))?;
        assert_eq!(stored, batch);
        assert_eq!(store.list_batch_children_owned(batch.id())?, children);
        assert_eq!(store.calls()?, vec![Call::CreateBatch(batch.id())]);
        Ok(())
    }

    #[tokio::test]
    async fn create_batch_rejects_empty_targets_without_touching_the_store()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);

        let error = engine
            .create_batch(
                OperationSource::Standalone,
                Vec::new(),
                one_command(),
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| io::Error::other("empty-target batch must fail"))?;
        assert_eq!(
            error.to_string(),
            "operation must target at least one object"
        );
        assert!(matches!(error, EngineError::EmptyTargets));
        // The store is never contacted for a batch that cannot execute.
        assert_eq!(store.calls()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn create_batch_rejects_more_than_128_targets_without_touching_the_store()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let targets = (0..=MAX_BATCH_TARGETS)
            .map(|_| one_target())
            .collect::<Vec<_>>();

        let error = engine
            .create_batch(
                OperationSource::Standalone,
                targets,
                one_command(),
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| io::Error::other("over-limit batch must fail"))?;
        assert_eq!(
            error.to_string(),
            format!("a batch may target at most {MAX_BATCH_TARGETS} endpoints")
        );
        assert!(matches!(
            error,
            EngineError::TooManyTargets {
                limit: MAX_BATCH_TARGETS
            }
        ));
        // The store is never contacted for an over-limit batch.
        assert_eq!(store.calls()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn create_batch_redelivery_is_a_no_op_that_never_duplicates_children()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let now = OffsetDateTime::now_utc();
        let (batch, children) = engine
            .create_batch(
                OperationSource::Center,
                vec![one_target(), one_target()],
                one_command(),
                now,
            )
            .await?;

        // At-least-once delivery (§15.4): the same batch id delivered again
        // must be a no-op — the stored batch and its children are
        // authoritative and must never be re-inserted.
        store.create_batch(&batch, &children).await?;
        store.create_batch(&batch, &children).await?;

        let stored_batch = store.find_batch_owned(batch.id())?;
        assert_eq!(
            stored_batch.as_ref(),
            Some(&batch),
            "re-delivery must not rewrite the stored batch"
        );
        assert_eq!(
            store.list_batch_children_owned(batch.id())?,
            children,
            "re-delivery must never re-insert the children"
        );
        Ok(())
    }

    #[tokio::test]
    async fn list_batches_restores_acceptance_order_and_children_restore_target_order()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let engine = OperationEngine::new(&store);
        let base = OffsetDateTime::now_utc();

        let (later_batch, later_children) = engine
            .create_batch(
                OperationSource::Site,
                vec![one_target(), one_target(), one_target()],
                one_command(),
                base + Duration::SECOND,
            )
            .await?;
        let (earlier_batch, earlier_children) = engine
            .create_batch(
                OperationSource::Center,
                vec![one_target()],
                one_command(),
                base,
            )
            .await?;

        // The listing restores acceptance order (creation time, then
        // identity), matching the operation listing's deterministic order.
        let batches = store.list_batches().await?;
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].id(), earlier_batch.id());
        assert_eq!(batches[1].id(), later_batch.id());

        // Children restore in target order, pairing every endpoint with its
        // child (§13.7), regardless of the order the targets were submitted
        // in; the engine never writes failure kinds, so every child reads
        // back unclassified.
        let mut expected_children = later_children;
        expected_children
            .sort_by_key(|child| child.targets().first().map(|target| target.target_id()));
        let mut expected_pairs = expected_children
            .iter()
            .cloned()
            .map(|child| (child, None))
            .collect::<Vec<_>>();
        assert_eq!(
            store.list_batch_children(later_batch.id()).await?,
            expected_pairs
        );
        expected_pairs = earlier_children
            .iter()
            .cloned()
            .map(|child| (child, None))
            .collect();
        assert_eq!(
            store.list_batch_children(earlier_batch.id()).await?,
            expected_pairs
        );
        // An unknown batch id reads an empty child list; the parent
        // existence is a separate read.
        assert!(
            store
                .list_batch_children(BatchOperationId::generate())
                .await?
                .is_empty()
        );
        assert_eq!(store.find_batch(BatchOperationId::generate()).await?, None);
        Ok(())
    }

    /// Creates one operation and advances it through the given events.
    ///
    /// Each event fires one second after the previous one so the timeline
    /// stays strictly increasing; an empty step list leaves the operation
    /// `Queued`. The recovery test parks operations in each state this way
    /// because every advance is a separate engine round trip (create then
    /// apply), exactly like the production scheduler's persisted steps.
    async fn advance_to(
        engine: &OperationEngine<&FakeStore>,
        created_at: OffsetDateTime,
        steps: &[OperationEvent],
    ) -> Result<Operation, Box<dyn Error>> {
        let mut operation = engine
            .create(
                OperationSource::Standalone,
                vec![one_target()],
                one_command(),
                created_at,
            )
            .await?;
        let mut occurred_at = created_at;
        for &event in steps {
            occurred_at += Duration::SECOND;
            operation = engine.apply(operation.id(), event, occurred_at).await?;
        }
        Ok(operation)
    }

    /// Builds one engine-friendly target value.
    ///
    /// The engine only forwards targets, so a single representative value is
    /// enough for every test.
    fn one_target() -> OperationTarget {
        OperationTarget::new(TargetId::generate(), EndpointId::generate())
    }

    /// Builds one engine-friendly command value.
    ///
    /// The engine only forwards commands, so a single representative value is
    /// enough for every test; the domain owns the command vocabulary.
    fn one_command() -> RedfishCommand {
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
    }
}
