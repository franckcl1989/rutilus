use std::error::Error;

use rutilus_domain::{
    InvalidTransition, Operation, OperationEvent, OperationId, OperationSource, OperationState,
    OperationTarget, RedfishCommand,
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
        EndpointId, OperationId, OperationState, OperationTarget, ResetType, SystemCommand,
        TargetId,
    };
    use thiserror::Error;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::{BoundaryFuture, RemoteTask, RemoteTaskState, RemoteTaskStore, TaskUri};

    /// One recorded store call, in order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Create(OperationId),
        Find(OperationId),
        ApplyTransition(OperationId, OperationState),
        List(Option<OperationState>),
        SaveRemoteTask(OperationId),
        FindRemoteTask(OperationId),
        ListRemoteTasks(RemoteTaskState),
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
        calls: Mutex<Vec<Call>>,
        steps: Mutex<Vec<TransitionStep>>,
        fail_next_write: Mutex<bool>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                remote_rows: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                steps: Mutex::new(Vec::new()),
                fail_next_write: Mutex::new(false),
            }
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
