//! The asynchronous Task monitor (design sections 13.3 step 8, 13.5, and
//! 13.6).
//!
//! When the executor accepts a `202` Task
//! ([`CommandOutcome::AsyncTaskAccepted`](crate::CommandOutcome::AsyncTaskAccepted)),
//! it persists one [`RemoteTask`] observation row and moves the operation to
//! `WaitingRemote`. [`TaskMonitor`] resumes that operation: each
//! [`TaskMonitor::poll`] reads the Task through the [`TaskReader`] boundary,
//! persists the newest observation through [`RemoteTaskStore`], and advances
//! the §13.2 state machine when the observation is terminal.
//!
//! # The terminal decision (§13.5)
//!
//! Terminality is decided by [`RemoteTaskState::is_terminal`] — exactly
//! `Completed`, `Exception`, `Killed`, and `Cancelled`:
//!
//! - `Completed` — the write finished; the operation moves to `Verifying`
//!   (`RemoteTaskCompleted`) and the target is re-read and verified through
//!   the [`CommandVerifier`] boundary (§13.3 steps 9-10, §13.6 recovery
//!   verification) to `Succeeded`, `Failed`, or `Unknown`.
//! - `Exception` / `Killed` / `Cancelled` — the BMC's own Task record proves
//!   the write did not achieve its result, a provable failure (§13.5), so the
//!   operation is recorded `Failed` directly. It is deliberately NOT routed
//!   through the verification re-read: the re-read's accepted-style check
//!   could confirm a readable resource and fabricate success out of a failed
//!   Task (design section 13.7 forbids pretending partial success is whole
//!   success).
//! - The Task disappears (`404`), the operation's observation row is missing,
//!   or the wire state cannot be classified (`None`) — the product cannot
//!   prove the outcome (§13.5), so the operation is recorded `Unknown`. A
//!   disappeared Task is never re-created (design section 13.6); the state
//!   machine is the only authority (§7.1).
//! - A transient read failure changes nothing: the operation stays
//!   `WaitingRemote` and the scheduler polls again later
//!   ([`TaskPoll::Deferred`]). Reading a Task is a side-effect-free GET, so
//!   deferring is safe — unlike the §13.5 rule that a dispatched write whose
//!   response was lost must never be re-dispatched blindly.
//!
//! # Recovery (design section 13.6)
//!
//! After a restart, [`TaskMonitor::recover_tasks`] lists the `WaitingRemote`
//! operations for the scheduling loop to poll. The listing goes through the
//! operation store's exact-state query
//! ([`OperationStore::list_operations`](rutilus_operation_engine::OperationStore::list_operations)
//! with `Some(WaitingRemote)`), not through
//! [`OperationEngine::recover_pending`](rutilus_operation_engine::OperationEngine::recover_pending):
//! the monitor only resumes asynchronous Tasks, while the multi-state
//! recovery sweep (`Validating`/`Running`/`WaitingRemote`/`Verifying`)
//! belongs to the general scheduler. Each poll re-reads the persisted row
//! (Task URI, endpoint id) and resumes from there, exactly what §13.6 asks
//! for; the actual scheduling loop (pacing, backoff, bounded retries) is the
//! next iteration's work.
//!
//! # Audit
//!
//! The §16.3 start fact is recorded by the executor before dispatch; the
//! monitor records the terminal fact when the operation reaches its final
//! state, with the same failure classes and verification semantics as the
//! executor's synchronous terminal facts, under the execute-operation
//! vocabulary with the [`AuditRedfishOperation::PollRemoteTask`] operation
//! type. Per-poll progress is not audited: the 0.1 `AuditProgress` vocabulary
//! has no truthful milestone for "task polled", and design section 13.6
//! progress is persisted on the `RemoteTask` row itself. The monitor
//! reconstructs the terminal fact's context from the operation's endpoint and
//! the injected actor/origin with a fresh correlation id — the append-only
//! audit boundary has no read path to recover the executor's start context,
//! so the start and terminal facts of one asynchronous operation carry
//! different `AuditOperationId`s until an audit-read boundary lands.
//!
//! # Test coverage
//!
//! The mock BMC (`rutilus-test-support`) serves only a static Running Task
//! fixture and never answers a write with `202`, so the §19.1 mock-BMC Task
//! coverage and the end-to-end acceptance → poll → completion cycle are left
//! for the scheduler iteration; this iteration exercises the full Task flow
//! through the fakes in this module's tests.

use std::{error::Error, fmt};

use rutilus_domain::{
    AuditActor, AuditEvent, AuditFailure, AuditFailureVerification, AuditOperationContext,
    AuditRedfishOperation, AuditSequence, DeploymentPosture, EndpointId, Operation, OperationEvent,
    OperationId, OperationState, RedfishCommand,
};
use rutilus_operation_engine::{
    EngineError, OperationEngine, OperationStore, RemoteTask, RemoteTaskError, RemoteTaskState,
    RemoteTaskStore, TaskUri,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AuditEventWriter, AuditRecordError, BoundaryFuture, CommandVerifier, VerificationVerdict,
    operation_executor::operation_audit_context,
};

/// The concrete failure type of one Task poll or recovery scan.
///
/// The generic parameters are the four boundary error types, in
/// [`TaskMonitorError`] order: operation store, remote-task store, target
/// verifier, and audit. Keeping them separate preserves every source chain,
/// exactly like the executor's error. The Task reader's error is not part of
/// the vocabulary: a failed read is [`TaskPoll::Deferred`], never an error.
type TaskMonitorErrorOf<Store, Reader, Audit> = TaskMonitorError<
    <Store as OperationStore>::Error,
    <Store as RemoteTaskStore>::Error,
    <Reader as CommandVerifier>::Error,
    <Audit as AuditEventWriter>::Error,
>;

/// Reads one asynchronous Task resource through the application-owned Redfish
/// boundary (design section 13.6).
///
/// The endpoint row (address, TLS trust, credential) is resolved by the
/// implementation from `endpoint_id`; the monitor never sees credentials,
/// addresses, or `nv-redfish` types (design section 7.2), mirroring
/// [`CommandExecutor`](crate::CommandExecutor). `Ok(None)` is the distinct
/// disappearance signal — the BMC no longer tracks the Task (`404`) — which
/// the monitor records as an outcome it cannot prove (§13.5) instead of a
/// transient failure.
///
/// # Errors
///
/// `Self::Error` reports every failed read (transport, session,
/// authentication, decode). The monitor treats any error as transient:
/// nothing is persisted and the operation stays `WaitingRemote` for the next
/// poll.
pub trait TaskReader: Send + Sync {
    /// The Task read boundary's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    fn read_task<'a>(
        &'a self,
        endpoint_id: EndpointId,
        task_uri: &'a TaskUri,
    ) -> BoundaryFuture<'a, Result<Option<TaskObservation>, Self::Error>>;
}

impl<Reader> TaskReader for &Reader
where
    Reader: TaskReader + ?Sized,
{
    type Error = Reader::Error;

    fn read_task<'a>(
        &'a self,
        endpoint_id: EndpointId,
        task_uri: &'a TaskUri,
    ) -> BoundaryFuture<'a, Result<Option<TaskObservation>, Self::Error>> {
        Reader::read_task(*self, endpoint_id, task_uri)
    }
}

/// One wire-observed Task document, projected for the §13.6 observation
/// contract.
///
/// The adapter constructs this from its gateway's Task projection. The
/// state is `Option<RemoteTaskState>` on purpose: a wire state this build
/// cannot classify (a newer CSDL code, or an absent `TaskState`) must not be
/// disguised as a known state (design section 7.6), and the monitor treats it
/// as an outcome it cannot prove. `percent_complete` must already lie in
/// `0..=100`; a corrupt wire value is dropped by the adapter and recorded as
/// no progress, never displayed as progress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskObservation {
    state: Option<RemoteTaskState>,
    message: Option<String>,
    percent_complete: Option<u64>,
    task_monitor_uri: Option<TaskUri>,
}

impl TaskObservation {
    #[must_use]
    pub fn new(
        state: Option<RemoteTaskState>,
        message: Option<String>,
        percent_complete: Option<u64>,
        task_monitor_uri: Option<TaskUri>,
    ) -> Self {
        Self {
            state,
            message,
            percent_complete,
            task_monitor_uri,
        }
    }

    /// Returns the classified wire state; `None` means the wire value cannot
    /// be classified and the outcome cannot be proven.
    #[must_use]
    pub const fn state(&self) -> Option<RemoteTaskState> {
        self.state
    }

    /// Returns the newest Task message, when the BMC reported one.
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns the observed completion percentage in `0..=100`, when the BMC
    /// provided one.
    #[must_use]
    pub const fn percent_complete(&self) -> Option<u64> {
        self.percent_complete
    }

    /// Returns the `TaskMonitor` URI the Task document advertises, when the
    /// BMC provided one.
    #[must_use]
    pub const fn task_monitor_uri(&self) -> Option<&TaskUri> {
        self.task_monitor_uri.as_ref()
    }
}

/// What one [`TaskMonitor::poll`] did to the operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskPoll {
    /// The Task is still in flight and the newest observation was persisted;
    /// the operation stays `WaitingRemote` and the scheduler polls again.
    StillRunning(Operation),
    /// The Task read failed transiently; nothing was persisted or audited and
    /// the operation stays `WaitingRemote`. The scheduler polls again later
    /// (a Task read is a side-effect-free GET, so deferring is always safe).
    Deferred(Operation),
    /// The poll drove the operation out of `WaitingRemote` into its terminal
    /// state (`Succeeded`, `Failed`, or `Unknown`); the scheduler stops
    /// polling it. When the terminal fact could not be recorded, the poll
    /// returns an error instead and the operation's state can be re-read.
    Terminal(Operation),
}

/// Resumes the §13.6 asynchronous Task flow of persisted operations.
///
/// `Store` stays one constructor parameter although it plays two roles —
/// operation lifecycle and remote-task observation rows — because every
/// runtime composes one `SqliteStore` implementing both, exactly like the
/// executor. `Reader` implements both Task reads and post-Task target
/// verification on the same Redfish gateway object (the executor's gateway
/// plays the same double role for dispatch and verification), and `Audit`
/// appends the §16.3 terminal fact.
///
/// # Why no clock
///
/// The observation time enters through [`Self::poll`]'s `now` argument
/// instead of an injected [`Clock`]: the scheduling loop owns the clock and
/// supplies the same instant for the observation row, the §13.2 step, and the
/// audit fact, exactly like the executor's callers supply `now` to the
/// engine. A clock field would be a second time authority that the poll's
/// argument would shadow, so the monitor stays deterministic under any clock.
pub struct TaskMonitor<Store, Reader, Audit> {
    store: Store,
    reader: Reader,
    audit: Audit,
    actor: AuditActor,
    origin: DeploymentPosture,
}

impl<Store, Reader, Audit> TaskMonitor<Store, Reader, Audit>
where
    Store: OperationStore + RemoteTaskStore,
    Reader: TaskReader + CommandVerifier,
    Audit: AuditEventWriter,
{
    /// Wraps the store, the Redfish reader/verifier, and the audit writer.
    ///
    /// `actor` and `origin` are injected the same way the executor does: they
    /// are the §16.3 "who" and "from where" facts of the recorded terminal
    /// event.
    #[must_use]
    pub fn new(
        store: Store,
        reader: Reader,
        audit: Audit,
        actor: AuditActor,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            store,
            reader,
            audit,
            actor,
            origin,
        }
    }

    /// Polls one asynchronous Task and drives the operation it belongs to.
    ///
    /// # Flow
    ///
    /// 1. Read the operation. Only `WaitingRemote` work is pollable; a
    ///    not-found id and a non-waiting state are defensive rejects that
    ///    change nothing and record no audit.
    /// 2. Read the §13.6 observation row. A `WaitingRemote` operation without
    ///    a row has lost its Task reference — the product cannot prove the
    ///    outcome — so it is recorded `Unknown` (§13.5).
    /// 3. Read the Task through [`TaskReader`]. A failed read changes
    ///    nothing ([`TaskPoll::Deferred`]); a disappeared Task (`Ok(None)`)
    ///    is an outcome the product cannot prove, recorded `Unknown` (§13.5,
    ///    §13.6: a disappeared Task is never re-created).
    /// 4. Persist the newest observation (state, message, progress, check
    ///    time) on the row — the §13.6 progress record, saved before any
    ///    state step so a crash cannot lose the terminal observation.
    /// 5. Decide by the terminality of the observed state (see the module
    ///    doc): still in flight keeps `WaitingRemote`; `Completed` moves to
    ///    `Verifying` and re-reads the target (§13.6 recovery verification);
    ///    `Exception`/`Killed`/`Cancelled` are provable failures; a
    ///    disappeared or unclassifiable Task is `Unknown`.
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::OperationNotFound`] for an unknown id,
    /// [`TaskMonitorError::NotWaitingRemote`] when the operation is no longer
    /// `WaitingRemote` (including a second driver racing this id — the engine
    /// reports the state the domain observed), [`TaskMonitorError::EmptyTargets`]
    /// for a corrupt zero-target row, and the store, verification, and audit
    /// boundary errors with their sources chained (a failed Task read is
    /// [`TaskPoll::Deferred`], not an error). A failed verification re-read
    /// still persists the operation's honest terminal state (`Unknown`)
    /// before the error is returned, so a caller that sees an error can
    /// re-read the operation for its outcome.
    pub async fn poll(
        &self,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> Result<TaskPoll, TaskMonitorErrorOf<Store, Reader, Audit>> {
        // The monitor drives only waiting work. The pre-read goes through the
        // same `OperationStore` boundary the engine itself uses: the poll
        // must inspect the aggregate (state, first target, command) before
        // the first persisted step.
        let Some(operation) = self
            .store
            .find_operation(operation_id)
            .await
            .map_err(TaskMonitorError::Store)?
        else {
            return Err(TaskMonitorError::OperationNotFound(operation_id));
        };
        if operation.state() != OperationState::WaitingRemote {
            return Err(TaskMonitorError::NotWaitingRemote {
                operation_id,
                state: operation.state(),
            });
        }
        let Some(endpoint_id) = operation
            .targets()
            .first()
            .map(|target| target.endpoint_id())
        else {
            // `OperationEngine::create` rejects empty target lists, but
            // rehydration does not re-check them, so a corrupt persisted row
            // can still reach the monitor; a target is needed for the §13.6
            // recovery verification.
            return Err(TaskMonitorError::EmptyTargets(operation_id));
        };
        let engine = OperationEngine::new(&self.store);

        let Some(task) = self
            .store
            .find_remote_task(operation_id)
            .await
            .map_err(TaskMonitorError::RemoteTaskStore)?
        else {
            // The operation claims to wait on a Task the product has no row
            // for: the reference is lost, the outcome cannot be proven.
            return self
                .resolve_unknown(&engine, operation_id, endpoint_id, now)
                .await;
        };

        match self.reader.read_task(endpoint_id, task.task_uri()).await {
            // A transient read failure is not a verdict: the write's Task
            // still exists or not, and only a successful read can tell.
            // Nothing is persisted and the operation stays WaitingRemote.
            Err(_) => Ok(TaskPoll::Deferred(operation)),
            // The BMC no longer tracks the Task: the outcome cannot be
            // proven and the Task is never re-created (§13.5, §13.6).
            Ok(None) => {
                self.resolve_unknown(&engine, operation_id, endpoint_id, now)
                    .await
            }
            Ok(Some(observation)) => {
                self.observe(&engine, operation, &task, &observation, now)
                    .await
            }
        }
    }

    /// Lists the operations the scheduling loop must poll after a restart
    /// (design section 13.6).
    ///
    /// Returns every operation currently in `WaitingRemote`, in store order.
    /// The listing needs no clock — it is a pure scan; the clock enters the
    /// loop through [`Self::poll`], which persists its own observation time —
    /// and it goes through the store's exact-state query so the persistence
    /// layer filters by state instead of scanning every operation. The
    /// returned list is a snapshot: the loop re-reads each operation in
    /// `poll` and the §13.2 state machine rejects any step that races another
    /// driver. The actual scheduling loop (pacing, backoff, bounded retries)
    /// is the next iteration's work.
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::Store`] when the operation store fails.
    pub async fn recover_tasks(
        &self,
    ) -> Result<Vec<Operation>, TaskMonitorErrorOf<Store, Reader, Audit>> {
        self.store
            .list_operations(Some(OperationState::WaitingRemote))
            .await
            .map_err(TaskMonitorError::Store)
    }

    /// Records the newest observation and decides the §13.2 step it selects.
    ///
    /// The observation row is always saved first — even for terminal
    /// observations, which become the durable final record the §14.2
    /// running-task projection reads — and only then is the operation state
    /// advanced.
    async fn observe(
        &self,
        engine: &OperationEngine<&Store>,
        operation: Operation,
        task: &RemoteTask,
        observation: &TaskObservation,
        now: OffsetDateTime,
    ) -> Result<TaskPoll, TaskMonitorErrorOf<Store, Reader, Audit>> {
        let Some(state) = observation.state() else {
            // A wire state this build cannot classify is not a state the
            // product may decide on (design section 7.6): the outcome cannot
            // be proven.
            return self
                .resolve_unknown(engine, operation.id(), task.endpoint_id(), now)
                .await;
        };
        let updated = Self::updated_row(task, observation, state, now).map_err(|source| {
            TaskMonitorError::RemoteTaskObservation {
                operation_id: task.operation_id(),
                source,
            }
        })?;
        self.store
            .save_remote_task(&updated)
            .await
            .map_err(TaskMonitorError::RemoteTaskStore)?;
        if !state.is_terminal() {
            return Ok(TaskPoll::StillRunning(operation));
        }
        let operation_id = operation.id();
        let endpoint_id = task.endpoint_id();
        let command = operation.command();
        if state == RemoteTaskState::Completed {
            // §13.3 step 8, Task completed: the write finished and the target
            // must now be re-read and verified (steps 9-10, §13.6 recovery
            // verification).
            self.apply_step(
                engine,
                operation_id,
                OperationEvent::RemoteTaskCompleted,
                now,
            )
            .await?;
            return self
                .verify_target(engine, operation_id, endpoint_id, &command, now)
                .await;
        }
        // `Exception`, `Killed`, and `Cancelled` are terminal states the
        // BMC's own Task record proves the write did not achieve: a provable
        // failure (§13.5), never routed through the weaker re-read that could
        // fabricate success (§13.7).
        let final_operation = self
            .apply_step(engine, operation_id, OperationEvent::Failed, now)
            .await?;
        self.record_failure(
            endpoint_id,
            AuditFailure::RedfishDiscoveryFailed,
            AuditFailureVerification::Rejected,
            now,
        )
        .await?;
        Ok(TaskPoll::Terminal(final_operation))
    }

    /// Builds the newest observation row from the stored row and the wire
    /// observation.
    ///
    /// The `TaskMonitor` URI of the wire document replaces the stored value
    /// when the BMC provided one (the acceptance-time row has none; the first
    /// read discovers it). A corrupt `PercentComplete` (outside `0..=100`) is
    /// recorded as no progress — it must not be displayed as progress — and
    /// never decides anything; the `try_from_parts` validation is the model's
    /// own defense.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteTaskError::PercentOutOfRange`] when the model rejects
    /// the observation — defensively reachable only through a future
    /// extension of the model's validation, since the percent is normalized
    /// here first.
    fn updated_row(
        task: &RemoteTask,
        observation: &TaskObservation,
        state: RemoteTaskState,
        now: OffsetDateTime,
    ) -> Result<RemoteTask, RemoteTaskError> {
        RemoteTask::try_from_parts(
            task.operation_id(),
            task.endpoint_id(),
            task.task_uri().clone(),
            observation
                .task_monitor_uri()
                .cloned()
                .or_else(|| task.task_monitor_uri().cloned()),
            state,
            observation.message().map(str::to_owned),
            observation
                .percent_complete()
                .filter(|percent| *percent <= 100),
            now,
        )
    }

    /// Re-reads the target and checks the expected result (§13.3 steps 9-10)
    /// after a completed Task, then writes the terminal state and audit fact
    /// (design section 13.6 recovery verification).
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::Verifier`] with the re-read error as its
    /// source after the operation has been persisted into `Unknown` (a failed
    /// re-read proves nothing about the completed Task, design section 13.5)
    /// and the terminal audit fact has been recorded.
    async fn verify_target(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
        now: OffsetDateTime,
    ) -> Result<TaskPoll, TaskMonitorErrorOf<Store, Reader, Audit>> {
        match self.reader.verify(endpoint_id, command).await {
            Ok(VerificationVerdict::Confirmed) => {
                let final_operation = self
                    .apply_step(
                        engine,
                        operation_id,
                        OperationEvent::VerificationPassed,
                        now,
                    )
                    .await?;
                self.record_success(endpoint_id, now).await?;
                Ok(TaskPoll::Terminal(final_operation))
            }
            Ok(VerificationVerdict::Mismatched) => {
                // The re-read proves the expected result is absent: the
                // completed Task did not achieve its result, a provable
                // failure.
                let final_operation = self
                    .apply_step(engine, operation_id, OperationEvent::Failed, now)
                    .await?;
                self.record_failure(
                    endpoint_id,
                    AuditFailure::CoreResourceReadFailed,
                    AuditFailureVerification::Rejected,
                    now,
                )
                .await?;
                Ok(TaskPoll::Terminal(final_operation))
            }
            Err(source) => {
                // §13.5: a failed re-read proves nothing about the write, so
                // the outcome cannot be confirmed and the operation is
                // recorded Unknown; the error escapes with its source chain.
                self.apply_step(engine, operation_id, OperationEvent::OutcomeUnknown, now)
                    .await?;
                self.record_failure(
                    endpoint_id,
                    AuditFailure::CoreResourceReadFailed,
                    AuditFailureVerification::Inconclusive,
                    now,
                )
                .await?;
                Err(TaskMonitorError::Verifier(source))
            }
        }
    }

    /// Records the operation `Unknown`: the product cannot prove the outcome
    /// of a Task it cannot observe (§13.5).
    ///
    /// # Errors
    ///
    /// Returns the store or audit boundary error when either write fails;
    /// the operation has already reached its terminal state in the store by
    /// then.
    async fn resolve_unknown(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<TaskPoll, TaskMonitorErrorOf<Store, Reader, Audit>> {
        let final_operation = self
            .apply_step(engine, operation_id, OperationEvent::OutcomeUnknown, now)
            .await?;
        self.record_failure(
            endpoint_id,
            AuditFailure::RedfishDiscoveryFailed,
            AuditFailureVerification::Inconclusive,
            now,
        )
        .await?;
        Ok(TaskPoll::Terminal(final_operation))
    }

    /// Persists one §13.2 state step through the operation engine.
    ///
    /// # Errors
    ///
    /// Maps the engine verdicts onto the monitor's error vocabulary: a store
    /// failure propagates with its source, a not-found race becomes
    /// [`TaskMonitorError::OperationNotFound`], and an invalid-transition
    /// race (a second driver advanced the operation between the poll's read
    /// and this step) becomes [`TaskMonitorError::NotWaitingRemote`] with the
    /// state the domain reported — the same defense as the initial
    /// waiting-remote-only check.
    async fn apply_step(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        event: OperationEvent,
        now: OffsetDateTime,
    ) -> Result<Operation, TaskMonitorErrorOf<Store, Reader, Audit>> {
        engine
            .apply(operation_id, event, now)
            .await
            .map_err(|error| match error {
                EngineError::NotFound(_) => TaskMonitorError::OperationNotFound(operation_id),
                EngineError::InvalidTransition {
                    operation_id,
                    source,
                } => TaskMonitorError::NotWaitingRemote {
                    operation_id,
                    state: source.from_state(),
                },
                // `apply` never reports StateChanged (that verdict is raised
                // only by the compare-and-set `apply_if_current`); the arm
                // exists only because `EngineError` is a closed enum, mapping
                // the moved state onto the same defensive guard.
                EngineError::StateChanged {
                    operation_id,
                    observed,
                    ..
                } => TaskMonitorError::NotWaitingRemote {
                    operation_id,
                    state: observed,
                },
                EngineError::Store(source) => TaskMonitorError::Store(source),
                // `apply` never reports EmptyTargets (the engine rejects
                // empty target lists at create time) or the batch-creation
                // limit (that verdict is raised only by `create_batch`); the
                // arms exist only because `EngineError` is a closed enum.
                EngineError::EmptyTargets | EngineError::TooManyTargets { .. } => {
                    TaskMonitorError::EmptyTargets(operation_id)
                }
            })
    }

    /// Appends the §16.3 terminal failure fact with the monitor's own
    /// reconstructed context.
    ///
    /// The failure classes are the same closest 0.1 vocabulary values the
    /// executor uses (a failed Task and an unobservable Task are recorded
    /// with the discovery class; a verification mismatch with the
    /// core-resource-read class), and the verification class is the truthful
    /// part: `Rejected` for every provable outcome and `Inconclusive` for
    /// every outcome the product cannot prove (design section 13.5).
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::Audit`] with the terminal stage when the
    /// event cannot be constructed or the append fails; the operation has
    /// already reached its terminal state in the store by then.
    async fn record_failure(
        &self,
        endpoint_id: EndpointId,
        failure: AuditFailure,
        verification: AuditFailureVerification,
        occurred_at: OffsetDateTime,
    ) -> Result<(), TaskMonitorErrorOf<Store, Reader, Audit>> {
        let context = self.audit_context(endpoint_id)?;
        let failed = AuditEvent::failed(
            context,
            Self::terminal_sequence()?,
            failure,
            verification,
            occurred_at,
        )
        .map_err(|source| TaskMonitorError::Audit {
            stage: MonitorAuditStage::Terminal,
            source: AuditRecordError::Event(source),
        })?;
        self.audit
            .append_audit_event(&failed)
            .await
            .map_err(|source| TaskMonitorError::Audit {
                stage: MonitorAuditStage::Terminal,
                source: AuditRecordError::Write(source),
            })
    }

    /// Appends the §16.3 terminal success fact.
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::Audit`] with the terminal stage when the
    /// event cannot be constructed or the append fails; the operation has
    /// already reached `Succeeded` in the store by then.
    async fn record_success(
        &self,
        endpoint_id: EndpointId,
        occurred_at: OffsetDateTime,
    ) -> Result<(), TaskMonitorErrorOf<Store, Reader, Audit>> {
        let context = self.audit_context(endpoint_id)?;
        let succeeded = AuditEvent::succeeded(context, Self::terminal_sequence()?, occurred_at)
            .map_err(|source| TaskMonitorError::Audit {
                stage: MonitorAuditStage::Terminal,
                source: AuditRecordError::Event(source),
            })?;
        self.audit
            .append_audit_event(&succeeded)
            .await
            .map_err(|source| TaskMonitorError::Audit {
                stage: MonitorAuditStage::Terminal,
                source: AuditRecordError::Write(source),
            })
    }

    /// Builds the monitor's §16.3 context for one endpoint.
    ///
    /// The context reuses the executor's execute-operation vocabulary (see
    /// [`operation_audit_context`]) with
    /// [`AuditRedfishOperation::PollRemoteTask`]: the terminal fact of an
    /// asynchronous lifecycle describes the Task polling that observed the
    /// outcome, not the write itself (which the executor's start fact
    /// already names). It carries a fresh `AuditOperationId`: the
    /// append-only audit boundary has no read path to recover the
    /// executor's start context, so the start (executor) and terminal
    /// (monitor) facts of one asynchronous operation are correlated only by
    /// the endpoint, actor, and origin until an audit-read boundary lands
    /// (see the module doc).
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::Audit`] with the terminal stage when the
    /// combination is not one the 0.1 vocabulary accepts.
    fn audit_context(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<AuditOperationContext, TaskMonitorErrorOf<Store, Reader, Audit>> {
        operation_audit_context(
            endpoint_id,
            AuditRedfishOperation::PollRemoteTask,
            self.actor,
            self.origin,
        )
        .map_err(|source| TaskMonitorError::Audit {
            stage: MonitorAuditStage::Terminal,
            source: AuditRecordError::Context(source),
        })
    }

    /// The terminal sequence of the operation lifecycle: the executor wrote
    /// the start fact as `AuditSequence::FIRST`, so the monitor's terminal
    /// fact is the next sequence.
    ///
    /// # Errors
    ///
    /// Returns [`TaskMonitorError::Audit`] with the terminal stage when the
    /// sequence cannot advance (an exhausted sequence counter).
    fn terminal_sequence() -> Result<AuditSequence, TaskMonitorErrorOf<Store, Reader, Audit>> {
        AuditSequence::FIRST
            .next()
            .map_err(|source| TaskMonitorError::Audit {
                stage: MonitorAuditStage::Terminal,
                source: AuditRecordError::Sequence(source),
            })
    }
}

/// A controlled failure while polling or recovering a §13.6 Task.
///
/// The four generic parameters are the boundary error types in dependency
/// order: the operation store, the remote-task store, the target verifier,
/// and the audit append. Every variant keeps its boundary source on the
/// error chain. The Task reader's own error type is deliberately absent: a
/// failed Task read is a transient, side-effect-free miss that the poll
/// encodes as [`TaskPoll::Deferred`] instead of an error.
#[derive(Debug, Error)]
pub enum TaskMonitorError<StoreError, RemoteTaskStoreError, VerifierError, AuditError>
where
    StoreError: Error + 'static,
    RemoteTaskStoreError: Error + 'static,
    VerifierError: Error + 'static,
    AuditError: Error + 'static,
{
    /// The operation id is not known to the store.
    #[error("operation {0} was not found")]
    OperationNotFound(OperationId),
    /// The poll tried to drive an operation that is no longer waiting on a
    /// Task.
    ///
    /// This is the defensive guard for the waiting-remote-only polling
    /// contract: either the caller passed a state the monitor must not
    /// touch, or a second driver advanced the operation between the poll's
    /// read and its first persisted step (the domain state machine reported
    /// the current state).
    #[error("operation {operation_id} is {state} and only waiting-remote operations are pollable")]
    NotWaitingRemote {
        operation_id: OperationId,
        state: OperationState,
    },
    /// The persisted operation carries no target and can never be verified.
    ///
    /// `OperationEngine::create` rejects empty target lists, so this is a
    /// corrupt row that rehydration (`Operation::try_from_parts`) failed to
    /// reject.
    #[error("operation {0} carries no target and cannot be verified")]
    EmptyTargets(OperationId),
    /// The operation store rejected a read or a persisted step.
    #[error("operation store failed: {0}")]
    Store(#[source] StoreError),
    /// The remote-task observation store rejected a read or a save.
    #[error("remote task store failed: {0}")]
    RemoteTaskStore(#[source] RemoteTaskStoreError),
    /// The newest Task observation cannot be represented in the persisted
    /// model.
    ///
    /// The monitor normalizes what it can (a corrupt `PercentComplete` is
    /// recorded as no progress), so this fires only when the model's own
    /// validation rejects the observation — a defense against a future
    /// extension of the validation rather than an expected poll outcome.
    #[error("the Task observation of operation {operation_id} is invalid: {source}")]
    RemoteTaskObservation {
        operation_id: OperationId,
        #[source]
        source: RemoteTaskError,
    },
    /// The §13.6 recovery verification re-read failed.
    ///
    /// The operation has already been persisted into `Unknown` (a failed
    /// re-read proves nothing about the completed Task, design section 13.5)
    /// and its terminal audit fact has been recorded before this error is
    /// returned.
    #[error("post-Task verification failed: {0}")]
    Verifier(#[source] VerifierError),
    /// The §16.3 audit lifecycle could not be fully recorded.
    #[error("task monitor audit {stage} failed: {source}")]
    Audit {
        stage: MonitorAuditStage,
        #[source]
        source: AuditRecordError<AuditError>,
    },
}

/// The audit lifecycle point that could not be recorded (§16.3).
///
/// The monitor only writes the terminal fact of an asynchronous lifecycle
/// (the executor writes the start fact), so this is the only stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitorAuditStage {
    /// The terminal fact could not be appended; the operation has already
    /// reached its terminal state in the store.
    Terminal,
}

impl fmt::Display for MonitorAuditStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Terminal => formatter.write_str("terminal"),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        error::Error,
        fmt,
        sync::Mutex,
    };

    use rutilus_domain::{
        AuditAction, AuditOutcomeKind, AuditRedfishOperation, AuditTarget, AuditVerification,
        EndpointId, OperationId, OperationSource, OperationState, OperationTarget, RedfishCommand,
        ResetType, SystemCommand, TargetId,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild,
    };
    use time::{Duration, OffsetDateTime};

    use crate::BoundaryFuture;

    use super::*;

    /// The creation time of every test operation.
    fn created_at() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// The fixed poll instants, one second apart so the timeline stays
    /// strictly increasing.
    fn first_poll_at() -> OffsetDateTime {
        created_at() + Duration::SECOND * 2
    }

    fn second_poll_at() -> OffsetDateTime {
        created_at() + Duration::SECOND * 3
    }

    /// The stable command every test operation carries.
    fn one_command() -> RedfishCommand {
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
    }

    /// Builds one operation parked in `WaitingRemote` on `endpoint_id`.
    fn waiting_operation(endpoint_id: EndpointId) -> Result<Operation, Box<dyn Error>> {
        Ok(Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            one_command(),
            OperationState::WaitingRemote,
            created_at(),
            created_at() + Duration::SECOND,
        )?)
    }

    /// Builds the acceptance row of one waiting operation.
    fn task_row(
        operation_id: OperationId,
        endpoint_id: EndpointId,
        task_uri: &str,
    ) -> Result<RemoteTask, Box<dyn Error>> {
        Ok(RemoteTask::new(
            operation_id,
            endpoint_id,
            TaskUri::parse(task_uri)?,
            None,
            created_at() + Duration::SECOND,
        ))
    }

    /// One recorded store call, in order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StoreCall {
        FindOperation(OperationId),
        ApplyTransition(OperationId, OperationState),
        ListOperations(Option<OperationState>),
        SaveRemoteTask(OperationId),
        FindRemoteTask(OperationId),
    }

    /// The single failure mode armed for the next matching store call.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailureKind {
        OperationRead,
        OperationWrite,
        RemoteTaskRead,
        RemoteTaskWrite,
    }

    /// In-memory store implementing both store boundaries the monitor uses,
    /// exactly like the production `SqliteStore`.
    ///
    /// `apply_transition` upholds the store contract: unknown ids and writes
    /// onto terminal states are rejected.
    struct FakeStore {
        operations: Mutex<HashMap<OperationId, Operation>>,
        remote_tasks: Mutex<HashMap<OperationId, RemoteTask>>,
        calls: Mutex<Vec<StoreCall>>,
        fail_once: Mutex<Option<FailureKind>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                operations: Mutex::new(HashMap::new()),
                remote_tasks: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
                fail_once: Mutex::new(None),
            }
        }

        fn insert_operation(&self, operation: Operation) -> Result<(), MockError> {
            self.operations
                .lock()
                .map_err(|_| MockError::Events)?
                .insert(operation.id(), operation);
            Ok(())
        }

        fn insert_remote_task(&self, task: RemoteTask) -> Result<(), MockError> {
            self.remote_tasks
                .lock()
                .map_err(|_| MockError::Events)?
                .insert(task.operation_id(), task);
            Ok(())
        }

        fn arm_failure(&self, kind: FailureKind) -> Result<(), MockError> {
            *self.fail_once.lock().map_err(|_| MockError::Events)? = Some(kind);
            Ok(())
        }

        fn recorded_calls(&self) -> Result<Vec<StoreCall>, MockError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }

        fn find_operation_owned(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<Operation>, MockError> {
            self.operations
                .lock()
                .map_err(|_| MockError::Events)
                .map(|rows| rows.get(&operation_id).cloned())
        }

        fn find_remote_task_owned(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<RemoteTask>, MockError> {
            self.remote_tasks
                .lock()
                .map_err(|_| MockError::Events)
                .map(|rows| rows.get(&operation_id).cloned())
        }

        /// Consumes the armed failure when it matches `kind`.
        fn consume_failure(&self, kind: FailureKind) -> Result<bool, MockError> {
            let mut slot = self.fail_once.lock().map_err(|_| MockError::Events)?;
            if *slot == Some(kind) {
                *slot = None;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    impl OperationStore for FakeStore {
        type Error = MockError;

        fn create_operation<'a>(
            &'a self,
            _operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The monitor never creates operations; the executor owns that
            // boundary, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn find_operation(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::FindOperation(operation_id));
                if self.consume_failure(FailureKind::OperationRead)? {
                    return Err(MockError::Store);
                }
                self.find_operation_owned(operation_id)
            })
        }

        fn apply_transition(
            &self,
            operation_id: OperationId,
            new_state: OperationState,
            occurred_at: OffsetDateTime,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::ApplyTransition(operation_id, new_state));
                if self.consume_failure(FailureKind::OperationWrite)? {
                    return Err(MockError::Store);
                }
                let mut rows = self.operations.lock().map_err(|_| MockError::Events)?;
                let row = rows.get(&operation_id).ok_or(MockError::Store)?;
                if row.is_terminal() {
                    return Err(MockError::Store);
                }
                let row = rows.get_mut(&operation_id).ok_or(MockError::Store)?;
                *row = Operation::try_from_parts(
                    row.id(),
                    row.source(),
                    row.targets().to_vec(),
                    row.command(),
                    new_state,
                    row.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockError::Store)?;
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
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::ApplyTransition(operation_id, new_state));
                if self.consume_failure(FailureKind::OperationWrite)? {
                    return Err(MockError::Store);
                }
                let mut rows = self.operations.lock().map_err(|_| MockError::Events)?;
                let row = rows.get(&operation_id).ok_or(MockError::Store)?;
                // The compare-and-set contract: the write lands only while
                // the persisted state still equals the expected one — the
                // monitor never issues a conditional step, so this arm is
                // unreachable here, but the boundary contract holds.
                if row.state() != expected_state || row.is_terminal() {
                    return Err(MockError::Store);
                }
                let row = rows.get_mut(&operation_id).ok_or(MockError::Store)?;
                *row = Operation::try_from_parts(
                    row.id(),
                    row.source(),
                    row.targets().to_vec(),
                    row.command(),
                    new_state,
                    row.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockError::Store)?;
                Ok(())
            })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::ListOperations(state));
                Ok(self
                    .operations
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .values()
                    .filter(|operation| state.is_none_or(|state| operation.state() == state))
                    .cloned()
                    .collect())
            })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a rutilus_domain::BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The monitor never creates batches; the submission path owns
            // that boundary, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn find_batch(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<rutilus_domain::BatchOperation>, Self::Error>>
        {
            // The monitor never reads batches; batch reporting owns that
            // projection, so this stub is unreachable here.
            Box::pin(async move { Ok(None) })
        }

        fn list_batches(
            &self,
        ) -> OperationBoundaryFuture<'_, Result<Vec<rutilus_domain::BatchOperation>, Self::Error>>
        {
            // The monitor never lists batches; batch reporting owns that
            // projection, so this stub is unreachable here.
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: rutilus_domain::FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            // The monitor never classifies failures; the executor's refusal
            // path owns that write, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn list_batch_children(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            // The monitor never lists batch children; batch reporting owns
            // that projection, so this stub is unreachable here.
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl RemoteTaskStore for FakeStore {
        type Error = MockError;

        fn save_remote_task<'a>(
            &'a self,
            task: &'a RemoteTask,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::SaveRemoteTask(task.operation_id()));
                if self.consume_failure(FailureKind::RemoteTaskWrite)? {
                    return Err(MockError::RemoteTaskStore);
                }
                self.remote_tasks
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .insert(task.operation_id(), task.clone());
                Ok(())
            })
        }

        fn find_remote_task(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<RemoteTask>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::FindRemoteTask(operation_id));
                if self.consume_failure(FailureKind::RemoteTaskRead)? {
                    return Err(MockError::RemoteTaskStore);
                }
                self.find_remote_task_owned(operation_id)
            })
        }

        fn list_remote_tasks_by_state(
            &self,
            _state: RemoteTaskState,
        ) -> OperationBoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>> {
            // The monitor's recovery scan goes through the operation listing;
            // this projection belongs to the home page (§14.2).
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    /// One recorded reader call with the exact endpoint and identifier.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum ReaderCall {
        ReadTask(EndpointId, TaskUri),
        Verify(EndpointId, RedfishCommand),
    }

    /// Scripted reader implementing both Task reads and target verification
    /// on one object, exactly like the production gateway.
    ///
    /// Every call pops the front of its script; a test that under-scripts
    /// fails on the state assertion instead of blocking.
    struct FakeReader {
        calls: Mutex<Vec<ReaderCall>>,
        task_script: Mutex<VecDeque<Result<Option<TaskObservation>, MockError>>>,
        verify_script: Mutex<VecDeque<Result<VerificationVerdict, MockError>>>,
    }

    impl FakeReader {
        fn new(
            task_script: Vec<Result<Option<TaskObservation>, MockError>>,
            verify_script: Vec<Result<VerificationVerdict, MockError>>,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                task_script: Mutex::new(VecDeque::from(task_script)),
                verify_script: Mutex::new(VecDeque::from(verify_script)),
            }
        }

        fn recorded_calls(&self) -> Result<Vec<ReaderCall>, MockError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }
    }

    impl TaskReader for FakeReader {
        type Error = MockError;

        fn read_task<'a>(
            &'a self,
            endpoint_id: EndpointId,
            task_uri: &'a TaskUri,
        ) -> BoundaryFuture<'a, Result<Option<TaskObservation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(ReaderCall::ReadTask(endpoint_id, task_uri.clone()));
                self.task_script
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .pop_front()
                    .ok_or(MockError::Reader)?
            })
        }
    }

    impl CommandVerifier for FakeReader {
        type Error = MockError;

        fn verify<'a>(
            &'a self,
            endpoint_id: EndpointId,
            command: &'a RedfishCommand,
        ) -> BoundaryFuture<'a, Result<VerificationVerdict, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(ReaderCall::Verify(endpoint_id, command.clone()));
                self.verify_script
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .pop_front()
                    .ok_or(MockError::Verifier)?
            })
        }
    }

    /// The single mock failure vocabulary of every boundary under test.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Store,
        RemoteTaskStore,
        Reader,
        Verifier,
        Audit,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock {self:?} failure")
        }
    }

    impl Error for MockError {}

    /// Append-only fake audit recording every event, with an optional
    /// fail-on-attempt switch.
    struct MockAudit {
        attempts: Mutex<usize>,
        events: Mutex<Vec<AuditEvent>>,
        fail_on: Option<usize>,
    }

    impl MockAudit {
        fn succeed() -> Self {
            Self {
                attempts: Mutex::new(0),
                events: Mutex::new(Vec::new()),
                fail_on: None,
            }
        }

        fn fail_on(attempt: usize) -> Self {
            Self {
                attempts: Mutex::new(0),
                events: Mutex::new(Vec::new()),
                fail_on: Some(attempt),
            }
        }

        fn recorded_events(&self) -> Result<Vec<AuditEvent>, MockError> {
            self.events
                .lock()
                .map(|events| events.clone())
                .map_err(|_| MockError::Events)
        }
    }

    impl AuditEventWriter for MockAudit {
        type Error = MockError;

        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut attempts = self.attempts.lock().map_err(|_| MockError::Events)?;
                *attempts += 1;
                if self.fail_on == Some(*attempts) {
                    return Err(MockError::Audit);
                }
                self.events
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(event.clone());
                Ok(())
            })
        }
    }

    /// Composes the monitor under test over the given fakes.
    fn monitor<'a>(
        store: &'a FakeStore,
        reader: &'a FakeReader,
        audit: &'a MockAudit,
    ) -> TaskMonitor<&'a FakeStore, &'a FakeReader, &'a MockAudit> {
        TaskMonitor::new(
            store,
            reader,
            audit,
            AuditActor::System,
            DeploymentPosture::Site,
        )
    }

    /// Extracts the persisted state sequence of one operation from the
    /// recorded store calls; each state maps one-to-one onto the §13.2 event
    /// that produced it.
    fn applied_states(calls: &[StoreCall]) -> Vec<OperationState> {
        calls
            .iter()
            .filter_map(|call| match call {
                StoreCall::ApplyTransition(_, state) => Some(*state),
                _ => None,
            })
            .collect()
    }

    /// A running Task observation, the shape the fixture Task serves.
    fn running_observation() -> TaskObservation {
        TaskObservation::new(
            Some(RemoteTaskState::Running),
            Some("applying firmware".to_owned()),
            Some(42),
            None,
        )
    }

    /// A completed Task observation with its discovered `TaskMonitor` URI.
    fn completed_observation() -> Result<TaskObservation, Box<dyn Error>> {
        Ok(TaskObservation::new(
            Some(RemoteTaskState::Completed),
            Some("power cycle completed".to_owned()),
            Some(100),
            Some(TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/1")?),
        ))
    }

    #[tokio::test]
    async fn still_running_poll_persists_progress_and_keeps_waiting_remote()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        let reader = FakeReader::new(vec![Ok(Some(running_observation()))], Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);
        let now = first_poll_at();

        let poll = monitor.poll(operation.id(), now).await?;

        let TaskPoll::StillRunning(waiting) = poll else {
            return Err(std::io::Error::other("a running Task must keep waiting").into());
        };
        assert_eq!(waiting.state(), OperationState::WaitingRemote);
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "a non-terminal Task must not move the state machine"
        );
        // The §13.6 observation row carries the newest wire facts and the
        // poll's own check time.
        let stored = store
            .find_remote_task_owned(operation.id())?
            .ok_or("the observation row must still exist")?;
        assert_eq!(stored.last_state(), RemoteTaskState::Running);
        assert_eq!(stored.last_message(), Some("applying firmware"));
        assert_eq!(stored.percent_complete(), Some(42));
        assert_eq!(stored.last_checked_at(), now);
        assert_eq!(audit.recorded_events()?.len(), 0);
        assert_eq!(
            reader.recorded_calls()?,
            [ReaderCall::ReadTask(endpoint_id, stored.task_uri().clone())]
        );
        Ok(())
    }

    #[tokio::test]
    async fn completed_task_drives_verification_to_success() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        let reader = FakeReader::new(
            vec![
                Ok(Some(running_observation())),
                Ok(Some(completed_observation()?)),
            ],
            vec![Ok(VerificationVerdict::Confirmed)],
        );
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);
        let operation_id = operation.id();

        // Poll 1: the Task is still running.
        let first = monitor.poll(operation_id, first_poll_at()).await?;
        assert!(matches!(first, TaskPoll::StillRunning(_)));
        // Poll 2: the Task completed; the operation moves WaitingRemote →
        // Verifying → Succeeded through the §13.6 recovery verification.
        let second = monitor.poll(operation_id, second_poll_at()).await?;
        let TaskPoll::Terminal(finished) = second else {
            return Err(std::io::Error::other("a completed Task must resolve").into());
        };
        assert_eq!(finished.state(), OperationState::Succeeded);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Verifying, OperationState::Succeeded,],
            "one poll drives exactly RemoteTaskCompleted then VerificationPassed"
        );
        // The terminal observation is persisted with its discovered
        // `TaskMonitor` URI, so the row records the final facts.
        let stored = store
            .find_remote_task_owned(operation_id)?
            .ok_or("the observation row must still exist")?;
        assert_eq!(stored.last_state(), RemoteTaskState::Completed);
        assert_eq!(stored.last_message(), Some("power cycle completed"));
        assert_eq!(stored.percent_complete(), Some(100));
        assert_eq!(stored.last_checked_at(), second_poll_at());
        assert_eq!(
            stored.task_monitor_uri(),
            Some(&TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/1")?)
        );
        // The verification re-read ran against the operation's endpoint and
        // command (design section 13.6 recovery verification).
        assert_eq!(
            reader.recorded_calls()?,
            [
                ReaderCall::ReadTask(endpoint_id, stored.task_uri().clone()),
                ReaderCall::ReadTask(endpoint_id, stored.task_uri().clone()),
                ReaderCall::Verify(endpoint_id, operation.command()),
            ]
        );
        // The §16.3 terminal fact is the lifecycle's second sequence, after
        // the executor's start fact, with a confirmed verification.
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(events[0].sequence(), AuditSequence::try_new(2)?);
        assert_eq!(
            events[0].outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        assert_eq!(
            events[0].context().target(),
            &AuditTarget::Endpoint(endpoint_id)
        );
        assert_eq!(events[0].context().action(), AuditAction::ExecuteOperation);
        assert_eq!(
            events[0].context().redfish_operation(),
            AuditRedfishOperation::PollRemoteTask,
            "the monitor's terminal fact names the Task polling that observed the outcome"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_task_records_failed_without_verification() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        // A task that ended in Exception: the BMC's own record proves the
        // write did not achieve its result.
        let reader = FakeReader::new(
            vec![Ok(Some(TaskObservation::new(
                Some(RemoteTaskState::Exception),
                Some("reset failed".to_owned()),
                Some(0),
                None,
            )))],
            Vec::new(),
        );
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let poll = monitor.poll(operation.id(), first_poll_at()).await?;

        let TaskPoll::Terminal(failed) = poll else {
            return Err(std::io::Error::other("a failed Task must resolve").into());
        };
        assert_eq!(failed.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(
            reader.recorded_calls()?.len(),
            1,
            "a provably failed Task must never be re-read for verification"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[0].outcome().verification(),
            Some(AuditVerification::Rejected),
            "the BMC's Task record is a provable failure (§13.5)"
        );
        Ok(())
    }

    #[tokio::test]
    async fn disappeared_task_records_unknown_without_re_creating_it() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        // `Ok(None)` is the disappearance signal: the BMC no longer tracks
        // the Task (404).
        let reader = FakeReader::new(vec![Ok(None)], Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let poll = monitor.poll(operation.id(), first_poll_at()).await?;

        let TaskPoll::Terminal(unknown) = poll else {
            return Err(std::io::Error::other("a disappeared Task must resolve").into());
        };
        assert_eq!(unknown.state(), OperationState::Unknown);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Unknown]
        );
        // The observation row is untouched: nothing was observed, so nothing
        // is rewritten (§13.6 — the Task is never re-created).
        assert_eq!(
            store
                .find_remote_task_owned(operation.id())?
                .ok_or("row missing")?,
            task_row(
                operation.id(),
                endpoint_id,
                "/redfish/v1/TaskService/Tasks/1"
            )?,
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[0].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn unclassifiable_task_state_records_unknown() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        // A wire state this build cannot classify must not be disguised as a
        // known state (§7.6): the outcome cannot be proven.
        let reader = FakeReader::new(
            vec![Ok(Some(TaskObservation::new(None, None, None, None)))],
            Vec::new(),
        );
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let poll = monitor.poll(operation.id(), first_poll_at()).await?;

        let TaskPoll::Terminal(unknown) = poll else {
            return Err(std::io::Error::other("an unclassifiable Task must resolve").into());
        };
        assert_eq!(unknown.state(), OperationState::Unknown);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Unknown]
        );
        assert_eq!(
            audit.recorded_events()?[0].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn transient_read_failure_defers_without_any_side_effects() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        let reader = FakeReader::new(vec![Err(MockError::Reader)], Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let poll = monitor.poll(operation.id(), first_poll_at()).await?;

        let TaskPoll::Deferred(waiting) = poll else {
            return Err(std::io::Error::other("a failed read must defer").into());
        };
        assert_eq!(waiting.state(), OperationState::WaitingRemote);
        // Nothing was persisted, stepped, or audited: a transient read
        // failure is not a verdict and the Task read is a side-effect-free
        // GET, so the next poll can safely retry it (§13.5).
        assert_eq!(store.recorded_calls()?.len(), 2);
        assert_eq!(applied_states(&store.recorded_calls()?).len(), 0);
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn poll_rejects_operations_that_are_not_waiting_remote() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new();
        // A Verifying operation is no longer waiting on its Task: the write
        // landed and only the re-read was in flight.
        let operation = Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            one_command(),
            OperationState::Verifying,
            created_at(),
            created_at() + Duration::SECOND,
        )?;
        store.insert_operation(operation.clone())?;
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let result = monitor.poll(operation.id(), first_poll_at()).await;

        assert!(matches!(
            result,
            Err(TaskMonitorError::NotWaitingRemote {
                operation_id,
                state: OperationState::Verifying,
            }) if operation_id == operation.id()
        ));
        assert_eq!(
            store.recorded_calls()?,
            [StoreCall::FindOperation(operation.id())],
            "the defense must not persist or read anything else"
        );
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_operation_reports_not_found() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);
        let unknown = OperationId::generate();

        let result = monitor.poll(unknown, first_poll_at()).await;

        assert!(matches!(
            result,
            Err(TaskMonitorError::OperationNotFound(id)) if id == unknown
        ));
        assert_eq!(store.recorded_calls()?, [StoreCall::FindOperation(unknown)]);
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn waiting_operation_without_an_observation_row_records_unknown()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        // No RemoteTask row: the product lost the Task reference.
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let poll = monitor.poll(operation.id(), first_poll_at()).await?;

        let TaskPoll::Terminal(unknown) = poll else {
            return Err(std::io::Error::other("a lost Task reference must resolve").into());
        };
        assert_eq!(unknown.state(), OperationState::Unknown);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Unknown]
        );
        assert_eq!(
            audit.recorded_events()?[0].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        assert_eq!(reader.recorded_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn verification_error_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        let reader = FakeReader::new(
            vec![Ok(Some(completed_observation()?))],
            vec![Err(MockError::Verifier)],
        );
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let result = monitor.poll(operation.id(), first_poll_at()).await;

        let error = result.err().ok_or("the re-read failure must escape")?;
        assert!(matches!(
            error,
            TaskMonitorError::Verifier(MockError::Verifier)
        ));
        // The completed Task's re-read proves nothing about the write, so the
        // operation is recorded Unknown before the error escapes (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Verifying, OperationState::Unknown,]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[0].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn verification_mismatch_records_failed() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        let reader = FakeReader::new(
            vec![Ok(Some(completed_observation()?))],
            vec![Ok(VerificationVerdict::Mismatched)],
        );
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let poll = monitor.poll(operation.id(), first_poll_at()).await?;

        let TaskPoll::Terminal(failed) = poll else {
            return Err(std::io::Error::other("a mismatch must resolve").into());
        };
        assert_eq!(failed.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Verifying, OperationState::Failed,]
        );
        let events = audit.recorded_events()?;
        assert_eq!(
            events[0].outcome().failure(),
            Some(rutilus_domain::AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(
            events[0].outcome().verification(),
            Some(AuditVerification::Rejected),
            "a proven-absent result is a provable failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn audit_failure_reports_after_the_terminal_state_was_persisted()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        let reader = FakeReader::new(
            vec![Ok(Some(completed_observation()?))],
            vec![Ok(VerificationVerdict::Confirmed)],
        );
        let audit = MockAudit::fail_on(1);
        let monitor = monitor(&store, &reader, &audit);

        let result = monitor.poll(operation.id(), first_poll_at()).await;

        assert!(matches!(
            result,
            Err(TaskMonitorError::Audit {
                stage: MonitorAuditStage::Terminal,
                source: AuditRecordError::Write(MockError::Audit),
            })
        ));
        // The operation still reached its honest terminal state; only the
        // terminal audit fact could not be appended.
        assert_eq!(
            store
                .find_operation_owned(operation.id())?
                .ok_or("the operation must still be stored")?
                .state(),
            OperationState::Succeeded
        );
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn recover_tasks_lists_only_waiting_remote_operations() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new();
        let waiting = waiting_operation(endpoint_id)?;
        store.insert_operation(waiting.clone())?;
        for state in [
            OperationState::Queued,
            OperationState::Validating,
            OperationState::Running,
            OperationState::Verifying,
            OperationState::Succeeded,
        ] {
            store.insert_operation(Operation::try_from_parts(
                OperationId::generate(),
                OperationSource::Standalone,
                vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
                one_command(),
                state,
                created_at(),
                created_at() + Duration::SECOND,
            )?)?;
        }
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let recovered = monitor.recover_tasks().await?;

        assert_eq!(
            recovered,
            [waiting],
            "the §13.6 scan resumes exactly the WaitingRemote operations"
        );
        assert_eq!(
            store.recorded_calls()?,
            [StoreCall::ListOperations(Some(
                OperationState::WaitingRemote
            ))]
        );
        Ok(())
    }

    #[tokio::test]
    async fn operation_store_failure_propagates_with_source_chain() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        store.arm_failure(FailureKind::OperationRead)?;
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let result = monitor.poll(OperationId::generate(), first_poll_at()).await;

        let error = result.err().ok_or("the store failure must escape")?;
        assert!(matches!(error, TaskMonitorError::Store(MockError::Store)));
        let source = Error::source(&error).ok_or("the error must expose its source")?;
        assert_eq!(source.to_string(), MockError::Store.to_string());
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn remote_task_store_failure_propagates_with_source_chain() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        let operation = waiting_operation(endpoint_id)?;
        let store = FakeStore::new();
        store.insert_operation(operation.clone())?;
        store.insert_remote_task(task_row(
            operation.id(),
            endpoint_id,
            "/redfish/v1/TaskService/Tasks/1",
        )?)?;
        store.arm_failure(FailureKind::RemoteTaskRead)?;
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let result = monitor.poll(operation.id(), first_poll_at()).await;

        let error = result.err().ok_or("the store failure must escape")?;
        assert!(matches!(
            error,
            TaskMonitorError::RemoteTaskStore(MockError::RemoteTaskStore)
        ));
        let source = Error::source(&error).ok_or("the error must expose its source")?;
        assert_eq!(source.to_string(), MockError::RemoteTaskStore.to_string());
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn zero_target_waiting_operation_is_rejected() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        // Rehydration does not re-check targets, so a corrupt zero-target row
        // can still be read back; it can never be verified (§13.6).
        let operation = Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Standalone,
            Vec::new(),
            one_command(),
            OperationState::WaitingRemote,
            created_at(),
            created_at() + Duration::SECOND,
        )?;
        store.insert_operation(operation.clone())?;
        let reader = FakeReader::new(Vec::new(), Vec::new());
        let audit = MockAudit::succeed();
        let monitor = monitor(&store, &reader, &audit);

        let result = monitor.poll(operation.id(), first_poll_at()).await;

        assert!(matches!(
            result,
            Err(TaskMonitorError::EmptyTargets(id)) if id == operation.id()
        ));
        assert_eq!(audit.recorded_events()?.len(), 0);
        assert_eq!(reader.recorded_calls()?.len(), 0);
        Ok(())
    }
}
