//! The command execution scheduler (design sections 13.3, 13.5, and 13.6).
//!
//! [`OperationExecutor`] drives one persisted operation through the §13.2
//! state machine.
//! [`OperationExecutor::execute_operation`] runs the execution flow: it
//! starts fresh `Queued` work and, after a crash, resumes work stranded in
//! `Validating` — the state is persisted before dispatch, so the write was
//! provably never issued and resuming the execution flow is always safe.
//! [`OperationExecutor::recover_operation`] resolves the outcome of work
//! stranded in `Running` or `Verifying` — states where the write may already
//! have landed and the response is lost — through the §13.5 re-read-and-decide
//! pattern (design section 13.6 restart recovery).
//!
//! The executor performs the first cut of the §13.3 pre-flight checks (steps
//! 1-2: endpoint existence and capability availability; step 4 for Update
//! commands: the referenced artifact must exist and be `Ready`, §14.3),
//! dispatches the typed command through the [`CommandExecutor`] boundary
//! (step 7) — and the §14.3 firmware update through the [`UpdateExecutor`]
//! boundary — and handles the §13.3 step 8 branch that the response selects:
//!
//! - synchronous acceptance (`Accepted`) is re-read and verified through the
//!   [`CommandVerifier`] boundary (steps 9-10) to a terminal state;
//! - a `202` ([`CommandOutcome::AsyncTaskAccepted`]) is persisted as a
//!   [`RemoteTask`] observation row (design section 13.6) and the operation
//!   moves to `WaitingRemote`, where the [`crate::TaskMonitor`] resumes it
//!   until the Task reaches a terminal state and verification finishes;
//! - a provable refusal (`Rejected`) and every classified dispatch error end
//!   the operation in `Failed` or `Unknown` (design section 13.5).
//!
//! The §16.3 audit start fact is recorded here before any dispatch; the
//! terminal fact of a synchronous execution is recorded here too, while the
//! terminal fact of an asynchronous execution is recorded by the Task
//! monitor once the Task completes (§13.6 recovery verification).

use std::{error::Error, fmt, fs, io, path::PathBuf};

use rutilus_domain::{
    AccountCommand, ArtifactId, ArtifactState, AuditAction, AuditActor, AuditEvent, AuditFailure,
    AuditFailureVerification, AuditOperationContext, AuditOperationContextError, AuditOperationId,
    AuditParameterSummary, AuditRedfishOperation, AuditSequence, AuditTarget, BootCommand,
    CapabilityState, ChassisCommand, ControlCommand, DeploymentPosture, EndpointCapability,
    EndpointId, EventCommand, FailureKind, LogCommand, ManagerCommand, OemCommand, Operation,
    OperationEvent, OperationId, OperationState, ProductPermission, RedfishCommand,
    SecureBootCommand, SystemCommand, TelemetryCommand, UpdateCommand,
};
use rutilus_operation_engine::{
    EngineError, OperationEngine, OperationStore, RemoteTask, RemoteTaskStore,
};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::task::spawn_blocking;

use crate::{
    ArtifactRepository, AuditEventWriter, AuditRecordError, CapabilityLedgerEntry,
    CapabilityQueryRepository, Clock, CommandExecutor, CommandOutcome, CommandVerifier,
    DispatchVerdict, DispatchVerdictClassifier, EndpointCapabilityQuery,
    EndpointCapabilityQueryError, EndpointRefreshRepository, UpdateArtifactPayload, UpdateExecutor,
    VerificationVerdict,
};

/// The concrete failure type of one execution attempt.
///
/// The generic parameters are the nine boundary error types, in
/// [`ExecutorError`] order: operation store, endpoint lookup, capability
/// query, remote-task store, artifact lookup, command dispatch, update
/// dispatch, verification, and audit. Keeping them separate preserves every
/// source chain, exactly like the refresh use case's error.
type ExecutorErrorOf<Store, Gateway, Audit> = ExecutorError<
    <Store as OperationStore>::Error,
    <Store as EndpointRefreshRepository>::Error,
    <Store as CapabilityQueryRepository>::Error,
    <Store as RemoteTaskStore>::Error,
    <Store as ArtifactRepository>::Error,
    <Gateway as CommandExecutor>::Error,
    <Gateway as UpdateExecutor>::Error,
    <Gateway as CommandVerifier>::Error,
    <Audit as AuditEventWriter>::Error,
>;

/// The §13.3 step-2 capability pre-flight verdict (§13.7).
///
/// The verdict splits the refusal by provability: a provably unsupported
/// capability is classified `capability-unsupported` before the `Failed`
/// transition (so batch reporting buckets it as `unsupported` instead of an
/// ordinary failure), while an unconfirmed capability is a plain provable
/// refusal with no classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CapabilityPreflight {
    /// The required capability is observed `Supported`: the write may
    /// dispatch.
    Usable,
    /// The required capability is provably unsupported — not compiled, not
    /// advertised, schema-incompatible, or read-only (§13.3 step 2). The
    /// refusal is classified `capability-unsupported` before it is recorded.
    Unsupported,
    /// The required capability cannot be confirmed but is not provably
    /// unsupported — unauthorized, temporarily unavailable, or never
    /// observed. The refusal is recorded without a classification.
    Unconfirmed,
}

/// Drives one persisted operation through the execution flow.
///
/// `Store` stays one constructor parameter although it plays five roles —
/// operation lifecycle, endpoint lookup, capability ledger, remote-task
/// observation rows, and artifact lookup (the §13.3 step-4 pre-flight of an
/// Update command) — because every runtime composes one `SqliteStore`
/// implementing all five, exactly like the refresh use case's repository.
/// `Gateway` implements dispatch, update dispatch, and verification on the
/// same Redfish gateway object, and `Audit` appends the §16.3 lifecycle
/// facts.
pub struct OperationExecutor<Store, Gateway, Audit, Time> {
    store: Store,
    gateway: Gateway,
    audit: Audit,
    clock: Time,
    actor: AuditActor,
    origin: DeploymentPosture,
}

impl<Store, Gateway, Audit, Time> OperationExecutor<Store, Gateway, Audit, Time>
where
    Store: OperationStore
        + EndpointRefreshRepository
        + CapabilityQueryRepository
        + RemoteTaskStore
        + ArtifactRepository,
    Gateway: CommandExecutor + CommandVerifier + UpdateExecutor,
    Audit: AuditEventWriter,
    Time: Clock,
{
    /// Wraps the store, the Redfish gateway, the audit writer, and the clock.
    ///
    /// `actor` and `origin` are injected the same way the other audited use
    /// cases do: they are the §16.3 "who" and "from where" facts of every
    /// recorded event.
    #[must_use]
    pub fn new(
        store: Store,
        gateway: Gateway,
        audit: Audit,
        clock: Time,
        actor: AuditActor,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            store,
            gateway,
            audit,
            clock,
            actor,
            origin,
        }
    }

    /// Executes one operation to a terminal state, starting fresh `Queued`
    /// work or resuming an operation stranded in `Validating` by a crash.
    ///
    /// # Flow
    ///
    /// 1. Read the operation. Only `Queued` and `Validating` work is
    ///    schedulable here: `Queued` work has never started, and a `Validating`
    ///    operation persisted its validation step before dispatch, so the
    ///    write was provably never issued and resuming is always safe (design
    ///    section 13.6). Every other state is a defensive reject that changes
    ///    nothing and records no audit (nothing was driven); the scheduler
    ///    dispatches `Running`/`Verifying` to [`Self::recover_operation`] and
    ///    `WaitingRemote` to the Task monitor.
    /// 2. Record the §16.3 start fact (before any pre-flight work, the same
    ///    order as the other audited use cases).
    /// 3. Pre-flight, first cut of §13.3 steps 1-2: the first target's
    ///    endpoint must exist and must advertise the command's required
    ///    capability as `Supported`. A failed pre-flight is a provable
    ///    refusal — nothing has been dispatched — so the operation is
    ///    recorded `Failed`, never `Unknown`.
    /// 4. Persist `ValidationStarted` (`Queued` work only — a resumed
    ///    `Validating` operation already persisted this step in the crashed
    ///    attempt) and `ValidationPassed` → `Running` (§13.3 step 6, then the
    ///    dispatch of step 7).
    /// 5. Dispatch through [`CommandExecutor`]. `Accepted` (synchronous
    ///    `200`/`201`/`204` handled) persists `ExecutionAccepted`;
    ///    `AsyncTaskAccepted` (`202`) persists the [`RemoteTask`] observation
    ///    row (design section 13.6) and `RemoteTaskStarted` → `WaitingRemote`,
    ///    returning the waiting operation to the scheduler — the Task monitor
    ///    (`crate::TaskMonitor`) resumes it; `Rejected` (provable BMC
    ///    refusal) persists `Failed`. A dispatch error is classified by its
    ///    own [`DispatchVerdict`] (design section 13.5): errors that prove
    ///    the write was never executed persist `Failed`, errors that cannot
    ///    prove it persist `OutcomeUnknown` → `Unknown`; either way the
    ///    operation reaches its honest terminal state and the underlying
    ///    error escapes as [`ExecutorError::Gateway`] with its source chain
    ///    intact.
    /// 6. Verify through [`CommandVerifier`] (§13.3 steps 9-10). `Confirmed`
    ///    persists `VerificationPassed` → `Succeeded`; `Mismatched` (the
    ///    re-read proves the expected result absent) persists `Failed`; a
    ///    failed re-read proves nothing about the already-landed write
    ///    (§13.5) and persists `OutcomeUnknown` → `Unknown`, escaping as
    ///    [`ExecutorError::Verifier`].
    /// 7. Record the §16.3 terminal fact: `Succeeded` with `Confirmed`
    ///    verification, or `Failed` with the failure class and the truthful
    ///    verification (`Rejected` for provable outcomes, `Inconclusive`
    ///    otherwise).
    ///
    /// The operation is executed against its first target's endpoint in this
    /// cut; per-target fan-out for multi-target operations (design section
    /// 13.7) is a later iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::OperationNotFound`] for an unknown id,
    /// [`ExecutorError::NotQueued`] when the operation is no longer `Queued`
    /// or `Validating` (including a second driver racing this id — the engine
    /// reports the state the domain observed), [`ExecutorError::EmptyTargets`]
    /// for a corrupt zero-target row, and the store, pre-flight, dispatch,
    /// verification, and audit boundary errors with their sources chained.
    /// Note that a failed dispatch or verification still persists the
    /// operation's honest terminal state before the error is returned, so a
    /// caller that sees an error can re-read the operation for its outcome.
    // The flow spans the full §13.3 pre-flight and dispatch sequence, so the
    // line count is the coverage, not a signal.
    #[allow(clippy::too_many_lines)]
    pub async fn execute_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        // The scheduler drives fresh and resumable work. The engine exposes
        // no read in this iteration, so the pre-read goes through the same
        // `OperationStore` boundary the engine itself uses: the scheduler
        // must inspect the aggregate (state, first target, command) before
        // the first persisted step.
        let Some(operation) = self
            .store
            .find_operation(operation_id)
            .await
            .map_err(ExecutorError::Store)?
        else {
            return Err(ExecutorError::OperationNotFound(operation_id));
        };
        let state = operation.state();
        if !matches!(state, OperationState::Queued | OperationState::Validating) {
            return Err(ExecutorError::NotQueued {
                operation_id,
                state,
            });
        }
        let Some(target) = operation.targets().first() else {
            // `OperationEngine::create` rejects empty target lists, but
            // rehydration (`Operation::try_from_parts`) does not re-check
            // them, so a corrupt persisted row can still reach the scheduler.
            return Err(ExecutorError::EmptyTargets(operation_id));
        };
        let endpoint_id = target.endpoint_id();
        let command = operation.command();
        let engine = OperationEngine::new(&self.store);

        let started = self.start_audit(endpoint_id, &command).await?;

        if !self.endpoint_exists(endpoint_id).await? {
            return self
                .refuse(
                    &engine,
                    operation_id,
                    &started,
                    AuditFailure::EndpointPersistenceFailed,
                )
                .await;
        }
        match self.capability_preflight(&command, endpoint_id).await? {
            // The required capability is observed `Supported`: the write may
            // dispatch.
            CapabilityPreflight::Usable => {}
            // The capability is provably unsupported (§13.7): the refusal is
            // classified before the `Failed` transition, so batch reporting
            // can bucket it as `unsupported` instead of an ordinary failure.
            // The kind write and the transition are two store writes; a crash
            // between them leaves an orphaned kind on a non-terminal row,
            // which reporting never reads (the kind buckets only `Failed`
            // children) and which the next transition overwrites or leaves
            // inert — the window is harmless by design.
            CapabilityPreflight::Unsupported => {
                self.store
                    .record_failure_kind(operation_id, FailureKind::CapabilityUnsupported)
                    .await
                    .map_err(ExecutorError::Store)?;
                return self
                    .refuse(
                        &engine,
                        operation_id,
                        &started,
                        AuditFailure::RedfishDiscoveryFailed,
                    )
                    .await;
            }
            // The capability cannot be confirmed but is not provably
            // unsupported: a plain provable refusal, never classified.
            CapabilityPreflight::Unconfirmed => {
                return self
                    .refuse(
                        &engine,
                        operation_id,
                        &started,
                        AuditFailure::RedfishDiscoveryFailed,
                    )
                    .await;
            }
        }

        // §13.3 step 4 (first cut, Update only): the referenced artifact must
        // exist and be `Ready` before any validation step is persisted — an
        // unusable artifact is a provable refusal, exactly like the endpoint
        // and capability pre-flight checks. The artifact bytes are resolved
        // here too (the file read runs under `spawn_blocking`, design §7.8),
        // so the update dispatch never starts without the payload it must
        // upload; the command itself carries only the database-serializable
        // `artifact_id` (§14.3).
        let update_artifact = match &command {
            RedfishCommand::Update(UpdateCommand::StartUpdate(payload)) => {
                match self.resolve_update_artifact(payload.artifact_id()).await {
                    Ok(artifact) => Some(artifact),
                    Err(error) => match error {
                        // The artifact store could not be read: the check
                        // cannot be decided, so the failure escalates like
                        // the endpoint pre-flight lookup failure (nothing is
                        // persisted).
                        UpdateArtifactResolutionError::Lookup(source) => {
                            return Err(ExecutorError::ArtifactPreflight(source));
                        }
                        // The artifact is provably unusable — missing, not
                        // `Ready`, or its file unreadable — so the write can
                        // never be dispatched and the refusal is provable
                        // (§13.5: recorded `Failed`, never `Unknown`).
                        UpdateArtifactResolutionError::Missing
                        | UpdateArtifactResolutionError::NotReady
                        | UpdateArtifactResolutionError::Unreadable => {
                            return self
                                .refuse(
                                    &engine,
                                    operation_id,
                                    &started,
                                    AuditFailure::EndpointPersistenceFailed,
                                )
                                .await;
                        }
                    },
                }
            }
            _ => None,
        };

        if state == OperationState::Queued {
            // §13.3 step 6 begins the validation phase. A resumed `Validating`
            // operation already persisted this step in the crashed attempt
            // (which is exactly why the crash left it in `Validating`), so it
            // resumes after the step.
            self.apply_step(&engine, operation_id, OperationEvent::ValidationStarted)
                .await?;
        }
        self.apply_step(&engine, operation_id, OperationEvent::ValidationPassed)
            .await?;

        self.dispatch_and_verify(
            &engine,
            operation_id,
            endpoint_id,
            &command,
            &started,
            update_artifact.as_ref(),
        )
        .await
    }

    /// Resolves the outcome of an operation stranded in `Running` or
    /// `Verifying` by a crash (design sections 13.5 and 13.6 restart
    /// recovery).
    ///
    /// These two states share one property: the write may already have landed
    /// and its response was lost, so the operation must never be re-dispatched
    /// blindly — §13.5 lists Create/Delete/Action/Reset among the writes whose
    /// lost response forbids a direct retry. Recovery therefore applies the
    /// §13.5 pattern instead: re-read the target (or the persisted Task
    /// record) and decide from what the re-read proves.
    ///
    /// # Per-state decisions
    ///
    /// - `Running` — the dispatch was in flight when the process died, so the
    ///   write may or may not have been issued:
    ///   - a persisted [`RemoteTask`] observation row proves the write was
    ///     accepted as an asynchronous Task (the row is saved before
    ///     `RemoteTaskStarted`, so a crash in that window leaves `Running`
    ///     with a row; the Task's effect is not yet observable and a target
    ///     re-read would misjudge it). Recovery back-fills `RemoteTaskStarted`
    ///     → `WaitingRemote` and the Task monitor resumes the polling. This
    ///     path records no audit: it performs no outcome work — the original
    ///     attempt's start fact and the monitor's terminal fact already
    ///     bracket the lifecycle.
    ///   - without a Task row, the target is re-read through
    ///     [`CommandVerifier`]:
    ///     - `Confirmed` — the re-read proves the write happened (§13.5
    ///       "判断是否已经发生"); `ExecutionAccepted` is back-filled (the
    ///       re-read takes the place of the lost response) and the
    ///       verification chain continues to `Succeeded`;
    ///     - `Mismatched` — the expected result is absent. The operation
    ///       provably did not achieve its result, so it is recorded `Failed`;
    ///       it is never re-dispatched: an absent expected result does not
    ///       confirm the write was never delivered (it may have been
    ///       delivered and failed, or its effect may be transient — a reset's
    ///       post-write state can equal its pre-write state), and §13.5
    ///       allows a retry only for requests confirmable as not delivered.
    ///       The verification is `Inconclusive` because — unlike the
    ///       synchronous path, where the `Accepted` response proves delivery
    ///       — the product cannot prove whether the write was ever delivered;
    ///     - a failed re-read proves nothing and the operation is recorded
    ///       `Unknown` (§13.5), escaping as [`ExecutorError::Verifier`].
    /// - `Verifying` — `ExecutionAccepted` was persisted, which happens only
    ///   after the synchronous response was received and fully handled, so
    ///   the write provably landed and only the re-read was in flight. The
    ///   target is re-read again (§13.5 re-read-and-decide):
    ///   `Confirmed` → `VerificationPassed` → `Succeeded`; `Mismatched` → a
    ///   provable failure (`Failed`, verification `Rejected` — delivery is
    ///   proven by the persisted step); a failed re-read → `Unknown`.
    ///
    /// Every judgement path (the `Running` re-read and the `Verifying`
    /// re-verify) records a fresh §16.3 start fact first: the append-only
    /// audit boundary has no read path to recover the crashed attempt's
    /// context, so each recovery attempt opens its own lifecycle (the same
    /// documented limitation as the Task monitor's terminal fact). The
    /// Task-row handoff above records no start — it performs no outcome
    /// work, so the original attempt's start fact and the monitor's terminal
    /// fact already bracket the lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::OperationNotFound`] for an unknown id,
    /// [`ExecutorError::NotRecoverable`] when the operation is not in
    /// `Running` or `Verifying`, [`ExecutorError::EmptyTargets`] for a
    /// corrupt zero-target row, and the store, remote-task, verification, and
    /// audit boundary errors with their sources chained. A failed judgement
    /// re-read still persists the operation's honest terminal state
    /// (`Unknown`) before the error is returned.
    pub async fn recover_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        let Some(operation) = self
            .store
            .find_operation(operation_id)
            .await
            .map_err(ExecutorError::Store)?
        else {
            return Err(ExecutorError::OperationNotFound(operation_id));
        };
        let state = operation.state();
        if !matches!(state, OperationState::Running | OperationState::Verifying) {
            return Err(ExecutorError::NotRecoverable {
                operation_id,
                state,
            });
        }
        let Some(target) = operation.targets().first() else {
            // Rehydration does not re-check targets, so a corrupt persisted
            // row can still reach the recovery path; a target is needed for
            // the §13.5 judgement re-read.
            return Err(ExecutorError::EmptyTargets(operation_id));
        };
        let endpoint_id = target.endpoint_id();
        let command = operation.command();
        let engine = OperationEngine::new(&self.store);

        if state == OperationState::Running {
            // The §13.6 observation row is persisted BEFORE the
            // `RemoteTaskStarted` step (the row is what a crash between
            // acceptance and the first poll must not lose), so a `Running`
            // operation that has a row provably waits on an accepted Task:
            // recovery resumes Task tracking instead of judging by re-read,
            // whose expected-result check cannot see a Task that is still
            // running and would misjudge it as not occurred.
            let accepted = self
                .store
                .find_remote_task(operation_id)
                .await
                .map_err(ExecutorError::RemoteTask)?
                .is_some();
            if accepted {
                return self
                    .recover_step(&engine, operation_id, OperationEvent::RemoteTaskStarted)
                    .await;
            }
            let started = self.start_audit(endpoint_id, &command).await?;
            return self
                .judge_running(&engine, operation_id, endpoint_id, &command, &started)
                .await;
        }
        let started = self.start_audit(endpoint_id, &command).await?;
        self.verify_target(&engine, operation_id, endpoint_id, &command, &started)
            .await
            .map_err(guard_recovery_race)
    }

    /// The §13.5 judgement of a `Running` orphan whose dispatch outcome is
    /// unknown: re-read the target and decide what the re-read proves.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Verifier`] with the re-read error as its
    /// source after the operation has been persisted into `Unknown` (a failed
    /// re-read proves nothing about the possibly-landed write, design section
    /// 13.5) and the terminal audit fact has been recorded.
    async fn judge_running(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
        started: &StartedAudit,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        match self.gateway.verify(endpoint_id, command).await {
            Ok(VerificationVerdict::Confirmed) => {
                // The re-read proves the write already happened (§13.5
                // "判断是否已经发生"), so `ExecutionAccepted` is back-filled —
                // the re-read takes the place of the lost response — and the
                // verification chain continues exactly as after a synchronous
                // acceptance.
                self.recover_step(engine, operation_id, OperationEvent::ExecutionAccepted)
                    .await?;
                let final_operation = self
                    .recover_step(engine, operation_id, OperationEvent::VerificationPassed)
                    .await?;
                self.record_success(started).await?;
                Ok(final_operation)
            }
            Ok(VerificationVerdict::Mismatched) => {
                // §13.5 decision: the expected result is absent, so the
                // operation provably did not achieve its result — but an
                // absent expected result does not confirm the write was never
                // delivered (it may have been delivered and failed, or its
                // effect may be transient), and §13.5 allows a retry only for
                // requests confirmable as not delivered. The operation is
                // therefore recorded `Failed`, never re-dispatched; the
                // verification is `Inconclusive` because the product cannot
                // prove whether the write was ever delivered.
                let final_operation = self
                    .recover_step(engine, operation_id, OperationEvent::Failed)
                    .await?;
                self.record_failure(
                    started,
                    AuditFailure::CoreResourceReadFailed,
                    AuditFailureVerification::Inconclusive,
                )
                .await?;
                Ok(final_operation)
            }
            Err(source) => {
                // §13.5: a failed re-read proves nothing about the
                // possibly-landed write, so the outcome cannot be confirmed
                // and the operation is recorded Unknown.
                self.recover_step(engine, operation_id, OperationEvent::OutcomeUnknown)
                    .await?;
                self.record_failure(
                    started,
                    AuditFailure::CoreResourceReadFailed,
                    AuditFailureVerification::Inconclusive,
                )
                .await?;
                Err(ExecutorError::Verifier(source))
            }
        }
    }

    /// Builds and appends the §16.3 start fact before any pre-flight work.
    ///
    /// The context names the command's §7.5 write family, so the audit record
    /// shows which typed write the attempt dispatched or judged.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Audit`] with the start stage when the context
    /// cannot be constructed or the append fails; no operation step is
    /// persisted then.
    async fn start_audit(
        &self,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
    ) -> Result<StartedAudit, ExecutorErrorOf<Store, Gateway, Audit>> {
        let context = operation_audit_context(
            endpoint_id,
            command_audit_operation(command),
            self.actor,
            self.origin,
        )
        .map_err(|source| ExecutorError::Audit {
            stage: OperationAuditStage::Start,
            source: AuditRecordError::Context(source),
        })?;
        let terminal_sequence =
            AuditSequence::FIRST
                .next()
                .map_err(|source| ExecutorError::Audit {
                    stage: OperationAuditStage::Start,
                    source: AuditRecordError::Sequence(source),
                })?;
        let started_at = self.clock.now();
        let started = AuditEvent::started(context.clone(), started_at);
        self.audit
            .append_audit_event(&started)
            .await
            .map_err(|source| ExecutorError::Audit {
                stage: OperationAuditStage::Start,
                source: AuditRecordError::Write(source),
            })?;
        Ok(StartedAudit {
            context,
            terminal_sequence,
            started_at,
        })
    }

    /// §13.3 step 1 (first cut): the first target's endpoint must exist.
    ///
    /// The existence check reuses the refresh boundary's endpoint lookup —
    /// the only existing application boundary that answers "does this
    /// endpoint exist" — instead of defining a new repository contract the
    /// persistence layer could not implement in this iteration.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::EndpointPreflight`] when the lookup itself
    /// fails.
    async fn endpoint_exists(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<bool, ExecutorErrorOf<Store, Gateway, Audit>> {
        Ok(self
            .store
            .find_endpoint(endpoint_id)
            .await
            .map_err(ExecutorError::EndpointPreflight)?
            .is_some())
    }

    /// §13.3 step 2 (first cut): the command's required capability must be
    /// currently usable for a write.
    ///
    /// The ledger merge is delegated to [`EndpointCapabilityQuery`] — the
    /// existing, already-tested capability projection — and this module adds
    /// only the command-to-capability mapping and the write-usable decision.
    /// Only [`CapabilityState::Supported`] passes. The refusal verdicts split
    /// by provability (§13.7): `NotCompiled`, `NotAdvertised`,
    /// `SchemaIncompatible`, and `ReadOnly` prove the capability itself
    /// cannot serve the write — the endpoint-side limitation is the reason,
    /// classified `capability-unsupported`; `Unauthorized`,
    /// `TemporarilyUnavailable`, and a never-observed capability do not
    /// prove the capability unusable (the endpoint may simply not have been
    /// probed or authorized yet), so those refusals stay unclassified
    /// ordinary failures. Either way the pre-flight refusal is provable —
    /// nothing has been dispatched — and is therefore recorded `Failed`,
    /// never `Unknown` (design section 13.5).
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::CapabilityPreflight`] when the ledger query
    /// fails.
    async fn capability_preflight(
        &self,
        command: &RedfishCommand,
        endpoint_id: EndpointId,
    ) -> Result<CapabilityPreflight, ExecutorErrorOf<Store, Gateway, Audit>> {
        let required = required_capability(command);
        let entries = EndpointCapabilityQuery::new(&self.store, endpoint_id)
            .execute()
            .await
            .map_err(ExecutorError::CapabilityPreflight)?;
        let state = entries.and_then(|entries| required_capability_state(required, &entries));
        Ok(match state {
            Some(CapabilityState::Supported) => CapabilityPreflight::Usable,
            Some(
                CapabilityState::NotCompiled
                | CapabilityState::NotAdvertised
                | CapabilityState::SchemaIncompatible
                | CapabilityState::ReadOnly,
            ) => CapabilityPreflight::Unsupported,
            Some(CapabilityState::Unauthorized | CapabilityState::TemporarilyUnavailable)
            | None => CapabilityPreflight::Unconfirmed,
        })
    }

    /// Records a provable pre-flight refusal: one `Failed` transition and the
    /// §16.3 terminal fact with `Rejected` verification.
    ///
    /// # Errors
    ///
    /// Returns the store or audit boundary error when either write fails.
    async fn refuse(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        started: &StartedAudit,
        failure: AuditFailure,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        let final_operation = self
            .apply_step(engine, operation_id, OperationEvent::Failed)
            .await?;
        self.record_failure(started, failure, AuditFailureVerification::Rejected)
            .await?;
        Ok(final_operation)
    }

    /// Persists one §13.2 state step through the operation engine.
    ///
    /// # Errors
    ///
    /// Maps the engine verdicts onto the scheduler's error vocabulary: a
    /// store failure propagates with its source, a not-found race becomes
    /// [`ExecutorError::OperationNotFound`], and an invalid-transition race
    /// (a second driver advanced the operation between our read and this
    /// step) becomes [`ExecutorError::NotQueued`] with the state the domain
    /// reported — the same defense as the initial queued-only check.
    async fn apply_step(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        event: OperationEvent,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        engine
            .apply(operation_id, event, self.clock.now())
            .await
            .map_err(|error| match error {
                EngineError::NotFound(_) => ExecutorError::OperationNotFound(operation_id),
                EngineError::InvalidTransition {
                    operation_id,
                    source,
                } => ExecutorError::NotQueued {
                    operation_id,
                    state: source.from_state(),
                },
                EngineError::Store(source) => ExecutorError::Store(source),
                // `apply` never reports EmptyTargets (the engine rejects empty
                // target lists at create time) or the batch-creation limit
                // (that verdict is raised only by `create_batch`); the arms
                // exist only because `EngineError` is a closed enum.
                EngineError::EmptyTargets | EngineError::TooManyTargets { .. } => {
                    ExecutorError::EmptyTargets(operation_id)
                }
            })
    }

    /// Persists one §13.2 step on the recovery path, mapping a transition
    /// race onto the recovery contract's own guard name.
    ///
    /// The shared step helper maps an `InvalidTransition` race onto
    /// [`ExecutorError::NotQueued`] — the execution flow's guard — but a
    /// recovery step races with another driver that moved the operation out
    /// of `Running`/`Verifying`, so the guard is
    /// [`ExecutorError::NotRecoverable`], with the state the domain reported
    /// preserved. Every other verdict passes through unchanged.
    ///
    /// # Errors
    ///
    /// Same vocabulary as [`Self::apply_step`], with the race verdict
    /// renamed for the recovery contract.
    async fn recover_step(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        event: OperationEvent,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        self.apply_step(engine, operation_id, event)
            .await
            .map_err(guard_recovery_race)
    }

    /// Dispatches the write (§13.3 step 7) — through the typed command
    /// boundary for every family except Update, through the update boundary
    /// for a §14.3 firmware update — and drives the outcome of the §13.3
    /// step 8 branch the response selects.
    ///
    /// `artifact` is the pre-flight-resolved update payload; it is `Some`
    /// exactly when `command` is an Update command (the §13.3 step-4 check
    /// resolved it before any validation step was persisted), and a missing
    /// payload in the Update arm would be a scheduling bug, refused
    /// defensively without any dispatch.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Gateway`] or [`ExecutorError::UpdateGateway`]
    /// with the classified dispatch error as its source after the operation
    /// has been persisted into its honest terminal state (`Failed` or
    /// `Unknown`) and the terminal audit fact has been recorded, and
    /// [`ExecutorError::RemoteTask`] when the §13.6 observation row of an
    /// accepted Task cannot be persisted — the operation is recorded
    /// `Unknown` (§13.5, because the BMC already accepted the write and it
    /// must never be re-dispatched) and the terminal audit fact is recorded
    /// before the error escapes.
    async fn dispatch_and_verify(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
        started: &StartedAudit,
        artifact: Option<&UpdateArtifactPayload>,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        if let RedfishCommand::Update(UpdateCommand::StartUpdate(payload)) = command {
            // The §13.3 step-4 pre-flight resolved the payload for every
            // Update command; a missing payload here would be a scheduling
            // bug, refused defensively without any dispatch (a provable
            // refusal — nothing reaches the BMC).
            let Some(artifact) = artifact else {
                return self
                    .refuse(
                        engine,
                        operation_id,
                        started,
                        AuditFailure::EndpointPersistenceFailed,
                    )
                    .await;
            };
            let outcome = self
                .gateway
                .execute_update(endpoint_id, artifact, payload.push_uri())
                .await;
            self.drive_outcome(
                engine,
                operation_id,
                endpoint_id,
                command,
                started,
                outcome,
                ExecutorError::UpdateGateway,
            )
            .await
        } else {
            let outcome = self.gateway.execute(endpoint_id, command).await;
            self.drive_outcome(
                engine,
                operation_id,
                endpoint_id,
                command,
                started,
                outcome,
                ExecutorError::Gateway,
            )
            .await
        }
    }

    /// Drives the outcome of a dispatched write (§13.3 step 8) through the
    /// branch the response selects, including the §13.5 classification of
    /// failed dispatches.
    ///
    /// `wrap_error` maps the boundary's own error type onto the executor's
    /// vocabulary — [`ExecutorError::Gateway`] for the typed command
    /// boundary, [`ExecutorError::UpdateGateway`] for the update boundary —
    /// so the outcome semantics stay in one place for both dispatch paths.
    ///
    /// # Errors
    ///
    /// Returns the wrapped dispatch error after the operation has been
    /// persisted into its honest terminal state (`Failed` or `Unknown`) and
    /// the terminal audit fact has been recorded, and
    /// [`ExecutorError::RemoteTask`] when the §13.6 observation row of an
    /// accepted Task cannot be persisted — the operation is recorded
    /// `Unknown` (§13.5, because the BMC already accepted the write and it
    /// must never be re-dispatched) and the terminal audit fact is recorded
    /// before the error escapes.
    // The engine, the operation's target facts, the audit bundle, the
    // outcome, and its error wrapper are all individually named facts of the
    // shared outcome handling; grouping them would hide the exact contract
    // that mirrors the two dispatch call sites (the same accepted trade-off
    // as `AuditOperationContext::try_new`).
    #[allow(clippy::too_many_arguments)]
    async fn drive_outcome<DispatchError>(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
        started: &StartedAudit,
        outcome: Result<CommandOutcome, DispatchError>,
        wrap_error: fn(DispatchError) -> ExecutorErrorOf<Store, Gateway, Audit>,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>>
    where
        DispatchError: DispatchVerdictClassifier,
    {
        match outcome {
            Ok(CommandOutcome::AsyncTaskAccepted { task_location }) => {
                // §13.3 step 8, asynchronous acceptance: the BMC accepted the
                // write as a Task whose result is only observable by polling.
                // The observation row is persisted BEFORE the state step —
                // the row is what a crash between acceptance and the first
                // poll must not lose (§13.6) — and then the operation moves
                // to WaitingRemote, where the Task monitor resumes it. The
                // TaskMonitor URI is unknown at acceptance time (it is
                // discovered from the first Task read) and the placeholder
                // observation state `New` is truthful: the product has not
                // observed the Task executing yet.
                let task = RemoteTask::new(
                    operation_id,
                    endpoint_id,
                    task_location,
                    None,
                    self.clock.now(),
                );
                if let Err(source) = self.store.save_remote_task(&task).await {
                    // The BMC already accepted the write, so the operation
                    // must never be left retryable: re-dispatching would
                    // execute it twice. The product cannot track the Task it
                    // cannot persist, so the outcome cannot be proven and the
                    // operation is recorded Unknown (§13.5), then the error
                    // escapes with its source chain.
                    self.apply_step(engine, operation_id, OperationEvent::OutcomeUnknown)
                        .await?;
                    self.record_failure(
                        started,
                        AuditFailure::RedfishDiscoveryFailed,
                        AuditFailureVerification::Inconclusive,
                    )
                    .await?;
                    return Err(ExecutorError::RemoteTask(source));
                }
                self.apply_step(engine, operation_id, OperationEvent::RemoteTaskStarted)
                    .await
            }
            Ok(CommandOutcome::Rejected) => {
                // §13.3 step 8, synchronous rejection: the BMC provably
                // refused, so the write was not executed and the product can
                // account for the outcome.
                let final_operation = self
                    .apply_step(engine, operation_id, OperationEvent::Failed)
                    .await?;
                self.record_failure(
                    started,
                    AuditFailure::RedfishDiscoveryFailed,
                    AuditFailureVerification::Rejected,
                )
                .await?;
                Ok(final_operation)
            }
            Ok(CommandOutcome::Accepted) => {
                // §13.3 step 8, synchronous acceptance: the write landed and
                // the target must be re-read (steps 9-10).
                self.apply_step(engine, operation_id, OperationEvent::ExecutionAccepted)
                    .await?;
                self.verify_target(engine, operation_id, endpoint_id, command, started)
                    .await
            }
            Err(source) => {
                // §13.5: a failed dispatch is either a provable
                // non-execution (recorded `Failed`) or an outcome the product
                // cannot prove (recorded `Unknown`); the classification is the
                // boundary's own verdict, and the error escapes with its
                // source chain so the caller keeps the cause.
                let (event, failure, verification) = match source.verdict() {
                    DispatchVerdict::NotExecuted => (
                        OperationEvent::Failed,
                        AuditFailure::RedfishDiscoveryFailed,
                        AuditFailureVerification::Rejected,
                    ),
                    DispatchVerdict::OutcomeUnknown => (
                        OperationEvent::OutcomeUnknown,
                        AuditFailure::RedfishDiscoveryFailed,
                        AuditFailureVerification::Inconclusive,
                    ),
                };
                self.apply_step(engine, operation_id, event).await?;
                self.record_failure(started, failure, verification).await?;
                Err(wrap_error(source))
            }
        }
    }

    /// §13.3 step 4 (first cut for Update): resolves the referenced artifact
    /// into the payload the update boundary uploads.
    ///
    /// The artifact row must exist and be `Ready`: an `Uploading` artifact
    /// has not passed its finalize SHA-256 check and a `Failed` artifact was
    /// already rejected, so neither may reach a BMC. The file bytes are read
    /// from the artifact store's deterministic path under `spawn_blocking`
    /// (design §7.8: large file reads must never block a Tokio worker). The
    /// command only carries the artifact id — a database-serializable
    /// identity; the bytes are resolved here, at execution time, never
    /// persisted inside the command (§14.3).
    ///
    /// # Errors
    ///
    /// Returns [`UpdateArtifactResolutionError::Lookup`] when the artifact
    /// store read fails (the pre-flight cannot be evaluated), and the refusal
    /// variants when the artifact is provably unusable — the caller records a
    /// `Failed` operation with `Rejected` verification (§13.3 step 4, §13.5).
    async fn resolve_update_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<
        UpdateArtifactPayload,
        UpdateArtifactResolutionError<<Store as ArtifactRepository>::Error>,
    > {
        let artifact = self
            .store
            .find_artifact(artifact_id)
            .await
            .map_err(UpdateArtifactResolutionError::Lookup)?
            .ok_or(UpdateArtifactResolutionError::Missing)?;
        if artifact.state() != ArtifactState::Ready {
            return Err(UpdateArtifactResolutionError::NotReady);
        }
        let path = self.store.artifact_file_path(artifact.id());
        let bytes = read_artifact_bytes(path)
            .await
            .map_err(|_| UpdateArtifactResolutionError::Unreadable)?;
        Ok(UpdateArtifactPayload::new(
            artifact.id(),
            artifact.name().clone(),
            bytes,
        ))
    }

    /// Re-reads the target and checks the expected result (§13.3 steps 9-10),
    /// then writes the terminal state and audit fact (§13.3 step 11).
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Verifier`] with the re-read error as its
    /// source after the operation has been persisted into `Unknown` (a failed
    /// re-read proves nothing about the already-landed write, design section
    /// 13.5) and the terminal audit fact has been recorded.
    async fn verify_target(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
        started: &StartedAudit,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        match self.gateway.verify(endpoint_id, command).await {
            Ok(VerificationVerdict::Confirmed) => {
                // §13.3 steps 9-10 confirmed; step 11 writes the terminal
                // state and the audit fact.
                let final_operation = self
                    .apply_step(engine, operation_id, OperationEvent::VerificationPassed)
                    .await?;
                self.record_success(started).await?;
                Ok(final_operation)
            }
            Ok(VerificationVerdict::Mismatched) => {
                // The re-read proves the expected result is absent: the write
                // did not achieve its result, a provable failure.
                let final_operation = self
                    .apply_step(engine, operation_id, OperationEvent::Failed)
                    .await?;
                self.record_failure(
                    started,
                    AuditFailure::CoreResourceReadFailed,
                    AuditFailureVerification::Rejected,
                )
                .await?;
                Ok(final_operation)
            }
            Err(source) => {
                // §13.5: a failed re-read proves nothing about the write, so
                // the outcome cannot be confirmed and the operation is
                // recorded Unknown.
                self.apply_step(engine, operation_id, OperationEvent::OutcomeUnknown)
                    .await?;
                self.record_failure(
                    started,
                    AuditFailure::CoreResourceReadFailed,
                    AuditFailureVerification::Inconclusive,
                )
                .await?;
                Err(ExecutorError::Verifier(source))
            }
        }
    }

    /// Appends the §16.3 terminal failure fact.
    ///
    /// The failure classes are the closest 0.1 vocabulary values for each
    /// phase (endpoint pre-flight, capability pre-flight, dispatch,
    /// verification); write-specific failure classes are a later iteration's
    /// work, while the action and Redfish-operation fields are now the
    /// truthful execute-operation vocabulary (see [`operation_audit_context`]).
    /// The verification class is the truthful part: `Rejected` for every
    /// provable outcome and `Inconclusive` for every outcome the product
    /// cannot prove (design section 13.5).
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Audit`] with the terminal stage when the
    /// event cannot be constructed or the append fails; the operation has
    /// already reached its terminal state in the store by then.
    async fn record_failure(
        &self,
        started: &StartedAudit,
        failure: AuditFailure,
        verification: AuditFailureVerification,
    ) -> Result<(), ExecutorErrorOf<Store, Gateway, Audit>> {
        let failed = AuditEvent::failed(
            started.context.clone(),
            started.terminal_sequence,
            failure,
            verification,
            at_or_after(started.started_at, self.clock.now()),
        )
        .map_err(|source| ExecutorError::Audit {
            stage: OperationAuditStage::Terminal,
            source: AuditRecordError::Event(source),
        })?;
        self.audit
            .append_audit_event(&failed)
            .await
            .map_err(|source| ExecutorError::Audit {
                stage: OperationAuditStage::Terminal,
                source: AuditRecordError::Write(source),
            })
    }

    /// Appends the §16.3 terminal success fact.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Audit`] with the terminal stage when the
    /// event cannot be constructed or the append fails; the operation has
    /// already reached `Succeeded` in the store by then.
    async fn record_success(
        &self,
        started: &StartedAudit,
    ) -> Result<(), ExecutorErrorOf<Store, Gateway, Audit>> {
        let succeeded = AuditEvent::succeeded(
            started.context.clone(),
            started.terminal_sequence,
            at_or_after(started.started_at, self.clock.now()),
        )
        .map_err(|source| ExecutorError::Audit {
            stage: OperationAuditStage::Terminal,
            source: AuditRecordError::Event(source),
        })?;
        self.audit
            .append_audit_event(&succeeded)
            .await
            .map_err(|source| ExecutorError::Audit {
                stage: OperationAuditStage::Terminal,
                source: AuditRecordError::Write(source),
            })
    }
}

/// The audit facts opened for one execution attempt (§16.3).
///
/// Bundled so the terminal-recording helpers do not take the three values as
/// separate parameters.
struct StartedAudit {
    context: AuditOperationContext,
    terminal_sequence: AuditSequence,
    started_at: OffsetDateTime,
}

/// Builds the audit context of one operation execution or Task-poll attempt.
///
/// Shared by the executor (start + synchronous terminal facts, naming the
/// command's §7.5 write family) and the Task monitor (the asynchronous
/// terminal fact, design section 13.6, naming
/// [`AuditRedfishOperation::PollRemoteTask`]).
///
/// # Why the execute-operation vocabulary
///
/// The §16.3 domain vocabulary names the execution of a persisted write
/// (§13.1): the action is [`AuditAction::ExecuteOperation`], the permission
/// checked before it is [`ProductPermission::ExecuteOperations`], and the
/// typed [`AuditRedfishOperation`] is the §7.5 write family the command
/// dispatches — so a viewer can distinguish an action that only reads from
/// one that changes the managed endpoint. The parameter summary stays
/// [`AuditParameterSummary::EndpointRefresh`]: the domain documents it as
/// the closest legal summary until an operation-scoped summary lands
/// together with its persistence projection. The truthful parts of every
/// recorded event are the actor, the origin, the endpoint target, the
/// occurrence time, the write family, and the outcome (started / succeeded /
/// failed with its verification class).
///
/// # Errors
///
/// Returns [`AuditOperationContextError`] when the combination is not one the
/// 0.1 vocabulary accepts.
pub(crate) fn operation_audit_context(
    endpoint_id: EndpointId,
    redfish_operation: AuditRedfishOperation,
    actor: AuditActor,
    origin: DeploymentPosture,
) -> Result<AuditOperationContext, AuditOperationContextError> {
    AuditOperationContext::try_new(
        AuditOperationId::generate(),
        actor,
        origin,
        AuditTarget::Endpoint(endpoint_id),
        AuditParameterSummary::EndpointRefresh,
        ProductPermission::ExecuteOperations,
        AuditAction::ExecuteOperation,
        redfish_operation,
    )
}

/// Maps one typed command to the §16.3 audit name of its §7.5 write family.
///
/// The mapping is exhaustive per the §7.5 family list, so a new command
/// variant fails to compile until its audit name is decided here — the same
/// rule as [`required_capability`]. The granularity mirrors the domain
/// vocabulary: the three resets, the two Secure Boot writes beyond enable,
/// and subscription create/delete are named separately because their
/// accountability differs.
fn command_audit_operation(command: &RedfishCommand) -> AuditRedfishOperation {
    match command {
        // The five account writes are audited separately because their
        // accountability differs: creating an account, changing its role,
        // changing its password, renaming it, and deleting it are different
        // security-relevant actions (§16.3 granularity decision).
        RedfishCommand::Account(account) => match account {
            AccountCommand::CreateAccount(_) => AuditRedfishOperation::CreateAccount,
            AccountCommand::UpdateAccount(_) => AuditRedfishOperation::UpdateAccount,
            AccountCommand::UpdateAccountPassword(_) => {
                AuditRedfishOperation::UpdateAccountPassword
            }
            AccountCommand::UpdateAccountUserName(_) => {
                AuditRedfishOperation::UpdateAccountUserName
            }
            AccountCommand::DeleteAccount(_) => AuditRedfishOperation::DeleteAccount,
        },
        RedfishCommand::System(SystemCommand::Reset(_)) => AuditRedfishOperation::ResetSystem,
        RedfishCommand::Manager(ManagerCommand::Reset(_)) => AuditRedfishOperation::ResetManager,
        // A factory-defaults wipe is materially different from a restart, so
        // the reset-to-defaults command gets its own audit name (§16.3).
        RedfishCommand::Manager(ManagerCommand::ResetToDefaults(_)) => {
            AuditRedfishOperation::ManagerResetToDefaults
        }
        RedfishCommand::Chassis(ChassisCommand::Reset(_)) => AuditRedfishOperation::ResetChassis,
        RedfishCommand::Chassis(ChassisCommand::PowerSupplyReset(_)) => {
            AuditRedfishOperation::PowerSupplyReset
        }
        RedfishCommand::Boot(BootCommand::SetBootSourceOverride(_)) => {
            AuditRedfishOperation::SetBootSourceOverride
        }
        RedfishCommand::SecureBoot(SecureBootCommand::Enable) => {
            AuditRedfishOperation::SecureBootEnable
        }
        RedfishCommand::SecureBoot(SecureBootCommand::Disable) => {
            AuditRedfishOperation::SecureBootDisable
        }
        RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(_)) => {
            AuditRedfishOperation::SecureBootResetKeys
        }
        RedfishCommand::Event(EventCommand::CreateSubscription(_)) => {
            AuditRedfishOperation::CreateEventSubscription
        }
        RedfishCommand::Event(EventCommand::DeleteSubscription(_)) => {
            AuditRedfishOperation::DeleteEventSubscription
        }
        RedfishCommand::Log(LogCommand::ClearLog(_)) => AuditRedfishOperation::LogClear,
        RedfishCommand::Control(ControlCommand::Update(_)) => AuditRedfishOperation::ControlUpdate,
        // The seven telemetry writes are audited separately because their
        // accountability differs: enabling or disabling the telemetry
        // service, creating, updating, or deleting a metric definition, and
        // creating, updating, or deleting a metric report definition are
        // materially different actions (§16.3 granularity decision).
        RedfishCommand::Telemetry(TelemetryCommand::SetEnabled { .. }) => {
            AuditRedfishOperation::SetTelemetryEnabled
        }
        RedfishCommand::Telemetry(TelemetryCommand::CreateMetricDefinition(_)) => {
            AuditRedfishOperation::CreateMetricDefinition
        }
        RedfishCommand::Telemetry(TelemetryCommand::UpdateMetricDefinition(_)) => {
            AuditRedfishOperation::UpdateMetricDefinition
        }
        RedfishCommand::Telemetry(TelemetryCommand::DeleteMetricDefinition(_)) => {
            AuditRedfishOperation::DeleteMetricDefinition
        }
        RedfishCommand::Telemetry(TelemetryCommand::CreateMetricReportDefinition(_)) => {
            AuditRedfishOperation::CreateMetricReportDefinition
        }
        RedfishCommand::Telemetry(TelemetryCommand::UpdateMetricReportDefinition(_)) => {
            AuditRedfishOperation::UpdateMetricReportDefinition
        }
        RedfishCommand::Telemetry(TelemetryCommand::DeleteMetricReportDefinition(_)) => {
            AuditRedfishOperation::DeleteMetricReportDefinition
        }
        RedfishCommand::Update(UpdateCommand::StartUpdate(_)) => {
            AuditRedfishOperation::UpdateFirmware
        }
        // Patching the `UpdateService` configuration is separate from
        // submitting firmware: the accountability of a service-configuration
        // change differs from an artifact upload (§16.3).
        RedfishCommand::Update(UpdateCommand::Patch(_)) => {
            AuditRedfishOperation::UpdateServicePatch
        }
        // The three OEM faces are audited separately because their
        // accountability differs: a profile-service write, a debug-token
        // write, and a power-smoothing write are different §11.5 surfaces.
        RedfishCommand::Oem(OemCommand::SystemConfigProfile(_)) => {
            AuditRedfishOperation::OemSystemConfigProfile
        }
        RedfishCommand::Oem(OemCommand::DebugToken(_)) => AuditRedfishOperation::OemDebugToken,
        RedfishCommand::Oem(OemCommand::PowerSmoothing(_)) => {
            AuditRedfishOperation::OemPowerSmoothing
        }
    }
}

/// Maps one typed command to the capability the endpoint must advertise.
///
/// The mapping is exhaustive per the §7.5 family list, so a new command
/// family fails to compile until its capability is decided here. Boot and
/// Secure Boot live on the `ComputerSystem` resource, so they require the
/// `Systems` capability (the stable 0.1 product code of the
/// `computer-systems` feature) and `SecureBoot` respectively; event
/// subscription writes require the event service.
pub(crate) fn required_capability(command: &RedfishCommand) -> EndpointCapability {
    match command {
        // Account writes target the BMC's `AccountService` (`ManagerAccount`
        // resources), so they require the accounts capability (§2.1).
        RedfishCommand::Account(_) => EndpointCapability::Accounts,
        // Boot configuration lives on the `ComputerSystem` resource, so a
        // boot command needs the same `Systems` capability as a system reset.
        RedfishCommand::System(_) | RedfishCommand::Boot(_) => EndpointCapability::Systems,
        RedfishCommand::Manager(_) => EndpointCapability::Managers,
        RedfishCommand::Chassis(_) => EndpointCapability::Chassis,
        RedfishCommand::SecureBoot(_) => EndpointCapability::SecureBoot,
        RedfishCommand::Event(_) => EndpointCapability::EventService,
        // A log-service write targets the BMC's `LogService` resources, so
        // it requires the log-services capability (§2.1, §3.1).
        RedfishCommand::Log(_) => EndpointCapability::LogServices,
        // A control write targets the chassis's `Control` resources, so it
        // requires the controls capability (§2.1, §3.1).
        RedfishCommand::Control(_) => EndpointCapability::Controls,
        // Telemetry writes target the BMC's `TelemetryService` (§14.4), so
        // they require the telemetry-service capability.
        RedfishCommand::Telemetry(_) => EndpointCapability::TelemetryService,
        // A firmware update targets the BMC's UpdateService (§14.3), so the
        // update command requires the update-service capability.
        RedfishCommand::Update(_) => EndpointCapability::UpdateService,
        // Each OEM face requires the §2.1 sub-capability of its chain: the
        // profile service, the debug-token surfaces, and the power-smoothing
        // resource each probe `Supported` whenever the endpoint advertises
        // the `Nvidia` namespace (§11.3 advertised layer).
        RedfishCommand::Oem(OemCommand::SystemConfigProfile(_)) => {
            EndpointCapability::OemNvidiaProfiles
        }
        RedfishCommand::Oem(OemCommand::DebugToken(_)) => EndpointCapability::OemNvidiaSecurity,
        RedfishCommand::Oem(OemCommand::PowerSmoothing(_)) => {
            EndpointCapability::OemNvidiaPowerManagement
        }
    }
}

/// Returns the observed state of one capability inside a full §2.1 ledger.
///
/// `None` means the capability has no observation yet (it is not the
/// `NotAdvertised` final state, which requires an explicit probe result).
pub(crate) fn required_capability_state(
    required: EndpointCapability,
    entries: &[CapabilityLedgerEntry],
) -> Option<CapabilityState> {
    entries
        .iter()
        .find(|entry| entry.capability() == required)
        .and_then(|entry| CapabilityLedgerEntry::state(*entry))
}

/// Returns the later of two observed times, keeping terminal audit facts at
/// or after the start fact even when the clock reports an identical instant.
fn at_or_after(previous: OffsetDateTime, observed: OffsetDateTime) -> OffsetDateTime {
    previous.max(observed)
}

/// Why the §13.3 step-4 artifact pre-flight cannot produce an update payload.
///
/// The first three variants are provable parameter violations — the caller
/// records a `Failed` operation with `Rejected` verification (§13.5: nothing
/// was dispatched). The refusal path treats them alike (the audit vocabulary
/// carries no reason string in this iteration; the specific reason is a
/// later diagnostic surface's work). [`Self::Lookup`] is an evaluation
/// failure: the artifact store could not be read, so the check cannot be
/// decided and the caller escalates it exactly like the endpoint pre-flight
/// lookup failure.
enum UpdateArtifactResolutionError<ArtifactRepositoryError> {
    /// The referenced artifact row does not exist.
    Missing,
    /// The referenced artifact exists but has not finished its upload
    /// lifecycle; only a `Ready` artifact may reach a BMC.
    NotReady,
    /// The artifact file cannot be read from the artifact store; the row is
    /// `Ready` but the bytes are gone.
    Unreadable,
    /// The artifact store rejected the lookup.
    Lookup(ArtifactRepositoryError),
}

/// Reads one artifact file under `spawn_blocking` (design §7.8).
///
/// The artifact store's deterministic path is a pure function of the artifact
/// id (§9.3), so the bytes are resolved here at execution time without the
/// command ever carrying file content.
async fn read_artifact_bytes(path: PathBuf) -> Result<Vec<u8>, io::Error> {
    spawn_blocking(move || fs::read(path))
        .await
        .map_err(io::Error::other)?
}

/// Renames the execution-flow race guard to the recovery contract's guard for
/// errors observed on the recovery path.
///
/// The recovery path shares the step helper of the execution flow, which
/// reports a transition race as [`ExecutorError::NotQueued`] ("only queued or
/// validating work"); on the recovery path the same race means "another
/// driver moved the operation out of `Running`/`Verifying`", which is
/// [`ExecutorError::NotRecoverable`]. Every other error passes through
/// unchanged.
fn guard_recovery_race<
    StoreError,
    RepositoryError,
    CapabilityError,
    RemoteTaskStoreError,
    ArtifactRepositoryError,
    GatewayError,
    UpdateGatewayError,
    VerifierError,
    AuditError,
>(
    error: ExecutorError<
        StoreError,
        RepositoryError,
        CapabilityError,
        RemoteTaskStoreError,
        ArtifactRepositoryError,
        GatewayError,
        UpdateGatewayError,
        VerifierError,
        AuditError,
    >,
) -> ExecutorError<
    StoreError,
    RepositoryError,
    CapabilityError,
    RemoteTaskStoreError,
    ArtifactRepositoryError,
    GatewayError,
    UpdateGatewayError,
    VerifierError,
    AuditError,
>
where
    StoreError: Error + 'static,
    RepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    RemoteTaskStoreError: Error + 'static,
    ArtifactRepositoryError: Error + 'static,
    GatewayError: Error + 'static,
    UpdateGatewayError: Error + 'static,
    VerifierError: Error + 'static,
    AuditError: Error + 'static,
{
    match error {
        ExecutorError::NotQueued {
            operation_id,
            state,
        } => ExecutorError::NotRecoverable {
            operation_id,
            state,
        },
        other => other,
    }
}

/// The audit lifecycle point that could not be recorded (§16.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationAuditStage {
    /// The start fact could not be appended; no operation step is persisted.
    Start,
    /// The terminal fact could not be appended; the operation has already
    /// reached its terminal state in the store.
    Terminal,
}

impl fmt::Display for OperationAuditStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => formatter.write_str("start"),
            Self::Terminal => formatter.write_str("terminal"),
        }
    }
}

/// A controlled failure while driving one operation toward its terminal
/// state.
///
/// The nine generic parameters are the boundary error types in dependency
/// order: the operation store, the endpoint lookup, the capability query, the
/// remote-task store, the artifact lookup, the command dispatch, the update
/// dispatch, the post-execution verification, and the audit append. Every
/// variant keeps its boundary source on the error chain.
#[derive(Debug, Error)]
pub enum ExecutorError<
    StoreError,
    RepositoryError,
    CapabilityError,
    RemoteTaskStoreError,
    ArtifactRepositoryError,
    GatewayError,
    UpdateGatewayError,
    VerifierError,
    AuditError,
> where
    StoreError: Error + 'static,
    RepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    RemoteTaskStoreError: Error + 'static,
    ArtifactRepositoryError: Error + 'static,
    GatewayError: Error + 'static,
    UpdateGatewayError: Error + 'static,
    VerifierError: Error + 'static,
    AuditError: Error + 'static,
{
    /// The operation id is not known to the store.
    #[error("operation {0} was not found")]
    OperationNotFound(OperationId),
    /// The scheduler tried to drive an operation that is no longer queued or
    /// validating.
    ///
    /// This is the defensive guard for the execution-flow scheduling contract
    /// (fresh `Queued` work and crash-resumed `Validating` work): either the
    /// caller passed a state the execution flow must not touch — the
    /// scheduler dispatches `Running`/`Verifying` to
    /// [`OperationExecutor::recover_operation`] and `WaitingRemote` to the
    /// Task monitor — or a second driver advanced the operation between the
    /// scheduler's read and its first persisted step (the domain state
    /// machine reported the current state).
    #[error(
        "operation {operation_id} is {state} and only queued or validating operations are schedulable"
    )]
    NotQueued {
        operation_id: OperationId,
        state: OperationState,
    },
    /// The scheduler tried to recover an operation that is not stranded in
    /// flight.
    ///
    /// This is the defensive guard for the recovery contract: only `Running`
    /// (dispatch outcome unknown, §13.5) and `Verifying` (re-read in flight)
    /// carry unfinished outcome work. `Validating` work resumes through
    /// [`OperationExecutor::execute_operation`], `WaitingRemote` work through
    /// the Task monitor, and terminal states are final.
    #[error(
        "operation {operation_id} is {state} and only running or verifying operations are recoverable"
    )]
    NotRecoverable {
        operation_id: OperationId,
        state: OperationState,
    },
    /// The persisted operation carries no target and can never execute.
    ///
    /// `OperationEngine::create` rejects empty target lists, so this is a
    /// corrupt row that rehydration (`Operation::try_from_parts`) failed to
    /// reject.
    #[error("operation {0} carries no target and cannot be executed")]
    EmptyTargets(OperationId),
    /// The operation store rejected a read or a persisted step.
    #[error("operation store failed: {0}")]
    Store(#[source] StoreError),
    /// The endpoint existence pre-flight (§13.3 step 1) could not be
    /// evaluated.
    #[error("endpoint pre-flight lookup failed: {0}")]
    EndpointPreflight(#[source] RepositoryError),
    /// The capability pre-flight (§13.3 step 2) could not be evaluated.
    #[error("capability pre-flight query failed: {0}")]
    CapabilityPreflight(#[source] EndpointCapabilityQueryError<CapabilityError>),
    /// The §13.6 observation row of an accepted Task could not be persisted
    /// or read.
    ///
    /// After a failed save, the BMC already accepted the write (the `202` was
    /// dispatched), so the operation is recorded `Unknown` — the product
    /// cannot prove the outcome of a Task it cannot track (§13.5), and
    /// re-dispatching would execute the write twice — and the terminal audit
    /// fact is recorded before this error is returned. A failed read on the
    /// recovery path (design section 13.6) carries the same error with no
    /// step persisted: the row could not be inspected, so the recovery cannot
    /// tell an accepted Task from a lost dispatch.
    #[error("remote task observation could not be persisted or read: {0}")]
    RemoteTask(#[source] RemoteTaskStoreError),
    /// The §13.3 step-4 artifact pre-flight could not be evaluated.
    ///
    /// The artifact store rejected the lookup of the artifact an Update
    /// command references; nothing has been dispatched and no operation step
    /// is persisted (the same contract as the endpoint pre-flight lookup
    /// failure).
    #[error("artifact pre-flight lookup failed: {0}")]
    ArtifactPreflight(#[source] ArtifactRepositoryError),
    /// The command dispatch (§13.3 step 7) failed.
    ///
    /// The operation has already been persisted into its honest terminal
    /// state (`Failed` or `Unknown`, per the error's own [`DispatchVerdict`])
    /// and its terminal audit fact has been recorded before this error is
    /// returned.
    #[error("command dispatch failed: {0}")]
    Gateway(#[source] GatewayError),
    /// The §14.3 update dispatch failed.
    ///
    /// The operation has already been persisted into its honest terminal
    /// state (`Failed` or `Unknown`, per the error's own [`DispatchVerdict`])
    /// and its terminal audit fact has been recorded before this error is
    /// returned — the same contract as [`Self::Gateway`], for the update
    /// boundary.
    #[error("update dispatch failed: {0}")]
    UpdateGateway(#[source] UpdateGatewayError),
    /// The post-execution verification re-read (§13.3 steps 9-10) failed.
    ///
    /// The operation has already been persisted into `Unknown` (a failed
    /// re-read proves nothing about the landed write, design section 13.5)
    /// and its terminal audit fact has been recorded before this error is
    /// returned.
    #[error("post-execution verification failed: {0}")]
    Verifier(#[source] VerifierError),
    /// The §16.3 audit lifecycle could not be fully recorded.
    #[error("operation audit {stage} failed: {source}")]
    Audit {
        stage: OperationAuditStage,
        #[source]
        source: AuditRecordError<AuditError>,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        error::Error,
        fmt,
        sync::{Arc, Mutex},
    };

    use rutilus_domain::{
        AccountCommand, AccountId, AccountPassword, AccountUserName, Artifact, ArtifactName,
        ArtifactState, AuditOutcomeKind, AuditVerification, BootCommand, BootSource,
        BootSourceOverrideEnabled, BootSourceOverrideMode, CapabilityState, ChassisCommand,
        ClearLog, ControlCommand, CreateAccount, CreateMetricDefinition,
        CreateMetricReportDefinition, CreateSubscription, CredentialId, DeleteAccount,
        DeleteMetricDefinition, DeleteMetricReportDefinition, DeleteSubscription, Endpoint,
        EndpointAddress, EndpointCapabilityObservation, EndpointDisplayName, EndpointId,
        EventCommand, EventDestinationProtocol, EventType, LogCommand, ManagerCommand,
        ManagerResetToDefaultsType, MetricDefinitionId, MetricReportDefinitionId,
        MetricReportDefinitionType, MetricReportMetric, MetricType, MetricUnits,
        NvidiaDebugTokenCommand, NvidiaPowerSmoothingCommand, NvidiaSystemConfigProfileCommand,
        OperationSource, OperationTarget, PowerSupplyReset, ResetKeysType, ResetType,
        ResourceSnapshot, RoleId, SecureBootCommand, SetBootSourceOverride, Sha256Hex, StartUpdate,
        SystemCommand, TargetId, TelemetryCommand, TlsCertificate, TlsTrust, UpdateAccount,
        UpdateAccountPassword, UpdateAccountUserName, UpdateCommand, UpdateControl,
        UpdateMetricDefinition, UpdateMetricReportDefinition, UpdatePatch,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild, RemoteTaskState, TaskUri,
    };
    use time::Duration;

    use crate::{BoundaryFuture, ResourceObservation, StoredCapability};

    use super::*;

    /// The creation time of every test operation; one second before the fixed
    /// clock so every persisted step strictly follows creation.
    fn created_at() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// The fixed wall clock every use case under test observes.
    fn clock_time() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::SECOND
    }

    /// Builds one schedulable queued operation targeting `endpoint_id`.
    fn queued_operation(endpoint_id: EndpointId) -> Operation {
        Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            created_at(),
        )
    }

    /// Builds one schedulable queued firmware-update operation (§14.3).
    fn queued_update_operation(
        endpoint_id: EndpointId,
        artifact_id: ArtifactId,
        push_uri: Option<String>,
    ) -> Operation {
        Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                artifact_id,
                push_uri,
            ))),
            created_at(),
        )
    }

    /// Builds one operation parked in the given in-flight state, exactly as
    /// rehydration would surface it after a crash (every step at the fixed
    /// clock time).
    ///
    /// Only the recovery states are parkable; any other state is a test bug,
    /// and the helper says so instead of constructing a meaningless row.
    fn parked_operation(
        endpoint_id: EndpointId,
        state: OperationState,
    ) -> Result<Operation, Box<dyn Error>> {
        let steps: &[OperationEvent] = match state {
            OperationState::Validating => &[OperationEvent::ValidationStarted],
            OperationState::Running => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
            ],
            OperationState::Verifying => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
                OperationEvent::ExecutionAccepted,
            ],
            _ => {
                return Err(
                    std::io::Error::other("test helper parks only in-flight states").into(),
                );
            }
        };
        let mut operation = queued_operation(endpoint_id);
        for step in steps {
            operation.apply(*step, clock_time())?;
        }
        Ok(operation)
    }

    /// Builds one trusted endpoint row for the pre-flight existence check.
    fn endpoint(endpoint_id: EndpointId) -> Result<Endpoint, Box<dyn Error>> {
        Ok(Endpoint::try_new(
            endpoint_id,
            EndpointDisplayName::parse("Operation test BMC")?,
            EndpointAddress::parse("https://192.0.2.100")?,
            TlsTrust::SystemCa {
                certificate: TlsCertificate::from_der(b"operation certificate".to_vec())?,
                verified_at: created_at(),
            },
            CredentialId::generate(),
            created_at(),
            created_at(),
        )?)
    }

    /// One persisted `Systems` capability observation at the supported state,
    /// which is what a System Reset command needs to pass pre-flight.
    fn supported_systems_capability() -> Vec<StoredCapability> {
        vec![StoredCapability::new(
            EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            created_at(),
        )]
    }

    /// One persisted `UpdateService` capability observation at the supported
    /// state, which is what an Update command needs to pass pre-flight
    /// (§14.3).
    fn supported_update_service_capability() -> Vec<StoredCapability> {
        vec![StoredCapability::new(
            EndpointCapabilityObservation::new(
                EndpointCapability::UpdateService,
                CapabilityState::Supported,
            ),
            created_at(),
        )]
    }

    /// Composes the executor under test over the given fakes.
    ///
    /// The executor borrows the fakes (every boundary has a forwarding impl
    /// for `&T`), so the tests keep ownership of the recorded state.
    fn executor<'a>(
        store: &'a FakeStore,
        gateway: &'a FakeGateway,
        audit: &'a MockAudit,
    ) -> OperationExecutor<&'a FakeStore, &'a FakeGateway, &'a MockAudit, FixedClock> {
        OperationExecutor::new(
            store,
            gateway,
            audit,
            FixedClock(clock_time()),
            AuditActor::System,
            DeploymentPosture::Site,
        )
    }

    /// Extracts the persisted state sequence of one execution from the
    /// recorded store calls; each state maps one-to-one onto the §13.2 event
    /// that produced it.
    fn applied_states(calls: &[Call]) -> Vec<OperationState> {
        calls
            .iter()
            .filter_map(|call| match call {
                Call::ApplyTransition(_, state) => Some(*state),
                _ => None,
            })
            .collect()
    }

    /// One recorded store call, in order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Create(OperationId),
        Find(OperationId),
        ApplyTransition(OperationId, OperationState),
        RecordFailureKind(OperationId),
        FindEndpoint(EndpointId),
        FindCapabilities(EndpointId),
        FindArtifact(ArtifactId),
        SaveRemoteTask(OperationId),
    }

    /// The single failure mode armed for the next matching store call.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockStoreFailure {
        Read,
        Write,
        EndpointLookup,
        CapabilityLookup,
        ArtifactLookup,
        RemoteTaskWrite,
    }

    /// In-memory store implementing every repository role the executor uses.
    ///
    /// One struct implements `OperationStore`, `EndpointRefreshRepository`,
    /// `CapabilityQueryRepository`, `RemoteTaskStore`, and
    /// `ArtifactRepository` exactly like the production `SqliteStore`, so the
    /// executor composes over a single test object. `apply_transition`
    /// upholds the store contract: unknown ids and writes onto terminal
    /// states are rejected. The artifact role uses a real temporary
    /// directory — the executor reads the artifact file from the
    /// deterministic path, so the update dispatch tests exercise the same
    /// file I/O the production flow performs.
    struct FakeStore {
        rows: Mutex<HashMap<OperationId, Operation>>,
        remote_tasks: Mutex<HashMap<OperationId, RemoteTask>>,
        artifacts: Mutex<HashMap<ArtifactId, Artifact>>,
        artifact_directory: Option<PathBuf>,
        artifact_tempdir: Option<tempfile::TempDir>,
        endpoint: Option<Endpoint>,
        capabilities: Vec<StoredCapability>,
        calls: Mutex<Vec<Call>>,
        // The kind value itself is a zero-sized type (the vocabulary has one
        // variant), so the record is the set of classified operations.
        classified: Mutex<HashSet<OperationId>>,
        fail_once: Mutex<Option<MockStoreFailure>>,
        find_calls: Mutex<usize>,
        find_race: Mutex<Option<(usize, OperationState)>>,
    }

    impl FakeStore {
        fn new(endpoint: Option<Endpoint>, capabilities: Vec<StoredCapability>) -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                remote_tasks: Mutex::new(HashMap::new()),
                artifacts: Mutex::new(HashMap::new()),
                artifact_directory: None,
                artifact_tempdir: None,
                endpoint,
                capabilities,
                calls: Mutex::new(Vec::new()),
                classified: Mutex::new(HashSet::new()),
                fail_once: Mutex::new(None),
                find_calls: Mutex::new(0),
                find_race: Mutex::new(None),
            }
        }

        /// Creates the artifact directory for tests that exercise the §14.3
        /// update dispatch; the temporary directory lives for the store's
        /// lifetime.
        fn with_artifact_directory(mut self) -> Result<Self, MockError> {
            let directory = tempfile::tempdir().map_err(|_| MockError::Artifact)?;
            let artifact_directory = directory.path().join("artifacts");
            std::fs::create_dir_all(&artifact_directory).map_err(|_| MockError::Artifact)?;
            self.artifact_directory = Some(artifact_directory);
            self.artifact_tempdir = Some(directory);
            Ok(self)
        }

        /// Stores one artifact row and, for the `Ready` state, its file
        /// bytes — exactly the invariant the domain guarantees (a ready
        /// artifact holds its complete verified content).
        fn store_artifact(
            &self,
            artifact_id: ArtifactId,
            state: ArtifactState,
            bytes: &[u8],
        ) -> Result<Artifact, MockError> {
            let uploaded = if state == ArtifactState::Ready {
                bytes.len() as u64
            } else {
                0
            };
            let artifact = Artifact::try_from_parts(
                artifact_id,
                ArtifactName::parse("firmware.bin").map_err(|_| MockError::Artifact)?,
                bytes.len() as u64,
                Sha256Hex::from_bytes([0xAB; 32]),
                state,
                uploaded,
                created_at(),
                clock_time(),
            )
            .map_err(|_| MockError::Artifact)?;
            self.artifacts
                .lock()
                .map_err(|_| MockError::Events)?
                .insert(artifact_id, artifact.clone());
            if state == ArtifactState::Ready {
                let directory = self
                    .artifact_directory
                    .as_ref()
                    .ok_or(MockError::Artifact)?;
                std::fs::write(directory.join(format!("{artifact_id}.bin")), bytes)
                    .map_err(|_| MockError::Artifact)?;
            }
            Ok(artifact)
        }

        /// Arms exactly one failure for the next call of `kind`.
        fn arm_failure(&self, kind: MockStoreFailure) -> Result<(), MockError> {
            *self.fail_once.lock().map_err(|_| MockError::Events)? = Some(kind);
            Ok(())
        }

        /// The operations that received a failure classification.
        fn recorded_failure_kinds(&self) -> Result<HashSet<OperationId>, MockError> {
            self.classified
                .lock()
                .map(|classified| classified.clone())
                .map_err(|_| MockError::Events)
        }

        /// Arms a transition race: the `n`-th `find_operation` read
        /// (1-based) reports the operation in `state` instead of its stored
        /// state.
        ///
        /// This is the injection seam for the `InvalidTransition` race the
        /// domain state machine reports when a second driver advances the
        /// operation between the executor's own read and the engine's step
        /// read — the engine's `find` inside `apply` is always exactly one
        /// `find_operation` call later, so tests arm `on_call = 2`. Every
        /// other read returns the stored row.
        fn arm_find_race(&self, on_call: usize, state: OperationState) -> Result<(), MockError> {
            *self.find_race.lock().map_err(|_| MockError::Events)? = Some((on_call, state));
            Ok(())
        }

        /// Inserts a prebuilt operation row (used for corrupt-row tests and
        /// for parking operations in a non-queued state).
        fn insert(&self, operation: Operation) -> Result<(), MockError> {
            self.rows
                .lock()
                .map_err(|_| MockError::Events)?
                .insert(operation.id(), operation);
            Ok(())
        }

        fn recorded_calls(&self) -> Result<Vec<Call>, MockError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }

        fn find_owned(&self, operation_id: OperationId) -> Result<Option<Operation>, MockError> {
            self.rows
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
        fn consume_failure(&self, kind: MockStoreFailure) -> Result<bool, MockError> {
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
            operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::Create(operation.id()));
                self.insert(operation.clone())
            })
        }

        fn find_operation(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::Find(operation_id));
                if self.consume_failure(MockStoreFailure::Read)? {
                    return Err(MockError::Store);
                }
                let mut find_count = self.find_calls.lock().map_err(|_| MockError::Events)?;
                *find_count += 1;
                let race = self.find_race.lock().map_err(|_| MockError::Events)?;
                let row = self
                    .rows
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .get(&operation_id)
                    .cloned();
                if let Some((target, state)) = *race
                    && *find_count == target
                {
                    // Report the operation in `state` instead of its
                    // stored state: a second driver advanced the operation,
                    // so the domain state machine will reject the next step
                    // as an invalid transition — the race the executor's
                    // step helpers guard against.
                    let row = row.ok_or(MockError::Store)?;
                    return Ok(Some(
                        Operation::try_from_parts(
                            row.id(),
                            row.source(),
                            row.targets().to_vec(),
                            row.command(),
                            state,
                            row.created_at(),
                            row.updated_at(),
                        )
                        .map_err(|_| MockError::Store)?,
                    ));
                }
                Ok(row)
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
                    .push(Call::ApplyTransition(operation_id, new_state));
                if self.consume_failure(MockStoreFailure::Write)? {
                    return Err(MockError::Store);
                }
                let mut rows = self.rows.lock().map_err(|_| MockError::Events)?;
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

        fn record_failure_kind(
            &self,
            operation_id: OperationId,
            kind: rutilus_domain::FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::RecordFailureKind(operation_id));
                if self.consume_failure(MockStoreFailure::Write)? {
                    return Err(MockError::Store);
                }
                // The vocabulary has one variant, so the record is the set of
                // classified operations; `kind` stays in the signature to pin
                // the boundary contract.
                let _ = kind;
                self.classified
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .insert(operation_id);
                Ok(())
            })
        }

        fn list_operations(
            &self,
            _state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a rutilus_domain::BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The executor never creates batches; the submission path owns
            // that boundary, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn find_batch(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<rutilus_domain::BatchOperation>, Self::Error>>
        {
            // The executor never reads batches; batch reporting owns that
            // projection, so this stub is unreachable here.
            Box::pin(async move { Ok(None) })
        }

        fn list_batches(
            &self,
        ) -> OperationBoundaryFuture<'_, Result<Vec<rutilus_domain::BatchOperation>, Self::Error>>
        {
            // The executor never lists batches; batch reporting owns that
            // projection, so this stub is unreachable here.
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_batch_children(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            // The executor never lists batch children; batch reporting owns
            // that projection, so this stub is unreachable here.
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl EndpointRefreshRepository for FakeStore {
        type Error = MockError;

        fn find_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::FindEndpoint(endpoint_id));
                if self.consume_failure(MockStoreFailure::EndpointLookup)? {
                    return Err(MockError::Repository);
                }
                Ok(self.endpoint.clone())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [ResourceObservation],
            _decode_failures: &'a [crate::ResourceDecodeFailure],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            // The operation scheduler never commits resource generations; the
            // refresh use case owns that boundary, so this stub is never
            // reached by the executor.
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl CapabilityQueryRepository for FakeStore {
        type Error = MockError;

        fn find_endpoint_capabilities(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::FindCapabilities(endpoint_id));
                if self.consume_failure(MockStoreFailure::CapabilityLookup)? {
                    return Err(MockError::Capability);
                }
                if self.endpoint.is_none() {
                    return Ok(None);
                }
                Ok(Some(self.capabilities.clone()))
            })
        }
    }

    impl ArtifactRepository for FakeStore {
        type Error = MockError;

        fn create_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            // The executor never creates artifacts; the upload use case owns
            // that boundary, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn find_artifact(
            &self,
            artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::FindArtifact(artifact_id));
                if self.consume_failure(MockStoreFailure::ArtifactLookup)? {
                    return Err(MockError::Artifact);
                }
                self.artifacts
                    .lock()
                    .map_err(|_| MockError::Events)
                    .map(|rows| rows.get(&artifact_id).cloned())
            })
        }

        fn list_artifacts_by_state(
            &self,
            _state: ArtifactState,
        ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
            // The executor never lists artifacts; the inventory use case owns
            // that projection, so this stub is unreachable here.
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn update_artifact(
            &self,
            _artifact_id: ArtifactId,
            _uploaded_bytes: u64,
            _state: ArtifactState,
            _occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            // The executor never advances artifact progress; the upload use
            // case owns that boundary, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
            match &self.artifact_directory {
                Some(directory) => directory.join(format!("{artifact_id}.bin")),
                None => PathBuf::from(format!("{artifact_id}.bin")),
            }
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
                    .push(Call::SaveRemoteTask(task.operation_id()));
                if self.consume_failure(MockStoreFailure::RemoteTaskWrite)? {
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
            Box::pin(async move { self.find_remote_task_owned(operation_id) })
        }

        fn list_remote_tasks_by_state(
            &self,
            _state: RemoteTaskState,
        ) -> OperationBoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>> {
            // The executor never lists task rows; the Task monitor owns that
            // projection, so this stub is unreachable here.
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    /// One recorded gateway call with the exact endpoint and command.
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct GatewayCall {
        kind: GatewayCallKind,
        endpoint_id: EndpointId,
        command: RedfishCommand,
    }

    /// The gateway boundary that produced the call.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum GatewayCallKind {
        Execute,
        Verify,
    }

    /// One recorded update-boundary call with the exact endpoint, artifact,
    /// and push URI (§14.3).
    #[derive(Clone, Debug, Eq, PartialEq)]
    struct UpdateCall {
        endpoint_id: EndpointId,
        artifact_id: ArtifactId,
        push_uri: Option<String>,
    }

    /// Scripted gateway: `outcome` is the dispatch result, `update_outcome`
    /// the update-boundary result, and `verdict` the verification result,
    /// each recorded per call.
    struct FakeGateway {
        calls: Mutex<Vec<GatewayCall>>,
        update_calls: Mutex<Vec<UpdateCall>>,
        outcome: Result<CommandOutcome, MockError>,
        update_outcome: Result<CommandOutcome, MockError>,
        verdict: Result<VerificationVerdict, MockError>,
    }

    impl FakeGateway {
        fn new(
            outcome: Result<CommandOutcome, MockError>,
            verdict: Result<VerificationVerdict, MockError>,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                update_calls: Mutex::new(Vec::new()),
                outcome,
                update_outcome: Ok(CommandOutcome::Accepted),
                verdict,
            }
        }

        /// Scripts the update-boundary result; the typed dispatch outcome
        /// stays `Accepted` unless a test changes it.
        fn with_update_outcome(
            mut self,
            update_outcome: Result<CommandOutcome, MockError>,
        ) -> Self {
            self.update_outcome = update_outcome;
            self
        }

        fn recorded_calls(&self) -> Result<Vec<GatewayCall>, MockError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }

        fn recorded_update_calls(&self) -> Result<Vec<UpdateCall>, MockError> {
            self.update_calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }
    }

    impl CommandExecutor for FakeGateway {
        type Error = MockError;

        fn execute<'a>(
            &'a self,
            endpoint_id: EndpointId,
            command: &'a RedfishCommand,
        ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(GatewayCall {
                        kind: GatewayCallKind::Execute,
                        endpoint_id,
                        command: command.clone(),
                    });
                self.outcome.clone()
            })
        }
    }

    impl CommandVerifier for FakeGateway {
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
                    .push(GatewayCall {
                        kind: GatewayCallKind::Verify,
                        endpoint_id,
                        command: command.clone(),
                    });
                self.verdict
            })
        }
    }

    impl UpdateExecutor for FakeGateway {
        type Error = MockError;

        fn execute_update<'a>(
            &'a self,
            endpoint_id: EndpointId,
            artifact: &'a UpdateArtifactPayload,
            push_uri: Option<&'a str>,
        ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>> {
            Box::pin(async move {
                self.update_calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(UpdateCall {
                        endpoint_id,
                        artifact_id: artifact.artifact_id(),
                        push_uri: push_uri.map(str::to_owned),
                    });
                self.update_outcome.clone()
            })
        }
    }

    /// The single mock failure vocabulary of every boundary under test.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Store,
        Repository,
        Capability,
        Artifact,
        RemoteTaskStore,
        GatewayNotExecuted,
        GatewayUnknown,
        Verifier,
        Audit,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock {self:?} failure")
        }
    }

    impl Error for MockError {}

    impl DispatchVerdictClassifier for MockError {
        /// Only the gateway error variants are ever classified by the
        /// executor; every other variant defaults to the outcome-unknown
        /// verdict so a miswired test fails on the state assertion instead of
        /// masking the error.
        fn verdict(&self) -> DispatchVerdict {
            match self {
                Self::GatewayNotExecuted => DispatchVerdict::NotExecuted,
                _ => DispatchVerdict::OutcomeUnknown,
            }
        }
    }

    /// Append-only fake audit recording every event, with an optional
    /// fail-on-attempt switch.
    struct MockAudit {
        state: Arc<Mutex<MockAuditState>>,
        fail_on: Option<usize>,
    }

    /// The recorded audit state of one fake writer.
    #[derive(Default)]
    struct MockAuditState {
        attempts: usize,
        events: Vec<AuditEvent>,
    }

    impl MockAudit {
        fn succeed() -> Self {
            Self {
                state: Arc::new(Mutex::new(MockAuditState::default())),
                fail_on: None,
            }
        }

        fn fail_on(attempt: usize) -> Self {
            Self {
                state: Arc::new(Mutex::new(MockAuditState::default())),
                fail_on: Some(attempt),
            }
        }

        fn recorded_events(&self) -> Result<Vec<AuditEvent>, MockError> {
            self.state
                .lock()
                .map(|state| state.events.clone())
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

    /// Fixed wall clock for deterministic timelines.
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    #[tokio::test]
    async fn synchronous_success_drives_the_full_event_order_and_records_audit()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let finished = executor.execute_operation(operation_id).await?;

        assert_eq!(finished.id(), operation_id);
        assert_eq!(finished.state(), OperationState::Succeeded);
        // The §13.2 event order, one state per event: ValidationStarted →
        // Validating, ValidationPassed → Running, ExecutionAccepted →
        // Verifying, VerificationPassed → Succeeded.
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Verifying,
                OperationState::Succeeded,
            ]
        );
        let calls = store.recorded_calls()?;
        assert_eq!(calls[0], Call::Find(operation_id));
        let first_apply = calls
            .iter()
            .position(|call| matches!(call, Call::ApplyTransition(..)))
            .ok_or("no persisted step was recorded")?;
        let endpoint_lookup = calls
            .iter()
            .position(|call| *call == Call::FindEndpoint(endpoint_id))
            .ok_or("the endpoint pre-flight never ran")?;
        assert!(
            endpoint_lookup < first_apply,
            "the endpoint pre-flight must run before any persisted step"
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [
                GatewayCall {
                    kind: GatewayCallKind::Execute,
                    endpoint_id,
                    command: operation.command(),
                },
                GatewayCall {
                    kind: GatewayCallKind::Verify,
                    endpoint_id,
                    command: operation.command(),
                },
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(events[0].sequence(), AuditSequence::FIRST);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        assert_eq!(events[1].sequence(), AuditSequence::try_new(2)?);
        assert_eq!(events[0].context(), events[1].context());
        assert_eq!(
            events[0].context().target(),
            &AuditTarget::Endpoint(endpoint_id)
        );
        assert_eq!(events[0].context().actor(), AuditActor::System);
        assert_eq!(events[0].context().origin(), DeploymentPosture::Site);
        Ok(())
    }

    #[tokio::test]
    async fn update_dispatch_resolves_the_ready_artifact_and_drives_the_full_event_order()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        store.store_artifact(artifact_id, ArtifactState::Ready, b"firmware image")?;
        let operation = queued_update_operation(
            endpoint_id,
            artifact_id,
            Some("https://192.0.2.10/upload".to_owned()),
        );
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let finished = executor.execute_operation(operation_id).await?;

        assert_eq!(finished.id(), operation_id);
        assert_eq!(finished.state(), OperationState::Succeeded);
        // The §13.2 event order matches every other family: the artifact
        // pre-flight (§13.3 step 4) resolves the payload before any persisted
        // step, then ValidationStarted → Validating, ValidationPassed →
        // Running, ExecutionAccepted → Verifying, VerificationPassed →
        // Succeeded.
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Verifying,
                OperationState::Succeeded,
            ]
        );
        let calls = store.recorded_calls()?;
        assert_eq!(calls[0], Call::Find(operation_id));
        let first_apply = calls
            .iter()
            .position(|call| matches!(call, Call::ApplyTransition(..)))
            .ok_or("no persisted step was recorded")?;
        let artifact_lookup = calls
            .iter()
            .position(|call| *call == Call::FindArtifact(artifact_id))
            .ok_or("the artifact pre-flight never ran")?;
        assert!(
            artifact_lookup < first_apply,
            "the artifact pre-flight must run before any persisted step"
        );
        // The update boundary received the exact artifact and the operator's
        // push URI, and the accepted update was then verified through the
        // shared re-read — the post-update SoftwareInventory check (§14.3).
        assert_eq!(
            gateway.recorded_update_calls()?,
            [UpdateCall {
                endpoint_id,
                artifact_id,
                push_uri: Some("https://192.0.2.10/upload".to_owned()),
            }]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Verify,
                endpoint_id,
                command: operation.command(),
            }],
            "an accepted update must be verified through the shared re-read"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        assert_eq!(events[0].context(), events[1].context());
        assert_eq!(
            events[0].context().redfish_operation(),
            AuditRedfishOperation::UpdateFirmware,
            "the §16.3 vocabulary names the firmware update family"
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_with_missing_artifact_is_refused_before_any_dispatch()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        );
        // No artifact row: the referenced firmware does not exist (§13.3
        // step 4 parameter check).
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed],
            "an unusable artifact is one Failed step from Queued"
        );
        assert_eq!(
            gateway.recorded_update_calls()?.len(),
            0,
            "no update may be dispatched after an artifact pre-flight refusal"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::EndpointPersistenceFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_with_uploading_artifact_is_refused_before_any_dispatch()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        // An Uploading artifact has not passed its finalize SHA-256 check
        // and must never reach a BMC.
        store.store_artifact(artifact_id, ArtifactState::Uploading, b"firmware image")?;
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(gateway.recorded_update_calls()?.len(), 0);
        assert_eq!(
            audit.recorded_events()?[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_with_unreadable_artifact_file_is_refused_before_any_dispatch()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        store.store_artifact(artifact_id, ArtifactState::Ready, b"firmware image")?;
        // The row is Ready but the bytes are gone — an environmental loss
        // that still proves the write was never dispatched.
        std::fs::remove_file(store.artifact_file_path(artifact_id))?;
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(gateway.recorded_update_calls()?.len(), 0);
        assert_eq!(
            audit.recorded_events()?[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_artifact_lookup_failure_propagates_as_artifact_preflight()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        );
        store.arm_failure(MockStoreFailure::ArtifactLookup)?;
        let operation = queued_update_operation(endpoint_id, ArtifactId::generate(), None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result
            .err()
            .ok_or("the artifact lookup failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::ArtifactPreflight(MockError::Artifact)
        ));
        assert_error_source(&error, MockError::Artifact)?;
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "no step may be persisted when the artifact pre-flight lookup itself fails"
        );
        assert_eq!(gateway.recorded_update_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn update_dispatch_async_acceptance_persists_the_task_row_and_waits()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        store.store_artifact(artifact_id, ArtifactState::Ready, b"firmware image")?;
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let task_location = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        )
        .with_update_outcome(Ok(CommandOutcome::AsyncTaskAccepted {
            task_location: task_location.clone(),
        }));
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let waiting = executor.execute_operation(operation_id).await?;

        assert_eq!(waiting.id(), operation_id);
        assert_eq!(waiting.state(), OperationState::WaitingRemote);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::WaitingRemote,
            ]
        );
        // The observation row exists with the exact task location from the
        // `202` `Location` header, exactly like the typed dispatch path.
        let task = store
            .find_remote_task_owned(operation_id)?
            .ok_or("the accepted update task row must be persisted")?;
        assert_eq!(task.task_uri(), &task_location);
        assert_eq!(
            gateway.recorded_update_calls()?.len(),
            1,
            "the update was dispatched exactly once"
        );
        assert_eq!(
            gateway.recorded_calls()?.len(),
            0,
            "an accepted update Task must never be verified synchronously"
        );
        assert_eq!(
            audit.recorded_events()?.len(),
            1,
            "only the start fact is audited; the terminal fact belongs to the Task monitor"
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_dispatch_provable_failure_records_failed_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        store.store_artifact(artifact_id, ArtifactState::Ready, b"firmware image")?;
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        )
        .with_update_outcome(Err(MockError::GatewayNotExecuted));
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result
            .err()
            .ok_or("the update dispatch failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::UpdateGateway(MockError::GatewayNotExecuted)
        ));
        assert_error_source(&error, MockError::GatewayNotExecuted)?;
        // The update boundary's own verdict classifies the failure: a
        // provable non-execution is Failed, never Unknown (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Failed,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_dispatch_unprovable_failure_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        store.store_artifact(artifact_id, ArtifactState::Ready, b"firmware image")?;
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        )
        .with_update_outcome(Err(MockError::GatewayUnknown));
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result
            .err()
            .ok_or("the update dispatch failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::UpdateGateway(MockError::GatewayUnknown)
        ));
        assert_error_source(&error, MockError::GatewayUnknown)?;
        // The firmware submission may already have been accepted by the BMC:
        // the operation is Unknown, never re-dispatched blindly (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Unknown,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn update_verification_mismatch_records_failed() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let artifact_id = ArtifactId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            supported_update_service_capability(),
        )
        .with_artifact_directory()?;
        store.store_artifact(artifact_id, ArtifactState::Ready, b"firmware image")?;
        let operation = queued_update_operation(endpoint_id, artifact_id, None);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Mismatched),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        // The post-update re-read proves the expected result absent (the
        // software-inventory surface is gone): a provable failure.
        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Verifying,
                OperationState::Failed,
            ]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Verify,
                endpoint_id,
                command: operation.command(),
            }],
            "the mismatch re-read ran against the update command"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected),
            "a proven-absent result is a provable failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_endpoint_refuses_before_any_dispatch() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(None, Vec::new());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed],
            "a pre-flight refusal is one Failed step from Queued"
        );
        assert_eq!(
            gateway.recorded_calls()?.len(),
            0,
            "no dispatch may happen after a pre-flight refusal"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::EndpointPersistenceFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_only_capability_refuses_before_any_dispatch() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        // ReadOnly advertises a read-only surface: a write must not be
        // dispatched against it, the refusal is provable, and the capability
        // itself is provably unsupported, so the failure is classified.
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            vec![StoredCapability::new(
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::ReadOnly,
                ),
                created_at(),
            )],
        );
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        // The classification is written before the Failed transition, so a
        // crash between the two writes can only orphan a kind on a
        // non-terminal row — never lose a recorded refusal.
        let calls = store.recorded_calls()?;
        let kind_call = calls
            .iter()
            .position(|call| *call == Call::RecordFailureKind(operation.id()))
            .ok_or("the capability refusal must record its failure kind")?;
        let failed_call = calls
            .iter()
            .position(|call| *call == Call::ApplyTransition(operation.id(), OperationState::Failed))
            .ok_or("the capability refusal must persist the Failed transition")?;
        assert!(
            kind_call < failed_call,
            "the failure kind must be written before the Failed transition"
        );
        assert_eq!(
            store.recorded_failure_kinds()?,
            HashSet::from([operation.id()])
        );
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::RedfishDiscoveryFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn provably_unsupported_capabilities_are_classified_before_the_refusal()
    -> Result<(), Box<dyn Error>> {
        // Every capability state that proves the capability itself cannot
        // serve the write is classified `capability-unsupported` (§13.7).
        for state in [
            CapabilityState::NotCompiled,
            CapabilityState::NotAdvertised,
            CapabilityState::SchemaIncompatible,
        ] {
            let endpoint_id = EndpointId::generate();
            let store = FakeStore::new(
                Some(endpoint(endpoint_id)?),
                vec![StoredCapability::new(
                    EndpointCapabilityObservation::new(EndpointCapability::Systems, state),
                    created_at(),
                )],
            );
            let operation = queued_operation(endpoint_id);
            store.insert(operation.clone())?;
            let gateway = FakeGateway::new(
                Ok(CommandOutcome::Accepted),
                Ok(VerificationVerdict::Confirmed),
            );
            let audit = MockAudit::succeed();
            let executor = executor(&store, &gateway, &audit);

            let finished = executor.execute_operation(operation.id()).await?;

            assert_eq!(
                finished.state(),
                OperationState::Failed,
                "a {state} capability must refuse the write"
            );
            assert_eq!(
                store.recorded_failure_kinds()?,
                HashSet::from([operation.id()]),
                "a {state} capability must classify the refusal as unsupported"
            );
            assert_eq!(
                applied_states(&store.recorded_calls()?),
                [OperationState::Failed]
            );
            assert_eq!(gateway.recorded_calls()?.len(), 0);
            assert_eq!(
                audit.recorded_events()?[1].outcome().verification(),
                Some(AuditVerification::Rejected)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn unconfirmed_capabilities_refuse_without_a_classification() -> Result<(), Box<dyn Error>>
    {
        // An unauthorized, temporarily unavailable, or never-observed
        // capability does not prove the capability unusable — the endpoint
        // may simply not have been probed or authorized yet — so the refusal
        // is an ordinary failure with no kind (§13.7).
        let unobserved_endpoint_id = EndpointId::generate();
        let unobserved = FakeStore::new(Some(endpoint(unobserved_endpoint_id)?), Vec::new());
        let unobserved_operation = queued_operation(unobserved_endpoint_id);
        unobserved.insert(unobserved_operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let unobserved_executor = executor(&unobserved, &gateway, &audit);
        let finished = unobserved_executor
            .execute_operation(unobserved_operation.id())
            .await?;
        assert_eq!(finished.state(), OperationState::Failed);
        assert!(
            unobserved.recorded_failure_kinds()?.is_empty(),
            "an unobserved capability must never be classified"
        );
        assert_eq!(gateway.recorded_calls()?.len(), 0);

        for state in [
            CapabilityState::Unauthorized,
            CapabilityState::TemporarilyUnavailable,
        ] {
            let endpoint_id = EndpointId::generate();
            let store = FakeStore::new(
                Some(endpoint(endpoint_id)?),
                vec![StoredCapability::new(
                    EndpointCapabilityObservation::new(EndpointCapability::Systems, state),
                    created_at(),
                )],
            );
            let operation = queued_operation(endpoint_id);
            store.insert(operation.clone())?;
            let gateway = FakeGateway::new(
                Ok(CommandOutcome::Accepted),
                Ok(VerificationVerdict::Confirmed),
            );
            let audit = MockAudit::succeed();
            let executor = executor(&store, &gateway, &audit);

            let finished = executor.execute_operation(operation.id()).await?;

            assert_eq!(
                finished.state(),
                OperationState::Failed,
                "a {state} capability must refuse the write"
            );
            assert!(
                store.recorded_failure_kinds()?.is_empty(),
                "a {state} capability must never be classified"
            );
            assert_eq!(
                applied_states(&store.recorded_calls()?),
                [OperationState::Failed]
            );
            assert_eq!(gateway.recorded_calls()?.len(), 0);
            assert_eq!(
                audit.recorded_events()?[1].outcome().verification(),
                Some(AuditVerification::Rejected)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn classification_write_failure_propagates_without_persisting_the_refusal()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            vec![StoredCapability::new(
                EndpointCapabilityObservation::new(
                    EndpointCapability::Systems,
                    CapabilityState::ReadOnly,
                ),
                created_at(),
            )],
        );
        // The armed write failure hits the record_failure_kind call, not the
        // transition: the classification is written first, and a failure
        // there must abort the refusal cleanly — the operation stays queued
        // and unclassified rather than half-refused.
        store.arm_failure(MockStoreFailure::Write)?;
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::Store(MockError::Store))
        ));
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "a failed classification write must not persist the refusal"
        );
        assert!(
            store.recorded_failure_kinds()?.is_empty(),
            "a failed classification write must not record a kind"
        );
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn never_observed_capability_refuses_before_any_dispatch() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        // An endpoint whose capability ledger has no observation for the
        // required capability cannot confirm it: the write is refused.
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), Vec::new());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        assert_eq!(
            audit.recorded_events()?[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn endpoint_preflight_lookup_failure_propagates_with_source_chain()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        store.arm_failure(MockStoreFailure::EndpointLookup)?;
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result
            .err()
            .ok_or("the endpoint lookup failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::EndpointPreflight(MockError::Repository)
        ));
        assert_error_source(&error, MockError::Repository)?;
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "no step may be persisted when the pre-flight lookup itself fails"
        );
        Ok(())
    }

    #[tokio::test]
    async fn capability_preflight_lookup_failure_propagates_with_source_chain()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        store.arm_failure(MockStoreFailure::CapabilityLookup)?;
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result
            .err()
            .ok_or("the capability lookup failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::CapabilityPreflight(EndpointCapabilityQueryError::Repository(
                MockError::Capability
            ))
        ));
        // The chain runs two levels here: the executor wraps the ledger query
        // error, which wraps the repository boundary error.
        let query_error = Error::source(&error)
            .ok_or("the executor error must expose the query error")?
            .downcast_ref::<EndpointCapabilityQueryError<MockError>>()
            .ok_or("the executor error must wrap the ledger query error")?;
        assert!(matches!(
            query_error,
            EndpointCapabilityQueryError::Repository(MockError::Capability)
        ));
        let inner =
            Error::source(query_error).ok_or("the query error must expose the repository error")?;
        assert_eq!(inner.to_string(), MockError::Capability.to_string());
        Ok(())
    }

    #[tokio::test]
    async fn store_read_failure_propagates_with_source_chain() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        store.arm_failure(MockStoreFailure::Read)?;
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result.err().ok_or("the store failure must escape")?;
        assert!(matches!(error, ExecutorError::Store(MockError::Store)));
        assert_error_source(&error, MockError::Store)?;
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn bmc_rejection_records_failed_without_verification() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Rejected),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Failed,
            ]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Execute,
                endpoint_id,
                command: operation.command(),
            }],
            "a rejected write must never be verified"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::RedfishDiscoveryFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn provable_dispatch_failure_records_failed_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Err(MockError::GatewayNotExecuted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result.err().ok_or("the dispatch failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::Gateway(MockError::GatewayNotExecuted)
        ));
        assert_error_source(&error, MockError::GatewayNotExecuted)?;
        // The verdict is provable non-execution, so the operation is Failed —
        // never Unknown (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Failed,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::RedfishDiscoveryFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn unprovable_dispatch_failure_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Err(MockError::GatewayUnknown),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result.err().ok_or("the dispatch failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::Gateway(MockError::GatewayUnknown)
        ));
        assert_error_source(&error, MockError::GatewayUnknown)?;
        // The write may have landed: the operation is Unknown, never retried
        // blindly (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Unknown,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn verification_mismatch_records_failed() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Mismatched),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Verifying,
                OperationState::Failed,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected),
            "a proven-absent result is a provable failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verification_error_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(Ok(CommandOutcome::Accepted), Err(MockError::Verifier));
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result.err().ok_or("the re-read failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::Verifier(MockError::Verifier)
        ));
        assert_error_source(&error, MockError::Verifier)?;
        // The write already landed (Accepted); the failed re-read proves
        // nothing, so the operation is Unknown (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Verifying,
                OperationState::Unknown,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn non_queued_operation_is_rejected_without_side_effects() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        // A Running operation belongs to the recovery path, not the execution
        // flow; the executor must refuse it without touching anything.
        let mut operation = queued_operation(endpoint_id);
        operation.apply(OperationEvent::ValidationStarted, clock_time())?;
        operation.apply(OperationEvent::ValidationPassed, clock_time())?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::NotQueued {
                operation_id,
                state: OperationState::Running,
            }) if operation_id == operation.id()
        ));
        assert_eq!(
            store.recorded_calls()?,
            [Call::Find(operation.id())],
            "the defense must not persist anything"
        );
        assert_eq!(audit.recorded_events()?.len(), 0);
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn validating_orphan_resumes_the_execution_flow() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Validating)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let finished = executor.execute_operation(operation_id).await?;

        assert_eq!(finished.id(), operation_id);
        assert_eq!(finished.state(), OperationState::Succeeded);
        // The resumed attempt skips ValidationStarted (the crashed attempt
        // already persisted it — that is exactly why the crash left the
        // operation in Validating) and re-runs the remaining execution flow:
        // pre-flight, ValidationPassed, dispatch, verification.
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Running,
                OperationState::Verifying,
                OperationState::Succeeded,
            ]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [
                GatewayCall {
                    kind: GatewayCallKind::Execute,
                    endpoint_id,
                    command: operation.command(),
                },
                GatewayCall {
                    kind: GatewayCallKind::Verify,
                    endpoint_id,
                    command: operation.command(),
                },
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(events[0].context(), events[1].context());
        assert_eq!(
            events[0].context().target(),
            &AuditTarget::Endpoint(endpoint_id)
        );
        assert_eq!(
            events[0].context().action(),
            AuditAction::ExecuteOperation,
            "the §16.3 vocabulary names the execution of the persisted write"
        );
        assert_eq!(
            events[0].context().permission(),
            ProductPermission::ExecuteOperations
        );
        assert_eq!(
            events[0].context().redfish_operation(),
            AuditRedfishOperation::ResetSystem,
            "the §16.3 vocabulary names the exact §7.5 write family"
        );
        Ok(())
    }

    #[tokio::test]
    async fn validating_orphan_preflight_refusal_records_failed() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        // The endpoint vanished while the operation was in flight: the resumed
        // pre-flight refuses the operation before anything is dispatched.
        let store = FakeStore::new(None, Vec::new());
        let operation = parked_operation(endpoint_id, OperationState::Validating)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(
            gateway.recorded_calls()?.len(),
            0,
            "no dispatch may happen after a resumed pre-flight refusal"
        );
        assert_eq!(
            audit.recorded_events()?[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn running_orphan_with_confirmed_judgement_backfills_acceptance_and_succeeds()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Running)?;
        store.insert(operation.clone())?;
        // No RemoteTask row: the dispatch outcome is judged by re-reading the
        // target (§13.5).
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let finished = executor.recover_operation(operation_id).await?;

        assert_eq!(finished.id(), operation_id);
        assert_eq!(finished.state(), OperationState::Succeeded);
        // The judgement re-read proves the write already happened, so
        // ExecutionAccepted is back-filled (the re-read takes the place of
        // the lost response) and the verification chain continues (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Verifying, OperationState::Succeeded,]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Verify,
                endpoint_id,
                command: operation.command(),
            }],
            "recovery must never re-dispatch; only the judgement re-read runs"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        assert_eq!(events[0].context(), events[1].context());
        assert_eq!(
            events[0].context().target(),
            &AuditTarget::Endpoint(endpoint_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn running_orphan_with_mismatched_judgement_records_failed_without_redispatch()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Running)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Mismatched),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let finished = executor.recover_operation(operation_id).await?;

        // The expected result is absent: the operation provably did not
        // achieve its result, but an absent result does not confirm the write
        // was never delivered (§13.5 retry gate), so the operation is Failed,
        // never re-dispatched.
        assert_eq!(finished.id(), operation_id);
        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Verify,
                endpoint_id,
                command: operation.command(),
            }],
            "an unconfirmed write must never be re-dispatched (§13.5)"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Inconclusive),
            "the product cannot prove whether the write was ever delivered"
        );
        Ok(())
    }

    #[tokio::test]
    async fn running_orphan_with_failed_judgement_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Running)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(Ok(CommandOutcome::Accepted), Err(MockError::Verifier));
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.recover_operation(operation.id()).await;

        let error = result.err().ok_or("the re-read failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::Verifier(MockError::Verifier)
        ));
        assert_error_source(&error, MockError::Verifier)?;
        // The failed re-read proves nothing about the possibly-landed write,
        // so the operation is recorded Unknown (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Unknown]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn running_orphan_with_persisted_task_row_resumes_task_tracking()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Running)?;
        store.insert(operation.clone())?;
        // The crash window between the 202 acceptance and the
        // RemoteTaskStarted step: the observation row is already durable
        // (§13.6), which proves the write was accepted as a Task.
        store
            .save_remote_task(&RemoteTask::new(
                operation.id(),
                endpoint_id,
                TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
                None,
                clock_time(),
            ))
            .await?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let waiting = executor.recover_operation(operation_id).await?;

        assert_eq!(waiting.id(), operation_id);
        assert_eq!(waiting.state(), OperationState::WaitingRemote);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::WaitingRemote]
        );
        assert_eq!(
            gateway.recorded_calls()?.len(),
            0,
            "an accepted Task is resumed by polling, never judged or re-dispatched"
        );
        assert_eq!(
            audit.recorded_events()?.len(),
            0,
            "the handoff performs no outcome work, so it records no audit fact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verifying_orphan_reverifies_to_success() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Verifying)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let finished = executor.recover_operation(operation_id).await?;

        assert_eq!(finished.state(), OperationState::Succeeded);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Succeeded]
        );
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Verify,
                endpoint_id,
                command: operation.command(),
            }],
            "a Verifying orphan re-runs only the verification re-read"
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn verifying_orphan_with_mismatch_records_failed() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Verifying)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Mismatched),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.recover_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().failure(),
            Some(AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Rejected),
            "delivery is proven by the persisted ExecutionAccepted step"
        );
        Ok(())
    }

    #[tokio::test]
    async fn verifying_orphan_with_failed_verification_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Verifying)?;
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(Ok(CommandOutcome::Accepted), Err(MockError::Verifier));
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.recover_operation(operation.id()).await;

        let error = result.err().ok_or("the re-read failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::Verifier(MockError::Verifier)
        ));
        assert_error_source(&error, MockError::Verifier)?;
        // The write already landed (ExecutionAccepted was persisted); the
        // failed re-read proves nothing, so the operation is Unknown (§13.5).
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Unknown]
        );
        assert_eq!(
            audit.recorded_events()?[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    #[tokio::test]
    async fn non_recoverable_states_are_rejected_without_side_effects() -> Result<(), Box<dyn Error>>
    {
        // Every state outside the recovery span (Running/Verifying) belongs
        // to another driver: Queued and Validating run the execution flow,
        // WaitingRemote runs the Task-monitor pass, and the terminal states
        // are final. The recovery path must refuse each of them without
        // touching anything.
        for state in [
            OperationState::Queued,
            OperationState::Validating,
            OperationState::WaitingRemote,
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Unknown,
            OperationState::Cancelled,
        ] {
            let endpoint_id = EndpointId::generate();
            let store =
                FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
            let operation = Operation::try_from_parts(
                OperationId::generate(),
                OperationSource::Standalone,
                vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
                RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
                state,
                created_at(),
                clock_time(),
            )?;
            store.insert(operation.clone())?;
            let gateway = FakeGateway::new(
                Ok(CommandOutcome::Accepted),
                Ok(VerificationVerdict::Confirmed),
            );
            let audit = MockAudit::succeed();
            let executor = executor(&store, &gateway, &audit);

            let result = executor.recover_operation(operation.id()).await;

            assert!(
                matches!(
                    result,
                    Err(ExecutorError::NotRecoverable {
                        operation_id,
                        state: observed,
                    }) if operation_id == operation.id() && observed == state
                ),
                "recovering a {state} operation must be refused"
            );
            assert_eq!(
                store.recorded_calls()?,
                [Call::Find(operation.id())],
                "the defense must not persist anything"
            );
            assert_eq!(audit.recorded_events()?.len(), 0);
            assert_eq!(gateway.recorded_calls()?.len(), 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn transition_race_during_execution_reports_not_queued() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        // A second driver advanced the operation to Running between the
        // executor's own read (find 1) and the engine's first step read
        // (find 2): ValidationStarted is invalid from Running, so the domain
        // state machine rejects the step.
        store.arm_find_race(2, OperationState::Running)?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::NotQueued {
                operation_id,
                state: OperationState::Running,
            }) if operation_id == operation.id()
        ));
        // The start audit fact of the attempt was recorded before the raced
        // step; the raced step itself was never persisted and nothing was
        // dispatched.
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "the raced step must not be persisted"
        );
        assert_eq!(audit.recorded_events()?.len(), 1);
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn transition_race_during_recovery_reports_not_recoverable() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = parked_operation(endpoint_id, OperationState::Running)?;
        store.insert(operation.clone())?;
        // A second driver moved the operation to WaitingRemote between the
        // executor's own read (find 1) and the engine's judgement-step read
        // (find 2): ExecutionAccepted is invalid from WaitingRemote, so the
        // recovery step is rejected with the recovery contract's own guard.
        store.arm_find_race(2, OperationState::WaitingRemote)?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.recover_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::NotRecoverable {
                operation_id,
                state: OperationState::WaitingRemote,
            }) if operation_id == operation.id()
        ));
        // The judgement re-read ran and the attempt's start fact landed
        // before the raced step; the raced step itself was never persisted.
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "the raced step must not be persisted"
        );
        assert_eq!(audit.recorded_events()?.len(), 1);
        assert_eq!(
            gateway.recorded_calls()?.len(),
            1,
            "the judgement re-read ran before the raced step"
        );
        Ok(())
    }

    // One pair per §7.5 write operation; the line count grows with the
    // operation count, so the lint is scoped here like the domain's family
    // enumeration tests.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn command_audit_operations_pin_the_thirty_write_families() -> Result<(), Box<dyn Error>>
    {
        // One representative command per §7.5 write family, pinned against
        // the audit operation type it must map to — the same exhaustive-pair
        // style as the domain's execute-context tests, so a swapped mapping
        // (Enable ↔ Disable, Create ↔ Delete, one Reset ↔ another, one OEM
        // face ↔ another) fails here instead of reaching the audit log. The
        // five account writes are pinned separately because their
        // accountability differs (§16.3), the seven telemetry writes are
        // pinned separately for the same reason (§14.4), and the three OEM
        // faces are pinned separately for the same reason (§11.5).
        let pairs: [(&RedfishCommand, AuditRedfishOperation); 30] = [
            (
                &RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
                    AccountUserName::parse("jane")?,
                    AccountPassword::parse("initial-secret".to_owned())?,
                    RoleId::parse("Operator")?,
                ))),
                AuditRedfishOperation::CreateAccount,
            ),
            (
                &RedfishCommand::Account(AccountCommand::UpdateAccount(UpdateAccount::new(
                    AccountId::parse("admin")?,
                    RoleId::parse("Operator")?,
                ))),
                AuditRedfishOperation::UpdateAccount,
            ),
            (
                &RedfishCommand::Account(AccountCommand::UpdateAccountPassword(
                    UpdateAccountPassword::new(
                        AccountId::parse("admin")?,
                        AccountPassword::parse("new-secret".to_owned())?,
                    ),
                )),
                AuditRedfishOperation::UpdateAccountPassword,
            ),
            (
                &RedfishCommand::Account(AccountCommand::UpdateAccountUserName(
                    UpdateAccountUserName::new(
                        AccountId::parse("admin")?,
                        AccountUserName::parse("admin.renamed")?,
                    ),
                )),
                AuditRedfishOperation::UpdateAccountUserName,
            ),
            (
                &RedfishCommand::Account(AccountCommand::DeleteAccount(DeleteAccount::new(
                    AccountId::parse("admin")?,
                ))),
                AuditRedfishOperation::DeleteAccount,
            ),
            (
                &RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
                AuditRedfishOperation::ResetSystem,
            ),
            (
                &RedfishCommand::Manager(ManagerCommand::Reset(ResetType::ForceRestart)),
                AuditRedfishOperation::ResetManager,
            ),
            (
                &RedfishCommand::Manager(ManagerCommand::ResetToDefaults(
                    ManagerResetToDefaultsType::ResetAll,
                )),
                AuditRedfishOperation::ManagerResetToDefaults,
            ),
            (
                &RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::PowerCycle)),
                AuditRedfishOperation::ResetChassis,
            ),
            (
                &RedfishCommand::Chassis(ChassisCommand::PowerSupplyReset(PowerSupplyReset::new(
                    None,
                ))),
                AuditRedfishOperation::PowerSupplyReset,
            ),
            (
                &RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                    SetBootSourceOverride::new(
                        BootSource::Pxe,
                        BootSourceOverrideEnabled::Once,
                        BootSourceOverrideMode::Uefi,
                    ),
                )),
                AuditRedfishOperation::SetBootSourceOverride,
            ),
            (
                &RedfishCommand::SecureBoot(SecureBootCommand::Enable),
                AuditRedfishOperation::SecureBootEnable,
            ),
            (
                &RedfishCommand::SecureBoot(SecureBootCommand::Disable),
                AuditRedfishOperation::SecureBootDisable,
            ),
            (
                &RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(
                    ResetKeysType::ResetAllKeysToDefault,
                )),
                AuditRedfishOperation::SecureBootResetKeys,
            ),
            (
                &RedfishCommand::Event(EventCommand::CreateSubscription(
                    CreateSubscription::try_new(
                        "https://events.example.test".to_owned(),
                        EventDestinationProtocol::Redfish,
                        vec![EventType::Alert],
                    )?,
                )),
                AuditRedfishOperation::CreateEventSubscription,
            ),
            (
                &RedfishCommand::Event(EventCommand::DeleteSubscription(DeleteSubscription::new(
                    "42".to_owned(),
                ))),
                AuditRedfishOperation::DeleteEventSubscription,
            ),
            (
                &RedfishCommand::Log(LogCommand::ClearLog(ClearLog::new(None, None))),
                AuditRedfishOperation::LogClear,
            ),
            (
                &RedfishCommand::Control(ControlCommand::Update(UpdateControl::new(
                    None,
                    Some(700.0),
                ))),
                AuditRedfishOperation::ControlUpdate,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::SetEnabled { enabled: false }),
                AuditRedfishOperation::SetTelemetryEnabled,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::CreateMetricDefinition(
                    CreateMetricDefinition::new(MetricType::Gauge, MetricUnits::parse("W")?),
                )),
                AuditRedfishOperation::CreateMetricDefinition,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::UpdateMetricDefinition(
                    UpdateMetricDefinition::new(
                        MetricDefinitionId::parse("PowerMetric")?,
                        MetricType::Counter,
                        MetricUnits::parse("W")?,
                    ),
                )),
                AuditRedfishOperation::UpdateMetricDefinition,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::DeleteMetricDefinition(
                    DeleteMetricDefinition::new(MetricDefinitionId::parse("PowerMetric")?),
                )),
                AuditRedfishOperation::DeleteMetricDefinition,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::CreateMetricReportDefinition(
                    CreateMetricReportDefinition::try_new(
                        MetricReportDefinitionType::OnRequest,
                        vec![MetricReportMetric::new(MetricDefinitionId::parse(
                            "PowerMetric",
                        )?)],
                    )?,
                )),
                AuditRedfishOperation::CreateMetricReportDefinition,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::UpdateMetricReportDefinition(
                    UpdateMetricReportDefinition::new(
                        MetricReportDefinitionId::parse("PowerReport")?,
                        MetricReportDefinitionType::OnChange,
                        vec![MetricReportMetric::new(MetricDefinitionId::parse(
                            "PowerMetric",
                        )?)],
                    ),
                )),
                AuditRedfishOperation::UpdateMetricReportDefinition,
            ),
            (
                &RedfishCommand::Telemetry(TelemetryCommand::DeleteMetricReportDefinition(
                    DeleteMetricReportDefinition::new(MetricReportDefinitionId::parse(
                        "PowerReport",
                    )?),
                )),
                AuditRedfishOperation::DeleteMetricReportDefinition,
            ),
            (
                &RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                    ArtifactId::generate(),
                    None,
                ))),
                AuditRedfishOperation::UpdateFirmware,
            ),
            (
                &RedfishCommand::Update(UpdateCommand::Patch(UpdatePatch::new(Some(true), None))),
                AuditRedfishOperation::UpdateServicePatch,
            ),
            (
                &RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
                AuditRedfishOperation::OemSystemConfigProfile,
            ),
            (
                &RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::DisableToken,
                )),
                AuditRedfishOperation::OemDebugToken,
            ),
            (
                &RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
                )),
                AuditRedfishOperation::OemPowerSmoothing,
            ),
        ];
        for (command, expected) in pairs {
            assert_eq!(
                command_audit_operation(command),
                expected,
                "the command family must map to exactly its own audit operation"
            );
        }
        Ok(())
    }

    #[test]
    fn account_commands_require_the_accounts_capability() -> Result<(), Box<dyn Error>> {
        // Every account write targets the BMC's `AccountService`
        // (`ManagerAccount` resources), so each of the five commands must
        // require the same §2.1 accounts capability.
        for command in [
            RedfishCommand::Account(AccountCommand::CreateAccount(CreateAccount::new(
                AccountUserName::parse("jane")?,
                AccountPassword::parse("initial-secret".to_owned())?,
                RoleId::parse("Operator")?,
            ))),
            RedfishCommand::Account(AccountCommand::UpdateAccount(UpdateAccount::new(
                AccountId::parse("admin")?,
                RoleId::parse("Operator")?,
            ))),
            RedfishCommand::Account(AccountCommand::UpdateAccountPassword(
                UpdateAccountPassword::new(
                    AccountId::parse("admin")?,
                    AccountPassword::parse("new-secret".to_owned())?,
                ),
            )),
            RedfishCommand::Account(AccountCommand::UpdateAccountUserName(
                UpdateAccountUserName::new(
                    AccountId::parse("admin")?,
                    AccountUserName::parse("admin.renamed")?,
                ),
            )),
            RedfishCommand::Account(AccountCommand::DeleteAccount(DeleteAccount::new(
                AccountId::parse("admin")?,
            ))),
        ] {
            assert_eq!(
                required_capability(&command),
                EndpointCapability::Accounts,
                "every account write must require the accounts capability"
            );
        }
        Ok(())
    }

    #[test]
    fn update_commands_require_the_update_service_capability() {
        for command in [
            RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                ArtifactId::generate(),
                None,
            ))),
            RedfishCommand::Update(UpdateCommand::Patch(UpdatePatch::new(Some(true), None))),
        ] {
            assert_eq!(
                required_capability(&command),
                EndpointCapability::UpdateService
            );
        }
    }

    #[test]
    fn log_and_control_commands_require_their_own_capability() {
        // A log-service write targets the BMC's `LogService` resources, and
        // a control write targets the chassis's `Control` resources, so each
        // family requires its own §2.1 capability.
        for (command, expected) in [
            (
                RedfishCommand::Log(LogCommand::ClearLog(ClearLog::new(None, None))),
                EndpointCapability::LogServices,
            ),
            (
                RedfishCommand::Control(ControlCommand::Update(UpdateControl::new(
                    None,
                    Some(700.0),
                ))),
                EndpointCapability::Controls,
            ),
        ] {
            assert_eq!(
                required_capability(&command),
                expected,
                "each family must require its own capability"
            );
        }
    }

    #[test]
    fn telemetry_commands_require_the_telemetry_service_capability() -> Result<(), Box<dyn Error>> {
        // Every telemetry write targets the BMC's `TelemetryService` (§14.4),
        // so each of the seven commands must require the same §2.1
        // telemetry-service capability.
        for command in [
            RedfishCommand::Telemetry(TelemetryCommand::SetEnabled { enabled: true }),
            RedfishCommand::Telemetry(TelemetryCommand::CreateMetricDefinition(
                CreateMetricDefinition::new(MetricType::Gauge, MetricUnits::parse("W")?),
            )),
            RedfishCommand::Telemetry(TelemetryCommand::UpdateMetricDefinition(
                UpdateMetricDefinition::new(
                    MetricDefinitionId::parse("PowerMetric")?,
                    MetricType::Counter,
                    MetricUnits::parse("W")?,
                ),
            )),
            RedfishCommand::Telemetry(TelemetryCommand::DeleteMetricDefinition(
                DeleteMetricDefinition::new(MetricDefinitionId::parse("PowerMetric")?),
            )),
            RedfishCommand::Telemetry(TelemetryCommand::CreateMetricReportDefinition(
                CreateMetricReportDefinition::try_new(
                    MetricReportDefinitionType::Periodic,
                    vec![MetricReportMetric::new(MetricDefinitionId::parse(
                        "PowerMetric",
                    )?)],
                )?,
            )),
            RedfishCommand::Telemetry(TelemetryCommand::UpdateMetricReportDefinition(
                UpdateMetricReportDefinition::new(
                    MetricReportDefinitionId::parse("PowerReport")?,
                    MetricReportDefinitionType::OnChange,
                    vec![MetricReportMetric::new(MetricDefinitionId::parse(
                        "PowerMetric",
                    )?)],
                ),
            )),
            RedfishCommand::Telemetry(TelemetryCommand::DeleteMetricReportDefinition(
                DeleteMetricReportDefinition::new(MetricReportDefinitionId::parse("PowerReport")?),
            )),
        ] {
            assert_eq!(
                required_capability(&command),
                EndpointCapability::TelemetryService,
                "every telemetry write must require the telemetry-service capability"
            );
        }
        Ok(())
    }

    #[test]
    fn oem_commands_require_their_own_capability() {
        // Each OEM face requires the §2.1 sub-capability of its chain: the
        // profile service, the debug-token surfaces, and the power-smoothing
        // resource each probe `Supported` whenever the endpoint advertises
        // the `Nvidia` namespace (§11.3 advertised layer).
        for (command, expected) in [
            (
                RedfishCommand::Oem(OemCommand::SystemConfigProfile(
                    NvidiaSystemConfigProfileCommand::FactoryReset,
                )),
                EndpointCapability::OemNvidiaProfiles,
            ),
            (
                RedfishCommand::Oem(OemCommand::DebugToken(
                    NvidiaDebugTokenCommand::DisableToken,
                )),
                EndpointCapability::OemNvidiaSecurity,
            ),
            (
                RedfishCommand::Oem(OemCommand::PowerSmoothing(
                    NvidiaPowerSmoothingCommand::ApplyAdminOverrides,
                )),
                EndpointCapability::OemNvidiaPowerManagement,
            ),
        ] {
            assert_eq!(
                required_capability(&command),
                expected,
                "each OEM face must require its own capability"
            );
        }
    }

    #[tokio::test]
    async fn debug_token_requires_the_oem_nvidia_security_capability() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        // The endpoint's ledger observes only the profile-service
        // sub-capability: the `OemNvidiaSecurity` capability the debug-token
        // write requires has no observation, so it cannot confirm the write
        // and the execution is refused before any dispatch.
        let store = FakeStore::new(
            Some(endpoint(endpoint_id)?),
            vec![StoredCapability::new(
                EndpointCapabilityObservation::new(
                    EndpointCapability::OemNvidiaProfiles,
                    CapabilityState::Supported,
                ),
                created_at(),
            )],
        );
        let operation = Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::Oem(OemCommand::DebugToken(
                NvidiaDebugTokenCommand::DisableToken,
            )),
            created_at(),
        );
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let finished = executor.execute_operation(operation.id()).await?;

        assert_eq!(finished.state(), OperationState::Failed);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [OperationState::Failed]
        );
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        assert_eq!(
            audit.recorded_events()?[1].outcome().verification(),
            Some(AuditVerification::Rejected)
        );
        Ok(())
    }

    #[tokio::test]
    async fn recovery_of_unknown_operation_reports_not_found() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let unknown = OperationId::generate();

        let result = executor.recover_operation(unknown).await;

        assert!(matches!(
            result,
            Err(ExecutorError::OperationNotFound(id)) if id == unknown
        ));
        assert_eq!(store.recorded_calls()?, [Call::Find(unknown)]);
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_operation_reports_not_found() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let unknown = OperationId::generate();

        let result = executor.execute_operation(unknown).await;

        assert!(matches!(
            result,
            Err(ExecutorError::OperationNotFound(id)) if id == unknown
        ));
        assert_eq!(store.recorded_calls()?, [Call::Find(unknown)]);
        assert_eq!(audit.recorded_events()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn zero_target_operation_is_rejected() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        // The engine rejects empty target lists at create time, but
        // rehydration does not, so a corrupt row can still be read back.
        let operation = Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            Vec::new(),
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            created_at(),
        );
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::EmptyTargets(id)) if id == operation.id()
        ));
        assert_eq!(audit.recorded_events()?.len(), 0);
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn audit_start_failure_prevents_all_work() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::fail_on(1);
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::Audit {
                stage: OperationAuditStage::Start,
                source: AuditRecordError::Write(MockError::Audit),
            })
        ));
        assert_eq!(
            applied_states(&store.recorded_calls()?).len(),
            0,
            "no step may be persisted when the start fact cannot be recorded"
        );
        assert_eq!(gateway.recorded_calls()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn audit_terminal_failure_reports_after_the_terminal_state_was_persisted()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::Accepted),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::fail_on(2);
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        assert!(matches!(
            result,
            Err(ExecutorError::Audit {
                stage: OperationAuditStage::Terminal,
                source: AuditRecordError::Write(MockError::Audit),
            })
        ));
        // The operation still reached its honest terminal state; only the
        // terminal audit fact could not be appended.
        assert_eq!(
            store
                .find_owned(operation.id())?
                .ok_or("the operation must still be stored")?
                .state(),
            OperationState::Succeeded
        );
        assert_eq!(
            audit.recorded_events()?.len(),
            1,
            "only the start fact landed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn async_task_acceptance_persists_the_task_row_and_waits() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let task_location = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::AsyncTaskAccepted {
                task_location: task_location.clone(),
            }),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);
        let operation_id = operation.id();

        let waiting = executor.execute_operation(operation_id).await?;

        // The operation is handed back to the scheduler in WaitingRemote, not
        // terminal: the Task monitor resumes it from the persisted row.
        assert_eq!(waiting.id(), operation_id);
        assert_eq!(waiting.state(), OperationState::WaitingRemote);
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::WaitingRemote,
            ]
        );
        // The observation row exists with the exact task location from the
        // `202` `Location` header, bound to the operation and its endpoint;
        // the placeholder state `New` is truthful (nothing observed yet) and
        // the acceptance clock time is the first check time.
        let task = store
            .find_remote_task_owned(operation_id)?
            .ok_or("the accepted task row must be persisted")?;
        assert_eq!(task.operation_id(), operation_id);
        assert_eq!(task.endpoint_id(), endpoint_id);
        assert_eq!(task.task_uri(), &task_location);
        assert_eq!(task.task_monitor_uri(), None);
        assert_eq!(task.last_state(), RemoteTaskState::New);
        assert_eq!(task.last_checked_at(), clock_time());
        // The write landed asynchronously, so only the start fact is audited;
        // the terminal fact belongs to the Task monitor (§13.6).
        assert_eq!(audit.recorded_events()?.len(), 1);
        assert_eq!(
            gateway.recorded_calls()?,
            [GatewayCall {
                kind: GatewayCallKind::Execute,
                endpoint_id,
                command: operation.command(),
            }],
            "an accepted Task must never be verified synchronously"
        );
        Ok(())
    }

    #[tokio::test]
    async fn remote_task_save_failure_records_unknown_and_propagates_the_source()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = FakeStore::new(Some(endpoint(endpoint_id)?), supported_systems_capability());
        store.arm_failure(MockStoreFailure::RemoteTaskWrite)?;
        let operation = queued_operation(endpoint_id);
        store.insert(operation.clone())?;
        let gateway = FakeGateway::new(
            Ok(CommandOutcome::AsyncTaskAccepted {
                task_location: TaskUri::parse("/redfish/v1/TaskService/Tasks/43")?,
            }),
            Ok(VerificationVerdict::Confirmed),
        );
        let audit = MockAudit::succeed();
        let executor = executor(&store, &gateway, &audit);

        let result = executor.execute_operation(operation.id()).await;

        let error = result
            .err()
            .ok_or("the row persistence failure must escape")?;
        assert!(matches!(
            error,
            ExecutorError::RemoteTask(MockError::RemoteTaskStore)
        ));
        assert_error_source(&error, MockError::RemoteTaskStore)?;
        // The BMC already accepted the write, so the operation must never be
        // left retryable: it is recorded Unknown (§13.5 cannot-prove), which
        // the scheduler never re-dispatches.
        assert_eq!(
            applied_states(&store.recorded_calls()?),
            [
                OperationState::Validating,
                OperationState::Running,
                OperationState::Unknown,
            ]
        );
        let events = audit.recorded_events()?;
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].outcome().kind(), AuditOutcomeKind::Failed);
        assert_eq!(
            events[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        Ok(())
    }

    /// Asserts that `error`'s source chain starts with the mock boundary
    /// failure, pinning the `#[source]` propagation of every variant.
    fn assert_error_source<ErrorType>(
        error: &ErrorType,
        expected: MockError,
    ) -> Result<(), Box<dyn Error>>
    where
        ErrorType: Error + 'static,
    {
        let source = Error::source(error).ok_or_else(|| {
            std::io::Error::other("the executor error must expose its boundary source")
        })?;
        assert_eq!(source.to_string(), expected.to_string());
        Ok(())
    }
}
