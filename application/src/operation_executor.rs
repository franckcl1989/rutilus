//! The synchronous command execution scheduler (design sections 13.3 and
//! 13.5).
//!
//! [`OperationExecutor`] drives one persisted operation from `Queued` to a
//! terminal state through the §13.2 state machine. It performs the first cut
//! of the §13.3 pre-flight checks (steps 1-2: endpoint existence and
//! capability availability), dispatches the typed command through the
//! [`CommandExecutor`] boundary (step 7), re-reads and verifies the target
//! through the [`CommandVerifier`] boundary (steps 9-10), and records the
//! §16.3 audit lifecycle (start + terminal fact) through
//! [`AuditEventWriter`].
//!
//! The asynchronous Task path (`202` responses,
//! [`OperationState::WaitingRemote`]) is deliberately absent from this cut:
//! Task monitoring (design section 13.6) is the next iteration's work. The
//! boundary contracts already document how a `202` must surface until then
//! (see [`CommandExecutor`]), and no empty shells are stubbed for the Task
//! machinery.

use std::{error::Error, fmt};

use rutilus_domain::{
    AuditAction, AuditActor, AuditEvent, AuditFailure, AuditFailureVerification,
    AuditOperationContext, AuditOperationContextError, AuditOperationId, AuditParameterSummary,
    AuditRedfishOperation, AuditSequence, AuditTarget, CapabilityState, DeploymentPosture,
    EndpointCapability, EndpointId, Operation, OperationEvent, OperationId, OperationState,
    ProductPermission, RedfishCommand,
};
use rutilus_operation_engine::{EngineError, OperationEngine, OperationStore};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    AuditEventWriter, AuditRecordError, CapabilityLedgerEntry, CapabilityQueryRepository, Clock,
    CommandExecutor, CommandOutcome, CommandVerifier, DispatchVerdict, DispatchVerdictClassifier,
    EndpointCapabilityQuery, EndpointCapabilityQueryError, EndpointRefreshRepository,
    VerificationVerdict,
};

/// The concrete failure type of one execution attempt.
///
/// The generic parameters are the six boundary error types, in
/// [`ExecutorError`] order: operation store, endpoint lookup, capability
/// query, command dispatch, verification, and audit. Keeping them separate
/// preserves every source chain, exactly like the refresh use case's error.
type ExecutorErrorOf<Store, Gateway, Audit> = ExecutorError<
    <Store as OperationStore>::Error,
    <Store as EndpointRefreshRepository>::Error,
    <Store as CapabilityQueryRepository>::Error,
    <Gateway as CommandExecutor>::Error,
    <Gateway as CommandVerifier>::Error,
    <Audit as AuditEventWriter>::Error,
>;

/// Drives one persisted operation through the synchronous execution flow.
///
/// `Store` stays one constructor parameter although it plays three roles —
/// operation lifecycle, endpoint lookup, and capability ledger — because
/// every runtime composes one `SqliteStore` implementing all three, exactly
/// like the refresh use case's repository. `Gateway` implements both dispatch
/// and verification on the same Redfish gateway object, and `Audit` appends
/// the §16.3 lifecycle facts.
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
    Store: OperationStore + EndpointRefreshRepository + CapabilityQueryRepository,
    Gateway: CommandExecutor + CommandVerifier,
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

    /// Executes one queued operation to a terminal state.
    ///
    /// # Flow
    ///
    /// 1. Read the operation. Only `Queued` work is schedulable; a
    ///    not-found id and a non-queued state are defensive rejects that
    ///    change nothing and record no audit (nothing was driven).
    /// 2. Record the §16.3 start fact (before any pre-flight work, the same
    ///    order as the other audited use cases).
    /// 3. Pre-flight, first cut of §13.3 steps 1-2: the first target's
    ///    endpoint must exist and must advertise the command's required
    ///    capability as `Supported`. A failed pre-flight is a provable
    ///    refusal — nothing has been dispatched — so the operation is
    ///    recorded `Failed`, never `Unknown`.
    /// 4. Persist `ValidationStarted` → `ValidationPassed` → `Running`
    ///    (§13.3 step 6, then the dispatch of step 7).
    /// 5. Dispatch through [`CommandExecutor`]. `Accepted` (synchronous
    ///    `200`/`201`/`204` handled) persists `ExecutionAccepted`; `Rejected`
    ///    (provable BMC refusal) persists `Failed`. A dispatch error is
    ///    classified by its own [`DispatchVerdict`] (design section 13.5):
    ///    errors that prove the write was never executed persist `Failed`,
    ///    errors that cannot prove it persist `OutcomeUnknown` → `Unknown`;
    ///    either way the operation reaches its honest terminal state and the
    ///    underlying error escapes as [`ExecutorError::Gateway`] with its
    ///    source chain intact.
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
    /// (including a second driver racing this id — the engine reports the
    /// state the domain observed), [`ExecutorError::EmptyTargets`] for a
    /// corrupt zero-target row, and the store, pre-flight, dispatch,
    /// verification, and audit boundary errors with their sources chained.
    /// Note that a failed dispatch or verification still persists the
    /// operation's honest terminal state before the error is returned, so a
    /// caller that sees an error can re-read the operation for its outcome.
    pub async fn execute_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        // The scheduler drives only queued work. The engine exposes no read
        // in this iteration, so the pre-read goes through the same
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
        if operation.state() != OperationState::Queued {
            return Err(ExecutorError::NotQueued {
                operation_id,
                state: operation.state(),
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

        let started = self.start_audit(endpoint_id).await?;

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
        if !self.capability_usable(&command, endpoint_id).await? {
            return self
                .refuse(
                    &engine,
                    operation_id,
                    &started,
                    AuditFailure::RedfishDiscoveryFailed,
                )
                .await;
        }

        self.apply_step(&engine, operation_id, OperationEvent::ValidationStarted)
            .await?;
        self.apply_step(&engine, operation_id, OperationEvent::ValidationPassed)
            .await?;

        self.dispatch_and_verify(&engine, operation_id, endpoint_id, &command, &started)
            .await
    }

    /// Builds and appends the §16.3 start fact before any pre-flight work.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Audit`] with the start stage when the context
    /// cannot be constructed or the append fails; no operation step is
    /// persisted then.
    async fn start_audit(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<StartedAudit, ExecutorErrorOf<Store, Gateway, Audit>> {
        let context =
            operation_audit_context(endpoint_id, self.actor, self.origin).map_err(|source| {
                ExecutorError::Audit {
                    stage: OperationAuditStage::Start,
                    source: AuditRecordError::Context(source),
                }
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
    /// Only [`CapabilityState::Supported`] passes: `ReadOnly` advertises a
    /// read-only surface (a write would be refused by the BMC), and every
    /// other state — unauthorized, temporarily unavailable,
    /// schema-incompatible, not advertised, not compiled, or not yet observed
    /// — means the product cannot confirm the capability, so dispatching
    /// would be unaccountable. A pre-flight refusal is provable — nothing
    /// has been dispatched — and is therefore recorded `Failed`, never
    /// `Unknown` (design section 13.5).
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::CapabilityPreflight`] when the ledger query
    /// fails.
    async fn capability_usable(
        &self,
        command: &RedfishCommand,
        endpoint_id: EndpointId,
    ) -> Result<bool, ExecutorErrorOf<Store, Gateway, Audit>> {
        let required = required_capability(command);
        let entries = EndpointCapabilityQuery::new(&self.store, endpoint_id)
            .execute()
            .await
            .map_err(ExecutorError::CapabilityPreflight)?;
        Ok(entries
            .and_then(|entries| required_capability_state(required, &entries))
            .is_some_and(|state| state == CapabilityState::Supported))
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
                // target lists at create time); the arm exists only because
                // `EngineError` is a closed enum.
                EngineError::EmptyTargets => ExecutorError::EmptyTargets(operation_id),
            })
    }

    /// Dispatches the write (§13.3 step 7) and drives the synchronous outcome
    /// (§13.3 step 8) including the §13.5 classification of failed dispatches.
    ///
    /// # Errors
    ///
    /// Returns [`ExecutorError::Gateway`] with the classified dispatch error
    /// as its source after the operation has been persisted into its honest
    /// terminal state (`Failed` or `Unknown`) and the terminal audit fact has
    /// been recorded.
    async fn dispatch_and_verify(
        &self,
        engine: &OperationEngine<&Store>,
        operation_id: OperationId,
        endpoint_id: EndpointId,
        command: &RedfishCommand,
        started: &StartedAudit,
    ) -> Result<Operation, ExecutorErrorOf<Store, Gateway, Audit>> {
        match self.gateway.execute(endpoint_id, command).await {
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
                Err(ExecutorError::Gateway(source))
            }
        }
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
    /// verification); the write-specific failure vocabulary is the next
    /// domain iteration's work (see [`operation_audit_context`]). The
    /// verification class is the truthful part: `Rejected` for every provable
    /// outcome and `Inconclusive` for every outcome the product cannot prove
    /// (design section 13.5).
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

/// Builds the audit context of one operation execution attempt.
///
/// # Why the refresh vocabulary
///
/// The 0.1 domain audit vocabulary (§16.3) accepts exactly three
/// (target, parameter summary, permission, action, Redfish operation)
/// combinations — enrollment, refresh, and CSV import — and none of them
/// describes executing a write. The domain crate is read-only for this
/// iteration, so the only legal context whose target is truthful (the managed
/// endpoint that receives the write) is the refresh combination. The
/// operation-specific vocabulary — an execute-operation action, the
/// Reset/Boot/SecureBoot/Event Redfish operation types, and the
/// write-failure classes — is the next domain iteration's work; until then
/// the permission, action, and Redfish-operation fields of the recorded
/// context are the closest legal values and must not be read as naming the
/// product action they display. The truthful parts of every recorded event
/// are the actor, the origin, the endpoint target, the occurrence time, and
/// the outcome (started / succeeded / failed with its verification class).
///
/// # Errors
///
/// Returns [`AuditOperationContextError`] when the combination is not one the
/// 0.1 vocabulary accepts.
fn operation_audit_context(
    endpoint_id: EndpointId,
    actor: AuditActor,
    origin: DeploymentPosture,
) -> Result<AuditOperationContext, AuditOperationContextError> {
    AuditOperationContext::try_new(
        AuditOperationId::generate(),
        actor,
        origin,
        AuditTarget::Endpoint(endpoint_id),
        AuditParameterSummary::EndpointRefresh,
        ProductPermission::RefreshEndpoints,
        AuditAction::RefreshEndpoint,
        AuditRedfishOperation::ReadCoreResources,
    )
}

/// Maps one typed command to the capability the endpoint must advertise.
///
/// The mapping is exhaustive per the §7.5 family list, so a new command
/// family fails to compile until its capability is decided here. Boot and
/// Secure Boot live on the `ComputerSystem` resource, so they require the
/// `Systems` capability (the stable 0.1 product code of the
/// `computer-systems` feature) and `SecureBoot` respectively; event
/// subscription writes require the event service.
fn required_capability(command: &RedfishCommand) -> EndpointCapability {
    match command {
        // Boot configuration lives on the `ComputerSystem` resource, so a
        // boot command needs the same `Systems` capability as a system reset.
        RedfishCommand::System(_) | RedfishCommand::Boot(_) => EndpointCapability::Systems,
        RedfishCommand::Manager(_) => EndpointCapability::Managers,
        RedfishCommand::Chassis(_) => EndpointCapability::Chassis,
        RedfishCommand::SecureBoot(_) => EndpointCapability::SecureBoot,
        RedfishCommand::Event(_) => EndpointCapability::EventService,
    }
}

/// Returns the observed state of one capability inside a full §2.1 ledger.
///
/// `None` means the capability has no observation yet (it is not the
/// `NotAdvertised` final state, which requires an explicit probe result).
fn required_capability_state(
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

/// A controlled failure while driving one operation to its terminal state.
///
/// The six generic parameters are the boundary error types in dependency
/// order: the operation store, the endpoint lookup, the capability query, the
/// command dispatch, the post-execution verification, and the audit append.
/// Every variant keeps its boundary source on the error chain.
#[derive(Debug, Error)]
pub enum ExecutorError<
    StoreError,
    RepositoryError,
    CapabilityError,
    GatewayError,
    VerifierError,
    AuditError,
> where
    StoreError: Error + 'static,
    RepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    GatewayError: Error + 'static,
    VerifierError: Error + 'static,
    AuditError: Error + 'static,
{
    /// The operation id is not known to the store.
    #[error("operation {0} was not found")]
    OperationNotFound(OperationId),
    /// The scheduler tried to drive an operation that is no longer queued.
    ///
    /// This is the defensive guard for the queued-only scheduling contract:
    /// either the caller passed a state the scheduler must not touch, or a
    /// second driver advanced the operation between the scheduler's read and
    /// its first persisted step (the domain state machine reported the
    /// current state).
    #[error("operation {operation_id} is {state} and only queued operations are schedulable")]
    NotQueued {
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
    /// The command dispatch (§13.3 step 7) failed.
    ///
    /// The operation has already been persisted into its honest terminal
    /// state (`Failed` or `Unknown`, per the error's own [`DispatchVerdict`])
    /// and its terminal audit fact has been recorded before this error is
    /// returned.
    #[error("command dispatch failed: {0}")]
    Gateway(#[source] GatewayError),
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
        collections::HashMap,
        error::Error,
        fmt,
        sync::{Arc, Mutex},
    };

    use rutilus_domain::{
        AuditOutcomeKind, AuditVerification, CapabilityState, CredentialId, Endpoint,
        EndpointAddress, EndpointCapabilityObservation, EndpointDisplayName, EndpointId,
        OperationSource, OperationTarget, ResetType, ResourceSnapshot, SystemCommand, TargetId,
        TlsCertificate, TlsTrust,
    };
    use rutilus_operation_engine::BoundaryFuture as OperationBoundaryFuture;
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
        FindEndpoint(EndpointId),
        FindCapabilities(EndpointId),
    }

    /// The single failure mode armed for the next matching store call.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum FailureKind {
        Read,
        Write,
        EndpointLookup,
        CapabilityLookup,
    }

    /// In-memory store implementing every repository role the executor uses.
    ///
    /// One struct implements `OperationStore`, `EndpointRefreshRepository`,
    /// and `CapabilityQueryRepository` exactly like the production
    /// `SqliteStore`, so the executor composes over a single test object.
    /// `apply_transition` upholds the store contract: unknown ids and writes
    /// onto terminal states are rejected.
    struct FakeStore {
        rows: Mutex<HashMap<OperationId, Operation>>,
        endpoint: Option<Endpoint>,
        capabilities: Vec<StoredCapability>,
        calls: Mutex<Vec<Call>>,
        fail_once: Mutex<Option<FailureKind>>,
    }

    impl FakeStore {
        fn new(endpoint: Option<Endpoint>, capabilities: Vec<StoredCapability>) -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                endpoint,
                capabilities,
                calls: Mutex::new(Vec::new()),
                fail_once: Mutex::new(None),
            }
        }

        /// Arms exactly one failure for the next call of `kind`.
        fn arm_failure(&self, kind: FailureKind) -> Result<(), MockError> {
            *self.fail_once.lock().map_err(|_| MockError::Events)? = Some(kind);
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
                if self.consume_failure(FailureKind::Read)? {
                    return Err(MockError::Store);
                }
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| MockError::Events)?
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
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(Call::ApplyTransition(operation_id, new_state));
                if self.consume_failure(FailureKind::Write)? {
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

        fn list_operations(
            &self,
            _state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
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
                if self.consume_failure(FailureKind::EndpointLookup)? {
                    return Err(MockError::Repository);
                }
                Ok(self.endpoint.clone())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [ResourceObservation],
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
                if self.consume_failure(FailureKind::CapabilityLookup)? {
                    return Err(MockError::Capability);
                }
                if self.endpoint.is_none() {
                    return Ok(None);
                }
                Ok(Some(self.capabilities.clone()))
            })
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

    /// Scripted gateway: `outcome` is the dispatch result and `verdict` the
    /// verification result, both recorded per call.
    struct FakeGateway {
        calls: Mutex<Vec<GatewayCall>>,
        outcome: Result<CommandOutcome, MockError>,
        verdict: Result<VerificationVerdict, MockError>,
    }

    impl FakeGateway {
        fn new(
            outcome: Result<CommandOutcome, MockError>,
            verdict: Result<VerificationVerdict, MockError>,
        ) -> Self {
            Self {
                calls: Mutex::new(Vec::new()),
                outcome,
                verdict,
            }
        }

        fn recorded_calls(&self) -> Result<Vec<GatewayCall>, MockError> {
            self.calls
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
                self.outcome
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

    /// The single mock failure vocabulary of every boundary under test.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Store,
        Repository,
        Capability,
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
        // dispatched against it, and the refusal is provable.
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
        store.arm_failure(FailureKind::EndpointLookup)?;
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
        store.arm_failure(FailureKind::CapabilityLookup)?;
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
        store.arm_failure(FailureKind::Read)?;
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
        let mut operation = queued_operation(endpoint_id);
        operation.apply(OperationEvent::ValidationStarted, clock_time())?;
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
                state: OperationState::Validating,
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
