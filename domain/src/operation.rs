//! The unified persisted operation model (§13).
//!
//! Every write request — from the Standalone GUI, the Site GUI, or the Center
//! — is converted into one persisted [`Operation`] (§13.1). The operation
//! lifecycle is driven exclusively by the §13.2 state machine through the pure
//! [`transition`] function; there is no other path that changes an operation's
//! state (§7.1). A string stored in the database is rehydrated with
//! [`Operation::try_from_parts`], but changing it still requires a legal
//! transition.

use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;

use crate::{EndpointId, OperationId, TargetId};

/// The lifecycle phase of one persisted operation (§13.2).
///
/// The phase code returned by [`Self::as_str`] is the stable snake-case code
/// used by persistence and protocols; it never changes across milestones.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationState {
    /// The operation is persisted (§13.3 step 6) but has not been picked up
    /// for pre-flight checks yet.
    Queued,
    /// Pre-flight checks are in progress: re-read the current resource, then
    /// capability, permission, operation parameters, and ETag/preconditions
    /// (§13.3 steps 1–5).
    Validating,
    /// All pre-flight checks passed and the typed Redfish method call is being
    /// dispatched (§13.3 step 7).
    Running,
    /// The BMC accepted the request as an asynchronous Task; the product is
    /// monitoring the `TaskMonitor` (§13.3 step 8, §13.6) and resumes this scan
    /// after a restart.
    WaitingRemote,
    /// The target resource is being re-read and the expected result verified
    /// (§13.3 steps 9–10). The write has already completed by now, so the
    /// operation can no longer be cancelled.
    Verifying,
    /// Verification confirmed the expected result; the final state and audit
    /// record are written (§13.3 step 11).
    Succeeded,
    /// A provable failure: pre-flight rejection, BMC rejection, a failed
    /// Task, or a verification mismatch. The product can account for the
    /// outcome — the operation did not achieve its result.
    Failed,
    /// The request may already have been accepted by the BMC, but the product
    /// currently cannot prove the final result (§13.2, §13.5: response lost,
    /// `TaskMonitor` unreachable, re-read inconclusive). This is an explicit
    /// terminal state, not an ordinary failure: recovery re-reads the target
    /// or the Task and then decides (§13.5).
    Unknown,
    /// The product decided to stop the operation and can prove that it
    /// stopped: either nothing had been dispatched yet, or the pending BMC
    /// Task was removed. When the stop cannot be proven, the caller must
    /// emit [`OperationEvent::OutcomeUnknown`] instead.
    Cancelled,
}

impl OperationState {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Validating => "validating",
            Self::Running => "running",
            Self::WaitingRemote => "waiting-remote",
            Self::Verifying => "verifying",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Cancelled => "cancelled",
        }
    }

    /// Reports whether the operation lifecycle has finished.
    ///
    /// Terminal states absorb every event: after `Succeeded`, `Failed`,
    /// `Unknown`, or `Cancelled`, no further transition is legal (§13.2).
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Unknown | Self::Cancelled
        )
    }

    /// Reports whether the product is still driving the operation.
    #[must_use]
    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Queued | Self::Validating | Self::Running | Self::WaitingRemote | Self::Verifying
        )
    }
}

impl fmt::Display for OperationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for OperationState {
    type Err = OperationStateParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "queued" => Ok(Self::Queued),
            "validating" => Ok(Self::Validating),
            "running" => Ok(Self::Running),
            "waiting-remote" => Ok(Self::WaitingRemote),
            "verifying" => Ok(Self::Verifying),
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "unknown" => Ok(Self::Unknown),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(OperationStateParseError),
        }
    }
}

/// A persisted operation state is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationStateParseError;

impl fmt::Display for OperationStateParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown operation state code")
    }
}

impl Error for OperationStateParseError {}

/// The input event that drives the §13.2 operation state machine.
///
/// Each event corresponds to one step (or one bounded group of steps) of the
/// §13.3 execution flow. The caller emits an event only after the referenced
/// work has actually completed; the domain records the resulting phase.
/// Events are transient inputs and are not persisted by the domain —
/// persistence stores the resulting [`OperationState`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationEvent {
    /// Pre-flight validation begins (§13.3 steps 1–5: re-read the target
    /// resource, then capability, permission, operation parameters, and
    /// ETag/preconditions). Moves `Queued` to `Validating`.
    ValidationStarted,
    /// Every pre-flight check passed (§13.3 steps 1–5); the typed method call
    /// may be dispatched. Moves `Validating` to `Running`.
    ValidationPassed,
    /// The BMC accepted the request synchronously (§13.3 step 7, success
    /// status without a pending Task) and the response has been fully handled
    /// (§13.3 step 8); the target must now be verified. Moves `Running` to
    /// `Verifying`.
    ExecutionAccepted,
    /// The BMC accepted the request as an asynchronous Task (§13.3 step 7
    /// returning 202); `TaskMonitor` tracking starts (§13.3 step 8, §13.6).
    /// Moves `Running` to `WaitingRemote`.
    RemoteTaskStarted,
    /// The monitored BMC Task reached a terminal state (§13.3 step 8); the
    /// target must now be verified. Moves `WaitingRemote` to `Verifying`.
    RemoteTaskCompleted,
    /// Re-reading the target confirmed the expected result (§13.3 steps 9–10).
    /// Moves `Verifying` to `Succeeded`.
    VerificationPassed,
    /// A step failed with a provable outcome: pre-flight rejection, BMC
    /// rejection (for example an error response proving the request was not
    /// executed), a failed Task, or a verification mismatch. When the outcome
    /// cannot be proven, [`Self::OutcomeUnknown`] must be used instead.
    /// Moves `Queued`, `Validating`, `Running`, `WaitingRemote`, or
    /// `Verifying` to `Failed`.
    Failed,
    /// The operator requested cancellation and the product confirmed that the
    /// operation can be recorded as cancelled: nothing was dispatched yet, or
    /// the pending BMC Task was removed (§13.5 re-read pattern). When the
    /// request may already have landed and the outcome cannot be proven,
    /// [`Self::OutcomeUnknown`] must be used instead. Moves `Queued`,
    /// `Validating`, `Running`, or `WaitingRemote` to `Cancelled`.
    CancellationRequested,
    /// The product lost the response or cannot prove the final result (§13.5:
    /// response lost, `TaskMonitor` unreachable, re-read inconclusive). Moves
    /// `Running`, `WaitingRemote`, or `Verifying` to the explicit terminal
    /// state [`OperationState::Unknown`].
    OutcomeUnknown,
}

impl OperationEvent {
    /// Returns a stable logging code for the event.
    ///
    /// Events are not persisted by the domain, so these codes are only a
    /// stable vocabulary for logs and error messages; if a later milestone
    /// persists events, these codes become the wire contract.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ValidationStarted => "validation-started",
            Self::ValidationPassed => "validation-passed",
            Self::ExecutionAccepted => "execution-accepted",
            Self::RemoteTaskStarted => "remote-task-started",
            Self::RemoteTaskCompleted => "remote-task-completed",
            Self::VerificationPassed => "verification-passed",
            Self::Failed => "failed",
            Self::CancellationRequested => "cancellation-requested",
            Self::OutcomeUnknown => "outcome-unknown",
        }
    }
}

impl fmt::Display for OperationEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A state-machine step was attempted from a state in which the event cannot
/// occur (§7.1).
///
/// This error carries the rejected step so callers can log or audit exactly
/// which event was refused in which phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidTransition {
    from: OperationState,
    event: OperationEvent,
}

impl InvalidTransition {
    /// Returns the state the operation was in when the event was attempted.
    #[must_use]
    pub const fn from_state(self) -> OperationState {
        self.from
    }

    /// Returns the event that cannot occur in [`Self::from_state`].
    #[must_use]
    pub const fn event(self) -> OperationEvent {
        self.event
    }
}

impl fmt::Display for InvalidTransition {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "event {} cannot occur in operation state {}",
            self.event, self.from
        )
    }
}

impl Error for InvalidTransition {}

/// Applies `event` to `current` and returns the next operation state (§7.1,
/// §13.2).
///
/// The matrix is fully enumerated: every `(state, event)` pair is named in an
/// explicit arm with no wildcard, so extending [`OperationState`] or
/// [`OperationEvent`] fails to compile until every phase has been reviewed.
///
/// # Errors
///
/// Returns [`InvalidTransition`] when the event cannot occur in the current
/// state. The operation is never modified in that case.
pub const fn transition(
    current: OperationState,
    event: OperationEvent,
) -> Result<OperationState, InvalidTransition> {
    use OperationEvent as Event;
    use OperationState as State;
    match current {
        State::Queued => match event {
            Event::ValidationStarted => Ok(State::Validating),
            Event::Failed => Ok(State::Failed),
            Event::CancellationRequested => Ok(State::Cancelled),
            Event::ValidationPassed
            | Event::ExecutionAccepted
            | Event::RemoteTaskStarted
            | Event::RemoteTaskCompleted
            | Event::VerificationPassed
            | Event::OutcomeUnknown => Err(invalid_transition(current, event)),
        },
        State::Validating => match event {
            Event::ValidationPassed => Ok(State::Running),
            Event::Failed => Ok(State::Failed),
            Event::CancellationRequested => Ok(State::Cancelled),
            Event::ValidationStarted
            | Event::ExecutionAccepted
            | Event::RemoteTaskStarted
            | Event::RemoteTaskCompleted
            | Event::VerificationPassed
            | Event::OutcomeUnknown => Err(invalid_transition(current, event)),
        },
        State::Running => match event {
            Event::ExecutionAccepted => Ok(State::Verifying),
            Event::RemoteTaskStarted => Ok(State::WaitingRemote),
            Event::Failed => Ok(State::Failed),
            Event::CancellationRequested => Ok(State::Cancelled),
            Event::OutcomeUnknown => Ok(State::Unknown),
            Event::ValidationStarted
            | Event::ValidationPassed
            | Event::RemoteTaskCompleted
            | Event::VerificationPassed => Err(invalid_transition(current, event)),
        },
        State::WaitingRemote => match event {
            Event::RemoteTaskCompleted => Ok(State::Verifying),
            Event::Failed => Ok(State::Failed),
            Event::CancellationRequested => Ok(State::Cancelled),
            Event::OutcomeUnknown => Ok(State::Unknown),
            Event::ValidationStarted
            | Event::ValidationPassed
            | Event::ExecutionAccepted
            | Event::RemoteTaskStarted
            | Event::VerificationPassed => Err(invalid_transition(current, event)),
        },
        State::Verifying => match event {
            Event::VerificationPassed => Ok(State::Succeeded),
            Event::Failed => Ok(State::Failed),
            Event::OutcomeUnknown => Ok(State::Unknown),
            Event::ValidationStarted
            | Event::ValidationPassed
            | Event::ExecutionAccepted
            | Event::RemoteTaskStarted
            | Event::RemoteTaskCompleted
            | Event::CancellationRequested => Err(invalid_transition(current, event)),
        },
        State::Succeeded | State::Failed | State::Unknown | State::Cancelled => match event {
            Event::ValidationStarted
            | Event::ValidationPassed
            | Event::ExecutionAccepted
            | Event::RemoteTaskStarted
            | Event::RemoteTaskCompleted
            | Event::VerificationPassed
            | Event::Failed
            | Event::CancellationRequested
            | Event::OutcomeUnknown => Err(invalid_transition(current, event)),
        },
    }
}

const fn invalid_transition(current: OperationState, event: OperationEvent) -> InvalidTransition {
    InvalidTransition {
        from: current,
        event,
    }
}

/// Where a persisted operation originated (§13.1).
///
/// Standalone GUI, Site GUI, and Center writes all land in the same operation
/// model, and the source is recorded on the persisted operation. This is its
/// own type rather than a reuse of `DeploymentPosture` because it is a fact
/// about one operation record, not about where the current binary runs.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum OperationSource {
    /// A write submitted from a standalone local GUI.
    Standalone,
    /// A write submitted from a site GUI.
    Site,
    /// A write dispatched by the Center.
    Center,
}

impl OperationSource {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Site => "site",
            Self::Center => "center",
        }
    }
}

impl fmt::Display for OperationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for OperationSource {
    type Err = OperationSourceParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "standalone" => Ok(Self::Standalone),
            "site" => Ok(Self::Site),
            "center" => Ok(Self::Center),
            _ => Err(OperationSourceParseError),
        }
    }
}

/// A persisted operation source is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationSourceParseError;

impl fmt::Display for OperationSourceParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown operation source code")
    }
}

impl Error for OperationSourceParseError {}

/// One object that an operation acts on, bound to the endpoint that receives
/// the Redfish request (§13.1).
///
/// A batch (§13.7) is a list of these targets inside one [`Operation`]; each
/// target's outcome is tracked independently and a partial failure never
/// becomes an overall success. The operation-level state machine in this
/// module records the lifecycle of the whole operation; per-target outcome
/// records are a later iteration. The §13.7 `BatchOperation` parent/child
/// tree is an engine-layer structure composed from these flat targets.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OperationTarget {
    target_id: TargetId,
    endpoint_id: EndpointId,
}

impl OperationTarget {
    /// Binds one operation target to the endpoint that will receive the
    /// Redfish request.
    #[must_use]
    pub const fn new(target_id: TargetId, endpoint_id: EndpointId) -> Self {
        Self {
            target_id,
            endpoint_id,
        }
    }

    /// Returns the identity of the target object.
    #[must_use]
    pub const fn target_id(self) -> TargetId {
        self.target_id
    }

    /// Returns the identity of the endpoint that receives the request.
    #[must_use]
    pub const fn endpoint_id(self) -> EndpointId {
        self.endpoint_id
    }
}

/// One persisted product operation (§13.1).
///
/// The state is private and only changes through [`Operation::apply`], which
/// routes through the pure [`transition`] matrix; there is no mutation path
/// that could write an arbitrary state (§7.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    id: OperationId,
    source: OperationSource,
    targets: Vec<OperationTarget>,
    state: OperationState,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Operation {
    /// Creates a persisted operation in the `Queued` phase.
    ///
    /// `targets` must contain at least one target: a batch (§13.7) is a list
    /// of targets and a zero-target operation cannot be executed, so callers
    /// never construct one.
    #[must_use]
    pub const fn new(
        id: OperationId,
        source: OperationSource,
        targets: Vec<OperationTarget>,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            source,
            targets,
            state: OperationState::Queued,
            created_at,
            updated_at: created_at,
        }
    }

    /// Rehydrates a persisted operation record.
    ///
    /// This is the only way to construct an operation in a non-`Queued`
    /// state; it is reserved for persistence loading, which must accept
    /// whatever the database stored. Transitions still go through the §13.2
    /// state machine.
    ///
    /// # Errors
    ///
    /// Returns [`OperationTimelineError`] when the update time precedes the
    /// creation time.
    pub fn try_from_parts(
        id: OperationId,
        source: OperationSource,
        targets: Vec<OperationTarget>,
        state: OperationState,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, OperationTimelineError> {
        if updated_at < created_at {
            return Err(OperationTimelineError);
        }
        Ok(Self {
            id,
            source,
            targets,
            state,
            created_at,
            updated_at,
        })
    }

    /// Applies `event` at `now`, advancing the §13.2 state machine.
    ///
    /// On success the state becomes `transition(state, event)` and the update
    /// time becomes `now`. On [`InvalidTransition`] the operation is left
    /// completely unchanged.
    ///
    /// The `now` parameter keeps the domain free of clock access; the caller
    /// supplies a monotonic clock and must never move it backwards, which is
    /// why `updated_at` is trusted from the argument rather than re-checked.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTransition`] when the event cannot occur in the
    /// current state.
    pub fn apply(
        &mut self,
        event: OperationEvent,
        now: OffsetDateTime,
    ) -> Result<(), InvalidTransition> {
        self.state = transition(self.state, event)?;
        self.updated_at = now;
        Ok(())
    }

    #[must_use]
    pub const fn id(&self) -> OperationId {
        self.id
    }

    #[must_use]
    pub const fn source(&self) -> OperationSource {
        self.source
    }

    /// Returns the flat target list; a batch (§13.7) carries several targets.
    #[must_use]
    pub fn targets(&self) -> &[OperationTarget] {
        &self.targets
    }

    #[must_use]
    pub const fn state(&self) -> OperationState {
        self.state
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns when the state last changed; equals `created_at` for a fresh
    /// operation.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }

    /// Reports whether the operation lifecycle has finished.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }
}

/// A persisted operation has an invalid timestamp ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OperationTimelineError;

impl fmt::Display for OperationTimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("operation update time cannot precede its creation time")
    }
}

impl Error for OperationTimelineError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every state, so the matrix tests cannot silently miss a variant.
    const ALL_STATES: [OperationState; 9] = [
        OperationState::Queued,
        OperationState::Validating,
        OperationState::Running,
        OperationState::WaitingRemote,
        OperationState::Verifying,
        OperationState::Succeeded,
        OperationState::Failed,
        OperationState::Unknown,
        OperationState::Cancelled,
    ];

    /// Every event, so the matrix tests cannot silently miss a variant.
    const ALL_EVENTS: [OperationEvent; 9] = [
        OperationEvent::ValidationStarted,
        OperationEvent::ValidationPassed,
        OperationEvent::ExecutionAccepted,
        OperationEvent::RemoteTaskStarted,
        OperationEvent::RemoteTaskCompleted,
        OperationEvent::VerificationPassed,
        OperationEvent::Failed,
        OperationEvent::CancellationRequested,
        OperationEvent::OutcomeUnknown,
    ];

    /// The complete §13.2 transition table: 18 legal moves out of the 81
    /// `(state, event)` pairs. Every other pair must be rejected.
    const LEGAL_TRANSITIONS: [(OperationState, OperationEvent, OperationState); 18] = [
        (
            OperationState::Queued,
            OperationEvent::ValidationStarted,
            OperationState::Validating,
        ),
        (
            OperationState::Queued,
            OperationEvent::Failed,
            OperationState::Failed,
        ),
        (
            OperationState::Queued,
            OperationEvent::CancellationRequested,
            OperationState::Cancelled,
        ),
        (
            OperationState::Validating,
            OperationEvent::ValidationPassed,
            OperationState::Running,
        ),
        (
            OperationState::Validating,
            OperationEvent::Failed,
            OperationState::Failed,
        ),
        (
            OperationState::Validating,
            OperationEvent::CancellationRequested,
            OperationState::Cancelled,
        ),
        (
            OperationState::Running,
            OperationEvent::ExecutionAccepted,
            OperationState::Verifying,
        ),
        (
            OperationState::Running,
            OperationEvent::RemoteTaskStarted,
            OperationState::WaitingRemote,
        ),
        (
            OperationState::Running,
            OperationEvent::Failed,
            OperationState::Failed,
        ),
        (
            OperationState::Running,
            OperationEvent::CancellationRequested,
            OperationState::Cancelled,
        ),
        (
            OperationState::Running,
            OperationEvent::OutcomeUnknown,
            OperationState::Unknown,
        ),
        (
            OperationState::WaitingRemote,
            OperationEvent::RemoteTaskCompleted,
            OperationState::Verifying,
        ),
        (
            OperationState::WaitingRemote,
            OperationEvent::Failed,
            OperationState::Failed,
        ),
        (
            OperationState::WaitingRemote,
            OperationEvent::CancellationRequested,
            OperationState::Cancelled,
        ),
        (
            OperationState::WaitingRemote,
            OperationEvent::OutcomeUnknown,
            OperationState::Unknown,
        ),
        (
            OperationState::Verifying,
            OperationEvent::VerificationPassed,
            OperationState::Succeeded,
        ),
        (
            OperationState::Verifying,
            OperationEvent::Failed,
            OperationState::Failed,
        ),
        (
            OperationState::Verifying,
            OperationEvent::OutcomeUnknown,
            OperationState::Unknown,
        ),
    ];

    #[test]
    fn state_codes_are_unique_non_empty_and_round_trip() {
        let mut seen = Vec::new();
        for state in ALL_STATES {
            let code = state.as_str();
            assert!(!code.is_empty(), "operation state codes must not be empty");
            assert!(
                !seen.contains(&code),
                "product code {code} is used by more than one operation state"
            );
            seen.push(code);
            assert_eq!(code.parse(), Ok(state));
            assert_eq!(state.to_string(), code);
        }
        assert_eq!(
            "done".parse::<OperationState>(),
            Err(OperationStateParseError)
        );
    }

    #[test]
    fn source_codes_round_trip_and_reject_unknown_values() {
        for source in [
            OperationSource::Standalone,
            OperationSource::Site,
            OperationSource::Center,
        ] {
            let code = source.as_str();
            assert!(!code.is_empty(), "operation source codes must not be empty");
            assert_eq!(code.parse(), Ok(source));
            assert_eq!(source.to_string(), code);
        }
        assert_eq!(
            "cluster".parse::<OperationSource>(),
            Err(OperationSourceParseError)
        );
    }

    #[test]
    fn event_codes_are_stable_for_logging() {
        for event in ALL_EVENTS {
            let code = event.as_str();
            assert!(!code.is_empty(), "operation event codes must not be empty");
            assert_eq!(event.to_string(), code);
        }
    }

    #[test]
    fn transition_matrix_is_exhaustive_and_consistent() {
        for from in ALL_STATES {
            for event in ALL_EVENTS {
                let result = transition(from, event);
                match LEGAL_TRANSITIONS
                    .iter()
                    .find(|&&(legal_from, legal_event, _)| {
                        legal_from == from && legal_event == event
                    }) {
                    Some(&(_, _, to)) => assert_eq!(
                        result,
                        Ok(to),
                        "transition from {from} on event {event} must reach {to}"
                    ),
                    None => assert_eq!(
                        result,
                        Err(InvalidTransition { from, event }),
                        "transition from {from} on event {event} must be rejected"
                    ),
                }
            }
        }
    }

    #[test]
    fn legal_transition_table_is_unambiguous() {
        let mut seen = Vec::new();
        for (from, event, to) in LEGAL_TRANSITIONS {
            assert!(
                !seen.contains(&(from, event)),
                "transition from {from} on event {event} is listed more than once"
            );
            seen.push((from, event));
            assert_eq!(transition(from, event), Ok(to));
        }
    }

    #[test]
    fn terminal_states_absorb_every_event() {
        for terminal in [
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Unknown,
            OperationState::Cancelled,
        ] {
            assert!(terminal.is_terminal(), "state {terminal} must be terminal");
            assert!(!terminal.is_active(), "state {terminal} must not be active");
            for event in ALL_EVENTS {
                assert_eq!(
                    transition(terminal, event),
                    Err(InvalidTransition {
                        from: terminal,
                        event
                    }),
                    "terminal state {terminal} must absorb event {event}"
                );
            }
        }
        for active in [
            OperationState::Queued,
            OperationState::Validating,
            OperationState::Running,
            OperationState::WaitingRemote,
            OperationState::Verifying,
        ] {
            assert!(active.is_active(), "state {active} must be active");
            assert!(!active.is_terminal(), "state {active} must not be terminal");
        }
    }

    #[test]
    fn cancellation_is_legal_only_from_cancellable_states() {
        for from in ALL_STATES {
            let result = transition(from, OperationEvent::CancellationRequested);
            if matches!(
                from,
                OperationState::Queued
                    | OperationState::Validating
                    | OperationState::Running
                    | OperationState::WaitingRemote
            ) {
                assert_eq!(
                    result,
                    Ok(OperationState::Cancelled),
                    "state {from} must be cancellable"
                );
            } else {
                assert_eq!(
                    result,
                    Err(InvalidTransition {
                        from,
                        event: OperationEvent::CancellationRequested,
                    }),
                    "state {from} must not accept cancellation"
                );
            }
        }
    }

    #[test]
    fn unknown_is_only_reachable_after_dispatch() {
        for from in ALL_STATES {
            let result = transition(from, OperationEvent::OutcomeUnknown);
            if matches!(
                from,
                OperationState::Running | OperationState::WaitingRemote | OperationState::Verifying
            ) {
                assert_eq!(result, Ok(OperationState::Unknown));
            } else {
                assert_eq!(
                    result,
                    Err(InvalidTransition {
                        from,
                        event: OperationEvent::OutcomeUnknown,
                    }),
                    "state {from} must not accept OutcomeUnknown"
                );
            }
        }
    }

    #[test]
    fn async_execution_walks_queued_to_succeeded() -> Result<(), Box<dyn Error>> {
        let mut operation = queued_operation(OffsetDateTime::now_utc());
        let started_at = operation.updated_at() + time::Duration::SECOND;

        operation.apply(OperationEvent::ValidationStarted, started_at)?;
        assert_eq!(operation.state(), OperationState::Validating);
        assert_eq!(operation.updated_at(), started_at);

        let validated_at = started_at + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationPassed, validated_at)?;
        assert_eq!(operation.state(), OperationState::Running);

        let dispatched_at = validated_at + time::Duration::SECOND;
        operation.apply(OperationEvent::RemoteTaskStarted, dispatched_at)?;
        assert_eq!(operation.state(), OperationState::WaitingRemote);

        let task_finished_at = dispatched_at + time::Duration::SECOND;
        operation.apply(OperationEvent::RemoteTaskCompleted, task_finished_at)?;
        assert_eq!(operation.state(), OperationState::Verifying);

        let verified_at = task_finished_at + time::Duration::SECOND;
        operation.apply(OperationEvent::VerificationPassed, verified_at)?;
        assert_eq!(operation.state(), OperationState::Succeeded);
        assert!(operation.is_terminal());
        assert_eq!(operation.updated_at(), verified_at);
        Ok(())
    }

    #[test]
    fn synchronous_execution_skips_waiting_remote() -> Result<(), Box<dyn Error>> {
        let mut operation = queued_operation(OffsetDateTime::now_utc());
        let started_at = operation.updated_at() + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationStarted, started_at)?;
        let validated_at = started_at + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationPassed, validated_at)?;
        let accepted_at = validated_at + time::Duration::SECOND;
        operation.apply(OperationEvent::ExecutionAccepted, accepted_at)?;
        assert_eq!(operation.state(), OperationState::Verifying);
        let verified_at = accepted_at + time::Duration::SECOND;
        operation.apply(OperationEvent::VerificationPassed, verified_at)?;
        assert_eq!(operation.state(), OperationState::Succeeded);
        Ok(())
    }

    #[test]
    fn lost_response_reaches_the_unknown_terminal_state() -> Result<(), Box<dyn Error>> {
        let mut operation = queued_operation(OffsetDateTime::now_utc());
        let started_at = operation.updated_at() + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationStarted, started_at)?;
        let validated_at = started_at + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationPassed, validated_at)?;
        let dispatched_at = validated_at + time::Duration::SECOND;
        operation.apply(OperationEvent::RemoteTaskStarted, dispatched_at)?;

        let lost_at = dispatched_at + time::Duration::SECOND;
        operation.apply(OperationEvent::OutcomeUnknown, lost_at)?;
        assert_eq!(operation.state(), OperationState::Unknown);
        assert!(operation.is_terminal());
        assert_eq!(operation.updated_at(), lost_at);
        Ok(())
    }

    #[test]
    fn cancellation_walk_from_waiting_remote() -> Result<(), Box<dyn Error>> {
        let mut operation = queued_operation(OffsetDateTime::now_utc());
        let started_at = operation.updated_at() + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationStarted, started_at)?;
        let validated_at = started_at + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationPassed, validated_at)?;
        let dispatched_at = validated_at + time::Duration::SECOND;
        operation.apply(OperationEvent::RemoteTaskStarted, dispatched_at)?;

        let cancelled_at = dispatched_at + time::Duration::SECOND;
        operation.apply(OperationEvent::CancellationRequested, cancelled_at)?;
        assert_eq!(operation.state(), OperationState::Cancelled);
        assert!(operation.is_terminal());
        Ok(())
    }

    #[test]
    fn new_operations_start_queued_with_matching_timestamps() {
        let created_at = OffsetDateTime::now_utc();
        let target = OperationTarget::new(TargetId::generate(), EndpointId::generate());
        let operation = Operation::new(
            OperationId::generate(),
            OperationSource::Center,
            vec![target],
            created_at,
        );

        assert_eq!(operation.state(), OperationState::Queued);
        assert!(!operation.is_terminal());
        assert_eq!(operation.created_at(), created_at);
        assert_eq!(operation.updated_at(), created_at);
        assert_eq!(operation.source(), OperationSource::Center);
        assert_eq!(operation.targets(), &[target]);
    }

    #[test]
    fn operation_target_binds_one_target_to_one_endpoint() {
        let target_id = TargetId::generate();
        let endpoint_id = EndpointId::generate();
        let target = OperationTarget::new(target_id, endpoint_id);

        assert_eq!(target.target_id(), target_id);
        assert_eq!(target.endpoint_id(), endpoint_id);
    }

    #[test]
    fn apply_rejects_invalid_events_without_mutation() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let mut operation = queued_operation(created_at);
        let started_at = created_at + time::Duration::SECOND;
        operation.apply(OperationEvent::ValidationStarted, started_at)?;
        assert_eq!(operation.state(), OperationState::Validating);

        let invalid = started_at + time::Duration::SECOND;
        assert_eq!(
            operation.apply(OperationEvent::ValidationStarted, invalid),
            Err(InvalidTransition {
                from: OperationState::Validating,
                event: OperationEvent::ValidationStarted,
            })
        );
        assert_eq!(operation.state(), OperationState::Validating);
        assert_eq!(operation.updated_at(), started_at);
        Ok(())
    }

    #[test]
    fn rehydration_restores_persisted_state_with_a_valid_timeline() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let updated_at = created_at + time::Duration::SECOND;
        let target = OperationTarget::new(TargetId::generate(), EndpointId::generate());

        let restored = Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![target],
            OperationState::WaitingRemote,
            created_at,
            updated_at,
        )?;
        assert_eq!(restored.state(), OperationState::WaitingRemote);
        assert_eq!(restored.created_at(), created_at);
        assert_eq!(restored.updated_at(), updated_at);

        let inverted = created_at - time::Duration::SECOND;
        assert_eq!(
            Operation::try_from_parts(
                OperationId::generate(),
                OperationSource::Standalone,
                vec![target],
                OperationState::Running,
                created_at,
                inverted,
            ),
            Err(OperationTimelineError)
        );
        Ok(())
    }

    fn queued_operation(created_at: OffsetDateTime) -> Operation {
        Operation::new(
            OperationId::generate(),
            OperationSource::Site,
            vec![OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            created_at,
        )
    }
}
