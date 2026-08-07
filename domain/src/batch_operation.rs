//! The persisted batch parent of one §13.7 batch submission.
//!
//! Design section 13.7 turns a multi-endpoint write request into one batch:
//! a single `batch_operations` parent record and one ordinary single-target
//! child [`Operation`] per submitted endpoint. The child operations are
//! completely ordinary — they carry one target each, run through the §13.2
//! state machine, and are executed by the same scheduler as any other
//! operation — so this module owns only the parent record and the two pure
//! reporting functions that derive a batch-level picture from the children's
//! individual states.
//!
//! The parent deliberately carries no target list and no state: the targets
//! are a fact of the child operations, and the batch state is derived from
//! the children by [`derive_batch_state`] (a partial failure never becomes an
//! overall success). There is no state machine here and no mutation path —
//! a `BatchOperation` is a fixed fact of one submission.
//!
//! This version has no batch-level cancellation: cancelling part of a batch
//! goes through the existing per-child path — each child is an ordinary
//! `Operation`, so `OperationEvent::CancellationRequested` applies to it
//! exactly as to any single submission, and the batch state then reflects the
//! cancelled children through the derivation rules above.

use time::OffsetDateTime;

use crate::{BatchOperationId, OperationSource, OperationState, RedfishCommand};

/// One persisted batch parent (§13.7).
///
/// The record names the submission facts only: the origin, the typed
/// [`RedfishCommand`] the batch dispatches (§13.3 step 7), and the acceptance
/// time. The child operations — one per submitted endpoint, each carrying its
/// own `OperationId` lifecycle — are the working records; the batch state is
/// always derived from them, never stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOperation {
    id: BatchOperationId,
    source: OperationSource,
    command: RedfishCommand,
    created_at: OffsetDateTime,
}

impl BatchOperation {
    /// Creates a fresh batch parent at its acceptance time.
    ///
    /// The child operations are constructed alongside the parent by the
    /// engine's batch creation path, so this constructor only records the
    /// submission facts; every batch has at least one child (the engine
    /// rejects empty target lists).
    #[must_use]
    pub const fn new(
        id: BatchOperationId,
        source: OperationSource,
        command: RedfishCommand,
        created_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            source,
            command,
            created_at,
        }
    }

    /// Rehydrates a persisted batch parent record.
    ///
    /// This is the persistence-loading path, mirroring the rehydration
    /// discipline of [`Operation::try_from_parts`](crate::Operation): the
    /// command arrives already deserialized through the domain type by the
    /// repository, and the record carries no state or timeline of its own, so
    /// there is nothing further to validate here.
    #[must_use]
    pub const fn try_from_parts(
        id: BatchOperationId,
        source: OperationSource,
        command: RedfishCommand,
        created_at: OffsetDateTime,
    ) -> Self {
        Self::new(id, source, command, created_at)
    }

    #[must_use]
    pub const fn id(&self) -> BatchOperationId {
        self.id
    }

    #[must_use]
    pub const fn source(&self) -> OperationSource {
        self.source
    }

    /// Returns the typed write command every child operation dispatches
    /// (§13.1, §13.3 step 7).
    ///
    /// Each call clones the command because it is a value type carrying
    /// payload data; the caller owns the clone.
    #[must_use]
    pub fn command(&self) -> RedfishCommand {
        self.command.clone()
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }
}

/// The derived lifecycle phase of one batch (§13.7).
///
/// Unlike [`OperationState`], this is not a persisted state machine: it is a
/// pure projection of the children's states, computed on demand by
/// [`derive_batch_state`] and never stored. The vocabulary is deliberately
/// smaller than the nine operation states — a batch is either still queued,
/// still running, or finished in one of four verdicts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BatchOperationState {
    /// Every child operation is still `Queued`; nothing has started.
    Queued,
    /// At least one child is still in flight (any non-terminal state);
    /// children may already have finished.
    Running,
    /// Every child operation succeeded; the batch achieved its whole intent.
    Succeeded,
    /// At least one child failed provably; the batch did not achieve its
    /// whole intent (a partial failure never becomes an overall success).
    Failed,
    /// At least one child ended `Unknown` and no child failed; the batch's
    /// final outcome cannot be proven.
    Unknown,
    /// Every child operation was cancelled; the batch was stopped before
    /// completing.
    Cancelled,
}

impl BatchOperationState {
    /// Returns the stable product code used by protocols and reporting.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
            Self::Cancelled => "cancelled",
        }
    }
}

impl std::fmt::Display for BatchOperationState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Derives the batch-level state from the children's individual states
/// (§13.7).
///
/// # Rules
///
/// - every child `Queued` → [`BatchOperationState::Queued`];
/// - otherwise, any child in a non-terminal state → `Running`;
/// - once every child is terminal: all `Succeeded` → `Succeeded`, all
///   `Cancelled` → `Cancelled`, any `Failed` → `Failed` (a failure outranks
///   an unprovable outcome), and every remaining mix (a partial success with
///   cancellations or at least one `Unknown` child) → `Unknown` — only a
///   batch whose children all succeeded is ever derived `Succeeded`, so a
///   partial failure never masquerades as an overall success.
///
/// An empty child list derives `Queued` vacuously; the engine never creates
/// a childless batch (empty target lists are rejected), so this is a total
/// function for the batch store, not a live call path.
#[must_use]
pub fn derive_batch_state(children: &[OperationState]) -> BatchOperationState {
    use BatchOperationState as Batch;
    use OperationState as State;
    if children.iter().all(|state| *state == State::Queued) {
        return Batch::Queued;
    }
    if children.iter().any(|state| !state.is_terminal()) {
        return Batch::Running;
    }
    if children.iter().all(|state| *state == State::Succeeded) {
        return Batch::Succeeded;
    }
    if children.iter().all(|state| *state == State::Cancelled) {
        return Batch::Cancelled;
    }
    if children.contains(&State::Failed) {
        return Batch::Failed;
    }
    Batch::Unknown
}

/// The outcome buckets of one batch's completed children (§13.7).
///
/// `total` counts every child; the named buckets count only terminal
/// outcomes. Children still in flight are deliberately not counted in any
/// bucket — a partial sum below `total` is the truthful picture of a batch
/// that has not finished yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BatchOutcomeCounts {
    succeeded: usize,
    failed: usize,
    unknown: usize,
    /// Counted from the batch's unsupported-command failures; always zero in
    /// this slice because the failure classification that separates
    /// "unsupported" from "failed" (`failure_kind`) lands with the batch
    /// reporting slice. Until then, an unsupported command fails its child
    /// operation like any other failure and is counted in [`Self::failed`].
    unsupported: usize,
    cancelled: usize,
    total: usize,
}

impl BatchOutcomeCounts {
    #[must_use]
    pub const fn succeeded(self) -> usize {
        self.succeeded
    }

    #[must_use]
    pub const fn failed(self) -> usize {
        self.failed
    }

    #[must_use]
    pub const fn unknown(self) -> usize {
        self.unknown
    }

    #[must_use]
    pub const fn unsupported(self) -> usize {
        self.unsupported
    }

    #[must_use]
    pub const fn cancelled(self) -> usize {
        self.cancelled
    }

    #[must_use]
    pub const fn total(self) -> usize {
        self.total
    }
}

/// Summarizes the children's terminal outcomes into the batch buckets
/// (§13.7).
///
/// Each terminal child state maps to exactly one bucket (`Succeeded`,
/// `Failed`, `Unknown`, or `Cancelled`); `unsupported` stays zero until the
/// failure classification that separates it from `Failed` lands, and
/// `total` counts every child, including the ones still in flight.
#[must_use]
pub fn summarize(children: &[OperationState]) -> BatchOutcomeCounts {
    let mut counts = BatchOutcomeCounts {
        succeeded: 0,
        failed: 0,
        unknown: 0,
        unsupported: 0,
        cancelled: 0,
        total: children.len(),
    };
    for state in children {
        match state {
            OperationState::Succeeded => counts.succeeded += 1,
            OperationState::Failed => counts.failed += 1,
            OperationState::Unknown => counts.unknown += 1,
            OperationState::Cancelled => counts.cancelled += 1,
            OperationState::Queued
            | OperationState::Validating
            | OperationState::Running
            | OperationState::WaitingRemote
            | OperationState::Verifying => {}
        }
    }
    counts
}

#[cfg(test)]
mod tests {
    use crate::{
        BatchOperationId, OperationSource, OperationState, RedfishCommand, ResetType, SystemCommand,
    };

    use super::*;

    /// Every §13.2 state, so the derivation tests cannot silently miss a
    /// variant.
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

    #[test]
    fn new_and_rehydration_carry_the_submission_facts() {
        let id = BatchOperationId::generate();
        let created_at = time::OffsetDateTime::UNIX_EPOCH;
        let command = one_command();

        let fresh = BatchOperation::new(id, OperationSource::Center, command.clone(), created_at);
        assert_eq!(fresh.id(), id);
        assert_eq!(fresh.source(), OperationSource::Center);
        assert_eq!(fresh.command(), command);
        assert_eq!(fresh.created_at(), created_at);

        // Rehydration is the persistence-loading path and restores the same
        // record; the record has no state or timeline to validate, so both
        // constructors are interchangeable by value.
        let restored =
            BatchOperation::try_from_parts(id, OperationSource::Center, command, created_at);
        assert_eq!(restored, fresh);
    }

    #[test]
    fn derive_batch_state_requires_every_child_queued_for_queued() {
        assert_eq!(
            derive_batch_state(&[OperationState::Queued, OperationState::Queued]),
            BatchOperationState::Queued
        );
        // One child moved on: the batch is running, not queued.
        assert_eq!(
            derive_batch_state(&[OperationState::Queued, OperationState::Validating]),
            BatchOperationState::Running
        );
        assert_eq!(
            derive_batch_state(&[OperationState::Queued, OperationState::Succeeded]),
            BatchOperationState::Running
        );
        // An empty batch is queued vacuously; the engine never creates one.
        assert_eq!(derive_batch_state(&[]), BatchOperationState::Queued);
    }

    #[test]
    fn derive_batch_state_runs_while_any_child_is_in_flight() {
        for state in ALL_STATES {
            let children = [OperationState::Succeeded, state];
            let expected = match state {
                OperationState::Succeeded => BatchOperationState::Succeeded,
                OperationState::Failed => BatchOperationState::Failed,
                // A cancelled or unknown child beside a success derives the
                // unprovable mix, never an overall success.
                OperationState::Cancelled | OperationState::Unknown => BatchOperationState::Unknown,
                // Every in-flight state keeps the batch running.
                OperationState::Queued
                | OperationState::Validating
                | OperationState::Running
                | OperationState::WaitingRemote
                | OperationState::Verifying => BatchOperationState::Running,
            };
            assert_eq!(
                derive_batch_state(&children),
                expected,
                "a batch with one {state} child must derive {expected}"
            );
        }
    }

    #[test]
    fn derive_batch_state_only_succeeds_when_every_child_succeeded() {
        assert_eq!(
            derive_batch_state(&[OperationState::Succeeded, OperationState::Succeeded]),
            BatchOperationState::Succeeded
        );
        // A partial failure never becomes an overall success.
        assert_eq!(
            derive_batch_state(&[OperationState::Succeeded, OperationState::Failed]),
            BatchOperationState::Failed
        );
        // A cancellation outranks a success for the overall verdict: the
        // batch did not achieve its whole intent, and the mix is reported
        // Unknown rather than misread as success or cancellation.
        assert_eq!(
            derive_batch_state(&[OperationState::Succeeded, OperationState::Cancelled]),
            BatchOperationState::Unknown
        );
    }

    #[test]
    fn derive_batch_state_failure_outranks_unknown() {
        assert_eq!(
            derive_batch_state(&[
                OperationState::Failed,
                OperationState::Unknown,
                OperationState::Succeeded,
            ]),
            BatchOperationState::Failed
        );
        assert_eq!(
            derive_batch_state(&[
                OperationState::Unknown,
                OperationState::Succeeded,
                OperationState::Succeeded,
            ]),
            BatchOperationState::Unknown
        );
    }

    #[test]
    fn derive_batch_state_cancellation_requires_every_child_cancelled() {
        assert_eq!(
            derive_batch_state(&[OperationState::Cancelled, OperationState::Cancelled]),
            BatchOperationState::Cancelled
        );
        assert_eq!(
            derive_batch_state(&[OperationState::Cancelled, OperationState::Failed]),
            BatchOperationState::Failed
        );
        assert_eq!(
            derive_batch_state(&[OperationState::Cancelled, OperationState::Unknown]),
            BatchOperationState::Unknown
        );
    }

    #[test]
    fn batch_state_codes_are_stable_and_unique() {
        let mut seen = Vec::new();
        for state in [
            BatchOperationState::Queued,
            BatchOperationState::Running,
            BatchOperationState::Succeeded,
            BatchOperationState::Failed,
            BatchOperationState::Unknown,
            BatchOperationState::Cancelled,
        ] {
            let code = state.as_str();
            assert!(!code.is_empty(), "batch state codes must not be empty");
            assert!(
                !seen.contains(&code),
                "product code {code} is used by more than one batch state"
            );
            seen.push(code);
            assert_eq!(state.to_string(), code);
        }
    }

    #[test]
    fn summarize_buckets_terminal_outcomes_and_counts_every_child() {
        let counts = summarize(&[
            OperationState::Succeeded,
            OperationState::Failed,
            OperationState::Unknown,
            OperationState::Cancelled,
            OperationState::Queued,
            OperationState::Running,
            OperationState::Succeeded,
        ]);
        assert_eq!(counts.succeeded(), 2);
        assert_eq!(counts.failed(), 1);
        assert_eq!(counts.unknown(), 1);
        assert_eq!(counts.cancelled(), 1);
        // In-flight children are counted in total but in no outcome bucket;
        // unsupported stays zero until the failure classification lands.
        assert_eq!(counts.unsupported(), 0);
        assert_eq!(counts.total(), 7);
    }

    #[test]
    fn summarize_of_an_empty_batch_is_all_zeros() {
        let counts = summarize(&[]);
        assert_eq!(counts.succeeded(), 0);
        assert_eq!(counts.failed(), 0);
        assert_eq!(counts.unknown(), 0);
        assert_eq!(counts.unsupported(), 0);
        assert_eq!(counts.cancelled(), 0);
        assert_eq!(counts.total(), 0);
    }

    /// One representative command value; the command vocabulary is the
    /// domain's own, so a single value covers the batch record's tests.
    fn one_command() -> RedfishCommand {
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
    }
}
