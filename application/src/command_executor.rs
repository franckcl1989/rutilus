//! The write-side Redfish boundary contract (design sections 13.3, 13.5, and
//! 13.6).
//!
//! [`CommandExecutor`] dispatches one typed write to one endpoint and handles
//! the response; [`CommandVerifier`] re-reads the target after the write and
//! checks the expected result (design section 13.3 steps 7 and 9-10).
//! `rutilus-infra-redfish` implements both contracts on its gateway; the
//! operation scheduler in `operation_executor` consumes only these
//! boundaries, so the gateway's `nv-redfish` and transport details never leak
//! into the use case (design section 7.2).
//!
//! The asynchronous Task branch (a `202` response, design section 13.6) is
//! handled as [`CommandOutcome::AsyncTaskAccepted`]: the scheduler persists
//! the accepted Task and moves the operation to `WaitingRemote`, where the
//! [`crate::TaskMonitor`] resumes it. An implementation that does not
//! surface the async outcome must keep reporting a `202` as an error whose
//! verdict is [`DispatchVerdict::OutcomeUnknown`] — the BMC accepted the
//! write and its outcome cannot be proven (§13.5), and the operation is
//! never blindly re-dispatched.

use std::error::Error;

use rutilus_domain::{EndpointId, RedfishCommand};
use rutilus_operation_engine::TaskUri;

use crate::BoundaryFuture;

/// The outcome of one dispatched write (design section 13.3 step 7, step 8).
///
/// HTTP `200`/`201`/`202`/`204` alone never equal business success (design
/// section 13.3): `Accepted` means the synchronous response was received AND
/// fully handled by the implementation, and the target still must be verified
/// (steps 9-10); `AsyncTaskAccepted` means the BMC returned `202` and the
/// result is only observable through the accepted Task (design section 13.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandOutcome {
    /// The BMC accepted the write synchronously — a `200`/`201`/`204`
    /// response was received and fully handled — and the target must now be
    /// re-read and verified (design section 13.3 steps 9-10). Maps to
    /// [`rutilus_domain::OperationEvent::ExecutionAccepted`].
    Accepted,
    /// The BMC accepted the write as an asynchronous Task — a `202` response
    /// whose `Location` names the Task (design section 13.3 step 8 async
    /// branch). The write may or may not eventually complete; the product
    /// persists the Task location and polls it (design section 13.6). The
    /// location is an exact identifier validated before it reaches this
    /// boundary, never a vendor URL the product follows (§15.6). Maps to
    /// [`rutilus_domain::OperationEvent::RemoteTaskStarted`].
    AsyncTaskAccepted {
        /// The `Location` of the accepted Task, to be persisted and polled.
        task_location: TaskUri,
    },
    /// The BMC provably refused the write: an error response, a permission
    /// denial, or a capability unavailable at dispatch time. The write was
    /// not executed and the product can account for the outcome. Maps to
    /// [`rutilus_domain::OperationEvent::Failed`].
    Rejected,
}

/// The design section 13.5 verdict of a failed dispatch.
///
/// Every dispatch failure must be classifiable into exactly one of these two
/// verdicts, because they drive two different terminal states: a provable
/// non-execution is recorded `Failed`, while an unprovable outcome is
/// recorded `Unknown` (never retried blindly — design section 13.5 lists
/// Create/Delete/Action/Reset among the operations that must not be
/// re-dispatched after a lost response).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchVerdict {
    /// The failure proves the write was never executed — for example the
    /// connection failed before the request could be sent, or an intermediate
    /// refused the request before it reached the BMC. The product can account
    /// for the outcome, so the operation is recorded `Failed`.
    NotExecuted,
    /// The write may already have been accepted by the BMC: a timeout after
    /// sending, a connection dropped mid-response, a lost response, or a `202`
    /// Task acceptance surfaced as an error by an implementation that does
    /// not expose [`CommandOutcome::AsyncTaskAccepted`]. Only a re-read can
    /// decide (design section 13.5), so the operation moves to the explicit
    /// terminal state [`rutilus_domain::OperationState::Unknown`].
    OutcomeUnknown,
}

/// Classifies a failed dispatch into the design section 13.5 verdicts.
///
/// Implemented by the [`CommandExecutor`] error type so the scheduler never
/// interprets opaque gateway errors: the implementation maps each of its own
/// failure modes into exactly one verdict, and the classification stays
/// reviewable at the boundary instead of being guessed inside the use case.
pub trait DispatchVerdictClassifier: Error + Send + Sync + 'static {
    /// Returns the design section 13.5 verdict of this failure.
    fn verdict(&self) -> DispatchVerdict;
}

/// Dispatches one typed Redfish write and handles the synchronous response.
///
/// # Why the endpoint identity, not the address
///
/// The endpoint row (address, TLS trust, selected credential) is resolved by
/// the implementation from `endpoint_id`; the scheduler never sees
/// credentials, addresses, or `nv-redfish` types (design section 7.2).
///
/// # Outcomes
///
/// - [`CommandOutcome::Accepted`] — the BMC completed the write synchronously
///   (`200`/`201`/`204` fully handled); the target must now be verified.
/// - [`CommandOutcome::AsyncTaskAccepted`] — the BMC returned `202` and the
///   write's result is only observable through the accepted Task; the
///   scheduler persists the Task location and polls it (design section 13.6).
/// - [`CommandOutcome::Rejected`] — the BMC provably refused the write; it
///   was not executed.
///
/// An implementation that does not surface a `202` as
/// [`CommandOutcome::AsyncTaskAccepted`] must keep reporting it as an error
/// whose verdict is [`DispatchVerdict::OutcomeUnknown`] — the BMC accepted
/// the write and the outcome cannot be proven (design section 13.5) — never
/// as `Accepted`.
///
/// # Errors
///
/// `Self::Error` must classify every failure through
/// [`DispatchVerdictClassifier`]: failures that prove the write was never
/// executed report [`DispatchVerdict::NotExecuted`] (the scheduler records
/// `Failed`), and failures that cannot prove that report
/// [`DispatchVerdict::OutcomeUnknown`] (the scheduler records `Unknown`,
/// design section 13.5).
pub trait CommandExecutor: Send + Sync {
    /// The dispatch boundary's controlled failure type; it must declare its
    /// own design section 13.5 verdict.
    type Error: DispatchVerdictClassifier;

    fn execute<'a>(
        &'a self,
        endpoint_id: EndpointId,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>>;
}

impl<Executor> CommandExecutor for &Executor
where
    Executor: CommandExecutor + ?Sized,
{
    type Error = Executor::Error;

    fn execute<'a>(
        &'a self,
        endpoint_id: EndpointId,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>> {
        Executor::execute(*self, endpoint_id, command)
    }
}

/// The verdict of a post-execution target re-read (design section 13.3 steps
/// 9-10).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationVerdict {
    /// The re-read confirmed the expected result; the operation can be
    /// recorded `Succeeded` (design section 13.3 step 11).
    Confirmed,
    /// The re-read proves the expected result is absent; the write did not
    /// achieve its result and the operation is recorded `Failed`.
    Mismatched,
}

/// Re-reads the target after a write and checks the expected result.
///
/// The expected result is derived from the command itself, so the boundary
/// carries no separate expectation parameter:
///
/// - [`EventCommand::CreateSubscription`](rutilus_domain::EventCommand::CreateSubscription) —
///   the re-read `EventSubscriptions` collection must contain the requested
///   `destination`; an absent destination is `Mismatched`.
/// - [`EventCommand::DeleteSubscription`](rutilus_domain::EventCommand::DeleteSubscription) —
///   the subscription id must be absent from the re-read collection.
/// - Reset, boot-source-override, and Secure Boot commands — "accepted"
///   verification: the target resource must re-read without error and the
///   implementation returns `Confirmed`. The physical effect (power state,
///   boot override, key state) takes effect asynchronously on most BMCs and
///   is deliberately NOT asserted: claiming the effect from a successful read
///   would fabricate a result (design section 13.7 forbids pretending partial
///   success is whole success). The honest semantics are documented here and
///   the same re-read pattern is what design section 13.6 recovery uses.
///
/// A failed re-read (an `Err`) proves nothing about the write: the write has
/// already landed (only `Accepted` operations reach the verifier), so the
/// scheduler records `Unknown` (design section 13.5) instead of a failure.
///
/// # Errors
///
/// Returns `Self::Error` when the target cannot be re-read at all.
pub trait CommandVerifier: Send + Sync {
    /// The verification boundary's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    fn verify<'a>(
        &'a self,
        endpoint_id: EndpointId,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<VerificationVerdict, Self::Error>>;
}

impl<Verifier> CommandVerifier for &Verifier
where
    Verifier: CommandVerifier + ?Sized,
{
    type Error = Verifier::Error;

    fn verify<'a>(
        &'a self,
        endpoint_id: EndpointId,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<VerificationVerdict, Self::Error>> {
        Verifier::verify(*self, endpoint_id, command)
    }
}
