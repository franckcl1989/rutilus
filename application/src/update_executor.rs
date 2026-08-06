//! The §14.3 firmware-update dispatch boundary.
//!
//! [`UpdateExecutor`] submits one resolved firmware artifact to one
//! endpoint's Redfish `UpdateService` and handles the response. It is the
//! update twin of [`CommandExecutor`](crate::CommandExecutor): the operation
//! scheduler resolves the persisted artifact — existence, `Ready` state, and
//! the file bytes read under `spawn_blocking` (design §7.8, §13.3 step 4) —
//! and hands the resolved payload to this boundary, which never sees the
//! artifact store, credentials, addresses, or `nv-redfish` types (design
//! section 7.2). `rutilus-infra-redfish` implements the contract on its
//! gateway.
//!
//! # The two submission methods (design section 14.3)
//!
//! - `push_uri: Some(...)` — the target `UpdateService` advertises a public
//!   HTTP push URI (`HttpPushUri`); the gateway submits the artifact bytes
//!   to that URI directly.
//! - `push_uri: None` — the gateway submits the artifact as a multipart
//!   upload through the `UpdateService`'s `MultipartHttpPushUri` action.
//!
//! Both methods return the same [`CommandOutcome`] vocabulary as the typed
//! command boundary, so a `202` acceptance flows through the existing
//! [`crate::TaskMonitor`] loop and a provable refusal is recorded `Failed`
//! (design section 13.5) — the operation scheduler's outcome handling is
//! shared between the two dispatch paths.

use rutilus_domain::{ArtifactId, ArtifactName, EndpointId};

use crate::{BoundaryFuture, CommandOutcome, DispatchVerdictClassifier};

/// The resolved artifact payload of one §14.3 firmware update.
///
/// The operation command carries only the database-serializable
/// [`ArtifactId`]; the bytes are resolved from the artifact store at
/// execution time (design section 14.3) and travel across this boundary as
/// this payload, so the gateway never touches the artifact store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpdateArtifactPayload {
    artifact_id: ArtifactId,
    name: ArtifactName,
    bytes: Vec<u8>,
}

impl UpdateArtifactPayload {
    /// Bundles the resolved artifact facts of one update dispatch.
    #[must_use]
    pub fn new(artifact_id: ArtifactId, name: ArtifactName, bytes: Vec<u8>) -> Self {
        Self {
            artifact_id,
            name,
            bytes,
        }
    }

    /// Returns the persisted artifact identity the payload was resolved from.
    #[must_use]
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the artifact's normalized label; a candidate multipart part
    /// filename for the upload.
    #[must_use]
    pub const fn name(&self) -> &ArtifactName {
        &self.name
    }

    /// Returns the artifact file bytes to upload.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Dispatches one §14.3 firmware update through the Redfish `UpdateService`.
///
/// # Why the resolved payload, not the artifact id
///
/// The endpoint row (address, TLS trust, selected credential) is resolved by
/// the implementation from `endpoint_id`, exactly like
/// [`CommandExecutor`](crate::CommandExecutor) — the scheduler never sees
/// credentials, addresses, or `nv-redfish` types (design section 7.2). The
/// artifact bytes are already resolved by the scheduler (design section
/// 14.3: the artifact file is read at execution time under `spawn_blocking`,
/// §7.8), so the boundary receives the full payload instead of a second
/// artifact-store dependency.
///
/// # Outcomes
///
/// - [`CommandOutcome::Accepted`] — the BMC accepted the submission
///   synchronously; the target must now be verified (the post-update
///   `SoftwareInventory` re-read, design section 14.3).
/// - [`CommandOutcome::AsyncTaskAccepted`] — the BMC returned `202` and the
///   update's result is only observable through the accepted Task; the
///   scheduler persists the Task location and the existing
///   [`crate::TaskMonitor`] polls it (design section 13.6).
/// - [`CommandOutcome::Rejected`] — the BMC provably refused the update; it
///   was not executed.
///
/// # Errors
///
/// `Self::Error` must classify every failure through
/// [`DispatchVerdictClassifier`], with the same §13.5 semantics as
/// [`CommandExecutor`](crate::CommandExecutor): failures that prove the
/// write was never executed report [`DispatchVerdict::NotExecuted`]
/// (the scheduler records `Failed`), and failures that cannot prove that
/// report [`DispatchVerdict::OutcomeUnknown`] (the scheduler records
/// `Unknown`).
pub trait UpdateExecutor: Send + Sync {
    /// The update dispatch boundary's controlled failure type; it must
    /// declare its own design section 13.5 verdict.
    type Error: DispatchVerdictClassifier;

    fn execute_update<'a>(
        &'a self,
        endpoint_id: EndpointId,
        artifact: &'a UpdateArtifactPayload,
        push_uri: Option<&'a str>,
    ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>>;
}

impl<Executor> UpdateExecutor for &Executor
where
    Executor: UpdateExecutor + ?Sized,
{
    type Error = Executor::Error;

    fn execute_update<'a>(
        &'a self,
        endpoint_id: EndpointId,
        artifact: &'a UpdateArtifactPayload,
        push_uri: Option<&'a str>,
    ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>> {
        Executor::execute_update(*self, endpoint_id, artifact, push_uri)
    }
}
