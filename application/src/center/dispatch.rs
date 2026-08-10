//! The center's operation dispatch and reply tracking (design §15.6, §16.1,
//! 0.7.0 S5).
//!
//! The center never executes operations (§15.6 — only the site's explicit
//! `Accepted` transfers execution responsibility). It constructs the
//! §15.6 offer — `RedfishCommand` + `Target` + `OperationId` +
//! `ExpiresAt` + `ActorContext` — and nothing else (no URL, no HTTP
//! method, no headers, no body, no script) — records the operation in its
//! tracking view, and enqueues the offer into the site's durable outbox.
//! The site's replies (`Accepted`, `Rejected`, `Progress`, `Completed`)
//! advance the recorded state and land in the center's inbox as the
//! durable reply receipt.
//!
//! # The permission check (§16.1, D3)
//!
//! Only the built-in roles may dispatch, and a center role can be scoped to
//! one site (D3: the `role_assignments.site_id` column): the `Administrator`
//! is global, the `Operator` dispatches to every site or to the one site of
//! a scoped assignment, and the `Viewer` never dispatches
//! ([`allows_dispatch`]).
//!
//! # The offer TTL
//!
//! Every offer carries the expiry
//! [`CENTER_OFFER_TTL`] (15 minutes) — the site refuses an offer past its
//! expiry with `OperationRejectedReason::Expired` (§15.6 recheck).

use std::error::Error;

use rutilus_center_protocol::{
    Envelope, EnvelopeMessage, OperationAccepted, OperationCompleted, OperationOffer,
    OperationProgress, OperationRejected,
};
use rutilus_domain::{
    EndpointId, InboxEntry, InboxEntryId, InboxEvent, InstanceId, Operation, OperationEvent,
    OperationId, OperationSource, OperationTarget, PrincipalId, RedfishCommand, ResourceODataId,
    Role, RoleAssignment, TargetId,
};
use rutilus_operation_engine::OperationStore;
use thiserror::Error;
use time::{Duration, OffsetDateTime};

use crate::{
    BoundaryFuture, CenterInbox, CenterOutbox,
    center::projection::{CenterContentConsumer, CenterProjectionRepository},
    center::session::ResolvedSite,
};

/// How long a dispatched operation offer stays actionable at the site:
/// 15 minutes (§15.6 — the site refuses an expired offer; the short bound
/// matches the D2 binding-code TTL and keeps a stale dispatch from
/// executing late).
pub const CENTER_OFFER_TTL: Duration = Duration::seconds(15 * 60);

/// One center-initiated operation dispatch (§15.6).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterOperationRequest {
    site_id: InstanceId,
    endpoint_id: EndpointId,
    target_odata_id: ResourceODataId,
    command: RedfishCommand,
    actor: PrincipalId,
}

impl CenterOperationRequest {
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        site_id: InstanceId,
        endpoint_id: EndpointId,
        target_odata_id: ResourceODataId,
        command: RedfishCommand,
        actor: PrincipalId,
    ) -> Self {
        Self {
            site_id,
            endpoint_id,
            target_odata_id,
            command,
            actor,
        }
    }

    /// The site the offer is addressed to.
    #[must_use]
    pub const fn site_id(&self) -> InstanceId {
        self.site_id
    }

    /// The endpoint the operation targets.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// The Redfish target of the operation.
    #[must_use]
    pub fn target_odata_id(&self) -> &ResourceODataId {
        &self.target_odata_id
    }

    /// The typed write command of the operation (§15.6 — the wire carries
    /// only the typed command, never URL, method, headers, or body).
    #[must_use]
    pub fn command(&self) -> &RedfishCommand {
        &self.command
    }

    /// The acting principal (the `ActorContext` of the offer).
    #[must_use]
    pub const fn actor(&self) -> PrincipalId {
        self.actor
    }
}

/// The record of one dispatched operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DispatchedOperation {
    operation_id: OperationId,
    expires_at: OffsetDateTime,
}

impl DispatchedOperation {
    #[must_use]
    pub const fn new(operation_id: OperationId, expires_at: OffsetDateTime) -> Self {
        Self {
            operation_id,
            expires_at,
        }
    }

    /// The stable operation id shared by the offer and the tracking record.
    #[must_use]
    pub const fn operation_id(&self) -> OperationId {
        self.operation_id
    }

    /// When the offer stops being actionable at the site.
    #[must_use]
    pub const fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }
}

/// The role-assignment boundary of the dispatch permission check (§16.1).
pub trait CenterRoleRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Reads one principal's role assignment.
    fn find_role_assignment(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>>;
}

impl<Roles> CenterRoleRepository for &Roles
where
    Roles: CenterRoleRepository + ?Sized,
{
    type Error = Roles::Error;

    fn find_role_assignment(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>> {
        Roles::find_role_assignment(*self, principal_id)
    }
}

/// The §16.1 dispatch judgment: may one role assignment dispatch an
/// operation to the target site?
///
/// The `Administrator` is the global role. The `Operator` dispatches to
/// every site when the assignment is unscoped (D3: `site_id` is `None`),
/// and only to the assigned site when it is scoped. The `Viewer` is
/// read-only and never dispatches.
#[must_use]
pub fn allows_dispatch(
    role: Role,
    assignment_site: Option<InstanceId>,
    target_site: InstanceId,
) -> bool {
    match role {
        Role::Administrator => true,
        Role::Operator => assignment_site.is_none() || assignment_site == Some(target_site),
        Role::Viewer => false,
    }
}

/// The center-side dispatch use case (design §15.6, S5).
///
/// `Store` is the projection and operation boundary on one store, `Outbox`
/// the durable §15.4 queue, and `Roles` the role boundary. The dispatch
/// records the operation before the offer is enqueued, so by the time the
/// site answers, the tracking record exists; an enqueue failure leaves the
/// recorded operation `Queued` — the caller sees the failure and a retry
/// starts a fresh operation identity.
pub struct CenterOperationDispatch<Store, Outbox, Roles> {
    store: Store,
    outbox: Outbox,
    roles: Roles,
}

impl<Store, Outbox, Roles> CenterOperationDispatch<Store, Outbox, Roles> {
    #[must_use]
    pub const fn new(store: Store, outbox: Outbox, roles: Roles) -> Self {
        Self {
            store,
            outbox,
            roles,
        }
    }
}

/// A controlled failure of one dispatch.
#[derive(Debug, Error)]
pub enum CenterDispatchError<ProjectionError, OperationError, OutboxError, RoleError>
where
    ProjectionError: Error + 'static,
    OperationError: Error + 'static,
    OutboxError: Error + 'static,
    RoleError: Error + 'static,
{
    /// The acting principal has no role assignment, or its role cannot
    /// dispatch to the target site (§16.1).
    #[error("the acting principal is not authorized to dispatch to the target site")]
    NotAuthorized,
    /// The endpoint is not in the center's projection.
    #[error("endpoint {endpoint_id} is not projected")]
    UnknownEndpoint { endpoint_id: EndpointId },
    /// The endpoint belongs to a different site; the offer would be dropped
    /// by the addressed site (§15.6).
    #[error("endpoint {endpoint_id} does not belong to site {site_id}")]
    EndpointNotInSite {
        endpoint_id: EndpointId,
        site_id: InstanceId,
    },
    /// The target is not part of the endpoint's projected resources.
    #[error("target {target} is not in the projection of endpoint {endpoint_id}")]
    UnknownTarget {
        endpoint_id: EndpointId,
        target: String,
    },
    /// The typed command could not be serialized into its wire payload.
    #[error("the command could not be serialized: {0}")]
    CommandSerialization(#[source] serde_json::Error),
    /// The projection repository failed; carries its own error.
    #[error("the projection repository failed: {0}")]
    Projection(#[source] ProjectionError),
    /// The operation store failed; carries its own error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationError),
    /// The durable outbox failed; carries its own error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
    /// The role repository failed; carries its own error.
    #[error("the role repository failed: {0}")]
    Role(#[source] RoleError),
}

/// The concrete failure type of one dispatch.
type DispatchErrorOf<Store, Outbox, Roles> = CenterDispatchError<
    <Store as CenterProjectionRepository>::Error,
    <Store as OperationStore>::Error,
    <Outbox as CenterOutbox>::Error,
    <Roles as CenterRoleRepository>::Error,
>;

impl<Store, Outbox, Roles> CenterOperationDispatch<Store, Outbox, Roles>
where
    Store: CenterProjectionRepository + OperationStore,
    Outbox: CenterOutbox,
    Roles: CenterRoleRepository,
{
    /// Dispatches one §15.6 operation offer to a bound site.
    ///
    /// The permission check runs first (the actor's role against the target
    /// site, §16.1/D3), then the routing checks (the endpoint must be the
    /// target site's projection, and the target must be part of it), then
    /// the tracking record and the offer. The offer wire shape carries
    /// exactly the §15.6 set — the typed command, the target, the
    /// operation id, the expiry, and the actor context — and nothing else.
    ///
    /// # Errors
    ///
    /// Returns [`CenterDispatchError::NotAuthorized`] when the actor's role
    /// cannot dispatch to the site, the routing variants for an endpoint or
    /// target outside the site's projection, and the boundary variants for
    /// persistence failures.
    pub async fn dispatch(
        &self,
        request: &CenterOperationRequest,
        now: OffsetDateTime,
    ) -> Result<DispatchedOperation, DispatchErrorOf<Store, Outbox, Roles>> {
        // §16.1: the actor's role, scoped by the D3 site association.
        let assignment = self
            .roles
            .find_role_assignment(request.actor)
            .await
            .map_err(CenterDispatchError::Role)?;
        let Some(assignment) = assignment else {
            return Err(CenterDispatchError::NotAuthorized);
        };
        if !allows_dispatch(assignment.role(), assignment.site_id(), request.site_id) {
            return Err(CenterDispatchError::NotAuthorized);
        }
        // §15.6 routing: the offer is addressed to one site, so its
        // endpoint must be that site's projection.
        let Some(endpoint) = self
            .store
            .find_endpoint_projection(request.endpoint_id)
            .await
            .map_err(CenterDispatchError::Projection)?
        else {
            return Err(CenterDispatchError::UnknownEndpoint {
                endpoint_id: request.endpoint_id,
            });
        };
        if endpoint.site_id() != Some(request.site_id) {
            return Err(CenterDispatchError::EndpointNotInSite {
                endpoint_id: request.endpoint_id,
                site_id: request.site_id,
            });
        }
        let target = request.target_odata_id.as_str();
        if !self
            .store
            .has_resource(request.endpoint_id, target)
            .await
            .map_err(CenterDispatchError::Projection)?
        {
            return Err(CenterDispatchError::UnknownTarget {
                endpoint_id: request.endpoint_id,
                target: target.to_owned(),
            });
        }
        // The tracking record precedes the offer, so the site's reply
        // always finds its record.
        let operation_id = OperationId::generate();
        let expires_at = now + CENTER_OFFER_TTL;
        let operation = Operation::new(
            operation_id,
            OperationSource::Center,
            vec![OperationTarget::new(
                TargetId::generate(),
                request.endpoint_id,
            )],
            request.command.clone(),
            now,
        );
        self.store
            .create_operation(&operation)
            .await
            .map_err(CenterDispatchError::Operation)?;
        // The §15.6 offer: the typed command as the §9.4 payload, plus the
        // target, the stable ids, the expiry, and the actor context — never
        // URL, method, headers, body, or script.
        let command_json = serde_json::to_vec(&request.command)
            .map_err(CenterDispatchError::CommandSerialization)?;
        let offer = OperationOffer {
            operation_id: operation_id.to_string(),
            endpoint_id: request.endpoint_id.to_string(),
            site_id: request.site_id.to_string(),
            command_json,
            target: target.to_owned(),
            expires_at_unix: expires_at.unix_timestamp(),
            actor_context: request.actor.to_string(),
        };
        self.outbox
            .enqueue(
                request.site_id,
                &EnvelopeMessage::OperationOffer(offer),
                now,
            )
            .await
            .map_err(CenterDispatchError::Outbox)?;
        Ok(DispatchedOperation::new(operation_id, expires_at))
    }
}

/// The tracking target of one site reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplyTarget {
    /// The site accepted the offer and is executing the operation.
    Running,
    /// The site refused the offer or the operation failed.
    Failed,
    /// The operation completed successfully.
    Succeeded,
}

impl ReplyTarget {
    /// The domain events that lead from the tracking record's current state
    /// to the target; events that do not apply are absorbed, so a duplicate
    /// reply is an idempotent no-op.
    fn events(self) -> &'static [OperationEvent] {
        match self {
            Self::Running => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
            ],
            Self::Failed => &[OperationEvent::Failed],
            Self::Succeeded => &[
                OperationEvent::ValidationStarted,
                OperationEvent::ValidationPassed,
                OperationEvent::ExecutionAccepted,
                OperationEvent::VerificationPassed,
            ],
        }
    }
}

/// The reply-receipt boundary of the processor: every §15.6 reply frame.
pub trait CenterReplyConsumer: Send + Sync {
    /// The consumer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Handles one reply frame from a site.
    fn on_reply<'a>(
        &'a self,
        site: InstanceId,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

/// The center-side reply tracking: advances the recorded operation state
/// and logs the reply receipt (design §15.6, S5).
///
/// Every reply is processed on arrival — the recorded operation's state
/// machine is the idempotency point, so a re-delivered reply is absorbed —
/// and the reply envelope is logged into the site's inbox row under the
/// operation id as the durable receipt.
pub struct CenterOperationTracking<Store, Inbox> {
    store: Store,
    inbox: Inbox,
}

impl<Store, Inbox> CenterOperationTracking<Store, Inbox> {
    #[must_use]
    pub const fn new(store: Store, inbox: Inbox) -> Self {
        Self { store, inbox }
    }
}

/// A controlled failure of one reply-tracking step.
#[derive(Debug, Error)]
pub enum CenterOperationTrackingError<OperationError, InboxError>
where
    OperationError: Error + 'static,
    InboxError: Error + 'static,
{
    /// The operation store failed; carries its own error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationError),
    /// The durable inbox failed; carries its own error.
    #[error("the center inbox failed: {0}")]
    Inbox(#[source] InboxError),
    /// The reply envelope could not be serialized into its payload record.
    #[error("the reply could not be serialized into its payload record: {0}")]
    Payload(#[source] serde_json::Error),
}

impl<Store, Inbox> CenterReplyConsumer for CenterOperationTracking<Store, Inbox>
where
    Store: OperationStore,
    Inbox: CenterInbox,
{
    type Error = CenterOperationTrackingError<Store::Error, Inbox::Error>;

    fn on_reply<'a>(
        &'a self,
        site: InstanceId,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            let Some(operation_id) = reply_operation_id(envelope.message.as_ref()) else {
                // A reply with an unparseable operation id cannot be
                // recorded; it is logged and absorbed so a corrupt frame
                // never ends the connection.
                eprintln!("site {site}: dropping a reply with an unparseable operation id");
                return Ok(());
            };
            let Some(target) = reply_target(envelope.message.as_ref()) else {
                eprintln!("site {site}: dropping a reply with an unknown operation state");
                return Ok(());
            };
            let Some(mut operation) = self
                .store
                .find_operation(operation_id)
                .await
                .map_err(CenterOperationTrackingError::Operation)?
            else {
                // A reply for an operation the center has no record of (a
                // restore that predates the offer, a manual DB change) is
                // absorbed: the connection must survive it.
                eprintln!(
                    "site {site}: absorbing a reply for the unknown operation {operation_id}"
                );
                return Ok(());
            };
            // The state machine is the idempotency point: the events that
            // do not apply (the record is already at the target or
            // terminal) are absorbed, and only a changed state is written.
            let loaded_state = operation.state();
            for event in target.events() {
                let _ = operation.apply(*event, now);
            }
            if operation.state() != loaded_state {
                self.store
                    .apply_transition(operation_id, operation.state(), now)
                    .await
                    .map_err(CenterOperationTrackingError::Operation)?;
            }
            // The durable reply receipt: one inbox row per operation id
            // mirroring the reply phase, so the audit trail shows exactly
            // what the site said.
            self.log_reply(site, envelope, operation_id, envelope.message.as_ref(), now)
                .await?;
            Ok(())
        })
    }
}

impl<Store, Inbox> CenterOperationTracking<Store, Inbox>
where
    Store: OperationStore,
    Inbox: CenterInbox,
{
    /// Persists the reply envelope as the operation's inbox receipt and
    /// advances the receipt's phase to mirror the reply.
    async fn log_reply(
        &self,
        site: InstanceId,
        envelope: &Envelope,
        operation_id: OperationId,
        message: Option<&EnvelopeMessage>,
        now: OffsetDateTime,
    ) -> Result<(), CenterOperationTrackingError<Store::Error, Inbox::Error>> {
        let payload_json =
            serde_json::to_string(envelope).map_err(CenterOperationTrackingError::Payload)?;
        let entry = InboxEntry::new(
            InboxEntryId::generate(),
            operation_id,
            site,
            payload_json,
            now,
            now,
        );
        self.inbox
            .insert(&entry)
            .await
            .map_err(CenterOperationTrackingError::Inbox)?;
        // The receipt's phase mirrors the reply lifecycle; the insert is
        // the durable record and the phase is best-effort — an advance the
        // stored phase refuses (a re-delivered older reply) is logged and
        // heals on the next reply.
        for event in reply_events(message) {
            match self.inbox.advance(operation_id, *event).await {
                Ok(()) => {}
                Err(source) => {
                    eprintln!(
                        "site {site}: the receipt of operation {operation_id} did not advance to \
                         {event}: {source}"
                    );
                    break;
                }
            }
        }
        Ok(())
    }
}

/// The operation id of one reply message.
fn reply_operation_id(message: Option<&EnvelopeMessage>) -> Option<OperationId> {
    let Some(
        EnvelopeMessage::OperationAccepted(OperationAccepted { operation_id, .. })
        | EnvelopeMessage::OperationRejected(OperationRejected { operation_id, .. })
        | EnvelopeMessage::OperationProgress(OperationProgress { operation_id, .. })
        | EnvelopeMessage::OperationCompleted(OperationCompleted { operation_id, .. }),
    ) = message
    else {
        return None;
    };
    operation_id.parse().ok()
}

/// The tracking target of one reply message.
fn reply_target(message: Option<&EnvelopeMessage>) -> Option<ReplyTarget> {
    match message {
        Some(EnvelopeMessage::OperationAccepted(_) | EnvelopeMessage::OperationProgress(_)) => {
            Some(ReplyTarget::Running)
        }
        Some(EnvelopeMessage::OperationRejected(_)) => Some(ReplyTarget::Failed),
        Some(EnvelopeMessage::OperationCompleted(completed)) => {
            if completed.succeeded {
                Some(ReplyTarget::Succeeded)
            } else {
                Some(ReplyTarget::Failed)
            }
        }
        _ => None,
    }
}

/// The receipt-phase advances of one reply (§17.5 vocabulary: a receipt is
/// `received` on the first reply, `accepted`/`rejected` on the decision,
/// `completed` on the terminal report).
fn reply_events(message: Option<&EnvelopeMessage>) -> &'static [InboxEvent] {
    match message {
        Some(EnvelopeMessage::OperationAccepted(_) | EnvelopeMessage::OperationProgress(_)) => {
            &[InboxEvent::Accepted]
        }
        Some(EnvelopeMessage::OperationRejected(_)) => &[InboxEvent::Rejected],
        Some(EnvelopeMessage::OperationCompleted(_)) => {
            &[InboxEvent::Accepted, InboxEvent::Completed]
        }
        _ => &[],
    }
}

/// The frame processor: the engine's [`crate::center::session::CenterFrameConsumer`]
/// composing the §15.5 projection and the §15.6 reply tracking.
///
/// `Projection` is the content boundary ([`CenterContentConsumer`], the
/// concrete [`CenterProjection`]) and `Tracking` the reply boundary
/// ([`CenterReplyConsumer`], the concrete [`CenterOperationTracking`]).
pub struct CenterFrameProcessor<Projection, Tracking> {
    projection: Projection,
    tracking: Tracking,
}

impl<Projection, Tracking> CenterFrameProcessor<Projection, Tracking> {
    #[must_use]
    pub const fn new(projection: Projection, tracking: Tracking) -> Self {
        Self {
            projection,
            tracking,
        }
    }
}

/// A controlled failure of one processor step.
#[derive(Debug, Error)]
pub enum CenterFrameProcessorError<ProjectionError, TrackingError>
where
    ProjectionError: Error + 'static,
    TrackingError: Error + 'static,
{
    /// The projection failed; carries its own error.
    #[error("the projection failed: {0}")]
    Projection(#[source] ProjectionError),
    /// The reply tracking failed; carries its own error.
    #[error("the reply tracking failed: {0}")]
    Tracking(#[source] TrackingError),
}

impl<Projection, Tracking> crate::center::session::CenterFrameConsumer
    for CenterFrameProcessor<Projection, Tracking>
where
    Projection: CenterContentConsumer,
    Tracking: CenterReplyConsumer,
{
    type Error = CenterFrameProcessorError<Projection::Error, Tracking::Error>;

    fn on_frame<'a>(
        &'a self,
        site: &'a ResolvedSite,
        envelope: &'a Envelope,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            match envelope.message.as_ref() {
                Some(
                    EnvelopeMessage::OperationAccepted(_)
                    | EnvelopeMessage::OperationRejected(_)
                    | EnvelopeMessage::OperationProgress(_)
                    | EnvelopeMessage::OperationCompleted(_),
                ) => self
                    .tracking
                    .on_reply(site.instance_id(), envelope, now)
                    .await
                    .map_err(CenterFrameProcessorError::Tracking),
                Some(message) => self
                    .projection
                    .on_frame(site, envelope.sequence, message, now)
                    .await
                    .map_err(CenterFrameProcessorError::Projection),
                None => Ok(()),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        path::PathBuf,
        sync::{Arc, Mutex},
    };

    use rutilus_center_protocol::{
        EndpointSnapshot, Envelope, EnvelopeMessage, OperationAccepted, OperationCompleted,
        OperationOffer, OperationProgress, OperationRejected, TlsTrust,
    };
    use rutilus_domain::{
        Artifact, ArtifactId, ArtifactState, BatchOperation, BatchOperationId, CenterBindingId,
        CertificateFingerprint, EndpointId, Event, FailureKind, InboxEntry, InboxEvent, InstanceId,
        Operation, OperationId, OperationSource, OperationState, OutboxEntry, OutboxEntryId,
        PrincipalId, RedfishCommand, ResetType, ResourceODataId, Role, RoleAssignment, SyncCursor,
        SyncCursorId, SyncStream, SystemCommand,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild, OperationStore,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::{
        ArtifactRepository, CenterInbox, CenterOutbox, InboxInsertOutcome,
        center::projection::{
            CenterEndpointProjection, CenterProjection, EndpointProjectionWrite,
            ProjectionWriteOutcome, ResourceProjectionWrite,
        },
        center::session::{CenterFrameConsumer, ResolvedSite},
    };

    /// A store error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock store never fails")]
    struct MockStoreError;

    /// The shared state of the mock dispatch store: the operation records
    /// and the projection reads the dispatch routing validates against.
    #[derive(Clone)]
    struct MockDispatchState {
        operations: Arc<Mutex<HashMap<OperationId, Operation>>>,
        endpoint: Arc<Mutex<Option<(EndpointId, InstanceId)>>>,
        endpoints: Arc<Mutex<Vec<EndpointProjectionWrite>>>,
        resources: Arc<Mutex<Vec<(EndpointId, String)>>>,
        inbox_entries: Arc<Mutex<Vec<InboxEntry>>>,
        offers: Arc<Mutex<Vec<OperationOffer>>>,
        roles: Arc<Mutex<Option<RoleAssignment>>>,
    }

    impl MockDispatchState {
        fn new() -> Self {
            Self {
                operations: Arc::new(Mutex::new(HashMap::new())),
                endpoint: Arc::new(Mutex::new(None)),
                endpoints: Arc::new(Mutex::new(Vec::new())),
                resources: Arc::new(Mutex::new(Vec::new())),
                inbox_entries: Arc::new(Mutex::new(Vec::new())),
                offers: Arc::new(Mutex::new(Vec::new())),
                roles: Arc::new(Mutex::new(None)),
            }
        }

        fn find_operation_owned(&self, operation_id: OperationId) -> Option<Operation> {
            self.operations
                .lock()
                .map(|rows| rows.get(&operation_id).cloned())
                .unwrap_or_default()
        }

        fn endpoints_owned(&self) -> Vec<EndpointProjectionWrite> {
            self.endpoints
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn offers_owned(&self) -> Vec<OperationOffer> {
            self.offers
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }

        fn inbox_entries_owned(&self) -> Vec<InboxEntry> {
            self.inbox_entries
                .lock()
                .map(|rows| rows.clone())
                .unwrap_or_default()
        }
    }

    #[derive(Clone)]
    struct MockDispatchStore {
        state: MockDispatchState,
    }

    impl MockDispatchStore {
        fn new() -> (Self, MockDispatchState) {
            let state = MockDispatchState::new();
            (
                Self {
                    state: state.clone(),
                },
                state,
            )
        }
    }

    impl CenterProjectionRepository for MockDispatchStore {
        type Error = MockStoreError;

        fn upsert_endpoint<'a>(
            &'a self,
            projection: &'a EndpointProjectionWrite,
            _site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move {
                self.state
                    .endpoints
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(projection.clone());
                Ok(ProjectionWriteOutcome::Applied)
            })
        }

        fn delete_endpoint(
            &self,
            _endpoint_id: EndpointId,
            _site: InstanceId,
        ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move { Ok(ProjectionWriteOutcome::Applied) })
        }

        fn upsert_resource<'a>(
            &'a self,
            _projection: &'a ResourceProjectionWrite,
            _site: InstanceId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move { Ok(ProjectionWriteOutcome::Applied) })
        }

        fn delete_resource(
            &self,
            _endpoint_id: EndpointId,
            _odata_id: &str,
            _site: InstanceId,
        ) -> BoundaryFuture<'_, Result<ProjectionWriteOutcome, Self::Error>> {
            Box::pin(async move { Ok(ProjectionWriteOutcome::Applied) })
        }

        fn upsert_event<'a>(
            &'a self,
            _event: &'a Event,
            _site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn declare_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
            _site: InstanceId,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_endpoint_projection(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<CenterEndpointProjection>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .endpoint
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .as_ref()
                    .filter(|(stored, _)| *stored == endpoint_id)
                    .map(|(stored, site)| CenterEndpointProjection::new(*stored, Some(*site))))
            })
        }

        fn has_resource(
            &self,
            endpoint_id: EndpointId,
            odata_id: &str,
        ) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
            let odata_id = odata_id.to_owned();
            Box::pin(async move {
                Ok(self
                    .state
                    .resources
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .any(|(stored, known)| *stored == endpoint_id && known == &odata_id))
            })
        }
    }

    impl ArtifactRepository for MockDispatchStore {
        type Error = MockStoreError;

        fn create_artifact<'a>(
            &'a self,
            _artifact: &'a Artifact,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_artifact(
            &self,
            _artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
            Box::pin(async move { Ok(None) })
        }

        fn list_artifacts_by_state(
            &self,
            _state: ArtifactState,
        ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn update_artifact(
            &self,
            _artifact_id: ArtifactId,
            _uploaded_bytes: u64,
            _state: ArtifactState,
            _occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn artifact_file_path(&self, _artifact_id: ArtifactId) -> PathBuf {
            PathBuf::new()
        }
    }

    impl OperationStore for MockDispatchStore {
        type Error = MockStoreError;

        fn create_operation<'a>(
            &'a self,
            operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.state
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(operation.id(), operation.clone());
                Ok(())
            })
        }

        fn find_operation(
            &self,
            operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
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
                let mut rows = self.state.operations.lock().map_err(|_| MockStoreError)?;
                let row = rows.get(&operation_id).ok_or(MockStoreError)?.clone();
                if row.is_terminal() {
                    return Err(MockStoreError);
                }
                let updated = Operation::try_from_parts(
                    row.id(),
                    row.source(),
                    row.targets().to_vec(),
                    row.command(),
                    new_state,
                    row.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockStoreError)?;
                rows.insert(operation_id, updated);
                Ok(())
            })
        }

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn list_operations(
            &self,
            _state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn find_batch(
            &self,
            _batch_id: BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
            Box::pin(async move { Ok(None) })
        }

        fn list_batches(
            &self,
        ) -> OperationBoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn list_batch_children(
            &self,
            _batch_id: BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl CenterRoleRepository for MockDispatchStore {
        type Error = MockStoreError;

        fn find_role_assignment(
            &self,
            _principal_id: PrincipalId,
        ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>> {
            Box::pin(
                async move { Ok(self.state.roles.lock().map_err(|_| MockStoreError)?.clone()) },
            )
        }
    }

    impl CenterOutbox for MockDispatchStore {
        type Error = MockStoreError;

        fn enqueue<'a>(
            &'a self,
            instance_id: InstanceId,
            message: &'a EnvelopeMessage,
            created_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
            Box::pin(async move {
                let EnvelopeMessage::OperationOffer(offer) = message else {
                    return Err(MockStoreError);
                };
                self.state
                    .offers
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .push(offer.clone());
                Ok(OutboxEntry::new(
                    OutboxEntryId::generate(),
                    instance_id,
                    1,
                    String::new(),
                    created_at,
                ))
            })
        }

        fn list_pending(
            &self,
            _instance_id: InstanceId,
            _limit: u64,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn acknowledge(
            &self,
            _entry_id: OutboxEntryId,
            _acked_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }
    }

    impl CenterInbox for MockDispatchStore {
        type Error = MockStoreError;

        fn insert<'a>(
            &'a self,
            entry: &'a InboxEntry,
        ) -> BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .inbox_entries
                    .lock()
                    .map_err(|_| MockStoreError)?;
                if rows
                    .iter()
                    .any(|row| row.operation_id() == entry.operation_id())
                {
                    return Ok(InboxInsertOutcome::DuplicateInProgress);
                }
                rows.push(entry.clone());
                Ok(InboxInsertOutcome::Created)
            })
        }

        fn find_by_operation(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .state
                    .inbox_entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .iter()
                    .find(|entry| entry.operation_id() == operation_id)
                    .cloned())
            })
        }

        fn advance(
            &self,
            operation_id: OperationId,
            event: InboxEvent,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self
                    .state
                    .inbox_entries
                    .lock()
                    .map_err(|_| MockStoreError)?;
                let entry = rows
                    .iter_mut()
                    .find(|entry| entry.operation_id() == operation_id)
                    .ok_or(MockStoreError)?;
                entry.apply(event).map_err(|_| MockStoreError)
            })
        }
    }

    fn base_time() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap_or(OffsetDateTime::UNIX_EPOCH)
    }

    fn request(
        site: InstanceId,
        endpoint_id: EndpointId,
        target: &str,
        actor: PrincipalId,
    ) -> Result<CenterOperationRequest, Box<dyn Error>> {
        Ok(CenterOperationRequest::new(
            site,
            endpoint_id,
            ResourceODataId::parse(target)?,
            RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown)),
            actor,
        ))
    }

    #[test]
    fn allows_dispatch_applies_the_role_and_site_scope_rules() {
        let site = InstanceId::generate();
        let other = InstanceId::generate();
        // The Administrator is global, scoped or not.
        assert!(allows_dispatch(Role::Administrator, None, site));
        assert!(allows_dispatch(Role::Administrator, Some(other), site));
        // The Operator dispatches globally when unscoped, and only to the
        // assigned site when scoped (D3).
        assert!(allows_dispatch(Role::Operator, None, site));
        assert!(allows_dispatch(Role::Operator, Some(site), site));
        assert!(!allows_dispatch(Role::Operator, Some(other), site));
        // The Viewer never dispatches.
        assert!(!allows_dispatch(Role::Viewer, None, site));
        assert!(!allows_dispatch(Role::Viewer, Some(site), site));
    }

    #[tokio::test]
    async fn dispatch_records_the_operation_and_enqueues_the_s15_6_offer_wire_shape()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store, outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));

        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        assert_eq!(dispatched.expires_at(), now + CENTER_OFFER_TTL);

        // The tracking record exists with the offer's operation id.
        let operation = state
            .find_operation_owned(dispatched.operation_id())
            .ok_or("the tracking record is missing")?;
        assert_eq!(operation.source(), OperationSource::Center);
        assert_eq!(operation.state(), OperationState::Queued);
        assert_eq!(operation.targets().len(), 1);
        assert_eq!(operation.targets()[0].endpoint_id(), endpoint_id);

        // The offer carries exactly the §15.6 set: the typed command, the
        // target, the stable ids, the expiry, and the actor context — and
        // nothing else (no URL, no method, no headers, no body).
        let offers = state.offers_owned();
        assert_eq!(offers.len(), 1);
        let offer = &offers[0];
        assert_eq!(offer.operation_id, dispatched.operation_id().to_string());
        assert_eq!(offer.endpoint_id, endpoint_id.to_string());
        assert_eq!(offer.site_id, site.to_string());
        assert_eq!(offer.target, "/redfish/v1/Systems/1");
        assert_eq!(
            offer.expires_at_unix,
            dispatched.expires_at().unix_timestamp()
        );
        assert_eq!(offer.actor_context, actor.to_string());
        let decoded: RedfishCommand = serde_json::from_slice(&offer.command_json)?;
        assert_eq!(
            decoded,
            RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown))
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_refuses_without_authorization_and_outside_the_site_scope()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store, outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let other = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));

        // No assignment at all is refused.
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::NotAuthorized)
        ));
        // A Viewer assignment is read-only.
        *state.roles.lock().map_err(|_| MockStoreError)? =
            Some(RoleAssignment::new(actor, Role::Viewer, None, now, None));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::NotAuthorized)
        ));
        // A site-scoped Operator cannot dispatch to another site (D3).
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Operator,
            None,
            now,
            Some(other),
        ));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::NotAuthorized)
        ));
        // The same scoped Operator dispatches to the assigned site.
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Operator,
            None,
            now,
            Some(site),
        ));
        assert!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await
                .is_ok()
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_refuses_unknown_endpoints_targets_and_cross_site_routes()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store, outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let other = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));

        // An endpoint outside the projection is refused.
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::UnknownEndpoint { .. })
        ));
        // An endpoint projected for another site is refused — the offer
        // would be dropped by the addressed site (§15.6 routing).
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, other));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::EndpointNotInSite { .. })
        ));
        // A target outside the endpoint's projection is refused.
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        assert!(matches!(
            dispatch
                .dispatch(
                    &request(site, endpoint_id, "/redfish/v1/Chassis/1", actor)?,
                    now
                )
                .await,
            Err(CenterDispatchError::UnknownTarget { .. })
        ));
        Ok(())
    }

    // Every reply phase and its duplicate absorption is spelled out as its
    // own assertion so a failure pinpoints the exact transition, which
    // exceeds the pedantic line budget (the persistence tests allow the
    // same lint on their exhaustive assertion tests).
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn replies_advance_the_tracking_state_machine_idempotently() -> Result<(), Box<dyn Error>>
    {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store.clone(), outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let operation_id = dispatched.operation_id();
        let tracking = CenterOperationTracking::new(store.clone(), store);

        // The accepted reply moves the record to Running.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );

        // A duplicate accepted reply is absorbed, not applied twice.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::seconds(2),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );

        // The completed reply reports the terminal outcome.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 3,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationCompleted(OperationCompleted {
                        operation_id: operation_id.to_string(),
                        succeeded: true,
                        summary: String::from("reset verified"),
                    })),
                },
                now + Duration::seconds(3),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Succeeded
        );
        // A reply after the terminal outcome is absorbed.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 4,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationProgress(OperationProgress {
                        operation_id: operation_id.to_string(),
                        state: String::from("running"),
                        detail: String::new(),
                    })),
                },
                now + Duration::seconds(4),
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Succeeded
        );
        // The reply receipts were logged under the operation id.
        let receipts = state.inbox_entries_owned();
        assert!(
            receipts
                .iter()
                .all(|entry| entry.operation_id() == operation_id)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_rejected_reply_marks_the_operation_failed_and_unknown_replies_are_absorbed()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let outbox = store.clone();
        let roles = store.clone();
        let dispatch = CenterOperationDispatch::new(store.clone(), outbox, roles);
        let now = base_time();
        let site = InstanceId::generate();
        let endpoint_id = EndpointId::generate();
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? = Some((endpoint_id, site));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        let dispatched = dispatch
            .dispatch(
                &request(site, endpoint_id, "/redfish/v1/Systems/1", actor)?,
                now,
            )
            .await?;
        let operation_id = dispatched.operation_id();
        let tracking = CenterOperationTracking::new(store.clone(), store);

        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 1,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationRejected(OperationRejected {
                        operation_id: operation_id.to_string(),
                        reason: rutilus_center_protocol::OperationRejectedReason::Expired as i32,
                        detail: String::from("the offer expired"),
                    })),
                },
                now + Duration::SECOND,
            )
            .await?;
        assert_eq!(
            state
                .find_operation_owned(operation_id)
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Failed
        );

        // A reply for an unknown operation id is absorbed, never an error.
        tracking
            .on_reply(
                site,
                &Envelope {
                    sequence: 2,
                    acked_sequence: 0,
                    message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                        operation_id: OperationId::generate().to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    })),
                },
                now + Duration::seconds(2),
            )
            .await?;
        Ok(())
    }

    /// An in-memory cursor store behind the processor test.
    #[derive(Clone)]
    struct MockCursor {
        cursors: Arc<Mutex<HashMap<SyncStream, u64>>>,
    }

    impl MockCursor {
        fn new() -> Self {
            Self {
                cursors: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl crate::CenterCursor for MockCursor {
        type Error = MockStoreError;

        fn get(
            &self,
            _instance_id: InstanceId,
            stream: SyncStream,
        ) -> BoundaryFuture<'_, Result<Option<SyncCursor>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&stream)
                    .map(|sequence| {
                        SyncCursor::new(
                            SyncCursorId::generate(),
                            InstanceId::generate(),
                            stream,
                            sequence.to_string(),
                            OffsetDateTime::UNIX_EPOCH,
                        )
                    }))
            })
        }

        fn set<'a>(
            &'a self,
            cursor: &'a SyncCursor,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let sequence = cursor
                    .cursor_value()
                    .parse::<u64>()
                    .map_err(|_| MockStoreError)?;
                self.cursors
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .insert(cursor.stream(), sequence);
                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn the_processor_routes_content_and_replies_to_the_right_consumers()
    -> Result<(), Box<dyn Error>> {
        let (store, state) = MockDispatchStore::new();
        let cursor = MockCursor::new();
        let projection = CenterProjection::new(store.clone(), cursor);
        let tracking = CenterOperationTracking::new(store.clone(), store.clone());
        let processor = CenterFrameProcessor::new(projection, tracking);
        let site = ResolvedSite::new(
            InstanceId::generate(),
            CenterBindingId::generate(),
            CertificateFingerprint::from_bytes([0x42; 32]),
        );
        let now = base_time();
        let endpoint_id = EndpointId::generate();

        // A dispatched offer gives the reply routing a record to advance.
        let actor = PrincipalId::generate();
        *state.endpoint.lock().map_err(|_| MockStoreError)? =
            Some((endpoint_id, site.instance_id()));
        state
            .resources
            .lock()
            .map_err(|_| MockStoreError)?
            .push((endpoint_id, String::from("/redfish/v1/Systems/1")));
        *state.roles.lock().map_err(|_| MockStoreError)? = Some(RoleAssignment::new(
            actor,
            Role::Administrator,
            None,
            now,
            None,
        ));
        let dispatch = CenterOperationDispatch::new(store.clone(), store.clone(), store.clone());
        let dispatched = dispatch
            .dispatch(
                &request(
                    site.instance_id(),
                    endpoint_id,
                    "/redfish/v1/Systems/1",
                    actor,
                )?,
                now,
            )
            .await?;

        // A content frame reaches the projection...
        let content = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::EndpointSnapshot(EndpointSnapshot {
                endpoint_id: endpoint_id.to_string(),
                display_name: String::from("Rack A PDU"),
                address: String::from("https://192.0.2.10"),
                trust: TlsTrust::SystemCa as i32,
                refresh_generation: 1,
                resources: Vec::new(),
                health: String::from("ok"),
            })),
        };
        processor.on_frame(&site, &content, now).await?;
        assert_eq!(state.endpoints_owned().len(), 1);

        // ...and a reply frame reaches the tracking: the record advances.
        let reply = Envelope {
            sequence: 2,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationAccepted(OperationAccepted {
                operation_id: dispatched.operation_id().to_string(),
                accepted_at_unix: now.unix_timestamp(),
            })),
        };
        processor
            .on_frame(&site, &reply, now + Duration::SECOND)
            .await?;
        assert_eq!(
            state
                .find_operation_owned(dispatched.operation_id())
                .ok_or("the tracking record is missing")?
                .state(),
            OperationState::Running
        );
        Ok(())
    }
}
