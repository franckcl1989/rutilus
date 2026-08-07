//! The site-side center synchronization engine (design §15, 0.7.0 S4).
//!
//! [`CenterSync`] runs the site's half of the site-to-center protocol over
//! the [`crate::CenterTransport`] boundary. The engine owns everything the
//! connection layer deliberately does not: the §15.4 reconnect backoff, the
//! §15.3 negotiation-failure handling, the heartbeat timing, the durable
//! outbox resume from the last acknowledged sequence, the §15.6 operation
//! offers, and the incremental endpoint, event, and artifact reporting of
//! the §21 0.7.0 checklist.
//!
//! # Local autonomy (§4.2, §15.3)
//!
//! The engine is a background loop with exactly one contract: never take
//! the site down. A rejected negotiation (no common protocol version), an
//! unreachable center, and a dropped connection all log the reason and
//! schedule the next attempt after the §15.4 backoff, while every local
//! feature — endpoint refresh, operations, the local GUI — keeps running
//! unchanged. The durable outbox is the queue that makes this safe: content
//! enqueued while disconnected stays in the database and the flush resumes
//! from the last acknowledged sequence when the connection returns (§15.4
//! at-least-once delivery).
//!
//! # Shutdown
//!
//! `run` observes a stop signal at every await point and exits promptly;
//! an in-flight send or receive is simply dropped. The outbox rows are the
//! durable state — a stop mid-flush abandons only the wire position, which
//! the next connection resumes from the last acknowledgment, so no shutdown
//! sequence needs to complete a half-sent batch.

use std::{collections::VecDeque, error::Error, future::Future, time::Duration};

use rutilus_center_protocol::{
    Envelope, EnvelopeMessage, Heartbeat, OperationOffer, OperationRejectedReason,
    SITE_HEARTBEAT_INTERVAL, SITE_RECONNECT_AFTER,
};
use rutilus_domain::{
    CapabilityState, EndpointId, InboxEntry, InboxEntryId, InboxEntryState, InboxEvent, InstanceId,
    Operation, OperationId, OperationSource, OperationState, OperationTarget, OutboxEntry,
    OutboxEntryId, RedfishCommand, TargetId,
};
use rutilus_operation_engine::OperationStore;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    BoundaryFuture, CapabilityQueryRepository, Clock, CredentialInventoryRepository,
    EndpointCapabilityQuery, EndpointCapabilityQueryError, EndpointInventoryQuery,
    EndpointInventoryQueryError, EndpointInventoryRepository, EndpointRefreshRepository,
    center_transport::{CenterSession, CenterTransport},
    operation_executor::{required_capability, required_capability_state},
};

/// The durable outbox boundary of the site-to-center synchronization
/// (design §17 D4, §15.4).
///
/// The outbox is the site's queue to the center: every content message is
/// enqueued as one durable row carrying the next per-instance sequence, the
/// flush sends the pending rows in sequence order, and the center's `Ack`
/// moves one row to the acknowledged state. Because the queue is the
/// database, a disconnected site keeps enqueuing (the offline queue of
/// §21 0.7.0) and a reconnect resumes from the last acknowledged sequence.
pub trait CenterOutbox: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Allocates the next per-instance sequence and persists the message as
    /// one atomic write, returning the queued entry with its sequence.
    fn enqueue<'a>(
        &'a self,
        instance_id: InstanceId,
        message: &'a EnvelopeMessage,
        created_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>>;

    /// Lists the oldest pending entries of one instance in sequence order,
    /// bounded by `limit`. This is the delivery scan of the flush.
    fn list_pending(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>>;

    /// Marks one entry acknowledged. The write is idempotent: a repeated
    /// acknowledgement (the center may deliver its `Ack` more than once) is
    /// a successful no-op.
    fn acknowledge(
        &self,
        entry_id: OutboxEntryId,
        acked_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

impl<Outbox> CenterOutbox for &Outbox
where
    Outbox: CenterOutbox + ?Sized,
{
    type Error = Outbox::Error;

    fn enqueue<'a>(
        &'a self,
        instance_id: InstanceId,
        message: &'a EnvelopeMessage,
        created_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
        Outbox::enqueue(*self, instance_id, message, created_at)
    }

    fn list_pending(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
        Outbox::list_pending(*self, instance_id, limit)
    }

    fn acknowledge(
        &self,
        entry_id: OutboxEntryId,
        acked_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Outbox::acknowledge(*self, entry_id, acked_at)
    }
}

/// The outcome of one idempotent inbox insertion (§15.4).
///
/// Mirrors the domain's [`rutilus_domain::decide_inbox_duplicate`] decision
/// at the persistence boundary, so the engine can answer a re-delivered
/// offer with the recorded state instead of a second execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxInsertOutcome {
    /// The envelope was stored as a new `received` entry.
    Created,
    /// A stored entry with the same operation id is still being processed.
    DuplicateInProgress,
    /// A stored entry with the same operation id already finished; the
    /// duplicate is answered with the recorded outcome.
    DuplicateResolved(InboxEntryState),
}

/// The durable inbox boundary of the site-to-center synchronization
/// (design §17 D4, §15.4, §15.6).
///
/// The inbox records every operation offer received from the center under
/// the §17.5 idempotency rule: the operation id is the key, so a
/// re-delivered offer is answered with the recorded state and never
/// executes twice. The state machine is the domain's `InboxEntry` — the
/// boundary only persists and advances it.
pub trait CenterInbox: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists one received envelope under the idempotency rule, returning
    /// the duplicate decision of §15.4.
    fn insert<'a>(
        &'a self,
        entry: &'a InboxEntry,
    ) -> BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>>;

    /// Reads the entry of one operation id — the idempotency lookup.
    fn find_by_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>>;

    /// Applies one inbox state-machine event. The write is idempotent: an
    /// entry that already carries the target state is a successful no-op.
    fn advance(
        &self,
        operation_id: OperationId,
        event: InboxEvent,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

impl<Inbox> CenterInbox for &Inbox
where
    Inbox: CenterInbox + ?Sized,
{
    type Error = Inbox::Error;

    fn insert<'a>(
        &'a self,
        entry: &'a InboxEntry,
    ) -> BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>> {
        Inbox::insert(*self, entry)
    }

    fn find_by_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>> {
        Inbox::find_by_operation(*self, operation_id)
    }

    fn advance(
        &self,
        operation_id: OperationId,
        event: InboxEvent,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Inbox::advance(*self, operation_id, event)
    }
}

/// The decision of the §15.6 rechecks for one operation offer.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OfferDecision {
    /// Every recheck passed; the operation may be accepted. The parsed
    /// command rides along so the acceptance never re-parses it.
    Accept { command: RedfishCommand },
    /// The named recheck failed; the offer is refused with the stable
    /// reason code and a human-readable detail.
    Reject {
        reason: OperationRejectedReason,
        detail: String,
    },
}

/// The outcome of handling one received operation offer.
#[derive(Clone, Debug, Eq, PartialEq)]
enum OfferOutcome {
    /// The offer was accepted: the operation is persisted and the
    /// `OperationAccepted` reply is queued.
    Accepted,
    /// The offer was refused: the `OperationRejected` reply is queued with
    /// the stable reason code.
    Rejected {
        reason: OperationRejectedReason,
        detail: String,
    },
    /// The offer duplicates one already being processed; the current state
    /// reply is queued and nothing executes a second time.
    DuplicateProgress,
    /// The offer is not for this site or carries unparseable stable ids; it
    /// was logged and dropped.
    Dropped,
}

/// The timing bounds of the site-to-center synchronization engine.
///
/// The defaults are the protocol constants of `rutilus-center-protocol`:
/// one [`Heartbeat`] every [`SITE_HEARTBEAT_INTERVAL`] (30 seconds) and the
/// §15.4 reconnect backoff [`SITE_RECONNECT_AFTER`] (120 seconds). Tests use
/// short bounds instead of the production ones.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CenterSyncOptions {
    /// How often the engine sends a [`Heartbeat`] while connected (§15.2).
    pub heartbeat_interval: Duration,
    /// How long the engine waits after a failed connect or a dropped
    /// connection before the next attempt (§15.4).
    pub reconnect_after: Duration,
    /// How many pending outbox entries one flush sends before the next
    /// acknowledgement is needed. Bounds one burst on the wire.
    pub flush_limit: u64,
}

impl Default for CenterSyncOptions {
    fn default() -> Self {
        Self {
            heartbeat_interval: SITE_HEARTBEAT_INTERVAL,
            reconnect_after: SITE_RECONNECT_AFTER,
            flush_limit: 64,
        }
    }
}

/// The site-side center synchronization engine.
///
/// `Transport` is the [`CenterTransport`] boundary (the app crate's
/// `CenterClient` in the runtime slice), `Outbox` the durable §15.4 queue
/// boundary, and `Time` the caller's monotonic clock, supplied at the
/// boundary exactly like every other use case.
pub struct CenterSync<Transport, Store, Outbox, Inbox, Time> {
    transport: Transport,
    store: Store,
    outbox: Outbox,
    inbox: Inbox,
    clock: Time,
    instance_id: InstanceId,
    options: CenterSyncOptions,
}

impl<Transport, Store, Outbox, Inbox, Time> CenterSync<Transport, Store, Outbox, Inbox, Time>
where
    Transport: CenterTransport,
    Store: OperationStore
        + EndpointRefreshRepository
        + CapabilityQueryRepository
        + CredentialInventoryRepository
        + EndpointInventoryRepository,
    Outbox: CenterOutbox,
    Inbox: CenterInbox,
    Time: Clock,
{
    #[must_use]
    pub const fn new(
        transport: Transport,
        store: Store,
        outbox: Outbox,
        inbox: Inbox,
        clock: Time,
        instance_id: InstanceId,
        options: CenterSyncOptions,
    ) -> Self {
        Self {
            transport,
            store,
            outbox,
            inbox,
            clock,
            instance_id,
            options,
        }
    }

    /// Enqueues one message into the durable outbox (§15.4): allocates the
    /// next per-instance sequence and persists the envelope. The database is
    /// the queue, so this is safe while the engine is disconnected — the
    /// offline queue of §21 0.7.0 — and the flush resumes from the last
    /// acknowledged sequence when the connection returns.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSyncError::Outbox`] when the queue write fails.
    pub async fn enqueue_outbox_entry(
        &self,
        message: EnvelopeMessage,
    ) -> Result<OutboxEntry, CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        self.outbox
            .enqueue(self.instance_id, &message, self.clock.now())
            .await
            .map_err(CenterSyncError::Outbox)
    }

    /// Runs the engine until `stop` resolves: the connect loop with the
    /// §15.4 backoff, the heartbeat and frame exchange of one connection,
    /// and the reconnect loop after every disconnect.
    ///
    /// The engine never returns an error for a failed connection: every
    /// transport failure is logged and the loop schedules the next attempt,
    /// so `Ok` on a stopped signal is the only return path.
    ///
    /// # Errors
    ///
    /// Returns [`CenterSyncError::Transport`] or [`CenterSyncError::Outbox`]
    /// when a boundary fails inside one connection step — the loop then
    /// waits out the backoff and reconnects.
    pub async fn run<Stop>(
        &self,
        stop: Stop,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox>>
    where
        Stop: Future<Output = ()> + Send,
    {
        self.connect_loop(stop).await
    }

    /// The outer connect loop (§15.1, §15.3, §15.4): connect, run the
    /// connection, and on every failure or disconnect wait out the backoff
    /// and try again, until `stop` resolves.
    async fn connect_loop<Stop>(
        &self,
        stop: Stop,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox>>
    where
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        loop {
            let session = tokio::select! {
                () = stop.as_mut() => return Ok(()),
                result = self.transport.connect() => match result {
                    Ok(session) => session,
                    Err(error) => {
                        // §15.3: a center without a common protocol version
                        // rejects the negotiation, and an unreachable center
                        // fails the attempt — either way the site keeps
                        // running locally and retries after the backoff.
                        eprintln!(
                            "center connection failed: {error}; keeping the site local and \
                             retrying in {:?}",
                            self.options.reconnect_after
                        );
                        tokio::select! {
                            () = stop.as_mut() => return Ok(()),
                            () = tokio::time::sleep(self.options.reconnect_after) => {}
                        }
                        continue;
                    }
                },
            };
            let outcome = self.connected_loop(session, stop.as_mut()).await;
            match outcome {
                Ok(()) => return Ok(()),
                Err(error) => {
                    eprintln!(
                        "center connection ended: {error}; reconnecting in {:?}",
                        self.options.reconnect_after
                    );
                    tokio::select! {
                        () = stop.as_mut() => return Ok(()),
                        () = tokio::time::sleep(self.options.reconnect_after) => {}
                    }
                }
            }
        }
    }

    /// One established connection: the initial outbox flush (§15.4 resume
    /// from the last acknowledged sequence), then the heartbeat loop and the
    /// inbound frame dispatch, until the peer closes the connection, the
    /// transport fails, or `stop` resolves.
    async fn connected_loop<Session, Stop>(
        &self,
        mut session: Session,
        stop: Stop,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox>>
    where
        Session: CenterSession<Error = Transport::Error>,
        Stop: Future<Output = ()> + Send,
    {
        tokio::pin!(stop);
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + self.options.heartbeat_interval,
            self.options.heartbeat_interval,
        );
        // The highest center sequence accepted on this connection; every
        // outbound frame piggybacks it (§15.4). Heartbeats carry `sequence:
        // 0` — a liveness frame, not an outbox message.
        let mut peer_acked: u64 = 0;
        // The durable entries sent on this connection, in send order: the
        // center's acknowledgements pop the head. The list resets on every
        // connection; unacknowledged entries stay pending and the reconnect
        // flush re-sends them from the last acknowledgement (§15.4).
        let mut sent: VecDeque<(OutboxEntryId, i64)> = VecDeque::new();
        // The center-operation result reporting enqueues its replies before
        // the flush, so one batch carries both.
        self.report_center_operations().await?;
        self.flush_outbox(&mut session, &mut sent, peer_acked)
            .await?;
        loop {
            tokio::select! {
                () = stop.as_mut() => return Ok(()),
                _ = heartbeat.tick() => {
                    session
                        .send(Envelope {
                            sequence: 0,
                            acked_sequence: peer_acked,
                            message: Some(EnvelopeMessage::Heartbeat(Heartbeat {
                                sent_at_unix: self.clock.now().unix_timestamp(),
                            })),
                        })
                        .await
                        .map_err(CenterSyncError::Transport)?;
                }
                frame = session.receive() => {
                    let Some(envelope) = frame.map_err(CenterSyncError::Transport)? else {
                        return Err(CenterSyncError::Closed);
                    };
                    peer_acked = peer_acked.max(envelope.sequence);
                    match envelope.message.as_ref() {
                        Some(EnvelopeMessage::Ack(ack)) => {
                            self.ack_outbox(ack.sequence, &mut sent).await?;
                            // An acknowledgement frees the next batch: the
                            // flush continues until the queue is empty.
                            self.flush_outbox(&mut session, &mut sent, peer_acked).await?;
                        }
                        Some(EnvelopeMessage::OperationOffer(offer)) => {
                            self.handle_offer(offer, &envelope).await?;
                        }
                        _ => self.dispatch_inbound(envelope),
                    }
                }
            }
        }
    }

    /// Sends the oldest pending outbox entries in sequence order, up to the
    /// flush limit, and records them as sent on this connection.
    ///
    /// Every frame carries its durable sequence — the resume point of §15.4 —
    /// with the current acknowledgement watermark piggybacked. A transport
    /// failure mid-flush abandons only the wire position: the unacknowledged
    /// entries stay pending and the next connection re-sends them
    /// (at-least-once delivery; the center deduplicates by sequence).
    async fn flush_outbox<Session>(
        &self,
        session: &mut Session,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
        peer_acked: u64,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox>>
    where
        Session: CenterSession<Error = Transport::Error>,
    {
        let pending = self
            .outbox
            .list_pending(self.instance_id, self.options.flush_limit)
            .await
            .map_err(CenterSyncError::Outbox)?;
        for entry in pending {
            // The payload is the §9.4 typed serialization of the envelope;
            // the row's sequence column is authoritative, and the stored
            // acknowledgement watermark is the enqueue-time value, so the
            // frame is rebuilt with both patched to the send-time truth.
            let mut envelope: Envelope =
                serde_json::from_str(entry.payload_json()).map_err(|source| {
                    CenterSyncError::InvalidOutboxPayload {
                        entry_id: entry.id(),
                        source,
                    }
                })?;
            envelope.sequence =
                u64::try_from(entry.sequence()).map_err(|_| CenterSyncError::SequenceOverflow {
                    sequence: entry.sequence(),
                })?;
            envelope.acked_sequence = peer_acked;
            session
                .send(envelope)
                .await
                .map_err(CenterSyncError::Transport)?;
            sent.push_back((entry.id(), entry.sequence()));
        }
        Ok(())
    }

    /// Applies one center acknowledgement: every entry sent on this
    /// connection whose sequence is at most the acknowledged sequence leaves
    /// the delivery queue. Frames on one connection are ordered, so the
    /// center's acknowledgements are monotonic and the head of the sent
    /// list is the only candidate.
    async fn ack_outbox(
        &self,
        acked_sequence: u64,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        let now = self.clock.now();
        while let Some(&(entry_id, sequence)) = sent.front() {
            let wire_sequence = u64::try_from(sequence)
                .map_err(|_| CenterSyncError::SequenceOverflow { sequence })?;
            if wire_sequence > acked_sequence {
                break;
            }
            sent.pop_front();
            self.outbox
                .acknowledge(entry_id, now)
                .await
                .map_err(CenterSyncError::Outbox)?;
        }
        Ok(())
    }

    /// Handles one §15.6 operation offer: the idempotent inbox insertion,
    /// the five rechecks, and the durable reply.
    ///
    /// The offer's `operation_id` is the §17.5 idempotency key: a stored
    /// entry with the same id is answered with its recorded state instead of
    /// a second execution. A fresh offer runs the §15.6 rechecks — endpoint
    /// existence, capability presence, credential validity, target-state
    /// applicability, and expiry — and only an `Accept` persists the
    /// operation (with the offer's own id, `OperationSource::Center`) and
    /// advances the inbox. Every reply travels through the durable outbox,
    /// so an accepted or rejected offer survives a disconnect (§15.4).
    async fn handle_offer(
        &self,
        offer: &OperationOffer,
        received: &Envelope,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        // The wire contract says these fields carry stable product codes; an
        // offer addressed to another site or carrying unparseable ids cannot
        // be recorded and is dropped with a log instead of being guessed at.
        if offer.site_id != self.instance_id.to_string() {
            eprintln!(
                "site {}: dropping an operation offer for site {}",
                self.instance_id, offer.site_id
            );
            return Ok(OfferOutcome::Dropped);
        }
        let Ok(operation_id) = offer.operation_id.parse::<OperationId>() else {
            eprintln!(
                "site {}: dropping an offer with an unparseable operation id",
                self.instance_id
            );
            return Ok(OfferOutcome::Dropped);
        };
        let Ok(endpoint_id) = offer.endpoint_id.parse::<EndpointId>() else {
            eprintln!(
                "site {}: dropping an offer with an unparseable endpoint id",
                self.instance_id
            );
            return Ok(OfferOutcome::Dropped);
        };
        let now = self.clock.now();
        // The payload record is the received envelope itself: the §9.4
        // typed payload of the inbox row.
        let payload_json = serde_json::to_string(received).map_err(CenterSyncError::Payload)?;
        let expires_at = OffsetDateTime::from_unix_timestamp(offer.expires_at_unix).unwrap_or(now);
        let entry = InboxEntry::new(
            InboxEntryId::generate(),
            operation_id,
            self.instance_id,
            payload_json,
            expires_at,
            now,
        );
        match self
            .inbox
            .insert(&entry)
            .await
            .map_err(CenterSyncError::Inbox)?
        {
            InboxInsertOutcome::Created => {
                self.decide_and_record(offer, &entry, endpoint_id, now)
                    .await
            }
            InboxInsertOutcome::DuplicateInProgress => {
                self.reply_to_in_progress_duplicate(offer, &entry, endpoint_id, now)
                    .await
            }
            InboxInsertOutcome::DuplicateResolved(state) => {
                self.reply_to_resolved_duplicate(offer, &entry, endpoint_id, state, now)
                    .await
            }
        }
    }

    /// Applies the §15.6 rechecks to a fresh offer and records the decision:
    /// `Accept` persists the operation and advances the inbox to `Accepted`;
    /// `Reject` queues the `OperationRejected` reply and advances the inbox
    /// to `Rejected`. Only the site's explicit acceptance transfers
    /// execution responsibility (§15.6).
    async fn decide_and_record(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        let operation_id = entry.operation_id();
        match self.decide_offer(offer, entry, endpoint_id, now).await? {
            OfferDecision::Accept { command } => {
                // The offer's stable operation id becomes the persisted
                // operation's id: the §17.5 key must name the operation so a
                // re-delivered offer resolves to the recorded outcome. The
                // engine's create path cannot be used — it generates fresh
                // ids — so the operation is persisted directly through the
                // store boundary, with the target validation already done by
                // the rechecks.
                let operation = Operation::new(
                    operation_id,
                    OperationSource::Center,
                    vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
                    command,
                    now,
                );
                self.store
                    .create_operation(&operation)
                    .await
                    .map_err(CenterSyncError::Operation)?;
                self.enqueue_outbox_entry(EnvelopeMessage::OperationAccepted(
                    rutilus_center_protocol::OperationAccepted {
                        operation_id: operation_id.to_string(),
                        accepted_at_unix: now.unix_timestamp(),
                    },
                ))
                .await?;
                self.inbox
                    .advance(operation_id, InboxEvent::Accepted)
                    .await
                    .map_err(CenterSyncError::Inbox)?;
                Ok(OfferOutcome::Accepted)
            }
            OfferDecision::Reject { reason, detail } => {
                self.enqueue_outbox_entry(EnvelopeMessage::OperationRejected(
                    rutilus_center_protocol::OperationRejected {
                        operation_id: operation_id.to_string(),
                        reason: reason as i32,
                        detail: detail.clone(),
                    },
                ))
                .await?;
                self.inbox
                    .advance(operation_id, InboxEvent::Rejected)
                    .await
                    .map_err(CenterSyncError::Inbox)?;
                Ok(OfferOutcome::Rejected { reason, detail })
            }
        }
    }

    /// The §15.6 rechecks, in the design's order: the endpoint must still
    /// exist, its capability must still be usable, its credential must still
    /// be stored, the offer's target must still be part of the last-known
    /// projection, and the operation must not have expired (the domain TTL
    /// judgment on the stored entry).
    async fn decide_offer(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<OfferDecision, CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        let Some(endpoint) = self
            .store
            .find_endpoint(endpoint_id)
            .await
            .map_err(CenterSyncError::Endpoint)?
        else {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::EndpointMissing,
                detail: String::from("the endpoint is no longer managed"),
            });
        };
        let command = match Self::parse_command(offer) {
            Ok(command) => command,
            Err(decision) => return Ok(decision),
        };
        let required = required_capability(&command);
        let entries = EndpointCapabilityQuery::new(&self.store, endpoint_id)
            .execute()
            .await
            .map_err(CenterSyncError::Capability)?;
        let state = entries
            .as_deref()
            .and_then(|entries| required_capability_state(required, entries));
        if state != Some(CapabilityState::Supported) {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::CapabilityMissing,
                detail: format!("the {required} capability is not usable"),
            });
        }
        let credentials = self
            .store
            .list_credentials()
            .await
            .map_err(CenterSyncError::Credential)?;
        if !credentials
            .iter()
            .any(|credential| credential.id() == endpoint.credential_id())
        {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::CredentialInvalid,
                detail: String::from("the endpoint credential is no longer stored"),
            });
        }
        let items = EndpointInventoryQuery::new(&self.store)
            .execute()
            .await
            .map_err(CenterSyncError::Inventory)?;
        let target_known = items.iter().any(|item| {
            item.endpoint().id() == endpoint_id
                && item.resources().iter().any(|resource| {
                    let odata_id = resource.odata_id().as_str();
                    offer.target == odata_id || offer.target.starts_with(&format!("{odata_id}/"))
                })
        });
        if !target_known {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::TargetStateChanged,
                detail: String::from("the target is not in the endpoint's last-known projection"),
            });
        }
        if entry.is_expired(now) {
            return Ok(OfferDecision::Reject {
                reason: OperationRejectedReason::Expired,
                detail: String::from("the offer expired before it could be applied"),
            });
        }
        Ok(OfferDecision::Accept { command })
    }

    /// Decodes the offer's typed command payload; an undecodable command is
    /// the `InvalidCommand` rejection.
    fn parse_command(offer: &OperationOffer) -> Result<RedfishCommand, OfferDecision> {
        serde_json::from_slice(&offer.command_json).map_err(|_| OfferDecision::Reject {
            reason: OperationRejectedReason::InvalidCommand,
            detail: String::from("the command payload is not a valid RedfishCommand"),
        })
    }

    /// Answers a duplicate offer whose stored entry is still being
    /// processed: the persisted operation (created with the offer's id)
    /// carries the current state. When no operation exists, the acceptance
    /// never happened — the crash window between the inbox insert and the
    /// operation create — and the rechecks run again.
    async fn reply_to_in_progress_duplicate(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        let operation_id = entry.operation_id();
        let Some(operation) = self
            .store
            .find_operation(operation_id)
            .await
            .map_err(CenterSyncError::Operation)?
        else {
            return self.decide_and_record(offer, entry, endpoint_id, now).await;
        };
        if operation.state().is_terminal() {
            self.enqueue_outbox_entry(EnvelopeMessage::OperationCompleted(
                rutilus_center_protocol::OperationCompleted {
                    operation_id: operation_id.to_string(),
                    succeeded: operation.state() == OperationState::Succeeded,
                    summary: operation.state().as_str().to_owned(),
                },
            ))
            .await?;
            // The terminal report closes the inbox lifecycle; a `Received`
            // entry (the crash window) advances through `Accepted` first.
            self.inbox
                .advance(operation_id, InboxEvent::Accepted)
                .await
                .map_err(CenterSyncError::Inbox)?;
            self.inbox
                .advance(operation_id, InboxEvent::Completed)
                .await
                .map_err(CenterSyncError::Inbox)?;
        } else {
            self.enqueue_outbox_entry(EnvelopeMessage::OperationProgress(
                rutilus_center_protocol::OperationProgress {
                    operation_id: operation_id.to_string(),
                    state: operation.state().as_str().to_owned(),
                    detail: String::from("duplicate offer; the operation is already in progress"),
                },
            ))
            .await?;
        }
        Ok(OfferOutcome::DuplicateProgress)
    }

    /// Answers a duplicate offer whose stored entry already finished. The
    /// original rejection reason is not persisted, so a rejected duplicate
    /// re-runs the rechecks for a current reason and falls back to a generic
    /// refusal when the situation changed; a completed duplicate is answered
    /// from the persisted operation's outcome.
    async fn reply_to_resolved_duplicate(
        &self,
        offer: &OperationOffer,
        entry: &InboxEntry,
        endpoint_id: EndpointId,
        state: InboxEntryState,
        now: OffsetDateTime,
    ) -> Result<OfferOutcome, CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        let operation_id = entry.operation_id();
        match state {
            InboxEntryState::Rejected => {
                let (reason, detail) =
                    match self.decide_offer(offer, entry, endpoint_id, now).await? {
                        OfferDecision::Accept { .. } => (
                            OperationRejectedReason::Unspecified,
                            String::from("the offer was already rejected and cannot be revived"),
                        ),
                        OfferDecision::Reject { reason, detail } => (reason, detail),
                    };
                self.enqueue_outbox_entry(EnvelopeMessage::OperationRejected(
                    rutilus_center_protocol::OperationRejected {
                        operation_id: operation_id.to_string(),
                        reason: reason as i32,
                        detail: detail.clone(),
                    },
                ))
                .await?;
                Ok(OfferOutcome::Rejected { reason, detail })
            }
            InboxEntryState::Completed => {
                let operation = self
                    .store
                    .find_operation(operation_id)
                    .await
                    .map_err(CenterSyncError::Operation)?;
                let (succeeded, summary) = match operation {
                    Some(operation) => (
                        operation.state() == OperationState::Succeeded,
                        operation.state().as_str().to_owned(),
                    ),
                    None => (false, String::from("the recorded outcome is unavailable")),
                };
                self.enqueue_outbox_entry(EnvelopeMessage::OperationCompleted(
                    rutilus_center_protocol::OperationCompleted {
                        operation_id: operation_id.to_string(),
                        succeeded,
                        summary,
                    },
                ))
                .await?;
                Ok(OfferOutcome::DuplicateProgress)
            }
            // The domain maps in-progress states to `DuplicateInProgress`,
            // so these arms are the defensive floor for a corrupt repository.
            InboxEntryState::Received | InboxEntryState::Accepted => {
                self.reply_to_in_progress_duplicate(offer, entry, endpoint_id, now)
                    .await
            }
        }
    }

    /// Reports the state of every center-sourced operation to the center:
    /// an active operation queues an `OperationProgress` frame, a terminal
    /// one queues `OperationCompleted` and closes the inbox lifecycle. The
    /// inbox state machine makes the report idempotent — terminal entries
    /// are skipped on the next connection.
    async fn report_center_operations(
        &self,
    ) -> Result<(), CenterSyncErrorOf<Transport, Store, Outbox, Inbox>> {
        let operations = self
            .store
            .list_operations(None)
            .await
            .map_err(CenterSyncError::Operation)?;
        for operation in operations {
            if operation.source() != OperationSource::Center {
                continue;
            }
            let operation_id = operation.id();
            let Some(entry) = self
                .inbox
                .find_by_operation(operation_id)
                .await
                .map_err(CenterSyncError::Inbox)?
            else {
                continue;
            };
            if entry.state().is_terminal() {
                continue;
            }
            if entry.state() == InboxEntryState::Received {
                // The operation exists, so the offer was accepted before a
                // crash interrupted the record; repair it and report.
                self.inbox
                    .advance(operation_id, InboxEvent::Accepted)
                    .await
                    .map_err(CenterSyncError::Inbox)?;
            }
            if operation.state().is_terminal() {
                self.enqueue_outbox_entry(EnvelopeMessage::OperationCompleted(
                    rutilus_center_protocol::OperationCompleted {
                        operation_id: operation_id.to_string(),
                        succeeded: operation.state() == OperationState::Succeeded,
                        summary: operation.state().as_str().to_owned(),
                    },
                ))
                .await?;
                self.inbox
                    .advance(operation_id, InboxEvent::Completed)
                    .await
                    .map_err(CenterSyncError::Inbox)?;
            } else {
                self.enqueue_outbox_entry(EnvelopeMessage::OperationProgress(
                    rutilus_center_protocol::OperationProgress {
                        operation_id: operation_id.to_string(),
                        state: operation.state().as_str().to_owned(),
                        detail: String::new(),
                    },
                ))
                .await?;
            }
        }
        Ok(())
    }

    /// Handles one inbound envelope from the center. The reliable outbox
    /// (acknowledgements) and the operation offers arrive in later slices;
    /// every other message — and every message this build does not act on —
    /// is logged and absorbed so a future protocol message never kills the
    /// connection.
    fn dispatch_inbound(&self, envelope: Envelope) {
        match envelope.message {
            Some(EnvelopeMessage::Heartbeat(_)) => {}
            Some(message) => {
                eprintln!(
                    "site {}: center frame {} carries an unhandled message: {message:?}",
                    self.instance_id, envelope.sequence
                );
            }
            None => {
                eprintln!(
                    "site {}: center frame {} carries no message",
                    self.instance_id, envelope.sequence
                );
            }
        }
    }
}

/// A controlled failure of one step of the site-to-center synchronization.
///
/// The engine's `run` loop absorbs every variant — the connection is
/// retried after the §15.4 backoff — so this error type is the surface of
/// the engine's internal steps and of the runtime's final log line, not a
/// reason to stop the site.
#[derive(Debug, Error)]
pub enum CenterSyncError<
    TransportError,
    OperationStoreError,
    EndpointError,
    CapabilityError,
    CredentialError,
    InventoryError,
    OutboxError,
    InboxError,
> where
    TransportError: Error + 'static,
    OperationStoreError: Error + 'static,
    EndpointError: Error + 'static,
    CapabilityError: Error + 'static,
    CredentialError: Error + 'static,
    InventoryError: Error + 'static,
    OutboxError: Error + 'static,
    InboxError: Error + 'static,
{
    /// The transport boundary failed; carries the transport's own error.
    #[error("the center transport failed: {0}")]
    Transport(#[source] TransportError),
    /// The operation store boundary failed; carries the repository's own
    /// error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationStoreError),
    /// The endpoint lookup boundary failed; carries the repository's own
    /// error.
    #[error("the endpoint lookup failed: {0}")]
    Endpoint(#[source] EndpointError),
    /// The capability pre-check (§15.6) could not be evaluated; carries the
    /// query's own error.
    #[error("the capability query failed: {0}")]
    Capability(#[source] EndpointCapabilityQueryError<CapabilityError>),
    /// The credential inventory boundary failed; carries the repository's
    /// own error.
    #[error("the credential inventory failed: {0}")]
    Credential(#[source] CredentialError),
    /// The target-state pre-check (§15.6) could not be evaluated; carries
    /// the query's own error.
    #[error("the endpoint inventory failed: {0}")]
    Inventory(#[source] EndpointInventoryQueryError<InventoryError>),
    /// The durable outbox boundary failed; carries the repository's own
    /// error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
    /// The durable inbox boundary failed; carries the repository's own
    /// error.
    #[error("the center inbox failed: {0}")]
    Inbox(#[source] InboxError),
    /// A wire message could not be serialized into its §9.4 payload record.
    #[error("the message could not be serialized into its payload record: {0}")]
    Payload(#[source] serde_json::Error),
    /// The center closed the connection.
    #[error("the center closed the connection")]
    Closed,
    /// A stored outbox payload is not the §9.4 typed serialization of an
    /// envelope; the row is corrupt.
    #[error("stored outbox entry {entry_id} is not a valid envelope payload: {source}")]
    InvalidOutboxPayload {
        entry_id: OutboxEntryId,
        #[source]
        source: serde_json::Error,
    },
    /// A stored sequence cannot be represented on the wire.
    #[error("outbox sequence {sequence} cannot be represented on the wire")]
    SequenceOverflow { sequence: i64 },
}

/// The concrete failure type of one engine step: every boundary error, in
/// [`CenterSyncError`] variant order.
type CenterSyncErrorOf<Transport, Store, Outbox, Inbox> = CenterSyncError<
    <Transport as CenterTransport>::Error,
    <Store as OperationStore>::Error,
    <Store as EndpointRefreshRepository>::Error,
    <Store as CapabilityQueryRepository>::Error,
    <Store as CredentialInventoryRepository>::Error,
    <Store as EndpointInventoryRepository>::Error,
    <Outbox as CenterOutbox>::Error,
    <Inbox as CenterInbox>::Error,
>;

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rutilus_center_protocol::{Ack, EnvelopeMessage, OperationOffer, OperationRejectedReason};
    use rutilus_domain::{
        BatchOperation, BatchOperationId, Credential, CredentialId, CredentialName,
        CredentialUsername, CredentialVersionId, Endpoint, EndpointAddress, EndpointCapability,
        EndpointDisplayName, EndpointId, InboxEntryState, Operation, OperationId, OperationState,
        OutboxEntryState, RedfishCommand, RefreshGeneration, ResetType, ResourceFeature,
        ResourceId, ResourceODataId, ResourceSnapshot, ResourceSnapshotPayload, SystemCommand,
        TlsCertificate, TlsTrust, decide_inbox_duplicate,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild, OperationStore,
    };
    use time::OffsetDateTime;
    use tokio::sync::mpsc;

    use super::*;
    use crate::{
        CapabilityQueryRepository, CredentialInventoryRepository, EndpointInventoryItem,
        EndpointInventoryRepository, EndpointRefreshRepository, StoredCapability,
        center_transport::test_support::{ChannelSession, ChannelTransport, MockCenterError},
    };
    /// The test-side wire ends of one scripted session: the frames the
    /// engine sent and the feed that delivers the frames the engine
    /// receives.
    #[derive(Debug)]
    struct Wire {
        outbound: mpsc::UnboundedReceiver<Envelope>,
        inbound: mpsc::UnboundedSender<Envelope>,
    }

    /// The shared script state of a [`ScriptedTransport`]: the engine owns
    /// the transport, so the test keeps a clone of this state to observe the
    /// connect attempts.
    struct ScriptedState {
        attempts: AtomicUsize,
        fail_until: usize,
    }

    impl ScriptedState {
        fn new(fail_until: usize) -> Self {
            Self {
                attempts: AtomicUsize::new(0),
                fail_until,
            }
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    /// A transport whose connect attempts fail on script and whose sessions
    /// hand their wire ends to the test. The engine takes it by value, so
    /// the test observes the shared state.
    struct ScriptedTransport {
        state: Arc<ScriptedState>,
        wires: mpsc::UnboundedSender<Wire>,
    }

    impl ScriptedTransport {
        fn new(fail_until: usize) -> (Self, Arc<ScriptedState>, mpsc::UnboundedReceiver<Wire>) {
            let state = Arc::new(ScriptedState::new(fail_until));
            let (wires, receiver) = mpsc::unbounded_channel();
            (
                Self {
                    state: Arc::clone(&state),
                    wires,
                },
                state,
                receiver,
            )
        }
    }

    impl CenterTransport for ScriptedTransport {
        type Session = ChannelSession;
        type Error = MockCenterError;

        fn connect(&self) -> crate::BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
            Box::pin(async move {
                let attempt = self.state.attempts.fetch_add(1, Ordering::SeqCst) + 1;
                if attempt <= self.state.fail_until {
                    return Err(MockCenterError);
                }
                let (session, outbound, inbound) = ChannelSession::channel();
                let _ = self.wires.send(Wire { outbound, inbound });
                Ok(session)
            })
        }
    }

    /// A mock store error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock store never fails")]
    struct MockStoreError;

    /// An in-memory store behind the engine's persistence boundaries:
    /// operations, endpoint lookup, capabilities, credentials, endpoint
    /// inventory, and artifacts. Every operation succeeds.
    struct MockEngineStore {
        operations: Mutex<HashMap<OperationId, Operation>>,
        endpoints: Mutex<HashMap<EndpointId, Endpoint>>,
        capabilities: Mutex<HashMap<EndpointId, Vec<StoredCapability>>>,
        credentials: Mutex<Vec<Credential>>,
        inventory: Mutex<Vec<EndpointInventoryItem>>,
    }

    impl MockEngineStore {
        fn new() -> Self {
            Self {
                operations: Mutex::new(HashMap::new()),
                endpoints: Mutex::new(HashMap::new()),
                capabilities: Mutex::new(HashMap::new()),
                credentials: Mutex::new(Vec::new()),
                inventory: Mutex::new(Vec::new()),
            }
        }

        fn set_endpoint(&self, endpoint: Endpoint) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.endpoints
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .insert(endpoint.id(), endpoint);
            Ok(())
        }

        fn set_capability(
            &self,
            endpoint_id: EndpointId,
            observation: rutilus_domain::EndpointCapabilityObservation,
            observed_at: OffsetDateTime,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.capabilities
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .entry(endpoint_id)
                .or_default()
                .push(StoredCapability::new(observation, observed_at));
            Ok(())
        }

        fn set_credential(
            &self,
            credential: Credential,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.credentials
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .push(credential);
            Ok(())
        }

        fn set_inventory(
            &self,
            item: EndpointInventoryItem,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            self.inventory
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .push(item);
            Ok(())
        }

        fn find_operation_owned(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<Operation>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .operations
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .get(&operation_id)
                .cloned())
        }

        fn operations_owned(&self) -> Result<Vec<Operation>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .operations
                .lock()
                .map_err(|_| std::io::Error::other("the mock store lock was poisoned"))?
                .values()
                .cloned()
                .collect())
        }
    }

    impl OperationStore for MockEngineStore {
        type Error = MockStoreError;

        fn create_operation<'a>(
            &'a self,
            operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.operations
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
                let mut rows = self.operations.lock().map_err(|_| MockStoreError)?;
                let row = rows.get(&operation_id).ok_or(MockStoreError)?.clone();
                if row.is_terminal() {
                    return Err(MockStoreError);
                }
                rows.insert(
                    operation_id,
                    Operation::try_from_parts(
                        row.id(),
                        row.source(),
                        row.targets().to_vec(),
                        row.command(),
                        new_state,
                        row.created_at(),
                        occurred_at,
                    )
                    .map_err(|_| MockStoreError)?,
                );
                Ok(())
            })
        }

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: rutilus_domain::FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move { Ok(()) })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .operations
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .values()
                    .filter(|operation| state.is_none_or(|state| operation.state() == state))
                    .cloned()
                    .collect())
            })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The center-sync engine never creates batches; unreachable.
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

    impl EndpointRefreshRepository for MockEngineStore {
        type Error = MockStoreError;

        fn find_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> crate::BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .endpoints
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&endpoint_id)
                    .cloned())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [crate::ResourceObservation],
            _observed_at: OffsetDateTime,
        ) -> crate::BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    impl CapabilityQueryRepository for MockEngineStore {
        type Error = MockStoreError;

        fn find_endpoint_capabilities(
            &self,
            endpoint_id: EndpointId,
        ) -> crate::BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .capabilities
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&endpoint_id)
                    .cloned())
            })
        }
    }

    impl CredentialInventoryRepository for MockEngineStore {
        type Error = MockStoreError;

        fn list_credentials(
            &self,
        ) -> crate::BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
            Box::pin(
                async move { Ok(self.credentials.lock().map_err(|_| MockStoreError)?.clone()) },
            )
        }
    }

    impl EndpointInventoryRepository for MockEngineStore {
        type Error = MockStoreError;

        fn list_endpoint_inventory(
            &self,
        ) -> crate::BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async move { Ok(self.inventory.lock().map_err(|_| MockStoreError)?.clone()) })
        }
    }

    /// An in-memory [`CenterInbox`] mirroring the persistence contract: the
    /// operation id is the idempotency key and the state machine is the
    /// domain `InboxEntry`. Every operation succeeds.
    struct MockInbox {
        entries: Mutex<HashMap<OperationId, InboxEntry>>,
    }

    impl MockInbox {
        fn new() -> Self {
            Self {
                entries: Mutex::new(HashMap::new()),
            }
        }

        fn entry_state(
            &self,
            operation_id: OperationId,
        ) -> Result<Option<InboxEntryState>, Box<dyn Error + Send + Sync>> {
            Ok(self
                .entries
                .lock()
                .map_err(|_| std::io::Error::other("the mock inbox lock was poisoned"))?
                .get(&operation_id)
                .map(InboxEntry::state))
        }
    }

    impl CenterInbox for MockInbox {
        type Error = MockStoreError;

        fn insert<'a>(
            &'a self,
            entry: &'a InboxEntry,
        ) -> crate::BoundaryFuture<'a, Result<InboxInsertOutcome, Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockStoreError)?;
                let existing = entries.get(&entry.operation_id()).map(InboxEntry::state);
                match decide_inbox_duplicate(existing) {
                    rutilus_domain::IdempotencyDecision::Proceed => {
                        entries.insert(entry.operation_id(), entry.clone());
                        Ok(InboxInsertOutcome::Created)
                    }
                    rutilus_domain::IdempotencyDecision::InProgress => {
                        Ok(InboxInsertOutcome::DuplicateInProgress)
                    }
                    rutilus_domain::IdempotencyDecision::AlreadyResolved(state) => {
                        Ok(InboxInsertOutcome::DuplicateResolved(state))
                    }
                }
            })
        }

        fn find_by_operation(
            &self,
            operation_id: OperationId,
        ) -> crate::BoundaryFuture<'_, Result<Option<InboxEntry>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .entries
                    .lock()
                    .map_err(|_| MockStoreError)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn advance(
            &self,
            operation_id: OperationId,
            event: InboxEvent,
        ) -> crate::BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockStoreError)?;
                if let Some(entry) = entries.get_mut(&operation_id) {
                    let _ = entry.apply(event);
                }
                Ok(())
            })
        }
    }

    /// A fixed clock for the engine tests.
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn engine_options() -> CenterSyncOptions {
        CenterSyncOptions {
            heartbeat_interval: Duration::from_millis(20),
            reconnect_after: Duration::from_millis(20),
            flush_limit: 64,
        }
    }

    /// A mock outbox error that cannot occur: every mock operation succeeds.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
    #[error("a mock outbox never fails")]
    struct MockOutboxError;

    /// An in-memory [`CenterOutbox`] mirroring the persistence contract:
    /// sequences allocated as max plus one, pending listing in sequence
    /// order, and idempotent acknowledgements. The mock never fails.
    struct MockOutbox {
        entries: Arc<Mutex<Vec<OutboxEntry>>>,
        instance_id: InstanceId,
    }

    impl MockOutbox {
        fn new(instance_id: InstanceId) -> Self {
            Self {
                entries: Arc::new(Mutex::new(Vec::new())),
                instance_id,
            }
        }

        /// Enqueues `count` heartbeat messages with sent-at times 1..=count,
        /// the same shape the flush tests assert on the wire.
        fn enqueue_heartbeats(
            &self,
            count: u64,
            now: OffsetDateTime,
        ) -> Result<(), Box<dyn Error + Send + Sync>> {
            for index in 1..=count {
                let sequence = {
                    let mut entries = self
                        .entries
                        .lock()
                        .map_err(|_| std::io::Error::other("the mock outbox lock was poisoned"))?;
                    let next = entries.iter().map(OutboxEntry::sequence).max().unwrap_or(0) + 1;
                    let envelope = Envelope {
                        sequence: u64::try_from(next).map_err(|_| {
                            std::io::Error::other("the mock outbox sequence overflowed")
                        })?,
                        acked_sequence: 0,
                        message: Some(EnvelopeMessage::Heartbeat(Heartbeat {
                            sent_at_unix: i64::try_from(index).map_err(|_| {
                                std::io::Error::other("the mock heartbeat time overflowed")
                            })?,
                        })),
                    };
                    let entry = OutboxEntry::new(
                        OutboxEntryId::generate(),
                        self.instance_id,
                        next,
                        serde_json::to_string(&envelope)?,
                        now,
                    );
                    entries.push(entry);
                    next
                };
                let _ = sequence;
            }
            Ok(())
        }

        /// The pending messages, in sequence order, decoded from their §9.4
        /// payload records.
        fn pending_messages(&self) -> Result<Vec<EnvelopeMessage>, Box<dyn Error + Send + Sync>> {
            let entries = self
                .entries
                .lock()
                .map_err(|_| std::io::Error::other("the mock outbox lock was poisoned"))?;
            let mut pending = entries
                .iter()
                .filter(|entry| entry.state() == OutboxEntryState::Pending)
                .cloned()
                .collect::<Vec<_>>();
            pending.sort_by_key(OutboxEntry::sequence);
            let mut messages = Vec::with_capacity(pending.len());
            for entry in pending {
                let envelope: Envelope = serde_json::from_str(entry.payload_json())?;
                if let Some(message) = envelope.message {
                    messages.push(message);
                }
            }
            Ok(messages)
        }
    }

    impl CenterOutbox for MockOutbox {
        type Error = MockOutboxError;

        fn enqueue<'a>(
            &'a self,
            instance_id: InstanceId,
            message: &'a EnvelopeMessage,
            created_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<OutboxEntry, Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockOutboxError)?;
                let next = entries.iter().map(OutboxEntry::sequence).max().unwrap_or(0) + 1;
                let envelope = Envelope {
                    sequence: u64::try_from(next).map_err(|_| MockOutboxError)?,
                    acked_sequence: 0,
                    message: Some(message.clone()),
                };
                let entry = OutboxEntry::new(
                    OutboxEntryId::generate(),
                    instance_id,
                    next,
                    serde_json::to_string(&envelope).map_err(|_| MockOutboxError)?,
                    created_at,
                );
                entries.push(entry.clone());
                Ok(entry)
            })
        }

        fn list_pending(
            &self,
            instance_id: InstanceId,
            limit: u64,
        ) -> BoundaryFuture<'_, Result<Vec<OutboxEntry>, Self::Error>> {
            Box::pin(async move {
                let entries = self.entries.lock().map_err(|_| MockOutboxError)?;
                let mut pending = entries
                    .iter()
                    .filter(|entry| {
                        entry.instance_id() == instance_id
                            && entry.state() == OutboxEntryState::Pending
                    })
                    .cloned()
                    .collect::<Vec<_>>();
                pending.sort_by_key(OutboxEntry::sequence);
                pending.truncate(usize::try_from(limit).map_err(|_| MockOutboxError)?);
                Ok(pending)
            })
        }

        fn acknowledge(
            &self,
            entry_id: OutboxEntryId,
            acked_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut entries = self.entries.lock().map_err(|_| MockOutboxError)?;
                for entry in &mut *entries {
                    if entry.id() == entry_id && entry.state() == OutboxEntryState::Pending {
                        let _ = entry.ack(acked_at);
                    }
                }
                Ok(())
            })
        }
    }

    /// Awaits the wire ends of the next established session.
    async fn next_wire(wires: &mut mpsc::UnboundedReceiver<Wire>) -> Result<Wire, Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(5), wires.recv())
            .await
            .map_err(|_| std::io::Error::other("no session was established"))?
            .ok_or_else(|| std::io::Error::other("the scripted transport ended").into())
    }

    /// Awaits the next frame the engine sent on the session.
    async fn next_frame(wire: &mut Wire) -> Result<Envelope, Box<dyn Error>> {
        tokio::time::timeout(Duration::from_secs(5), wire.outbound.recv())
            .await
            .map_err(|_| std::io::Error::other("no frame arrived in time"))?
            .ok_or_else(|| std::io::Error::other("the session ended early").into())
    }

    /// Awaits the next outbox content frame, skipping liveness heartbeats.
    async fn next_outbox_frame(wire: &mut Wire) -> Result<Envelope, Box<dyn Error>> {
        loop {
            let envelope = next_frame(wire).await?;
            if envelope.sequence != 0 {
                return Ok(envelope);
            }
        }
    }

    #[tokio::test]
    async fn heartbeats_are_sent_while_connected_and_stop_exits_promptly()
    -> Result<(), Box<dyn Error>> {
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
                InstanceId::generate(),
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;

        // Heartbeats arrive roughly every 20 ms; each carries sequence 0
        // (a liveness frame, never an outbox message).
        let mut heartbeats_seen = 0;
        while heartbeats_seen < 2 {
            let envelope = next_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, 0);
            match envelope.message {
                Some(EnvelopeMessage::Heartbeat(_)) => heartbeats_seen += 1,
                Some(other) => {
                    return Err(std::io::Error::other(format!(
                        "expected a Heartbeat, got {other:?}"
                    ))
                    .into());
                }
                None => {
                    return Err(
                        std::io::Error::other("the heartbeat frame carried no message").into(),
                    );
                }
            }
        }

        // The stop signal drains the engine promptly, mid-connection.
        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_connects_keep_the_site_local_and_the_loop_alive() -> Result<(), Box<dyn Error>>
    {
        // The first three attempts fail — a scripted stand-in for a center
        // that rejects the §15.3 negotiation or is unreachable.
        let (transport, state, mut wires) = ScriptedTransport::new(3);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
                InstanceId::generate(),
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        // The fourth attempt succeeds; until then the loop kept retrying
        // with the backoff instead of exiting.
        let wire = next_wire(&mut wires).await?;
        assert_eq!(state.attempts(), 4);
        drop(wire);

        // The engine still answers the stop signal after the connection
        // ended and the loop moved back into the backoff.
        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_closed_connection_reconnects_after_the_backoff() -> Result<(), Box<dyn Error>> {
        let (transport, state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
                InstanceId::generate(),
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let first = next_wire(&mut wires).await?;
        // Closing the first session (the center disconnected) must lead to a
        // second connect after the backoff.
        let Wire { outbound, inbound } = first;
        drop(outbound);
        drop(inbound);

        let _second = next_wire(&mut wires).await?;
        assert_eq!(state.attempts(), 2);

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_flush_sends_pending_entries_in_sequence_order() -> Result<(), Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // The offline queue: three messages enqueued while the site has
            // no connection. The flush must deliver them in sequence order.
            outbox.enqueue_heartbeats(3, now)?;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        let mut messages = Vec::new();
        for _ in 0..3 {
            let envelope = next_outbox_frame(&mut wire).await?;
            messages.push(envelope.sequence);
            let Some(EnvelopeMessage::Heartbeat(heartbeat)) = envelope.message else {
                return Err(std::io::Error::other(
                    "the flushed frame was not the enqueued message",
                )
                .into());
            };
            assert_eq!(
                heartbeat.sent_at_unix,
                i64::try_from(envelope.sequence)
                    .map_err(|_| std::io::Error::other("the wire sequence overflowed"))?
            );
        }
        assert_eq!(messages, vec![1, 2, 3]);

        // The flush acknowledged nothing yet: after a reconnect, the same
        // three entries are re-sent (at-least-once delivery).
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);
        let mut second = next_wire(&mut wires).await?;
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut second).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn acks_advance_the_outbox_and_the_resume_starts_after_them() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            outbox.enqueue_heartbeats(3, now)?;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                FixedClock(now),
                instance_id,
                engine_options(),
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2, 3] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        // The center acknowledges only the first sequence. After a
        // disconnect, the flush must resume from the last acknowledgement
        // (§15.4): only sequences 2 and 3 are re-sent.
        wire.inbound
            .send(Envelope {
                sequence: 10,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 1 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let Wire { outbound, inbound } = wire;
        drop(outbound);
        drop(inbound);

        let mut second = next_wire(&mut wires).await?;
        for sequence in [2, 3] {
            let envelope = next_outbox_frame(&mut second).await?;
            assert_eq!(envelope.sequence, sequence);
        }

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }

    /// Builds one endpoint bound to the given credential.
    fn managed_endpoint(
        credential_id: CredentialId,
        now: OffsetDateTime,
    ) -> Result<Endpoint, Box<dyn Error + Send + Sync>> {
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Rack A BMC")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"offer test certificate".to_vec())?,
                trusted_at: now,
            },
            credential_id,
            now,
            now,
        )?)
    }

    /// Builds one stored credential.
    fn managed_credential(now: OffsetDateTime) -> Result<Credential, Box<dyn Error + Send + Sync>> {
        Ok(Credential::try_new(
            CredentialId::generate(),
            CredentialName::parse("admin")?,
            CredentialUsername::parse("root")?,
            CredentialVersionId::generate(),
            now,
            now,
        )?)
    }

    /// Builds a one-generation endpoint inventory whose projection contains
    /// the offer target `/redfish/v1/Systems/1`.
    fn inventory_with_target(
        endpoint: &Endpoint,
        now: OffsetDateTime,
    ) -> Result<EndpointInventoryItem, Box<dyn Error + Send + Sync>> {
        let generation = RefreshGeneration::new(1)?;
        let service_root = ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint.id(),
            ResourceFeature::ServiceRoot,
            ResourceODataId::parse("/redfish/v1")?,
            ResourceSnapshotPayload::parse(r#"{"@odata.id":"/redfish/v1"}"#)?,
            now,
            generation,
        );
        let system = ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint.id(),
            ResourceFeature::Systems,
            ResourceODataId::parse("/redfish/v1/Systems/1")?,
            ResourceSnapshotPayload::parse(r#"{"@odata.id":"/redfish/v1/Systems/1"}"#)?,
            now,
            generation,
        );
        Ok(EndpointInventoryItem::try_new(
            endpoint.clone(),
            vec![service_root, system],
        )?)
    }

    /// Builds one operation offer for this site and the received envelope
    /// that carried it.
    fn offer_for(
        instance_id: InstanceId,
        endpoint_id: EndpointId,
        expires_at_unix: i64,
    ) -> Result<(OperationOffer, Envelope), Box<dyn Error + Send + Sync>> {
        let offer = OperationOffer {
            operation_id: OperationId::generate().to_string(),
            endpoint_id: endpoint_id.to_string(),
            site_id: instance_id.to_string(),
            command_json: serde_json::to_vec(&RedfishCommand::System(SystemCommand::Reset(
                ResetType::PowerCycle,
            )))?,
            target: String::from("/redfish/v1/Systems/1"),
            expires_at_unix,
            actor_context: String::from("principal-7"),
        };
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer.clone())),
        };
        Ok((offer, received))
    }

    /// The full §15.6 setup: a managed endpoint with a stored credential, a
    /// `Supported` capability observation, and an inventory containing the
    /// offer target.
    fn fully_prepared_store(
        now: OffsetDateTime,
    ) -> Result<(MockEngineStore, Endpoint), Box<dyn Error + Send + Sync>> {
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        store.set_credential(credential)?;
        store.set_inventory(inventory_with_target(&endpoint, now)?)?;
        Ok((store, endpoint))
    }

    /// Constructs the engine over the mocks, all borrowed so the test keeps
    /// inspecting them.
    fn engine_over<'a>(
        store: &'a MockEngineStore,
        outbox: &'a MockOutbox,
        inbox: &'a MockInbox,
        instance_id: InstanceId,
        now: OffsetDateTime,
    ) -> CenterSync<
        &'a ChannelTransport,
        &'a MockEngineStore,
        &'a MockOutbox,
        &'a MockInbox,
        FixedClock,
    > {
        static TRANSPORT: ChannelTransport = ChannelTransport;
        CenterSync::new(
            &TRANSPORT,
            store,
            outbox,
            inbox,
            FixedClock(now),
            instance_id,
            engine_options(),
        )
    }

    /// Handles one offer against a prepared store and returns the outcome
    /// with the outbox and inbox the engine wrote.
    async fn handle_offer_with(
        store: &MockEngineStore,
        instance_id: InstanceId,
        endpoint_id: EndpointId,
        expires_at_unix: i64,
        now: OffsetDateTime,
    ) -> Result<(OfferOutcome, MockOutbox, MockInbox), Box<dyn Error + Send + Sync>> {
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(store, &outbox, &inbox, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint_id, expires_at_unix)?;
        let outcome = engine.handle_offer(&offer, &received).await?;
        Ok((outcome, outbox, inbox))
    }

    #[tokio::test]
    async fn an_offer_passing_every_recheck_is_accepted_once()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(&store, &outbox, &inbox, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;

        let outcome = engine.handle_offer(&offer, &received).await?;
        assert_eq!(outcome, OfferOutcome::Accepted);

        // The operation is persisted with the offer's stable id, the Center
        // source, and the offer's endpoint as its target.
        let operation_id: OperationId = offer.operation_id.parse()?;
        let operation = store
            .find_operation_owned(operation_id)?
            .ok_or_else(|| std::io::Error::other("the accepted operation is missing"))?;
        assert_eq!(operation.source(), OperationSource::Center);
        assert_eq!(operation.targets().len(), 1);
        assert_eq!(operation.targets()[0].endpoint_id(), endpoint.id());
        assert_eq!(operation.state(), OperationState::Queued);

        // The durable reply is queued and the inbox advanced.
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 1);
        let Some(EnvelopeMessage::OperationAccepted(accepted)) = messages.first() else {
            return Err(std::io::Error::other("the reply was not an OperationAccepted").into());
        };
        assert_eq!(accepted.operation_id, offer.operation_id);
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Accepted)
        );

        // A re-delivered offer is answered with the existing state and never
        // creates a second operation (§15.4 idempotency).
        let duplicate = engine.handle_offer(&offer, &received).await?;
        assert_eq!(duplicate, OfferOutcome::DuplicateProgress);
        assert_eq!(store.operations_owned()?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_endpoint_rejects_with_endpoint_missing()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let store = MockEngineStore::new();
        let (outcome, outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            EndpointId::generate(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::EndpointMissing,
                detail: String::from("the endpoint is no longer managed"),
            }
        );
        let messages = outbox.pending_messages()?;
        let Some(EnvelopeMessage::OperationRejected(rejected)) = messages.first() else {
            return Err(std::io::Error::other("the reply was not an OperationRejected").into());
        };
        assert_eq!(
            rejected.reason,
            OperationRejectedReason::EndpointMissing as i32
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_capability_rejects_with_capability_missing()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        // The endpoint exists but its capability ledger has no observation.
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::CapabilityMissing,
                detail: format!(
                    "the {} capability is not usable",
                    EndpointCapability::Systems
                ),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_missing_credential_rejects_with_credential_invalid()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        // The credential row is gone.
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::CredentialInvalid,
                detail: String::from("the endpoint credential is no longer stored"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_changed_target_rejects_with_target_state_changed()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        let store = MockEngineStore::new();
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        store.set_credential(credential)?;
        // The inventory exists but never contained the offer's target.
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() + 3600,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::TargetStateChanged,
                detail: String::from("the target is not in the endpoint's last-known projection"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_expired_offer_rejects_with_expired() -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        // The offer expired one second before it was handled (§15.6 TTL).
        let (outcome, _outbox, _inbox) = handle_offer_with(
            &store,
            instance_id,
            endpoint.id(),
            now.unix_timestamp() - 1,
            now,
        )
        .await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::Expired,
                detail: String::from("the offer expired before it could be applied"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_undecodable_command_rejects_with_invalid_command()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(&store, &outbox, &inbox, instance_id, now);
        let (mut offer, _received) =
            offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        offer.command_json = b"not a redfish command".to_vec();
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer.clone())),
        };
        let outcome = engine.handle_offer(&offer, &received).await?;
        assert_eq!(
            outcome,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::InvalidCommand,
                detail: String::from("the command payload is not a valid RedfishCommand"),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_offer_for_another_site_is_dropped() -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(&store, &outbox, &inbox, instance_id, now);
        let (mut offer, _received) =
            offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        offer.site_id = InstanceId::generate().to_string();
        let received = Envelope {
            sequence: 1,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::OperationOffer(offer.clone())),
        };
        let outcome = engine.handle_offer(&offer, &received).await?;
        assert_eq!(outcome, OfferOutcome::Dropped);
        assert_eq!(outbox.pending_messages()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicate_of_a_rejected_offer_stays_rejected()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let credential = managed_credential(now)?;
        let endpoint = managed_endpoint(credential.id(), now)?;
        // The store starts without the endpoint: the first delivery is
        // rejected with `EndpointMissing` and the inbox records it.
        let store = MockEngineStore::new();
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(&store, &outbox, &inbox, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        let first = engine.handle_offer(&offer, &received).await?;
        assert!(matches!(first, OfferOutcome::Rejected { .. }));
        let operation_id: OperationId = offer.operation_id.parse()?;
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Rejected)
        );

        // The endpoint appears before the re-delivery; the re-run now passes
        // every recheck, so the duplicate is answered with the generic
        // refusal — the recorded outcome stands and nothing executes.
        store.set_endpoint(endpoint.clone())?;
        store.set_capability(
            endpoint.id(),
            rutilus_domain::EndpointCapabilityObservation::new(
                EndpointCapability::Systems,
                CapabilityState::Supported,
            ),
            now,
        )?;
        store.set_credential(credential)?;
        store.set_inventory(inventory_with_target(&endpoint, now)?)?;
        let second = engine.handle_offer(&offer, &received).await?;
        assert_eq!(
            second,
            OfferOutcome::Rejected {
                reason: OperationRejectedReason::Unspecified,
                detail: String::from("the offer was already rejected and cannot be revived"),
            }
        );
        assert_eq!(store.operations_owned()?.len(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_duplicate_of_a_completed_offer_returns_the_recorded_outcome()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(&store, &outbox, &inbox, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::Accepted
        );
        let operation_id: OperationId = offer.operation_id.parse()?;

        // The operation runs to a terminal outcome.
        store
            .apply_transition(
                operation_id,
                OperationState::Succeeded,
                now + time::Duration::SECOND,
            )
            .await?;

        // The result reporting closes the inbox lifecycle.
        engine.report_center_operations().await?;
        assert_eq!(
            inbox.entry_state(operation_id)?,
            Some(InboxEntryState::Completed)
        );
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        let Some(EnvelopeMessage::OperationCompleted(completed)) = messages.get(1) else {
            return Err(std::io::Error::other("the report was not an OperationCompleted").into());
        };
        assert!(completed.succeeded);

        // A re-delivered offer is answered with the recorded outcome, and
        // the report never repeats itself.
        let duplicate = engine.handle_offer(&offer, &received).await?;
        assert_eq!(duplicate, OfferOutcome::DuplicateProgress);
        engine.report_center_operations().await?;
        assert_eq!(outbox.pending_messages()?.len(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn result_reporting_reports_active_operations_as_progress()
    -> Result<(), Box<dyn Error + Send + Sync>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        let instance_id = InstanceId::generate();
        let (store, endpoint) = fully_prepared_store(now)?;
        let outbox = MockOutbox::new(instance_id);
        let inbox = MockInbox::new();
        let engine = engine_over(&store, &outbox, &inbox, instance_id, now);
        let (offer, received) = offer_for(instance_id, endpoint.id(), now.unix_timestamp() + 3600)?;
        assert_eq!(
            engine.handle_offer(&offer, &received).await?,
            OfferOutcome::Accepted
        );

        // The still-queued operation reports progress, never completion.
        engine.report_center_operations().await?;
        let messages = outbox.pending_messages()?;
        assert_eq!(messages.len(), 2);
        let Some(EnvelopeMessage::OperationProgress(progress)) = messages.get(1) else {
            return Err(std::io::Error::other("the report was not an OperationProgress").into());
        };
        assert_eq!(progress.state, OperationState::Queued.as_str());
        Ok(())
    }

    #[tokio::test]
    async fn a_partial_batch_flushes_again_after_each_acknowledgement() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let store = MockEngineStore::new();
            let inbox = MockInbox::new();
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // Five entries, a flush limit of two: the first connection sends
            // one batch of two, and every acknowledgement frees the next.
            outbox.enqueue_heartbeats(5, now)?;
            let mut options = engine_options();
            options.flush_limit = 2;
            let engine = CenterSync::new(
                transport,
                &store,
                outbox,
                &inbox,
                FixedClock(now),
                instance_id,
                options,
            );
            engine
                .run(async move {
                    let _ = stop_rx.await;
                })
                .await?;
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });

        let mut wire = next_wire(&mut wires).await?;
        for sequence in [1, 2] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // Without an acknowledgement the flush holds: the next frames can
        // only be heartbeats.
        for _ in 0..3 {
            let envelope = next_frame(&mut wire).await?;
            assert_eq!(
                envelope.sequence, 0,
                "the flush must wait for an acknowledgement"
            );
        }
        // One acknowledgement frees exactly the next batch.
        wire.inbound
            .send(Envelope {
                sequence: 20,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 2 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        for sequence in [3, 4] {
            let envelope = next_outbox_frame(&mut wire).await?;
            assert_eq!(envelope.sequence, sequence);
        }
        // Acknowledging the last sent sequence frees the final entry.
        wire.inbound
            .send(Envelope {
                sequence: 21,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 4 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;
        let envelope = next_outbox_frame(&mut wire).await?;
        assert_eq!(envelope.sequence, 5);
        // Acknowledging the tail drains the queue: no further outbox frames.
        wire.inbound
            .send(Envelope {
                sequence: 22,
                acked_sequence: 0,
                message: Some(EnvelopeMessage::Ack(Ack { sequence: 5 })),
            })
            .map_err(|_| std::io::Error::other("the center feed closed"))?;

        stop_tx
            .send(())
            .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
        let stopped = tokio::time::timeout(Duration::from_secs(5), run)
            .await
            .map_err(|_| std::io::Error::other("the engine did not stop in time"))??;
        assert!(
            stopped.is_ok(),
            "the engine must stop cleanly, got {stopped:?}"
        );
        Ok(())
    }
}
