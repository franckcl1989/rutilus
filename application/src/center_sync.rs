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
    Envelope, EnvelopeMessage, Heartbeat, SITE_HEARTBEAT_INTERVAL, SITE_RECONNECT_AFTER,
};
use rutilus_domain::{InstanceId, OutboxEntry, OutboxEntryId};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    BoundaryFuture, Clock,
    center_transport::{CenterSession, CenterTransport},
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
pub struct CenterSync<Transport, Outbox, Time> {
    transport: Transport,
    outbox: Outbox,
    clock: Time,
    instance_id: InstanceId,
    options: CenterSyncOptions,
}

impl<Transport, Outbox, Time> CenterSync<Transport, Outbox, Time>
where
    Transport: CenterTransport,
    Outbox: CenterOutbox,
    Time: Clock,
{
    #[must_use]
    pub const fn new(
        transport: Transport,
        outbox: Outbox,
        clock: Time,
        instance_id: InstanceId,
        options: CenterSyncOptions,
    ) -> Self {
        Self {
            transport,
            outbox,
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
    ) -> Result<OutboxEntry, CenterSyncError<Transport::Error, Outbox::Error>> {
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
    ) -> Result<(), CenterSyncError<Transport::Error, Outbox::Error>>
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
    ) -> Result<(), CenterSyncError<Transport::Error, Outbox::Error>>
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
    ) -> Result<(), CenterSyncError<Session::Error, Outbox::Error>>
    where
        Session: CenterSession,
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
                    match envelope.message {
                        Some(EnvelopeMessage::Ack(ack)) => {
                            self.ack_outbox(ack.sequence, &mut sent).await?;
                            // An acknowledgement frees the next batch: the
                            // flush continues until the queue is empty.
                            self.flush_outbox(&mut session, &mut sent, peer_acked).await?;
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
    ) -> Result<(), CenterSyncError<Session::Error, Outbox::Error>>
    where
        Session: CenterSession,
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
    ///
    /// `TransportError` is the caller's transport error type — the engine's
    /// error enum carries it even though this step never touches the
    /// transport, so the caller's error type flows through unchanged.
    async fn ack_outbox<TransportError>(
        &self,
        acked_sequence: u64,
        sent: &mut VecDeque<(OutboxEntryId, i64)>,
    ) -> Result<(), CenterSyncError<TransportError, Outbox::Error>>
    where
        TransportError: Error + 'static,
    {
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

    /// Handles one inbound envelope from the center. The §15.6 operation
    /// offers arrive in the next slice; every other message — and every
    /// message this build does not act on — is logged and absorbed so a
    /// future protocol message never kills the connection.
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
pub enum CenterSyncError<TransportError, OutboxError>
where
    TransportError: Error + 'static,
    OutboxError: Error + 'static,
{
    /// The transport boundary failed; carries the transport's own error.
    #[error("the center transport failed: {0}")]
    Transport(#[source] TransportError),
    /// The durable outbox boundary failed; carries the repository's own
    /// error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] OutboxError),
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

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rutilus_center_protocol::{Ack, EnvelopeMessage};
    use rutilus_domain::OutboxEntryState;
    use time::OffsetDateTime;
    use tokio::sync::mpsc;

    use super::*;
    use crate::center_transport::test_support::{ChannelSession, MockCenterError};
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
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                outbox,
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
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                outbox,
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
            let outbox = MockOutbox::new(InstanceId::generate());
            let engine = CenterSync::new(
                transport,
                outbox,
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
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // The offline queue: three messages enqueued while the site has
            // no connection. The flush must deliver them in sequence order.
            outbox.enqueue_heartbeats(3, now)?;
            let engine = CenterSync::new(
                transport,
                outbox,
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
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            outbox.enqueue_heartbeats(3, now)?;
            let engine = CenterSync::new(
                transport,
                outbox,
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

    #[tokio::test]
    async fn a_partial_batch_flushes_again_after_each_acknowledgement() -> Result<(), Box<dyn Error>>
    {
        let now = OffsetDateTime::UNIX_EPOCH;
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let instance_id = InstanceId::generate();
            let outbox = MockOutbox::new(instance_id);
            // Five entries, a flush limit of two: the first connection sends
            // one batch of two, and every acknowledgement frees the next.
            outbox.enqueue_heartbeats(5, now)?;
            let mut options = engine_options();
            options.flush_limit = 2;
            let engine = CenterSync::new(transport, outbox, FixedClock(now), instance_id, options);
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
