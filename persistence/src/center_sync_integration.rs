//! Integration tests of the site-side center synchronization engine against
//! the real `SqliteStore` (0.7.0 S4).
//!
//! The application crate cannot depend on this crate (the dependency points
//! the other way), so the engine's integration coverage — the real durable
//! outbox behind the mock-transport engine — lives here: a channel-backed
//! mock center drives [`CenterSync`] through its public API while the store
//! keeps the outbox rows. The engine's unit-level tests (heartbeat timing,
//! reconnect backoff, stop draining, batch flushing) live in the
//! application crate against an in-memory outbox.

use std::{error::Error, future::Future, time::Duration};

use rutilus_application::{
    BoundaryFuture, CenterSession, CenterSync, CenterSyncOptions, CenterTransport,
};
use rutilus_center_protocol::{Ack, Envelope, EnvelopeMessage, Heartbeat};
use rutilus_domain::{InstanceId, InstanceKind, OutboxEntry, SiteInstance};
use time::OffsetDateTime;
use tokio::sync::mpsc;

use crate::SqliteStore;

/// A mock center session error that cannot occur: every mock operation
/// succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("a mock center never fails")]
struct MockCenterError;

/// A channel-backed mock center session.
struct MockSession {
    outbound: mpsc::UnboundedSender<Envelope>,
    inbound: mpsc::UnboundedReceiver<Envelope>,
}

impl CenterSession for MockSession {
    type Error = MockCenterError;

    fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            let _ = self.outbound.send(envelope);
            Ok(())
        })
    }

    fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>> {
        Box::pin(async move { Ok(self.inbound.recv().await) })
    }
}

/// The wire ends of one mock session, handed to the test on every connect.
struct Wire {
    outbound: mpsc::UnboundedReceiver<Envelope>,
    inbound: mpsc::UnboundedSender<Envelope>,
}

/// A mock center transport whose sessions hand their wire ends to the test.
struct MockTransport {
    wires: mpsc::UnboundedSender<Wire>,
}

impl MockTransport {
    fn new() -> (Self, mpsc::UnboundedReceiver<Wire>) {
        let (wires, receiver) = mpsc::unbounded_channel();
        (Self { wires }, receiver)
    }
}

impl CenterTransport for MockTransport {
    type Session = MockSession;
    type Error = MockCenterError;

    fn connect(&self) -> BoundaryFuture<'_, Result<Self::Session, Self::Error>> {
        Box::pin(async move {
            let (outbound, outbound_rx) = mpsc::unbounded_channel();
            let (inbound, inbound_rx) = mpsc::unbounded_channel();
            let _ = self.wires.send(Wire {
                outbound: outbound_rx,
                inbound,
            });
            Ok(MockSession {
                outbound,
                inbound: inbound_rx,
            })
        })
    }
}

/// A fixed clock for the engine tests.
struct FixedClock(OffsetDateTime);

impl rutilus_application::Clock for FixedClock {
    fn now(&self) -> OffsetDateTime {
        self.0
    }
}

fn engine_options() -> CenterSyncOptions {
    // The heartbeat stays far below the test's frame timeouts; the seconds
    // unit is intentional (see center-protocol for the same allowance).
    #[allow(clippy::duration_suboptimal_units)]
    let heartbeat_interval = Duration::from_secs(60);
    CenterSyncOptions {
        heartbeat_interval,
        reconnect_after: Duration::from_millis(20),
        flush_limit: 64,
        event_batch_limit: 256,
        artifact_chunk_bytes: 1024 * 1024,
    }
}

/// Awaits the wire ends of the next established session, stepping the
/// engine future while waiting.
async fn next_wire<EngineRun>(
    engine_run: &mut EngineRun,
    wires: &mut mpsc::UnboundedReceiver<Wire>,
) -> Result<Wire, Box<dyn Error>>
where
    EngineRun: Future + Unpin,
    EngineRun::Output: std::fmt::Debug,
{
    tokio::select! {
        result = &mut *engine_run => {
            Err(std::io::Error::other(format!(
                "the engine exited before connecting: {result:?}"
            ))
            .into())
        }
        wire = tokio::time::timeout(Duration::from_secs(5), wires.recv()) => {
            let wire = wire
                .map_err(|_| std::io::Error::other("no session was established"))?
                .ok_or_else(|| std::io::Error::other("the mock transport ended"))?;
            Ok(wire)
        }
    }
}

#[tokio::test]
async fn the_engine_flushes_the_real_outbox_and_resumes_from_the_last_ack()
-> Result<(), Box<dyn Error>> {
    let now = OffsetDateTime::UNIX_EPOCH;
    let directory = tempfile::tempdir()?;
    let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
    let instance_id = InstanceId::generate();
    let site = SiteInstance::new(
        instance_id,
        String::from("Site One"),
        InstanceKind::Site,
        now,
    );
    store.create_instance(&site).await?;

    // The offline queue: three messages enqueued while the site has no
    // connection (§21 0.7.0). The database is the queue.
    for index in 1..=3 {
        store
            .enqueue_outbox_entry(
                instance_id,
                &EnvelopeMessage::Heartbeat(Heartbeat {
                    sent_at_unix: index,
                }),
                now,
            )
            .await?;
    }
    let pending = store.list_pending_outbox(instance_id, 10).await?;
    assert_eq!(
        pending
            .iter()
            .map(OutboxEntry::sequence)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );

    // The engine borrows the store, so it runs inline: the test steps the
    // engine future and the wire in one task.
    let (transport, mut wires) = MockTransport::new();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let engine = CenterSync::new(
        transport,
        &store,
        &store,
        &store,
        &store,
        &store,
        FixedClock(now),
        instance_id,
        engine_options(),
    );
    let mut engine_run = Box::pin(engine.run(async move {
        let _ = stop_rx.await;
    }));

    // The first connection flushes the whole offline queue in sequence order.
    let mut first = next_wire(&mut engine_run, &mut wires).await?;
    for sequence in [1, 2, 3] {
        let envelope = await_engine_or_frame(&mut engine_run, &mut first).await?;
        assert_eq!(envelope.sequence, sequence);
    }
    // The center acknowledges only the first entry, then the connection
    // dies. The reconnect must resume from the last acknowledgement (§15.4).
    first
        .inbound
        .send(Envelope {
            sequence: 10,
            acked_sequence: 0,
            message: Some(EnvelopeMessage::Ack(Ack { sequence: 1 })),
        })
        .map_err(|_| std::io::Error::other("the center feed closed"))?;
    drop(first);

    let mut second = next_wire(&mut engine_run, &mut wires).await?;
    for sequence in [2, 3] {
        let envelope = await_engine_or_frame(&mut engine_run, &mut second).await?;
        assert_eq!(envelope.sequence, sequence);
    }

    // The durable state agrees with the wire: only entry 1 was acknowledged.
    let pending = store.list_pending_outbox(instance_id, 10).await?;
    assert_eq!(
        pending
            .iter()
            .map(OutboxEntry::sequence)
            .collect::<Vec<_>>(),
        vec![2, 3],
        "the acknowledged entry must leave the delivery scan"
    );

    stop_tx
        .send(())
        .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
    let stopped = tokio::time::timeout(Duration::from_secs(5), &mut engine_run)
        .await
        .map_err(|_| std::io::Error::other("the engine did not stop in time"))?;
    assert!(
        stopped.is_ok(),
        "the engine must stop cleanly, got {stopped:?}"
    );
    Ok(())
}

#[tokio::test]
async fn the_engine_keeps_running_locally_while_the_center_is_gone() -> Result<(), Box<dyn Error>> {
    // A center nothing answers: the engine keeps the site local (§4.2,
    // §15.3) — the outbox stays enqueueable and the engine still answers
    // the stop signal.
    let now = OffsetDateTime::UNIX_EPOCH;
    let directory = tempfile::tempdir()?;
    let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
    let instance_id = InstanceId::generate();
    let site = SiteInstance::new(
        instance_id,
        String::from("Site One"),
        InstanceKind::Site,
        now,
    );
    store.create_instance(&site).await?;
    let (transport, mut wires) = MockTransport::new();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let engine = CenterSync::new(
        transport,
        &store,
        &store,
        &store,
        &store,
        &store,
        FixedClock(now),
        instance_id,
        engine_options(),
    );
    let mut engine_run = Box::pin(engine.run(async move {
        let _ = stop_rx.await;
    }));

    // The first connections never answer: drop the session's wire ends on
    // connect, so the engine reconnects forever. While it does, the local
    // site keeps enqueuing through the durable outbox.
    for _ in 0..2 {
        let wire = next_wire(&mut engine_run, &mut wires).await?;
        drop(wire);
        store
            .enqueue_outbox_entry(
                instance_id,
                &EnvelopeMessage::Heartbeat(Heartbeat { sent_at_unix: 1 }),
                now,
            )
            .await?;
    }
    let pending = store.list_pending_outbox(instance_id, 10).await?;
    assert_eq!(pending.len(), 2, "the offline queue must keep the entries");

    stop_tx
        .send(())
        .map_err(|()| std::io::Error::other("the engine stopped before the signal"))?;
    let stopped = tokio::time::timeout(Duration::from_secs(5), &mut engine_run)
        .await
        .map_err(|_| std::io::Error::other("the engine did not stop in time"))?;
    assert!(
        stopped.is_ok(),
        "the engine must stop cleanly, got {stopped:?}"
    );
    Ok(())
}

/// Steps the engine future and the session wire together: the next outbox
/// content frame, or the engine's error if it exits first.
async fn await_engine_or_frame<EngineRun>(
    engine_run: &mut EngineRun,
    wire: &mut Wire,
) -> Result<Envelope, Box<dyn Error>>
where
    EngineRun: Future + Unpin,
    EngineRun::Output: std::fmt::Debug,
{
    loop {
        tokio::select! {
            result = &mut *engine_run => {
                return Err(std::io::Error::other(format!(
                    "the engine exited before the expected frame: {result:?}"
                ))
                .into())
            }
            frame = wire.outbound.recv() => {
                let envelope =
                    frame.ok_or_else(|| std::io::Error::other("the session ended early"))?;
                if envelope.sequence != 0 {
                    return Ok(envelope);
                }
            }
        }
    }
}
