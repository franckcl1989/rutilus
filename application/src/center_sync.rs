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

use std::{error::Error, future::Future, time::Duration};

use rutilus_center_protocol::{
    Envelope, EnvelopeMessage, Heartbeat, SITE_HEARTBEAT_INTERVAL, SITE_RECONNECT_AFTER,
};
use rutilus_domain::InstanceId;
use thiserror::Error;

use crate::{
    Clock,
    center_transport::{CenterSession, CenterTransport},
};

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
}

impl Default for CenterSyncOptions {
    fn default() -> Self {
        Self {
            heartbeat_interval: SITE_HEARTBEAT_INTERVAL,
            reconnect_after: SITE_RECONNECT_AFTER,
        }
    }
}

/// The site-side center synchronization engine.
///
/// `Transport` is the [`CenterTransport`] boundary (the app crate's
/// `CenterClient` in the runtime slice); `Time` is the caller's monotonic
/// clock, supplied at the boundary exactly like every other use case.
pub struct CenterSync<Transport, Time> {
    transport: Transport,
    clock: Time,
    instance_id: InstanceId,
    options: CenterSyncOptions,
}

impl<Transport, Time> CenterSync<Transport, Time>
where
    Transport: CenterTransport,
    Time: Clock,
{
    #[must_use]
    pub const fn new(
        transport: Transport,
        clock: Time,
        instance_id: InstanceId,
        options: CenterSyncOptions,
    ) -> Self {
        Self {
            transport,
            clock,
            instance_id,
            options,
        }
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
    /// Returns [`CenterSyncError::Transport`] when the transport boundary
    /// fails inside one connection step — the loop then waits out the
    /// backoff and reconnects.
    pub async fn run<Stop>(&self, stop: Stop) -> Result<(), CenterSyncError<Transport::Error>>
    where
        Stop: Future<Output = ()> + Send,
    {
        self.connect_loop(stop).await
    }

    /// The outer connect loop (§15.1, §15.3, §15.4): connect, run the
    /// connection, and on every failure or disconnect wait out the backoff
    /// and try again, until `stop` resolves.
    async fn connect_loop<Stop>(&self, stop: Stop) -> Result<(), CenterSyncError<Transport::Error>>
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

    /// One established connection: the heartbeat loop and the inbound frame
    /// dispatch, until the peer closes the connection, the transport fails,
    /// or `stop` resolves.
    async fn connected_loop<Session, Stop>(
        &self,
        mut session: Session,
        stop: Stop,
    ) -> Result<(), CenterSyncError<Session::Error>>
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
                    self.dispatch_inbound(envelope);
                }
            }
        }
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
pub enum CenterSyncError<TransportError>
where
    TransportError: Error + 'static,
{
    /// The transport boundary failed; carries the transport's own error.
    #[error("the center transport failed: {0}")]
    Transport(#[source] TransportError),
    /// The center closed the connection.
    #[error("the center closed the connection")]
    Closed,
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use rutilus_center_protocol::EnvelopeMessage;
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

    #[tokio::test]
    async fn heartbeats_are_sent_while_connected_and_stop_exits_promptly()
    -> Result<(), Box<dyn Error>> {
        let (transport, _state, mut wires) = ScriptedTransport::new(0);
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
        let run = tokio::spawn(async move {
            let engine = CenterSync::new(
                transport,
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
            let engine = CenterSync::new(
                transport,
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
            let engine = CenterSync::new(
                transport,
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
}
