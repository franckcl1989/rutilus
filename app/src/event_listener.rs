//! The per-endpoint `EventService` listeners (design §14.4 and §7.8).
//!
//! One background task per enrolled endpoint opens the endpoint's
//! `EventService` SSE stream through the [`EventStream`] boundary (implemented
//! over the Redfish gateway) and records every event through the
//! [`EventSink`] seam (wired to the application `EventIngestion` use case,
//! which appends through the repository boundary).
//!
//! # The supervisor: listeners follow the enrolled-endpoint set
//!
//! The [`EventListeners`] supervisor reconciles its listener set against the
//! enrolled-endpoint set on every [`LISTENER_RECONCILE_INTERVAL`] sweep,
//! listed through the [`EndpointLister`] seam. The first sweep fires
//! immediately — the restart recovery, re-arming every endpoint enrolled
//! before the process start — and every later sweep starts a listener for
//! an endpoint enrolled mid-run (the lazy start at enrollment time: no hook
//! in the enrollment path needed, the next sweep picks the endpoint up) and
//! stops the listener of an endpoint that left the enrolled set.
//!
//! # Reconnect discipline
//!
//! Every stream termination — a clean server close, a transport failure, or
//! a failed open — is reconnectable, and reconnection is bounded (design
//! §7.8 有界): consecutive failures back off exponentially from
//! [`EVENT_RECONNECT_BASE_INTERVAL`], doubling per failure up to
//! [`EVENT_RECONNECT_MAX_INTERVAL`], and after
//! [`EVENT_RECONNECT_MAX_ATTEMPTS`] consecutive failures the endpoint's
//! listener gives up, marks its [`ListenerStatus`] `Failed`, and exits. The
//! budget is deliberately generous enough to absorb a typical BMC reboot
//! (the §0.4.0 "BMC 重启后的重连" requirement) — the production waits sum to
//! roughly four minutes — while an endpoint that stays unreachable beyond it
//! is surfaced as failed instead of retrying hot forever. Re-arming failed
//! listeners is a later iteration: the reconciling sweep (above)
//! deliberately does not restart an endpoint whose listener gave up, so the
//! `Failed` state stays terminal within a process run.
//!
//! # Cancellation and drain (design §7.8)
//!
//! Every task holds its own [`StopWatch`] clone. The stop signal is observed
//! at three points: while waiting for the open, while waiting for the next
//! pull, and while sleeping through a backoff. A stop that lands while a
//! pull is pending abandons the pull and then runs the stream boundary's
//! graceful close ([`rutilus_application::EventStreamPull::close`]), so the
//! implementation deletes its transient Session instead of leaking it; a
//! stop during the open or the backoff simply returns. An event already
//! being recorded is never
//! interrupted: the ingest happens outside the `tokio::select!`, so the
//! in-flight event finishes before the task exits (structured drain). The
//! supervisor tracks every task and joins them all on shutdown, so no
//! detached task outlives the store close.
//!
//! # Failure isolation
//!
//! One endpoint's listener failing never touches the others: each task owns
//! its stream, its sink calls, and its status row, and the loop never panics
//! (every fallible call is recorded through `tracing::error!`, the crate's
//! operational-failure precedent). A failed event record does not kill the
//! stream either: the failure is recorded and the next event is consumed —
//! the SSE connection stays healthy, and a later iteration can add buffering.

use std::{
    collections::{HashMap, HashSet},
    error::Error,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use rutilus_application::{
    BoundaryFuture, EventIngestion, EventRepository, EventStream, EventStreamPull, IngestionError,
};
use rutilus_domain::{EndpointId, Event};

use crate::scheduler::{StopSignal, StopWatch};

/// The first reconnect delay after one failed stream attempt (§14.4).
///
/// One second is long enough that a flapping BMC does not make the listener
/// reconnect hot, yet short enough that a moment of downtime costs almost
/// nothing. The exponential growth means the cadence degrades gracefully
/// instead of hammering an unreachable BMC.
pub(crate) const EVENT_RECONNECT_BASE_INTERVAL: Duration = Duration::from_secs(1);

/// How much each consecutive failure stretches the next wait.
pub(crate) const EVENT_RECONNECT_FACTOR: u32 = 2;

/// The longest wait between reconnect attempts (the 间隔上限 of §7.8).
///
/// A minute is the point where further growth only delays the inevitable
/// give-up without improving the reconnect odds; beyond it the cadence stays
/// flat so the budget's sum stays predictable.
// std's `Duration` has no minutes constructor (the lint's `from_mins`
// suggestion is the time crate's), and the sixty-second value is spelled in
// seconds to match the budget sequence documented on
// `EVENT_RECONNECT_MAX_ATTEMPTS`.
#[allow(clippy::duration_suboptimal_units)]
pub(crate) const EVENT_RECONNECT_MAX_INTERVAL: Duration = Duration::from_secs(60);

/// Consecutive failures before an endpoint's listener is marked failed.
///
/// Ten failures with the constants above sum to roughly four minutes of
/// waiting (1+2+4+8+16+30+60+60+60 seconds plus the attempts themselves) —
/// enough to absorb a typical BMC reboot (§0.4.0 "BMC 重启后的重连") — while
/// still surfacing a permanently unreachable endpoint as failed instead of
/// retrying forever.
pub(crate) const EVENT_RECONNECT_MAX_ATTEMPTS: usize = 10;

/// The cadence of one listener-set reconciliation sweep.
///
/// # Why ten seconds
///
/// Each sweep re-lists the enrolled endpoints (one light `SQLite` query) and
/// diffs the listener set against it, so the interval bounds how quickly a
/// freshly enrolled endpoint starts being listened to and a removed one
/// stops. Ten seconds keeps that latency well below what a human notices
/// after enrolling an endpoint, while the sweep's cost stays trivial — the
/// listeners themselves hold the network connections, the sweep only
/// compares sets. A faster cadence would re-run the same diff needlessly
/// often, and a slower one would make a just-enrolled endpoint feel ignored.
pub(crate) const LISTENER_RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

/// The bounded reconnect policy of one endpoint listener (design §7.8).
///
/// The policy is a parameter — not a constant — so the tests can run the
/// listener at a fast cadence, exactly like the scheduler's injected
/// `period`. Production uses [`Default`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReconnectPolicy {
    base_interval: Duration,
    factor: u32,
    max_interval: Duration,
    max_attempts: usize,
}

impl ReconnectPolicy {
    /// The wait before the `failures`-th consecutive retry.
    ///
    /// The `failures`-th consecutive failure (counting from 1) waits
    /// `base × factor^(failures - 1)`, capped at [`Self::max_interval`].
    /// The loop instead of the closed form keeps the arithmetic in
    /// `Duration::checked_mul` and naturally saturates at the cap.
    fn delay(&self, failures: usize) -> Duration {
        let mut delay = self.base_interval;
        let mut applied = 1;
        while applied < failures && delay < self.max_interval {
            delay = delay
                .checked_mul(self.factor)
                .unwrap_or(self.max_interval)
                .min(self.max_interval);
            applied += 1;
        }
        delay
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self {
            base_interval: EVENT_RECONNECT_BASE_INTERVAL,
            factor: EVENT_RECONNECT_FACTOR,
            max_interval: EVENT_RECONNECT_MAX_INTERVAL,
            max_attempts: EVENT_RECONNECT_MAX_ATTEMPTS,
        }
    }
}

/// The observable event-listening state of one endpoint (§14.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ListenerStatus {
    /// The listener is running and consuming the endpoint's stream.
    Listening,
    /// The reconnect budget is exhausted; the endpoint's events are no
    /// longer being consumed until a later iteration re-arms it.
    Failed { reason: String },
}

/// The record seam the listener drives.
///
/// # Why a seam
///
/// Exactly like the scheduler's `OperationDriver`: the listener only needs
/// "record one endpoint event" and must never interpret the use case's
/// verdicts itself. The seam keeps the listener testable with scripted fakes
/// and erases the ingestion error vocabulary into one opaque failure that the
/// listener records and moves on from.
pub(crate) trait EventSink: Send + Sync {
    /// The sink's controlled failure type; only its `Display` is used.
    type Error: Error + Send + Sync + 'static;

    /// Records one endpoint event.
    fn ingest<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>>;
}

impl<Sink> EventSink for &Sink
where
    Sink: EventSink + ?Sized,
{
    type Error = Sink::Error;

    fn ingest<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Sink::ingest(*self, event)
    }
}

/// The application ingestion use case behind the sink seam.
impl<Repository> EventSink for EventIngestion<Repository>
where
    Repository: EventRepository,
{
    type Error = IngestionError<Repository::Error>;

    fn ingest<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(EventIngestion::ingest(self, event.clone()))
    }
}

/// The enrolled-endpoint listing seam of the reconciling supervisor.
///
/// The supervisor re-lists every sweep — unlike a one-shot startup sweep —
/// so an endpoint enrolled mid-run is listened to from the next sweep on and
/// a removed one stops being listened to.
pub(crate) trait EndpointLister: Send + Sync {
    /// The listing's controlled failure type; only its `Display` is used.
    type Error: Error + Send + Sync + 'static;

    /// Lists the ids of every enrolled endpoint.
    fn list_enrolled_endpoints(&self) -> BoundaryFuture<'_, Result<Vec<EndpointId>, Self::Error>>;
}

/// The supervisor of one listener task per enrolled endpoint (§14.4).
///
/// Tracks one [`tokio::task::JoinHandle`] and one per-endpoint stop signal
/// per armed endpoint (design §7.8: every task is tracked and cancellable —
/// never a detached task), keeps the observable [`ListenerStatus`] per
/// endpoint, and joins every task on [`Self::drain_all`] so the runtime can
/// drain the listeners before closing the store. The armed set is
/// reconciled against the enrolled set by [`Self::reconcile`]: a freshly
/// enrolled endpoint gets a listener, a removed one loses it.
pub(crate) struct EventListeners {
    statuses: Arc<Mutex<HashMap<EndpointId, ListenerStatus>>>,
    listeners: HashMap<EndpointId, EndpointListener>,
}

/// One armed listener: its per-endpoint stop signal and its task handle.
///
/// The per-endpoint signal is what makes removal possible: stopping one
/// endpoint's listener must never touch the others. The §7.8 structured
/// drain applies per listener — the in-flight event finishes and the stream
/// closes gracefully before the task exits — and the supervisor joins the
/// task, so a removed endpoint's listener never touches the store again.
struct EndpointListener {
    stop: StopSignal,
    task: tokio::task::JoinHandle<()>,
}

impl EventListeners {
    /// Creates an empty supervisor; [`Self::reconcile`] arms it.
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            statuses: Arc::new(Mutex::new(HashMap::new())),
            listeners: HashMap::new(),
        }
    }

    /// Reconciles the listener set against the listed enrolled endpoints.
    ///
    /// The stop watch, stream boundary, and sink are only ever cloned into
    /// the spawned tasks, so the caller keeps owning them. The sweep starts
    /// a listener for every enrolled endpoint that was never armed in this
    /// run — an endpoint whose listener gave up stays armed but stopped, so
    /// the `Failed` state survives the sweep (re-arming is a later
    /// iteration) — and stops, through the per-endpoint stop signal, the
    /// listener of every armed endpoint that is no longer enrolled.
    pub(crate) async fn reconcile<Stream, Sink>(
        &mut self,
        listed: Vec<EndpointId>,
        stream: &Arc<Stream>,
        sink: &Arc<Sink>,
        policy: ReconnectPolicy,
    ) where
        Stream: EventStream + 'static,
        Sink: EventSink + 'static,
    {
        let listed: HashSet<EndpointId> = listed.into_iter().collect();
        let removed: Vec<EndpointId> = self
            .listeners
            .keys()
            .filter(|endpoint_id| !listed.contains(endpoint_id))
            .copied()
            .collect();
        for endpoint_id in removed {
            self.stop_listener(endpoint_id).await;
        }
        for endpoint_id in listed {
            if self.listeners.contains_key(&endpoint_id) {
                continue;
            }
            self.spawn_listener(endpoint_id, stream, sink, policy);
        }
    }

    /// Spawns one endpoint's listener task and records it as `Listening`.
    ///
    /// The task owns its stop watch, stream, sink, and status-map clones; a
    /// poisoned status map is a programming defect, not a shutdown path, so
    /// the bookkeeping recovers the value.
    fn spawn_listener<Stream, Sink>(
        &mut self,
        endpoint_id: EndpointId,
        stream: &Arc<Stream>,
        sink: &Arc<Sink>,
        policy: ReconnectPolicy,
    ) where
        Stream: EventStream + 'static,
        Sink: EventSink + 'static,
    {
        self.statuses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(endpoint_id, ListenerStatus::Listening);
        let (stop, task_stop) = StopSignal::new();
        let task_stream = Arc::clone(stream);
        let task_sink = Arc::clone(sink);
        let task_statuses = Arc::clone(&self.statuses);
        let task = tokio::spawn(async move {
            run_endpoint_stream(
                task_stop,
                endpoint_id,
                task_stream.as_ref(),
                task_sink.as_ref(),
                policy,
                task_statuses.as_ref(),
            )
            .await;
        });
        self.listeners
            .insert(endpoint_id, EndpointListener { stop, task });
    }

    /// Stops one endpoint's listener and forgets the endpoint.
    ///
    /// The per-endpoint signal fires, then the task is joined: the in-flight
    /// event finishes and the stream closes gracefully (§7.8) before the
    /// supervisor moves on, so a removed endpoint's listener never touches
    /// the store afterwards. The status entry goes with it, so the endpoint
    /// is armed afresh if it is ever enrolled again.
    async fn stop_listener(&mut self, endpoint_id: EndpointId) {
        let Some(listener) = self.listeners.remove(&endpoint_id) else {
            return;
        };
        listener.stop.signal();
        if let Err(join_error) = listener.task.await {
            tracing::error!("event listener task failed: {join_error}");
        }
        self.statuses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&endpoint_id);
    }

    /// Stops every listener (design §7.8 structured drain), then surfaces
    /// every endpoint whose listener gave up.
    ///
    /// Every per-endpoint signal fires before any task is joined, so all the
    /// listeners stop in parallel; each in-flight event finishes before its
    /// task exits, so joining here guarantees no listener touches the store
    /// afterwards. The failed-endpoint report is the operational consumption
    /// of the §14.4 标记端点事件监听失败状态 status map: at shutdown the
    /// runtime's log shows exactly which endpoints stopped being listened
    /// to.
    pub(crate) async fn drain_all(self) {
        for listener in self.listeners.values() {
            listener.stop.signal();
        }
        for listener in self.listeners.into_values() {
            if let Err(join_error) = listener.task.await {
                tracing::error!("event listener task failed: {join_error}");
            }
        }
        for (endpoint_id, status) in self
            .statuses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            if let ListenerStatus::Failed { reason } = status {
                tracing::error!("event listening failed for endpoint {endpoint_id}: {reason}");
            }
        }
    }

    /// Returns the current listening state of one endpoint.
    ///
    /// # Why test-only
    ///
    /// The status map's production consumers are the drain report and the
    /// failed-state marking; per-endpoint polling is the tests' observability
    /// of the supervisor, so the accessor is compiled in only for them.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn status(&self, endpoint_id: EndpointId) -> Option<ListenerStatus> {
        self.statuses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&endpoint_id)
            .cloned()
    }
}

/// Runs the reconciling supervisor until the stop signal, sweeping once per
/// interval.
///
/// The loop mirrors the scheduler's and sampler's §7.8 shape: the stop
/// signal is observed while waiting for the next sweep and before starting
/// one, the in-flight sweep finishes before the loop exits (structured
/// drain), and a failed sweep is recorded and retried on the next tick. The
/// first sweep fires immediately, so the restart recovery — re-arming every
/// endpoint enrolled before the process start — is exactly the first
/// reconciliation. The caller passes the interval so tests can drive the
/// cadence fast, and the runtime owns the policy.
pub(crate) async fn run<Stream, Sink, Lister>(
    mut stop: StopWatch,
    lister: &Lister,
    stream: &Arc<Stream>,
    sink: &Arc<Sink>,
    policy: ReconnectPolicy,
    interval: Duration,
) where
    Stream: EventStream + 'static,
    Sink: EventSink + 'static,
    Lister: EndpointLister,
{
    let mut listeners = EventListeners::new();
    let mut ticker = tokio::time::interval(interval);
    // Sweeps never burst: if one reconciliation outlasts the interval, the
    // next sweep starts as soon as possible after it instead of piling up.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.stopped() => break,
            _ = ticker.tick() => {
                // The stop may have landed while the interval arm was ready
                // (`select!` picks a ready arm at random): a signalled loop
                // must not start new work, so the sweep is skipped.
                if stop.has_stopped() {
                    break;
                }
                let enrolled = match lister.list_enrolled_endpoints().await {
                    Ok(enrolled) => enrolled,
                    Err(error) => {
                        tracing::error!(
                            "event listener sweep could not list enrolled endpoints: {error}"
                        );
                        continue;
                    }
                };
                listeners.reconcile(enrolled, stream, sink, policy).await;
            }
        }
    }
    listeners.drain_all().await;
}

/// The verdict of one bounded reconnect wait.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconnectOutcome {
    /// The wait elapsed; the next attempt starts.
    Retry,
    /// The reconnect budget is exhausted; the endpoint is marked failed.
    GiveUp,
    /// The stop signal landed during the wait.
    Stopped,
}

/// One endpoint's listener loop: open, consume, record, reconnect.
///
/// The loop never returns an error and never panics: every fallible call is
/// recorded through `tracing::error!` and either isolated to one event or one
/// reconnect attempt. It exits only on the stop signal (after the in-flight
/// event finishes) or on a terminal give-up after
/// [`ReconnectPolicy::max_attempts`] consecutive failures.
async fn run_endpoint_stream<Stream, Sink>(
    mut stop: StopWatch,
    endpoint_id: EndpointId,
    boundary: &Stream,
    sink: &Sink,
    policy: ReconnectPolicy,
    statuses: &Mutex<HashMap<EndpointId, ListenerStatus>>,
) where
    Stream: EventStream,
    Sink: EventSink,
{
    let mut consecutive_failures = 0_usize;
    loop {
        // The §7.8 cancellable open: a hanging connection attempt cannot
        // block shutdown, because the select drops the open future when the
        // stop signal lands.
        let mut stream = match tokio::select! {
            () = stop.stopped() => return,
            opened = boundary.open_stream(endpoint_id) => opened,
        } {
            Ok(stream) => stream,
            Err(error) => {
                tracing::error!(
                    "could not open the event stream of endpoint {endpoint_id}: {error}"
                );
                match reconnect_wait(
                    &mut stop,
                    endpoint_id,
                    &mut consecutive_failures,
                    policy,
                    statuses,
                )
                .await
                {
                    ReconnectOutcome::Retry => continue,
                    ReconnectOutcome::GiveUp | ReconnectOutcome::Stopped => return,
                }
            }
        };
        // The consume phase: pull one event at a time and record it.
        loop {
            let item = tokio::select! {
                () = stop.stopped() => {
                    // The §7.8 drain contract of the stream boundary: the
                    // pending pull is abandoned, then the stream is closed
                    // gracefully so the implementation can delete its
                    // transient Session — never simply dropped.
                    stream.close().await;
                    return;
                }
                item = stream.pull() => item,
            };
            match item {
                Ok(Some(event)) => {
                    // A delivered event is the recovery signal: the endpoint
                    // demonstrably streams, so the reconnect budget starts
                    // over (it counts consecutive failed cycles — opens that
                    // fail and streams that end without ever delivering).
                    // The ingest is deliberately outside the select: a stop
                    // that lands mid-record is honored only after the event
                    // is fully recorded (§7.8 structured drain).
                    consecutive_failures = 0;
                    if let Err(error) = sink.ingest(&event).await {
                        tracing::error!(
                            "event for endpoint {endpoint_id} could not be recorded: {error}"
                        );
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    tracing::error!("event stream of endpoint {endpoint_id} failed: {error}");
                    break;
                }
            }
        }
        match reconnect_wait(
            &mut stop,
            endpoint_id,
            &mut consecutive_failures,
            policy,
            statuses,
        )
        .await
        {
            ReconnectOutcome::Retry => {}
            ReconnectOutcome::GiveUp | ReconnectOutcome::Stopped => return,
        }
    }
}

/// One bounded reconnect wait: advances the failure budget, waits the
/// exponential backoff, and reports whether to retry.
///
/// The wait itself is cancellable — a stop landing during the backoff exits
/// immediately, so shutdown never waits out a backoff.
async fn reconnect_wait(
    stop: &mut StopWatch,
    endpoint_id: EndpointId,
    consecutive_failures: &mut usize,
    policy: ReconnectPolicy,
    statuses: &Mutex<HashMap<EndpointId, ListenerStatus>>,
) -> ReconnectOutcome {
    *consecutive_failures += 1;
    if *consecutive_failures >= policy.max_attempts {
        // The budget is exhausted: the endpoint's event-listening state is
        // marked failed so the product surfaces the broken listening, and
        // this endpoint's task exits. Re-arming failed endpoints is a later
        // iteration (see the module doc).
        let reason = format!(
            "event stream could not be re-established after {} consecutive failures",
            policy.max_attempts
        );
        statuses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                endpoint_id,
                ListenerStatus::Failed {
                    reason: reason.clone(),
                },
            );
        tracing::error!("giving up on the event stream of endpoint {endpoint_id}: {reason}");
        return ReconnectOutcome::GiveUp;
    }
    let delay = policy.delay(*consecutive_failures);
    tokio::select! {
        () = stop.stopped() => ReconnectOutcome::Stopped,
        () = tokio::time::sleep(delay) => ReconnectOutcome::Retry,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        error::Error,
        fmt,
        sync::{Arc, Mutex},
        time::Duration as StdDuration,
    };

    use rutilus_application::{EventStream, EventStreamPull};
    use rutilus_domain::{EventId, EventSeverity, MessageId};
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Notify;

    use super::*;

    /// A complete domain event every test streams, in the shape the gateway
    /// stream yields (receive time already stamped).
    fn event(endpoint_id: EndpointId, sequence: u8) -> Result<Event, Box<dyn Error>> {
        let observed_at = OffsetDateTime::UNIX_EPOCH + Duration::SECOND * sequence * 10;
        Ok(Event::new(
            EventId::generate(),
            endpoint_id,
            MessageId::parse(&format!("Alert.1.0.PowerSupplyFailure{sequence}"))?,
            EventSeverity::Critical,
            Some(format!("power supply {sequence} lost input")),
            observed_at - Duration::SECOND,
            observed_at,
        )?)
    }

    /// One opened stream's behavior: its items, or a failed open.
    type Episode = Result<VecDeque<Result<Event, MockError>>, MockError>;

    /// Scripted stream boundary serving every endpoint from one object, like
    /// the real gateway.
    ///
    /// Each open pops one episode for the requested endpoint; an endpoint
    /// with no scripted episode opens a stream that ends immediately (a
    /// clean, reconnectable end).
    #[derive(Clone, Debug, Default)]
    struct FakeStream {
        episodes: Arc<Mutex<HashMap<EndpointId, VecDeque<Episode>>>>,
        opens: Arc<Mutex<HashMap<EndpointId, usize>>>,
        closes: Arc<Mutex<HashMap<EndpointId, usize>>>,
        pull_gate: Option<Arc<Notify>>,
    }

    impl FakeStream {
        fn for_endpoint(endpoint_id: EndpointId, episodes: Vec<Episode>) -> Self {
            let mut by_endpoint = HashMap::new();
            by_endpoint.insert(endpoint_id, VecDeque::from(episodes));
            Self {
                episodes: Arc::new(Mutex::new(by_endpoint)),
                opens: Arc::new(Mutex::new(HashMap::new())),
                closes: Arc::new(Mutex::new(HashMap::new())),
                pull_gate: None,
            }
        }

        /// Builds a stream whose pulls block until the gate fires, pinning
        /// the listener's close-on-stop drain behavior.
        fn gated_pull(endpoint_id: EndpointId) -> (Self, Arc<Notify>) {
            let gate = Arc::new(Notify::new());
            let mut stream = Self::for_endpoint(endpoint_id, Vec::new());
            stream.pull_gate = Some(Arc::clone(&gate));
            (stream, gate)
        }

        fn opens(&self, endpoint_id: EndpointId) -> Result<usize, MockError> {
            self.opens
                .lock()
                .map_err(|_| MockError::Lock)?
                .get(&endpoint_id)
                .copied()
                .ok_or(MockError::EmptyScript)
        }

        fn closes(&self, endpoint_id: EndpointId) -> Result<usize, MockError> {
            self.closes
                .lock()
                .map_err(|_| MockError::Lock)?
                .get(&endpoint_id)
                .copied()
                .ok_or(MockError::EmptyScript)
        }
    }

    impl EventStream for FakeStream {
        type Error = MockError;
        type Stream = FakePull;

        fn open_stream(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Self::Stream, Self::Error>> {
            Box::pin(async move {
                *self
                    .opens
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .entry(endpoint_id)
                    .or_insert(0) += 1;
                let episode = self
                    .episodes
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .get_mut(&endpoint_id)
                    .and_then(VecDeque::pop_front)
                    .unwrap_or_else(|| Ok(VecDeque::new()));
                match episode {
                    Ok(items) => Ok(FakePull {
                        endpoint_id,
                        items: Arc::new(Mutex::new(items)),
                        closes: Arc::clone(&self.closes),
                        pull_gate: self.pull_gate.clone(),
                    }),
                    Err(error) => Err(error),
                }
            })
        }
    }

    /// Pulls one scripted episode; an exhausted episode is a clean end.
    struct FakePull {
        endpoint_id: EndpointId,
        items: Arc<Mutex<VecDeque<Result<Event, MockError>>>>,
        closes: Arc<Mutex<HashMap<EndpointId, usize>>>,
        pull_gate: Option<Arc<Notify>>,
    }

    impl EventStreamPull for FakePull {
        type Error = MockError;

        fn pull(&mut self) -> BoundaryFuture<'_, Result<Option<Event>, Self::Error>> {
            Box::pin(async move {
                if let Some(gate) = &self.pull_gate {
                    // The release future is registered before the pull
                    // blocks, so a release fired while the pull is in
                    // flight is never lost.
                    let released = gate.notified();
                    released.await;
                }
                match self.items.lock().map_err(|_| MockError::Lock)?.pop_front() {
                    Some(Ok(event)) => Ok(Some(event)),
                    Some(Err(error)) => Err(error),
                    None => Ok(None),
                }
            })
        }

        fn close(&mut self) -> BoundaryFuture<'_, ()> {
            Box::pin(async move {
                // The close bookkeeping is best-effort (a poisoned map is a
                // test-defect signal, not a shutdown path), and `close`
                // returns no error of its own.
                *self
                    .closes
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .entry(self.endpoint_id)
                    .or_insert(0) += 1;
            })
        }
    }

    /// Scripted sink recording every ingested event in order, with one
    /// script per endpoint.
    ///
    /// Each ingest pops the endpoint's script; an `Ok` entry completes the
    /// record, an `Err` entry is the fake's controlled failure, and an
    /// exhausted script is itself a loud failure so a miswired test fails on
    /// the assertion instead of silently succeeding.
    /// A one-shot ingest gate: the first ingest blocks until the gate
    /// fires; every later ingest passes straight through.
    #[derive(Debug)]
    struct Gate {
        notify: Notify,
        fired: std::sync::atomic::AtomicBool,
    }

    /// One endpoint's scripted ingest outcomes, in delivery order.
    type SinkScript = HashMap<EndpointId, VecDeque<Result<(), MockError>>>;

    #[derive(Clone, Debug, Default)]
    struct FakeSink {
        recorded: Arc<Mutex<Vec<(EndpointId, Event)>>>,
        script: Arc<Mutex<SinkScript>>,
        gate: Option<Arc<Gate>>,
    }

    impl FakeSink {
        fn for_endpoint(endpoint_id: EndpointId, script: Vec<Result<(), MockError>>) -> Self {
            let mut by_endpoint = HashMap::new();
            by_endpoint.insert(endpoint_id, VecDeque::from(script));
            Self {
                recorded: Arc::new(Mutex::new(Vec::new())),
                script: Arc::new(Mutex::new(by_endpoint)),
                gate: None,
            }
        }

        /// Builds a sink whose first ingest blocks until the gate fires,
        /// pinning the listener's in-flight-event drain behavior.
        fn gated_for(endpoint_id: EndpointId) -> Self {
            let mut by_endpoint = HashMap::new();
            by_endpoint.insert(endpoint_id, VecDeque::from(vec![Ok(()), Ok(())]));
            Self {
                recorded: Arc::new(Mutex::new(Vec::new())),
                script: Arc::new(Mutex::new(by_endpoint)),
                gate: Some(Arc::new(Gate {
                    notify: Notify::new(),
                    fired: std::sync::atomic::AtomicBool::new(false),
                })),
            }
        }

        fn recorded(&self) -> Result<Vec<(EndpointId, Event)>, MockError> {
            self.recorded
                .lock()
                .map(|recorded| recorded.clone())
                .map_err(|_| MockError::Lock)
        }
    }

    impl EventSink for FakeSink {
        type Error = MockError;

        fn ingest<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.recorded
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .push((event.endpoint_id(), event.clone()));
                if let Some(gate) = &self.gate
                    && !gate.fired.load(std::sync::atomic::Ordering::Relaxed)
                {
                    // The release future is registered before the ingest
                    // blocks, so a release fired while the ingest is in
                    // flight is never lost.
                    let released = gate.notify.notified();
                    released.await;
                    gate.fired.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                match self
                    .script
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .get_mut(&event.endpoint_id())
                    .and_then(VecDeque::pop_front)
                {
                    Some(Ok(())) => Ok(()),
                    Some(Err(error)) => Err(error),
                    None => Err(MockError::EmptyScript),
                }
            })
        }
    }

    /// A fast production-shaped policy for tests.
    fn fast_policy(max_attempts: usize) -> ReconnectPolicy {
        ReconnectPolicy {
            base_interval: StdDuration::from_millis(1),
            factor: EVENT_RECONNECT_FACTOR,
            max_interval: StdDuration::from_millis(10),
            max_attempts,
        }
    }

    /// A fast reconciliation cadence for the `run` loop tests.
    const FAST_RECONCILE_INTERVAL: StdDuration = StdDuration::from_millis(1);

    /// Scripted enrolled-endpoint listing with a shared failure flag, so the
    /// test can flip the failure while the loop task holds its clone.
    #[derive(Clone, Debug, Default)]
    struct FakeLister {
        endpoints: Arc<Mutex<Vec<EndpointId>>>,
        fail_listing: Arc<std::sync::atomic::AtomicBool>,
    }

    impl FakeLister {
        fn with_endpoints(endpoints: Vec<EndpointId>) -> Self {
            Self {
                endpoints: Arc::new(Mutex::new(endpoints)),
                fail_listing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            }
        }
    }

    impl EndpointLister for FakeLister {
        type Error = MockError;

        fn list_enrolled_endpoints(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointId>, Self::Error>> {
            Box::pin(async move {
                if self.fail_listing.load(std::sync::atomic::Ordering::Relaxed) {
                    return Err(MockError::Store);
                }
                self.endpoints
                    .lock()
                    .map(|endpoints| endpoints.clone())
                    .map_err(|_| MockError::Lock)
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Store,
        Lock,
        EmptyScript,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::Store => "mock stream failed",
                Self::Lock => "mock state is unavailable",
                Self::EmptyScript => "the mock script is exhausted",
            })
        }
    }

    impl Error for MockError {}

    /// One spawned listener task and its status map.
    type SpawnedListener = (
        tokio::task::JoinHandle<()>,
        Arc<Mutex<HashMap<EndpointId, ListenerStatus>>>,
    );

    /// Spawns one endpoint listener and returns its task handle and status
    /// map.
    ///
    /// # Why a helper
    ///
    /// The listener loop exits only on stop or terminal give-up, so every
    /// test shares this spawn shape; [`join_with_timeout`] then makes a
    /// listener that fails to exit fail the test loudly instead of hanging
    /// it.
    fn spawn_and_join(
        endpoint_id: EndpointId,
        stream: FakeStream,
        sink: FakeSink,
        policy: ReconnectPolicy,
        stop_watch: StopWatch,
    ) -> SpawnedListener {
        let statuses = Arc::new(Mutex::new(HashMap::new()));
        let task_statuses = Arc::clone(&statuses);
        let task = tokio::spawn(async move {
            run_endpoint_stream(
                stop_watch,
                endpoint_id,
                &stream,
                &sink,
                policy,
                task_statuses.as_ref(),
            )
            .await;
        });
        (task, statuses)
    }

    async fn join_with_timeout(task: tokio::task::JoinHandle<()>) -> Result<(), Box<dyn Error>> {
        tokio::time::timeout(StdDuration::from_secs(2), task)
            .await
            .map_err(|_| std::io::Error::other("the listener did not stop"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))?;
        Ok(())
    }

    #[tokio::test]
    async fn listener_ingests_events_in_stream_order() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let first = event(endpoint_id, 1)?;
        let second = event(endpoint_id, 2)?;
        let third = event(endpoint_id, 3)?;
        let stream = FakeStream::for_endpoint(
            endpoint_id,
            vec![Ok(VecDeque::from([
                Ok(first.clone()),
                Ok(second.clone()),
                Ok(third.clone()),
            ]))],
        );
        let sink = FakeSink::for_endpoint(endpoint_id, vec![Ok(()), Ok(()), Ok(())]);
        let (stop_signal, stop_watch) = StopSignal::new();

        let (task, _statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            sink.clone(),
            fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            stop_watch,
        );
        // Wait until all three events were recorded, then stop.
        for _ in 0..200 {
            if sink.recorded()?.len() >= 3 {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            sink.recorded()?.len() >= 3,
            "the listener never recorded all three events"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;

        assert_eq!(
            sink.recorded()?,
            [
                (endpoint_id, first),
                (endpoint_id, second),
                (endpoint_id, third),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_reconnects_after_a_clean_stream_end() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let first = event(endpoint_id, 1)?;
        let second = event(endpoint_id, 2)?;
        // The first opened stream carries one event and ends; the second
        // carries the next one. The listener must reopen and keep the order.
        let stream = FakeStream::for_endpoint(
            endpoint_id,
            vec![
                Ok(VecDeque::from([Ok(first.clone())])),
                Ok(VecDeque::from([Ok(second.clone())])),
            ],
        );
        let sink = FakeSink::for_endpoint(endpoint_id, vec![Ok(()), Ok(())]);
        let (stop_signal, stop_watch) = StopSignal::new();

        let (task, _statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            sink.clone(),
            fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            stop_watch,
        );
        for _ in 0..200 {
            if sink.recorded()?.len() >= 2 {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            sink.recorded()?.len() >= 2,
            "the listener never reopened the stream"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;

        assert_eq!(
            sink.recorded()?,
            [(endpoint_id, first), (endpoint_id, second)]
        );
        assert!(
            stream.opens(endpoint_id)? >= 2,
            "the stream must have been reopened"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_reconnects_after_a_stream_failure_and_an_open_failure()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let recovered = event(endpoint_id, 9)?;
        // The first stream fails mid-stream, the second open fails outright,
        // and the third opens and delivers — each interruption must be
        // absorbed by the bounded reconnect.
        let stream = FakeStream::for_endpoint(
            endpoint_id,
            vec![
                Ok(VecDeque::from([Err(MockError::Store)])),
                Err(MockError::Store),
                Ok(VecDeque::from([Ok(recovered.clone())])),
            ],
        );
        let sink = FakeSink::for_endpoint(endpoint_id, vec![Ok(())]);
        let (stop_signal, stop_watch) = StopSignal::new();

        let (task, _statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            sink.clone(),
            fast_policy(5),
            stop_watch,
        );
        for _ in 0..200 {
            if !sink.recorded()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            !sink.recorded()?.is_empty(),
            "the listener never recovered the stream"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;

        assert_eq!(sink.recorded()?, [(endpoint_id, recovered)]);
        assert!(
            stream.opens(endpoint_id)? >= 3,
            "each interruption must be reopened"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_exhausting_the_budget_marks_the_endpoint_failed() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        // Every open succeeds but every stream ends immediately: the budget
        // of two consecutive failures must terminate the listener and mark
        // the endpoint failed — without any stop signal.
        let stream = FakeStream::for_endpoint(endpoint_id, Vec::new());
        let sink = FakeSink::for_endpoint(endpoint_id, Vec::new());
        let (stop_signal, stop_watch) = StopSignal::new();

        let (task, statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            sink.clone(),
            fast_policy(2),
            stop_watch,
        );
        tokio::time::timeout(StdDuration::from_secs(2), task)
            .await
            .map_err(|_| std::io::Error::other("the listener did not give up"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))?;
        let _ = stop_signal;

        let status = statuses
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&endpoint_id)
            .cloned();
        assert!(matches!(status, Some(ListenerStatus::Failed { .. })));
        assert_eq!(sink.recorded()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn listener_finishes_the_event_in_flight_before_stopping() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let in_flight = event(endpoint_id, 1)?;
        let stream = FakeStream::for_endpoint(
            endpoint_id,
            vec![Ok(VecDeque::from([Ok(in_flight.clone())]))],
        );
        let gated = FakeSink::gated_for(endpoint_id);
        let gate = gated
            .gate
            .clone()
            .ok_or_else(|| std::io::Error::other("the gated sink lost its gate"))?;
        let (stop_signal, stop_watch) = StopSignal::new();

        let (mut task, _statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            gated.clone(),
            fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            stop_watch,
        );
        // Wait until the ingest is in flight, blocked inside the sink.
        for _ in 0..200 {
            if !gated.recorded()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(!gated.recorded()?.is_empty(), "the ingest never started");
        stop_signal.signal();
        // While the ingest is still blocked, the listener must not exit
        // (§7.8 structured drain: the in-flight event finishes first).
        assert!(
            tokio::time::timeout(StdDuration::from_millis(80), &mut task)
                .await
                .is_err(),
            "the listener exited while its event was still being recorded"
        );
        gate.notify.notify_one();
        join_with_timeout(task).await?;
        // The in-flight event ran to completion exactly once before the
        // listener observed the stop signal.
        assert_eq!(
            gated.recorded()?,
            [(endpoint_id, in_flight)],
            "the in-flight event must have been recorded"
        );
        Ok(())
    }

    #[tokio::test]
    async fn listener_closes_the_stream_gracefully_when_stopped_while_pulling()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        // The pull blocks until the gate fires: the stop signal must drop
        // the pending pull and run the boundary's graceful close instead of
        // abandoning the handle (§7.8: no transient Session survives the
        // listener).
        let (stream, pull_gate) = FakeStream::gated_pull(endpoint_id);
        let sink = FakeSink::for_endpoint(endpoint_id, Vec::new());
        let (stop_signal, stop_watch) = StopSignal::new();

        let (task, _statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            sink.clone(),
            fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            stop_watch,
        );
        // Wait until the pull is in flight, blocked inside the stream.
        for _ in 0..200 {
            if stream.opens(endpoint_id).is_ok() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            stream.opens(endpoint_id).is_ok(),
            "the listener never opened the stream"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;
        let _ = pull_gate;
        assert_eq!(
            stream.closes(endpoint_id)?,
            1,
            "the stream must be closed gracefully after the stop"
        );
        Ok(())
    }

    // std's `Duration` has no minutes constructor; the sixty-second spellings
    // mirror the production constant's unit.
    #[allow(clippy::duration_suboptimal_units)]
    #[tokio::test]
    async fn listener_exits_immediately_when_stopped_during_a_backoff() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        // The stream ends at once, then the listener must sleep through a
        // backoff that is far longer than the test's patience.
        let stream = FakeStream::for_endpoint(endpoint_id, Vec::new());
        let sink = FakeSink::for_endpoint(endpoint_id, Vec::new());
        let (stop_signal, stop_watch) = StopSignal::new();

        let (task, _statuses) = spawn_and_join(
            endpoint_id,
            stream.clone(),
            sink.clone(),
            ReconnectPolicy {
                base_interval: StdDuration::from_secs(60),
                factor: EVENT_RECONNECT_FACTOR,
                max_interval: StdDuration::from_secs(60),
                max_attempts: EVENT_RECONNECT_MAX_ATTEMPTS,
            },
            stop_watch,
        );
        // Let the listener reach the backoff, then stop it.
        for _ in 0..200 {
            if stream.opens(endpoint_id).is_ok() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            stream.opens(endpoint_id).is_ok(),
            "the listener never opened the stream"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;
        assert_eq!(
            stream.opens(endpoint_id)?,
            1,
            "no attempt may start after the stop"
        );
        Ok(())
    }

    #[test]
    fn reconnect_delay_grows_exponentially_and_saturates_at_the_cap() {
        let policy = ReconnectPolicy {
            base_interval: StdDuration::from_secs(1),
            factor: 2,
            max_interval: StdDuration::from_secs(8),
            max_attempts: EVENT_RECONNECT_MAX_ATTEMPTS,
        };

        assert_eq!(policy.delay(1), StdDuration::from_secs(1));
        assert_eq!(policy.delay(2), StdDuration::from_secs(2));
        assert_eq!(policy.delay(3), StdDuration::from_secs(4));
        // The cap stops the growth: every later failure waits the maximum.
        assert_eq!(policy.delay(4), StdDuration::from_secs(8));
        assert_eq!(policy.delay(10), StdDuration::from_secs(8));
    }

    #[tokio::test]
    async fn one_failed_endpoint_does_not_affect_the_others() -> Result<(), Box<dyn Error>> {
        let doomed = EndpointId::generate();
        let healthy = EndpointId::generate();
        let first = event(healthy, 1)?;
        let second = event(healthy, 2)?;
        // The doomed endpoint's stream always ends immediately (budget two,
        // so it gives up fast); the healthy endpoint streams two events. Its
        // sink is gated so its listener stays mid-stream — deterministically
        // `Listening` — while the doomed endpoint fails.
        let stream = FakeStream::for_endpoint(
            healthy,
            vec![Ok(VecDeque::from([Ok(first.clone()), Ok(second.clone())]))],
        );
        let sink = FakeSink::gated_for(healthy);
        let gate = sink
            .gate
            .clone()
            .ok_or_else(|| std::io::Error::other("the gated sink lost its gate"))?;

        let stream = Arc::new(stream);
        let sink = Arc::new(sink.clone());
        let mut listeners = EventListeners::new();
        listeners
            .reconcile(vec![doomed, healthy], &stream, &sink, fast_policy(2))
            .await;

        // Wait until the doomed endpoint failed while the healthy one is
        // still consuming (blocked inside its first ingest).
        for _ in 0..200 {
            let doomed_status = listeners.status(doomed);
            let healthy_recorded = sink.recorded()?.len();
            if matches!(doomed_status, Some(ListenerStatus::Failed { .. })) && healthy_recorded >= 1
            {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(matches!(
            listeners.status(doomed),
            Some(ListenerStatus::Failed { .. })
        ));
        assert!(
            matches!(listeners.status(healthy), Some(ListenerStatus::Listening)),
            "the healthy endpoint's listener must survive the doomed one's give-up"
        );
        assert_eq!(sink.recorded()?, [(healthy, first.clone())]);

        // Release the healthy listener, let it finish both events, and stop.
        gate.notify.notify_one();
        for _ in 0..200 {
            if sink.recorded()?.len() >= 2 {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert_eq!(sink.recorded()?, [(healthy, first), (healthy, second)]);
        // `drain_all` stops every remaining listener through its own
        // per-endpoint signal and joins each task.
        tokio::time::timeout(StdDuration::from_secs(2), listeners.drain_all())
            .await
            .map_err(|_| std::io::Error::other("the listeners did not drain"))?;
        Ok(())
    }

    #[tokio::test]
    async fn listener_starts_for_an_endpoint_enrolled_mid_run() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let first = event(endpoint_id, 1)?;
        let stream =
            FakeStream::for_endpoint(endpoint_id, vec![Ok(VecDeque::from([Ok(first.clone())]))]);
        let sink = FakeSink::for_endpoint(endpoint_id, vec![Ok(())]);
        let stream = Arc::new(stream);
        let sink = Arc::new(sink);

        let mut listeners = EventListeners::new();
        // The endpoint is not yet enrolled: the sweep must arm nothing.
        listeners
            .reconcile(
                Vec::new(),
                &stream,
                &sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            )
            .await;
        assert_eq!(listeners.status(endpoint_id), None);
        // The endpoint is enrolled mid-run: the next sweep must arm its
        // listener (the lazy start).
        listeners
            .reconcile(
                vec![endpoint_id],
                &stream,
                &sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            )
            .await;
        for _ in 0..200 {
            if !sink.recorded()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert_eq!(sink.recorded()?, [(endpoint_id, first)]);
        assert_eq!(
            listeners.status(endpoint_id),
            Some(ListenerStatus::Listening)
        );
        listeners.drain_all().await;
        Ok(())
    }

    #[tokio::test]
    async fn removing_an_endpoint_stops_its_listener() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let (stream, _pull_gate) = FakeStream::gated_pull(endpoint_id);
        let sink = FakeSink::for_endpoint(endpoint_id, Vec::new());
        let stream = Arc::new(stream);
        let sink = Arc::new(sink);

        let mut listeners = EventListeners::new();
        listeners
            .reconcile(
                vec![endpoint_id],
                &stream,
                &sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            )
            .await;
        // Wait until the listener is consuming (its pull is in flight).
        for _ in 0..200 {
            if stream.opens(endpoint_id).is_ok() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            stream.opens(endpoint_id).is_ok(),
            "the listener never opened the stream"
        );
        // The endpoint leaves the enrolled set: the sweep must stop the
        // listener — the pending pull is dropped and the stream closes
        // gracefully (§7.8) — and forget the endpoint.
        listeners
            .reconcile(
                Vec::new(),
                &stream,
                &sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
            )
            .await;
        assert!(listeners.listeners.is_empty());
        assert_eq!(listeners.status(endpoint_id), None);
        assert_eq!(
            stream.closes(endpoint_id)?,
            1,
            "the stream must be closed gracefully after the removal"
        );
        assert_eq!(
            stream.opens(endpoint_id)?,
            1,
            "no attempt may start after the removal"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_listener_is_not_re_armed_by_a_later_sweep() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let stream = FakeStream::for_endpoint(endpoint_id, Vec::new());
        let sink = FakeSink::for_endpoint(endpoint_id, Vec::new());
        let stream = Arc::new(stream);
        let sink = Arc::new(sink);

        let mut listeners = EventListeners::new();
        listeners
            .reconcile(vec![endpoint_id], &stream, &sink, fast_policy(2))
            .await;
        // Wait until the listener exhausted its budget.
        for _ in 0..200 {
            if matches!(
                listeners.status(endpoint_id),
                Some(ListenerStatus::Failed { .. })
            ) {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(matches!(
            listeners.status(endpoint_id),
            Some(ListenerStatus::Failed { .. })
        ));
        // The budget of two consecutive failed cycles consumed both opens.
        let opens_after_give_up = stream.opens(endpoint_id)?;
        assert_eq!(opens_after_give_up, 2);
        // The endpoint is still enrolled: the sweep must not re-arm the
        // failed listener — re-arming is a later iteration, so the `Failed`
        // state survives the sweep.
        listeners
            .reconcile(vec![endpoint_id], &stream, &sink, fast_policy(2))
            .await;
        assert_eq!(
            stream.opens(endpoint_id)?,
            opens_after_give_up,
            "no new listener may start for the failed endpoint"
        );
        assert!(matches!(
            listeners.status(endpoint_id),
            Some(ListenerStatus::Failed { .. })
        ));
        listeners.drain_all().await;
        Ok(())
    }

    #[tokio::test]
    async fn run_arms_preexisting_endpoints_on_the_first_sweep() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let first = event(endpoint_id, 1)?;
        // The endpoint was enrolled before the process start: the first
        // sweep (which fires immediately) must arm it — the restart
        // recovery.
        let stream =
            FakeStream::for_endpoint(endpoint_id, vec![Ok(VecDeque::from([Ok(first.clone())]))]);
        let sink = FakeSink::for_endpoint(endpoint_id, vec![Ok(())]);
        let lister = FakeLister::with_endpoints(vec![endpoint_id]);
        let loop_lister = lister.clone();
        let stream = Arc::new(stream);
        let sink = Arc::new(sink);
        let loop_stream = Arc::clone(&stream);
        let loop_sink = Arc::clone(&sink);
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_lister,
                &loop_stream,
                &loop_sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
                FAST_RECONCILE_INTERVAL,
            )
            .await;
        });
        for _ in 0..200 {
            if !sink.recorded()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert_eq!(
            sink.recorded()?,
            [(endpoint_id, first)],
            "the first sweep must arm the preexisting endpoint"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;
        Ok(())
    }

    #[tokio::test]
    async fn run_stops_a_listener_when_its_endpoint_leaves_the_enrolled_set()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let (stream, _pull_gate) = FakeStream::gated_pull(endpoint_id);
        let sink = FakeSink::for_endpoint(endpoint_id, Vec::new());
        let lister = FakeLister::with_endpoints(vec![endpoint_id]);
        let loop_lister = lister.clone();
        let stream = Arc::new(stream);
        let sink = Arc::new(sink);
        let loop_stream = Arc::clone(&stream);
        let loop_sink = Arc::clone(&sink);
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_lister,
                &loop_stream,
                &loop_sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
                FAST_RECONCILE_INTERVAL,
            )
            .await;
        });
        // Wait until the listener is consuming, then remove the endpoint
        // from the enrolled set: the next sweep must stop the listener and
        // close its stream gracefully.
        for _ in 0..200 {
            if stream.opens(endpoint_id).is_ok() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            stream.opens(endpoint_id).is_ok(),
            "the listener never opened the stream"
        );
        lister
            .endpoints
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        for _ in 0..200 {
            if stream.closes(endpoint_id).is_ok() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert_eq!(
            stream.closes(endpoint_id)?,
            1,
            "the stream must be closed gracefully after the removal"
        );
        assert_eq!(
            stream.opens(endpoint_id)?,
            1,
            "no attempt may start after the removal"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_listing_aborts_only_the_sweep_and_retries_later() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        let first = event(endpoint_id, 1)?;
        let stream =
            FakeStream::for_endpoint(endpoint_id, vec![Ok(VecDeque::from([Ok(first.clone())]))]);
        let sink = FakeSink::for_endpoint(endpoint_id, vec![Ok(())]);
        let lister = FakeLister::with_endpoints(vec![endpoint_id]);
        lister
            .fail_listing
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let loop_lister = lister.clone();
        let stream = Arc::new(stream);
        let sink = Arc::new(sink);
        let loop_stream = Arc::clone(&stream);
        let loop_sink = Arc::clone(&sink);
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_lister,
                &loop_stream,
                &loop_sink,
                fast_policy(EVENT_RECONNECT_MAX_ATTEMPTS),
                FAST_RECONCILE_INTERVAL,
            )
            .await;
        });
        // Several sweeps land while the listing fails: nothing may be armed.
        tokio::time::sleep(StdDuration::from_millis(20)).await;
        assert!(
            stream.opens(endpoint_id).is_err(),
            "a sweep without a listing must not arm anything"
        );
        // The listing recovers: the very next sweep must arm the endpoint.
        lister
            .fail_listing
            .store(false, std::sync::atomic::Ordering::Relaxed);
        for _ in 0..200 {
            if !sink.recorded()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert_eq!(
            sink.recorded()?,
            [(endpoint_id, first)],
            "the recovered listing must arm the endpoint"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;
        Ok(())
    }
}
