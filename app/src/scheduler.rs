//! The operation scheduling loop (design sections 13.3, 13.6, and 7.8).
//!
//! One background task ticks every [`TICK_INTERVAL`]. Each tick sweeps the
//! persisted operation store and dispatches the work it finds:
//!
//! - the executor pass drives the work by state through the
//!   [`OperationExecutor`] — fresh `Queued` work and crash-resumed
//!   `Validating` work run the execution flow
//!   ([`OperationDriver::execute_operation`], whose `Validating` resume is
//!   safe because the state is persisted before dispatch), while `Running`
//!   and `Verifying` orphans are resolved through
//!   [`OperationDriver::recover_operation`] — the §13.5 re-read-and-decide
//!   recovery, since the write may already have landed and must never be
//!   re-dispatched blindly;
//! - the monitor pass resumes every `WaitingRemote` operation through the
//!   [`TaskMonitor`] — the §13.6 Task polling that continues after a restart.
//!
//! The two passes of one tick run concurrently, and the executor pass drives
//! its operations concurrently (design §13.7 default concurrency: site-global
//! operations bounded, same-endpoint writes serial): one slow drive — a
//! hung BMC — never blocks the other endpoints' operations or the §13.6 Task
//! polling. Same-endpoint serialization is guaranteed by the process-wide
//! per-endpoint write gate [`endpoint_write_gate`] (design §7.8 "写操作默认
//! 每个端点串行"), which every drive holds for its whole duration.
//!
//! The loop follows the design §7.8 async discipline: it is cancellable
//! through a [`StopWatch`] (every task has a cancellation token), it never
//! panics, one failing operation never interrupts the sweep, and it finishes
//! its in-flight tick before exiting (structured drain). Every recorded
//! failure goes through `tracing::error!` (the §6.2 diagnostic log, on the
//! app binary's RUST_LOG-filtered stderr subscriber).
//!
//! Pacing, backoff, and bounded retries are deliberately later iterations:
//! each sweep is a full re-scan of the store, so a skipped or failed tick
//! loses nothing.

use std::{
    collections::HashMap,
    error::Error,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use futures::stream::{self, StreamExt};
use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository, Clock,
    CommandExecutor, CommandVerifier, EndpointRefreshRepository, ExecutorError, OperationExecutor,
    TaskMonitor, TaskMonitorError, TaskPoll, TaskReader, UpdateExecutor,
};
use rutilus_domain::{EndpointId, Operation, OperationId, OperationState};
use rutilus_operation_engine::{EngineError, OperationEngine, OperationStore, RemoteTaskStore};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::sync::{Semaphore, watch};
use tracing::instrument;

/// The cadence of one full scheduling sweep.
///
/// # Why two seconds
///
/// Each tick re-lists every in-flight and queued operation, so the period
/// bounds how quickly newly submitted work starts and how quickly an
/// asynchronous Task is polled after acceptance. Two seconds keeps both
/// latencies well below what a human notices in the operation console, while
/// leaving the loop room to run multi-request BMC sequences (a dispatch plus
/// its verification re-read) between sweeps. A faster period would poll
/// unfinished Tasks needlessly often — every poll is an authenticated Redfish
/// GET (§13.6) — and a slower period would make freshly submitted operations
/// feel stuck. Pacing, backoff, and bounded retries are later iterations, so
/// this is deliberately a single constant, not a configuration surface yet.
pub(crate) const TICK_INTERVAL: Duration = Duration::from_secs(2);

/// The upper bound of one tick's concurrently driven operations (design
/// §13.7 default concurrency: "Site 全局操作：有界").
///
/// Four concurrent drives bound one sweep's in-flight BMC and persistence
/// work while still pipelining a large store: the same value as the refresh
/// batch's [`MAX_CONCURRENT_REFRESHES`](rutilus_application::MAX_CONCURRENT_REFRESHES),
/// because a drive and a refresh are the same class of multi-request
/// endpoint work. Same-endpoint drives stay serial regardless of this bound:
/// every drive additionally passes through its endpoint's one-permit write
/// gate ([`endpoint_write_gate`], §7.8 "写操作默认每个端点串行").
const MAX_CONCURRENT_DRIVES: usize = 4;

/// The process-wide registry of per-endpoint operation-write gates (design
/// §7.8 "写操作默认每个端点串行", §13.7 "同一 Endpoint 写操作：1").
///
/// One tick drives its operations concurrently, so two operations on the
/// same endpoint would otherwise dispatch to the same BMC at the same time.
/// Every drive of one endpoint — execution or recovery, across any number of
/// concurrent sweeps — passes through the same one-permit gate, so the
/// endpoint's BMC writes are serial while different endpoints progress in
/// parallel. The permit is held for the whole drive (pre-flight, dispatch,
/// verification re-read, and the persisted steps), exactly like the refresh
/// batch holds its endpoint gate for the whole refresh.
///
/// Entries are intentionally retained for the process lifetime: a gate must
/// never be dropped while a drive holds its permit, because dropping the
/// registry's last `Arc` would free the semaphore and admit a concurrent
/// drive of the same endpoint. The registry therefore holds at most one
/// entry per managed endpoint the process has ever driven — bounded by the
/// fleet size.
static ENDPOINT_WRITE_GATES: OnceLock<Mutex<HashMap<EndpointId, Arc<Semaphore>>>> = OnceLock::new();

/// Returns the process-wide one-permit write gate of one endpoint, or `None`
/// when the registry cannot be locked.
///
/// The gate is created on first use and shared by every drive of the
/// endpoint. A poisoned registry is the same process-level break as a closed
/// semaphore, so the caller records the drive as failed instead of driving
/// the endpoint ungated.
fn endpoint_write_gate(endpoint_id: EndpointId) -> Option<Arc<Semaphore>> {
    let mut gates = ENDPOINT_WRITE_GATES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .ok()?;
    Some(
        gates
            .entry(endpoint_id)
            .or_insert_with(|| Arc::new(Semaphore::new(1)))
            .clone(),
    )
}

/// The control side of the scheduling-loop stop signal (design §7.8: every
/// task has a cancellation token).
///
/// # Why `tokio::sync::watch`, not a `CancellationToken`
///
/// The app crate has no `tokio-util` dependency, and the loop needs only the
/// two properties `watch` gives us: multiple waiters observe one signal, and
/// dropping the signal side resolves every waiter, so shutdown is guaranteed
/// even if `signal` is never called. A watch channel is the smallest tokio
/// primitive with both properties.
pub(crate) struct StopSignal {
    sender: watch::Sender<()>,
}

/// The wait side of the stop signal; one clone per waiter.
///
/// The scheduling loop and the HTTP server's graceful-shutdown future each
/// hold one, so one Ctrl-C stops both in the §7.8 drain order.
#[derive(Clone)]
pub(crate) struct StopWatch {
    receiver: watch::Receiver<()>,
}

impl StopSignal {
    /// Creates one signal and a wait handle for it.
    #[must_use]
    pub(crate) fn new() -> (Self, StopWatch) {
        let (sender, receiver) = watch::channel(());
        (Self { sender }, StopWatch { receiver })
    }

    /// Fires the signal: every existing waiter resolves, and the scheduling
    /// loop stops after its current tick.
    pub(crate) fn signal(&self) {
        // The `()` value is a sentinel; waiters only observe that it changed.
        let _ = self.sender.send(());
    }
}

impl StopWatch {
    /// Completes when the signal fires or the signal side is dropped.
    pub(crate) async fn stopped(&mut self) {
        let _ = self.receiver.changed().await;
    }

    /// Reports whether the signal has already fired or the signal side was
    /// dropped.
    ///
    /// The synchronous twin of [`Self::stopped`]: the loop re-checks it when
    /// a tick fires, so a stop that landed while the tick was pending is
    /// honored before any new sweep starts.
    pub(crate) fn has_stopped(&self) -> bool {
        self.receiver.has_changed().unwrap_or(true)
    }
}

/// The executor seam the scheduling loop drives.
///
/// # Why a seam
///
/// `OperationExecutor` is a concrete composition with a nine-boundary error
/// vocabulary; the loop only needs "drive one operation" and must never
/// interpret the executor's verdicts itself. The seam keeps the loop
/// testable with scripted fakes (the same pattern the application layer's
/// tests use) and erases the executor's error vocabulary into one opaque
/// failure that the loop records and moves on from.
pub(crate) trait OperationDriver {
    /// The driver's controlled failure type; only its `Display` is used,
    /// so the loop stays independent of the executor's error vocabulary.
    type Error: Error;

    /// Drives one operation through the execution flow (§13.3): fresh
    /// `Queued` work, or work resumed from `Validating` after a crash (the
    /// state is persisted before dispatch, so the write was never issued).
    fn execute_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Operation, Self::Error>>;

    /// Resolves the §13.5/§13.6 recovery of one operation stranded in
    /// `Running` or `Verifying`: the write may already have landed, so the
    /// outcome is judged by re-reading the target (or the persisted Task
    /// record) instead of re-dispatching.
    fn recover_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Operation, Self::Error>>;
}

/// The Task-poll seam the scheduling loop drives.
///
/// Like [`OperationDriver`], the seam keeps the §13.6 monitor pass testable
/// with scripted fakes and erases the monitor's error vocabulary.
pub(crate) trait TaskPollDriver {
    /// The driver's controlled failure type; only its `Display` is used.
    type Error: Error;

    /// Lists the operations waiting on asynchronous Tasks (§13.6).
    fn recover_tasks(&self) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>>;

    /// Polls one waiting operation's Task with the sweep's shared instant.
    fn poll_operation(
        &self,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<TaskPoll, Self::Error>>;
}

impl<Store, Gateway, Audit, Time> OperationDriver for OperationExecutor<Store, Gateway, Audit, Time>
where
    Store: OperationStore
        + EndpointRefreshRepository
        + CapabilityQueryRepository
        + RemoteTaskStore
        + ArtifactRepository,
    Gateway: CommandExecutor + CommandVerifier + UpdateExecutor,
    Audit: AuditEventWriter,
    Time: Clock,
{
    type Error = ExecutorError<
        <Store as OperationStore>::Error,
        <Store as EndpointRefreshRepository>::Error,
        <Store as CapabilityQueryRepository>::Error,
        <Store as RemoteTaskStore>::Error,
        <Store as ArtifactRepository>::Error,
        <Gateway as CommandExecutor>::Error,
        <Gateway as UpdateExecutor>::Error,
        <Gateway as CommandVerifier>::Error,
        <Audit as AuditEventWriter>::Error,
    >;

    fn execute_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Operation, Self::Error>> {
        Box::pin(OperationExecutor::execute_operation(self, operation_id))
    }

    fn recover_operation(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Operation, Self::Error>> {
        Box::pin(OperationExecutor::recover_operation(self, operation_id))
    }
}

impl<Store, Reader, Audit> TaskPollDriver for TaskMonitor<Store, Reader, Audit>
where
    Store: OperationStore + RemoteTaskStore,
    Reader: TaskReader + CommandVerifier,
    Audit: AuditEventWriter,
{
    type Error = TaskMonitorError<
        <Store as OperationStore>::Error,
        <Store as RemoteTaskStore>::Error,
        <Reader as CommandVerifier>::Error,
        <Audit as AuditEventWriter>::Error,
    >;

    fn recover_tasks(&self) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        Box::pin(TaskMonitor::recover_tasks(self))
    }

    fn poll_operation(
        &self,
        operation_id: OperationId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<TaskPoll, Self::Error>> {
        Box::pin(TaskMonitor::poll(self, operation_id, now))
    }
}

/// Runs the scheduling loop until the stop signal fires.
///
/// The first tick fires immediately: after a restart, the §13.6 recovery scan
/// must resume unfinished work without waiting for the first period to
/// elapse. The stop signal is only observed between ticks — a tick already
/// in flight runs to completion, which is the §7.8 structured-drain contract
/// (the caller joins this task before closing `SQLite`).
///
/// The loop never returns an error and never panics: every fallible call
/// either isolates its failure to one operation or records the failed sweep
/// and retries on the next tick. `period` is injected so tests run the loop
/// at a fast cadence; production passes [`TICK_INTERVAL`].
#[instrument(skip_all, fields(period = ?period))]
pub(crate) async fn run<Store, Executor, Monitor, Time>(
    mut stop: StopWatch,
    engine: OperationEngine<&Store>,
    executor: Executor,
    monitor: Monitor,
    period: Duration,
    clock: Time,
) where
    Store: OperationStore,
    Executor: OperationDriver,
    Monitor: TaskPollDriver,
    Time: Clock,
{
    let mut interval = tokio::time::interval(period);
    // Ticks never burst: if one sweep outlasts the period, the next sweep
    // starts as soon as possible after it instead of piling up. Nothing is
    // skipped — every sweep is a full re-scan of the store.
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.stopped() => return,
            _ = interval.tick() => {
                // The stop may have landed while the interval arm was ready
                // (`select!` picks a ready arm at random): a signalled loop
                // must not start new work, so the sweep is skipped.
                if stop.has_stopped() {
                    return;
                }
                // One instant per sweep: every poll of the tick records the
                // same observation time (§13.6 `LastCheckedAt`).
                let now = clock.now();
                if let Err(error) = run_tick(&engine, &executor, &monitor, now).await {
                    // A failed sweep is not fatal: the loop stays alive and
                    // retries the whole sweep on the next tick.
                    tracing::error!("operation scheduling sweep failed: {error}");
                }
            }
        }
    }
}

/// One sweep of the scheduling loop.
///
/// # The pass structure
///
/// The sweep first lists the §13.6 recovery states
/// (`Validating`/`Running`/`WaitingRemote`/`Verifying`) and the new `Queued`
/// work; both lists are snapshots. The two passes then run concurrently:
///
/// 1. The executor pass dispatches each listed operation by its state:
///    - `Queued` and `Validating` run the execution flow through
///      [`OperationDriver::execute_operation`] — fresh work, and the
///      crash-resumed validation whose write was provably never issued
///      (design section 13.6);
///    - `Running` and `Verifying` are resolved through
///      [`OperationDriver::recover_operation`] — the §13.5
///      re-read-and-decide recovery for work whose write may already have
///      landed and must never be re-dispatched blindly;
///    - `WaitingRemote` operations are skipped here — the monitor pass owns
///      them.
///
///    The drives run concurrently (design §13.7 default concurrency) under
///    the [`MAX_CONCURRENT_DRIVES`] global bound, and each drive holds its
///    endpoint's one-permit write gate ([`endpoint_write_gate`], §7.8) for
///    its whole duration: one slow drive never blocks the other endpoints'
///    operations, while same-endpoint drives stay serial. Both lists are
///    snapshots; the driver rejects any state a second driver advanced in
///    the meantime, and that rejection is recorded like any per-operation
///    failure.
/// 2. The monitor pass lists the `WaitingRemote` operations through
///    [`TaskPollDriver::recover_tasks`] (the §13.6 resume scan) and polls
///    each with the sweep's shared instant.
///
/// Running the monitor pass concurrently with the executor drives is what
/// keeps a hung BMC from delaying the §13.6 Task polling: a drive may take
/// the full HTTP timeout, but the polls of this sweep are issued the moment
/// the waiting listing is available, not after the slowest drive finishes.
/// The tick still awaits every drive before returning — the §7.8
/// structured-drain contract, which also guarantees the next tick never
/// overlaps this one.
///
/// # Failure isolation
///
/// One operation's failure never interrupts the sweep: it is recorded and
/// the other operations run. Only a sweep-level failure (a listing) aborts
/// the tick, and the loop retries the whole sweep on the next tick. The
/// sweep itself never panics: every fallible call is handled.
///
/// # Errors
///
/// Returns [`TickSweepError::Recovery`] or [`TickSweepError::QueuedListing`]
/// when a store listing fails before the executor pass, and
/// [`TickSweepError::MonitorRecovery`] when the monitor's waiting listing
/// fails — the executor drives still drain before the error is returned. A
/// returned error always leaves at least one pass undispatched.
async fn run_tick<Store, Executor, Monitor>(
    engine: &OperationEngine<&Store>,
    executor: &Executor,
    monitor: &Monitor,
    now: OffsetDateTime,
) -> Result<(), TickSweepError<Store, Monitor>>
where
    Store: OperationStore,
    Executor: OperationDriver,
    Monitor: TaskPollDriver,
{
    // The §13.6 recovery states first (they are why a crash must not strand
    // operations), then the queued work submitted since the last sweep.
    let recovered = engine
        .recover_pending()
        .await
        .map_err(TickSweepError::Recovery)?;
    let queued = engine
        .list(Some(OperationState::Queued))
        .await
        .map_err(TickSweepError::QueuedListing)?;

    // The executor pass: one drive per operation, dispatched by state. The
    // terminal states can never appear in either listing, but the arm keeps
    // the dispatch exhaustive over the whole state vocabulary. Every drive
    // is a [`drive_one`] future — the endpoint's write gate, then the seam
    // call — so the whole pass is one homogeneous stream the concurrency
    // bound applies to.
    let drives = recovered.into_iter().chain(queued).filter_map(|operation| {
        let operation_id = operation.id();
        let endpoint_id = operation
            .targets()
            .first()
            .map(|target| target.endpoint_id());
        let outcome = match operation.state() {
            OperationState::Queued | OperationState::Validating => {
                Some(executor.execute_operation(operation_id))
            }
            OperationState::Running | OperationState::Verifying => {
                Some(executor.recover_operation(operation_id))
            }
            OperationState::WaitingRemote
            | OperationState::Succeeded
            | OperationState::Failed
            | OperationState::Unknown
            | OperationState::Cancelled => None,
        };
        outcome.map(|outcome| drive_one(outcome, operation_id, endpoint_id))
    });

    // The monitor pass runs concurrently with the executor drives and both
    // drain before the sweep returns: no drive is ever left running
    // detached, and a monitor-listing failure is reported only after the
    // already-dispatched drives have been awaited (§7.8 structured drain).
    let (_, monitor_result) = tokio::join!(
        stream::iter(drives)
            .buffer_unordered(MAX_CONCURRENT_DRIVES)
            .collect::<Vec<()>>(),
        async {
            let waiting = monitor
                .recover_tasks()
                .await
                .map_err(TickSweepError::MonitorRecovery)?;
            for operation in waiting {
                let operation_id = operation.id();
                if let Err(error) = monitor.poll_operation(operation_id, now).await {
                    tracing::error!("operation {operation_id} Task poll failed: {error}");
                }
            }
            Ok(())
        },
    );
    monitor_result
}

/// Runs one operation drive: holds the endpoint's one-permit write gate for
/// the whole drive (design §7.8 "写操作默认每个端点串行"), then awaits the
/// seam future and records any failure.
///
/// The gate is process-wide and never closed, so its acquire can only fail
/// if the registry itself broke; the drive is then recorded as failed
/// instead of running the endpoint ungated — the same controlled dead-end
/// as the refresh batch's coordination failure. A corrupt zero-target row
/// has no endpoint to gate; the drive proceeds and the driver's own
/// empty-target defense refuses it.
async fn drive_one<ErrorType>(
    outcome: BoundaryFuture<'_, Result<Operation, ErrorType>>,
    operation_id: OperationId,
    endpoint_id: Option<EndpointId>,
) where
    ErrorType: Error,
{
    // The permit is bound here, at the drive's scope, so it is held across
    // `outcome.await` and released only when the whole drive finishes — the
    // endpoint's next drive acquires the gate only after this one is done.
    let _permit = match endpoint_id {
        Some(endpoint_id) => {
            let Some(gate) = endpoint_write_gate(endpoint_id) else {
                tracing::error!(
                    "operation {operation_id} could not be gated: the write-gate registry is unavailable"
                );
                return;
            };
            let Ok(permit) = gate.acquire_owned().await else {
                tracing::error!(
                    "operation {operation_id} could not be gated: the endpoint write gate is closed"
                );
                return;
            };
            Some(permit)
        }
        None => None,
    };
    if let Err(error) = outcome.await {
        // One failed operation never stops the sweep; the next tick re-lists
        // it and tries again.
        tracing::error!("operation {operation_id} could not be driven: {error}");
    }
}

/// A controlled failure of one whole sweep.
///
/// Per-operation failures never appear here: they are recorded by the sweep
/// and the loop continues. Only the sweep's own listings can abort a tick,
/// and the loop retries the whole sweep on the next tick.
#[derive(Debug, Error)]
pub(crate) enum TickSweepError<Store, Monitor>
where
    Store: OperationStore,
    Monitor: TaskPollDriver,
{
    /// The §13.6 recovery listing failed; no operation was driven.
    #[error("failed to list recoverable operations: {0}")]
    Recovery(#[source] EngineError<Store::Error>),
    /// The queued-work listing failed; no operation was driven.
    #[error("failed to list queued operations: {0}")]
    QueuedListing(#[source] EngineError<Store::Error>),
    /// The waiting-remote listing failed; no Task was polled.
    #[error("failed to list waiting operations: {0}")]
    MonitorRecovery(#[source] Monitor::Error),
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        error::Error,
        fmt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration as StdDuration,
    };

    use rutilus_domain::{
        EndpointId, OperationSource, OperationTarget, RedfishCommand, ResetType, SystemCommand,
        TargetId,
    };
    use rutilus_operation_engine::{
        BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild,
    };
    use time::{Duration, OffsetDateTime};
    use tokio::sync::Notify;

    use super::*;

    /// The creation time of every test operation.
    fn created_at() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    /// The stable command every test operation carries.
    fn one_command() -> RedfishCommand {
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
    }

    /// Builds one engine-friendly target value.
    fn one_target() -> OperationTarget {
        OperationTarget::new(TargetId::generate(), EndpointId::generate())
    }

    /// Builds one queued operation.
    fn queued_operation() -> Operation {
        Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![one_target()],
            one_command(),
            created_at(),
        )
    }

    /// Builds one queued operation targeting exactly `endpoint_id`, so two
    /// operations can be pinned to the same endpoint.
    fn queued_operation_on(endpoint_id: EndpointId) -> Operation {
        Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            one_command(),
            created_at(),
        )
    }

    /// Builds one operation parked in the given state, as rehydration would.
    fn parked_operation(state: OperationState) -> Result<Operation, Box<dyn Error>> {
        Ok(Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![one_target()],
            one_command(),
            state,
            created_at(),
            created_at() + Duration::SECOND,
        )?)
    }

    /// The single mock failure vocabulary of every boundary under test.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Store,
        Driver,
        EmptyScript,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock {self:?} failure")
        }
    }

    impl Error for MockError {}

    /// One recorded store call, in order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum StoreCall {
        List(Option<OperationState>),
    }

    /// Which of the sweep's two listings is armed to fail.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ListingFailure {
        /// The §13.6 recovery listing (`List(None)`).
        Recovery,
        /// The queued-work listing (`List(Some(Queued))`).
        Queued,
    }

    /// In-memory operation store recording the sweep's listing calls.
    ///
    /// The sweep only lists through `OperationStore`, so the fake needs no
    /// remote-task rows; it mirrors the operation-engine tests' store fake.
    #[derive(Clone, Debug)]
    struct FakeStore {
        rows: Arc<Mutex<HashMap<OperationId, Operation>>>,
        calls: Arc<Mutex<Vec<StoreCall>>>,
        fail_listing: Arc<Mutex<Option<ListingFailure>>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                rows: Arc::new(Mutex::new(HashMap::new())),
                calls: Arc::new(Mutex::new(Vec::new())),
                fail_listing: Arc::new(Mutex::new(None)),
            }
        }

        fn insert(&self, operation: Operation) -> Result<(), MockError> {
            self.rows
                .lock()
                .map_err(|_| MockError::Events)?
                .insert(operation.id(), operation);
            Ok(())
        }

        /// Arms exactly one failure for the next listing of `state`: `None`
        /// arms the recovery listing, `Some` arms the queued listing.
        fn arm_listing_failure(&self, state: Option<OperationState>) -> Result<(), MockError> {
            *self.fail_listing.lock().map_err(|_| MockError::Events)? = Some(match state {
                None => ListingFailure::Recovery,
                // The sweep's second listing is always the queued one.
                Some(_) => ListingFailure::Queued,
            });
            Ok(())
        }

        fn recorded_calls(&self) -> Result<Vec<StoreCall>, MockError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }
    }

    impl OperationStore for FakeStore {
        type Error = MockError;

        fn create_operation<'a>(
            &'a self,
            _operation: &'a Operation,
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The sweep never creates operations; the submission path owns
            // that boundary.
            Box::pin(async move { Ok(()) })
        }

        fn find_operation(
            &self,
            _operation_id: OperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            // The sweep never reads single operations; the drivers re-read
            // every operation they drive.
            Box::pin(async move { Ok(None) })
        }

        fn apply_transition(
            &self,
            _operation_id: OperationId,
            _new_state: OperationState,
            _occurred_at: OffsetDateTime,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            // The sweep never steps the state machine; the executor owns
            // that boundary.
            Box::pin(async move { Ok(()) })
        }

        fn apply_transition_if_current(
            &self,
            _operation_id: OperationId,
            _expected_state: OperationState,
            _new_state: OperationState,
            _occurred_at: OffsetDateTime,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            // The sweep never steps the state machine; the executor owns
            // that boundary.
            Box::pin(async move { Ok(()) })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push(StoreCall::List(state));
                // The sweep only ever lists `None` and `Some(Queued)`, so the
                // armed listing is identified by the filter it carries.
                let armed = match state {
                    None => Some(ListingFailure::Recovery),
                    Some(OperationState::Queued) => Some(ListingFailure::Queued),
                    Some(_) => None,
                };
                let mut fail = self.fail_listing.lock().map_err(|_| MockError::Events)?;
                if *fail == armed {
                    *fail = None;
                    return Err(MockError::Store);
                }
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .values()
                    .filter(|operation| state.is_none_or(|state| operation.state() == state))
                    .cloned()
                    .collect())
            })
        }

        fn create_batch<'a>(
            &'a self,
            _batch: &'a rutilus_domain::BatchOperation,
            _children: &'a [Operation],
        ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
            // The sweep never creates batches; the submission path owns
            // that boundary.
            Box::pin(async move { Ok(()) })
        }

        fn find_batch(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Option<rutilus_domain::BatchOperation>, Self::Error>>
        {
            // The sweep never reads batches; batch reporting owns that
            // projection.
            Box::pin(async move { Ok(None) })
        }

        fn list_batches(
            &self,
        ) -> OperationBoundaryFuture<'_, Result<Vec<rutilus_domain::BatchOperation>, Self::Error>>
        {
            // The sweep never lists batches; batch reporting owns that
            // projection.
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: rutilus_domain::FailureKind,
        ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
            // The sweep never classifies failures; the executor's refusal
            // path owns that write.
            Box::pin(async move { Ok(()) })
        }

        fn list_batch_children(
            &self,
            _batch_id: rutilus_domain::BatchOperationId,
        ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            // The sweep never lists batch children; batch reporting owns
            // that projection.
            Box::pin(async move { Ok(Vec::new()) })
        }
    }

    /// One recorded driver call with the seam method that produced it.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum DriverCall {
        /// [`OperationDriver::execute_operation`] drove the operation.
        Execute(OperationId),
        /// [`OperationDriver::recover_operation`] drove the operation.
        Recover(OperationId),
    }

    /// Scripted executor double recording every driven operation and the
    /// seam method that drove it.
    ///
    /// The script pops one entry per call; an `Ok` entry records a completed
    /// drive, an `Err` entry records the fake's controlled failure, and an
    /// exhausted script is itself a loud failure so a miswired test fails on
    /// the assertion instead of silently succeeding.
    #[derive(Clone, Debug)]
    struct FakeExecutor {
        calls: Arc<Mutex<Vec<DriverCall>>>,
        script: Arc<Mutex<VecDeque<Result<(), MockError>>>>,
        gate: Option<Arc<Notify>>,
        gate_for: Option<OperationId>,
        gate_first: Option<Arc<AtomicUsize>>,
    }

    impl FakeExecutor {
        fn new(script: Vec<Result<(), MockError>>) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                script: Arc::new(Mutex::new(VecDeque::from(script))),
                gate: None,
                gate_for: None,
                gate_first: None,
            }
        }

        /// Builds an executor whose calls block until the gate fires,
        /// pinning the loop's in-flight-tick drain behavior.
        fn gated() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                script: Arc::new(Mutex::new(VecDeque::from(vec![Ok(())]))),
                gate: Some(Arc::new(Notify::new())),
                gate_for: None,
                gate_first: None,
            }
        }

        /// Builds an executor whose drive of exactly `operation_id` blocks
        /// until the gate fires; every other drive passes through — the
        /// model of one slow BMC drive next to healthy ones.
        fn gated_for(operation_id: OperationId) -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                script: Arc::new(Mutex::new(VecDeque::from(vec![Ok(()); 2]))),
                gate: Some(Arc::new(Notify::new())),
                gate_for: Some(operation_id),
                gate_first: None,
            }
        }

        /// Builds an executor whose first call blocks until the gate fires
        /// and every later call passes through — the model of one drive
        /// holding an endpoint gate while another waits on it.
        fn gated_first() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
                script: Arc::new(Mutex::new(VecDeque::from(vec![Ok(()); 2]))),
                gate: Some(Arc::new(Notify::new())),
                gate_for: None,
                gate_first: Some(Arc::new(AtomicUsize::new(1))),
            }
        }

        fn recorded_calls(&self) -> Result<Vec<DriverCall>, MockError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| MockError::Events)
        }

        /// One scripted drive, shared by both seam methods.
        async fn drive(&self, call: DriverCall) -> Result<Operation, MockError> {
            self.calls.lock().map_err(|_| MockError::Events)?.push(call);
            if let Some(gate) = &self.gate {
                // The release future is registered before the call
                // blocks, so a release fired while the call is in flight
                // is never lost.
                let blocked = match &self.gate_for {
                    Some(operation_id) => call.operation_id() == *operation_id,
                    None => match &self.gate_first {
                        Some(remaining) => remaining.fetch_sub(1, Ordering::SeqCst) > 0,
                        None => true,
                    },
                };
                if blocked {
                    gate.notified().await;
                }
            }
            match self
                .script
                .lock()
                .map_err(|_| MockError::Events)?
                .pop_front()
            {
                Some(Ok(())) => Ok(Operation::new(
                    call.operation_id(),
                    OperationSource::Standalone,
                    vec![one_target()],
                    one_command(),
                    created_at(),
                )),
                Some(Err(error)) => Err(error),
                None => Err(MockError::EmptyScript),
            }
        }
    }

    impl DriverCall {
        /// The operation id the call drove.
        const fn operation_id(self) -> OperationId {
            match self {
                Self::Execute(operation_id) | Self::Recover(operation_id) => operation_id,
            }
        }
    }

    impl OperationDriver for FakeExecutor {
        type Error = MockError;

        fn execute_operation(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Operation, Self::Error>> {
            Box::pin(async move { self.drive(DriverCall::Execute(operation_id)).await })
        }

        fn recover_operation(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Operation, Self::Error>> {
            Box::pin(async move { self.drive(DriverCall::Recover(operation_id)).await })
        }
    }

    /// Scripted Task-poll double recording every poll.
    ///
    /// The recovery listing serves one fixed list (the sweep never mutates
    /// it), and each poll pops its script like the executor's.
    #[derive(Clone, Debug)]
    struct FakeMonitor {
        recovered: Arc<Mutex<Vec<Operation>>>,
        fail_recovery: Arc<Mutex<bool>>,
        polls: Arc<Mutex<Vec<(OperationId, OffsetDateTime)>>>,
        poll_script: Arc<Mutex<VecDeque<Result<(), MockError>>>>,
    }

    impl FakeMonitor {
        fn new(recovered: Vec<Operation>, poll_script: Vec<Result<(), MockError>>) -> Self {
            Self {
                recovered: Arc::new(Mutex::new(recovered)),
                fail_recovery: Arc::new(Mutex::new(false)),
                polls: Arc::new(Mutex::new(Vec::new())),
                poll_script: Arc::new(Mutex::new(VecDeque::from(poll_script))),
            }
        }

        /// Arms exactly one recovery-listing failure.
        fn arm_recovery_failure(&self) -> Result<(), MockError> {
            *self.fail_recovery.lock().map_err(|_| MockError::Events)? = true;
            Ok(())
        }

        fn recorded_polls(&self) -> Result<Vec<(OperationId, OffsetDateTime)>, MockError> {
            self.polls
                .lock()
                .map(|polls| polls.clone())
                .map_err(|_| MockError::Events)
        }
    }

    impl TaskPollDriver for FakeMonitor {
        type Error = MockError;

        fn recover_tasks(&self) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                let mut fail = self.fail_recovery.lock().map_err(|_| MockError::Events)?;
                if *fail {
                    *fail = false;
                    return Err(MockError::Driver);
                }
                Ok(self
                    .recovered
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .clone())
            })
        }

        fn poll_operation(
            &self,
            operation_id: OperationId,
            now: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<TaskPoll, Self::Error>> {
            Box::pin(async move {
                self.polls
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .push((operation_id, now));
                match self
                    .poll_script
                    .lock()
                    .map_err(|_| MockError::Events)?
                    .pop_front()
                {
                    Some(Ok(())) => Ok(TaskPoll::StillRunning(Operation::new(
                        operation_id,
                        OperationSource::Standalone,
                        vec![one_target()],
                        one_command(),
                        created_at(),
                    ))),
                    Some(Err(error)) => Err(error),
                    None => Err(MockError::EmptyScript),
                }
            })
        }
    }

    /// Fixed wall clock for deterministic tick instants.
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    #[tokio::test]
    async fn tick_drives_queued_and_recovered_work_then_polls_waiting_tasks()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let queued = queued_operation();
        store.insert(queued.clone())?;
        let validating = parked_operation(OperationState::Validating)?;
        store.insert(validating.clone())?;
        let running = parked_operation(OperationState::Running)?;
        store.insert(running.clone())?;
        let waiting = parked_operation(OperationState::WaitingRemote)?;
        store.insert(waiting.clone())?;
        let executor = FakeExecutor::new(vec![Ok(()), Ok(()), Ok(())]);
        let monitor = FakeMonitor::new(vec![waiting.clone()], vec![Ok(())]);
        let now = created_at() + Duration::SECOND * 4;

        run_tick(&OperationEngine::new(&store), &executor, &monitor, now).await?;

        // One listing for the §13.6 recovery scan, one for the new work.
        assert_eq!(
            store.recorded_calls()?,
            [
                StoreCall::List(None),
                StoreCall::List(Some(OperationState::Queued)),
            ]
        );
        // The executor pass dispatches by state: the recovered Validating
        // operation and the queued operation run the execution flow, the
        // recovered Running operation runs the §13.5 recovery flow, and the
        // WaitingRemote operation is skipped (the monitor pass owns it). The
        // two recovered operations are driven in store order, which the fake
        // lists in hash-map order, so their relative order is not pinned —
        // only the state-to-seam mapping is.
        let driven = executor.recorded_calls()?;
        assert_eq!(driven.len(), 3);
        assert!(driven.contains(&DriverCall::Execute(validating.id())));
        assert!(driven.contains(&DriverCall::Recover(running.id())));
        assert!(driven.contains(&DriverCall::Execute(queued.id())));
        // The monitor pass polls exactly the waiting operations with the
        // sweep's shared instant.
        assert_eq!(monitor.recorded_polls()?, [(waiting.id(), now)]);
        Ok(())
    }

    #[tokio::test]
    async fn tick_isolates_single_operation_failures_and_keeps_going() -> Result<(), Box<dyn Error>>
    {
        let store = FakeStore::new();
        let first = queued_operation();
        let second = queued_operation();
        store.insert(first.clone())?;
        store.insert(second.clone())?;
        let executor = FakeExecutor::new(vec![Err(MockError::Driver), Ok(())]);
        let waiting = parked_operation(OperationState::WaitingRemote)?;
        let monitor = FakeMonitor::new(vec![waiting.clone()], vec![Err(MockError::Driver)]);
        let now = created_at() + Duration::SECOND * 2;

        run_tick(&OperationEngine::new(&store), &executor, &monitor, now).await?;

        // Both failed operations were still driven and the sweep reported no
        // error: failures are recorded, never fatal. The drive order is not
        // pinned: the store fake lists rows in hash-map order, so the two
        // queued operations may be driven in either order.
        let driven = executor.recorded_calls()?;
        assert_eq!(driven.len(), 2);
        assert!(driven.contains(&DriverCall::Execute(first.id())));
        assert!(driven.contains(&DriverCall::Execute(second.id())));
        assert_eq!(monitor.recorded_polls()?, [(waiting.id(), now)]);
        Ok(())
    }

    #[tokio::test]
    async fn tick_aborts_before_dispatching_when_the_recovery_listing_fails()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        store.insert(queued_operation())?;
        store.arm_listing_failure(None)?;
        let executor = FakeExecutor::new(Vec::new());
        let monitor = FakeMonitor::new(Vec::new(), Vec::new());

        match run_tick(
            &OperationEngine::new(&store),
            &executor,
            &monitor,
            created_at(),
        )
        .await
        {
            Err(TickSweepError::Recovery(_)) => {}
            other => {
                return Err(std::io::Error::other(format!(
                    "expected a recovery failure, got {other:?}"
                ))
                .into());
            }
        }
        assert_eq!(executor.recorded_calls()?, Vec::new());
        assert_eq!(monitor.recorded_polls()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn tick_aborts_before_dispatching_when_the_queued_listing_fails()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        store.insert(parked_operation(OperationState::Validating)?)?;
        // The recovery listing succeeds first; the queued listing fails.
        store.arm_listing_failure(Some(OperationState::Queued))?;
        let executor = FakeExecutor::new(Vec::new());
        let monitor = FakeMonitor::new(Vec::new(), Vec::new());

        match run_tick(
            &OperationEngine::new(&store),
            &executor,
            &monitor,
            created_at(),
        )
        .await
        {
            Err(TickSweepError::QueuedListing(_)) => {}
            other => {
                return Err(std::io::Error::other(format!(
                    "expected a queued-listing failure, got {other:?}"
                ))
                .into());
            }
        }
        assert_eq!(executor.recorded_calls()?, Vec::new());
        assert_eq!(monitor.recorded_polls()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn tick_reports_the_monitor_recovery_failure_alongside_the_executor_pass()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let queued = queued_operation();
        store.insert(queued.clone())?;
        let executor = FakeExecutor::new(vec![Ok(())]);
        let monitor = FakeMonitor::new(Vec::new(), Vec::new());
        monitor.arm_recovery_failure()?;

        match run_tick(
            &OperationEngine::new(&store),
            &executor,
            &monitor,
            created_at(),
        )
        .await
        {
            Err(TickSweepError::MonitorRecovery(_)) => {}
            other => {
                return Err(std::io::Error::other(format!(
                    "expected a monitor recovery failure, got {other:?}"
                ))
                .into());
            }
        }
        // The passes run concurrently, but the sweep still drained the
        // executor drive before returning: no drive is ever left running
        // detached (§7.8), and the failed monitor listing aborted the sweep
        // after the executor pass had already dispatched its work.
        assert_eq!(
            executor.recorded_calls()?,
            [DriverCall::Execute(queued.id())]
        );
        assert_eq!(monitor.recorded_polls()?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn stop_watch_resolves_on_signal_and_on_signal_drop() -> Result<(), Box<dyn Error>> {
        let (stop_signal, stop_watch) = StopSignal::new();
        let mut first = stop_watch.clone();
        let mut second = stop_watch;

        stop_signal.signal();
        first.stopped().await;

        // Dropping the signal side also resolves every waiter, so shutdown
        // is guaranteed even when `signal` is never called.
        drop(stop_signal);
        second.stopped().await;
        Ok(())
    }

    #[tokio::test]
    async fn loop_ticks_until_the_stop_signal() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        store.insert(queued_operation())?;
        let executor = FakeExecutor::new(vec![Ok(()); 8]);
        let loop_executor = executor.clone();
        let monitor = FakeMonitor::new(Vec::new(), Vec::new());
        let (stop_signal, stop_watch) = StopSignal::new();
        let loop_task = tokio::spawn(async move {
            let engine = OperationEngine::new(&store);
            run(
                stop_watch,
                engine,
                loop_executor,
                monitor,
                StdDuration::from_millis(20),
                FixedClock(created_at()),
            )
            .await;
        });

        // Wait for at least two ticks, then stop the loop.
        for _ in 0..200 {
            if executor.recorded_calls()?.len() >= 2 {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
        assert!(
            executor.recorded_calls()?.len() >= 2,
            "the loop never completed two ticks"
        );
        stop_signal.signal();
        tokio::time::timeout(StdDuration::from_secs(2), loop_task)
            .await
            .map_err(|_| std::io::Error::other("the loop did not stop"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))?;
        Ok(())
    }

    #[tokio::test]
    async fn loop_finishes_the_tick_in_flight_before_stopping() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        store.insert(queued_operation())?;
        let gated = FakeExecutor::gated();
        let loop_executor = gated.clone();
        let gate = loop_executor
            .gate
            .clone()
            .ok_or_else(|| std::io::Error::other("the gated fake lost its gate"))?;
        let monitor = FakeMonitor::new(Vec::new(), Vec::new());
        let (stop_signal, stop_watch) = StopSignal::new();
        let mut loop_task = tokio::spawn(async move {
            let engine = OperationEngine::new(&store);
            run(
                stop_watch,
                engine,
                loop_executor,
                monitor,
                StdDuration::from_millis(100),
                FixedClock(created_at()),
            )
            .await;
        });

        // Wait until the first tick is in flight, blocked inside the driver.
        for _ in 0..200 {
            if !gated.recorded_calls()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            !gated.recorded_calls()?.is_empty(),
            "the first tick never started"
        );
        stop_signal.signal();
        // While the tick is still blocked, the loop must not exit (§7.8
        // structured drain: the in-flight tick finishes first).
        assert!(
            tokio::time::timeout(StdDuration::from_millis(80), &mut loop_task)
                .await
                .is_err(),
            "the loop exited while its tick was still in flight"
        );
        gate.notify_one();
        tokio::time::timeout(StdDuration::from_secs(2), loop_task)
            .await
            .map_err(|_| std::io::Error::other("the loop did not stop"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))?;
        // The in-flight tick ran to completion exactly once before the loop
        // observed the stop signal: no second tick started.
        assert_eq!(
            gated.recorded_calls()?.len(),
            1,
            "a second tick started after the stop signal"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_slow_drive_never_blocks_other_endpoints_or_task_polling()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let slow = queued_operation();
        let fast = queued_operation();
        store.insert(slow.clone())?;
        store.insert(fast.clone())?;
        let waiting = parked_operation(OperationState::WaitingRemote)?;
        store.insert(waiting.clone())?;
        let executor = FakeExecutor::gated_for(slow.id());
        let probe = executor.clone();
        let gate = executor
            .gate
            .clone()
            .ok_or_else(|| std::io::Error::other("the gated fake lost its gate"))?;
        let monitor = FakeMonitor::new(vec![waiting.clone()], vec![Ok(())]);
        let monitor_probe = monitor.clone();
        let waiting_id = waiting.id();
        let now = created_at() + Duration::SECOND * 4;

        let mut tick = tokio::spawn(async move {
            run_tick(&OperationEngine::new(&store), &executor, &monitor, now).await
        });

        // The slow drive blocks inside the fake; the other endpoint's
        // operation and the §13.6 Task poll must still complete while it is
        // stuck.
        for _ in 0..200 {
            if !monitor_probe.recorded_polls()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(10)).await;
        }
        let driven = probe.recorded_calls()?;
        assert!(
            driven.contains(&DriverCall::Execute(fast.id())),
            "the other endpoint's operation must be driven while the slow drive is blocked"
        );
        assert_eq!(
            monitor_probe.recorded_polls()?,
            [(waiting_id, now)],
            "the Task poll must run while the slow drive is blocked"
        );
        // The tick is still in flight: the slow drive has not completed, and
        // the sweep waits for it only as its own structured drain.
        assert!(
            tokio::time::timeout(StdDuration::from_millis(80), &mut tick)
                .await
                .is_err(),
            "the tick exited while the slow drive was still blocked"
        );

        // Releasing the gate lets the slow drive finish and the sweep return.
        gate.notify_one();
        tokio::time::timeout(StdDuration::from_secs(2), tick)
            .await
            .map_err(|_| std::io::Error::other("the tick did not finish"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))??;
        Ok(())
    }

    #[tokio::test]
    async fn same_endpoint_drives_are_serialized_by_the_endpoint_write_gate()
    -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let endpoint_id = EndpointId::generate();
        let first = queued_operation_on(endpoint_id);
        let second = queued_operation_on(endpoint_id);
        store.insert(first.clone())?;
        store.insert(second.clone())?;
        let executor = FakeExecutor::gated_first();
        let probe = executor.clone();
        let gate = executor
            .gate
            .clone()
            .ok_or_else(|| std::io::Error::other("the gated fake lost its gate"))?;
        let monitor = FakeMonitor::new(Vec::new(), Vec::new());

        let tick = tokio::spawn(async move {
            run_tick(
                &OperationEngine::new(&store),
                &executor,
                &monitor,
                created_at(),
            )
            .await
        });

        // Wait until one drive is recorded and blocked inside the fake.
        for _ in 0..200 {
            if !probe.recorded_calls()?.is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        // The first drive holds the endpoint's one-permit write gate, so the
        // second same-endpoint drive is queued at the gate — its seam call
        // is not even recorded (§7.8 "写操作默认每个端点串行").
        assert_eq!(
            probe.recorded_calls()?.len(),
            1,
            "the same-endpoint drive must wait on the endpoint write gate"
        );

        // Releasing the gate lets the first drive finish and the second run.
        gate.notify_one();
        tokio::time::timeout(StdDuration::from_secs(2), tick)
            .await
            .map_err(|_| std::io::Error::other("the tick did not finish"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))??;
        assert_eq!(
            probe.recorded_calls()?.len(),
            2,
            "the second drive must run after the first released the gate"
        );
        Ok(())
    }
}
