//! The §14.4 telemetry sampling loop (design sections 14.4 and 7.8).
//!
//! One background task ticks every [`TELEMETRY_SAMPLE_INTERVAL`]. Each tick
//! re-lists the enrolled endpoints (so an endpoint enrolled mid-run is
//! picked up by the next tick, unlike the event listeners' startup sweep),
//! samples every endpoint through the [`TelemetryDriver`] seam — the
//! application [`TelemetrySampler`] use case over the stored-snapshot reader
//! — and prunes the history older than [`TELEMETRY_RETENTION`] through the
//! same seam. The listing failure aborts only the sweep, never the loop: the
//! next tick retries.
//!
//! # Why sixty seconds
//!
//! Sampling cadence is a product choice (design §14.4: 采样器节奏由产品控
//! 制), and the sampler reads *stored* refresh snapshots, so its freshness is
//! bounded by the refresh cadence anyway — a faster tick would re-read the
//! same Generation uselessly. Sixty seconds matches the typical Redfish
//! telemetry collection cadence and keeps a series' stored history small
//! (10,080 samples per series per week at this cadence), while the
//! scheduler's two-second tick stays reserved for operations, where a human
//! waits on the latency.
//!
//! # Why the retention is a constant
//!
//! Design §14.4 requires the history retention to be configurable (历史保留
//! 周期可配置); 0.4.0 realizes it as the [`TELEMETRY_RETENTION`] constant,
//! and the configuration surface (the settings page of a later iteration)
//! will pass the same constant through to the prune use case. The honest
//! 0.4.0 position: the retention is a product constant, documented where an
//! operator can find it, not yet a setting.
//!
//! # Cancellation and drain (design §7.8)
//!
//! The loop observes its [`StopWatch`] at two points, exactly like the
//! scheduling loop: while waiting for the next tick, and before starting a
//! sweep that a stop may have landed on while the tick was pending. A stop
//! that lands mid-sweep is honored only after the sweep finishes — every
//! in-flight sample completes and the prune runs — so no store write is
//! abandoned mid-flight (structured drain). The runtime joins the task
//! before closing `SQLite`.
//!
//! # Failure isolation
//!
//! One endpoint's failed sampling never touches the others: each failure is
//! recorded through `tracing::error!` (the crate's operational-failure
//! precedent) and the next endpoint runs. Only a sweep-level failure (the
//! endpoint listing) aborts the tick, and the loop retries it on the next
//! tick. The loop itself never panics: every fallible call is handled.

use std::{error::Error, time::Duration};

use rutilus_application::{
    BoundaryFuture, Clock, EndpointSampling, MetricReportReader, TelemetryRepository,
    TelemetrySampler, TelemetrySamplerError,
};
use rutilus_domain::EndpointId;
use time::OffsetDateTime;

use crate::scheduler::StopWatch;

/// The cadence of one full sampling sweep.
///
/// # Why sixty seconds
///
/// See the module doc: the sampler reads stored refresh snapshots, so a
/// faster tick would re-read the same Generation uselessly; sixty seconds
/// matches the typical Redfish metric collection cadence and bounds the
/// stored history to 10,080 samples per series per week.
///
/// The unit is `std::time::Duration` because it feeds the tokio ticker.
// std's `Duration` has no minutes constructor (the lint's `from_mins`
// suggestion is the time crate's), and the sixty-second value is spelled in
// seconds to match the module doc's cadence arithmetic.
#[allow(clippy::duration_suboptimal_units)]
pub(crate) const TELEMETRY_SAMPLE_INTERVAL: Duration = Duration::from_secs(60);

/// How long one series' samples are kept before the prune deletes them.
///
/// # Why seven days
///
/// A week of history at the sixty-second cadence is 10,080 samples per
/// series — enough to see a trend across a maintenance cycle while keeping
/// the `SQLite` store small. The §14.4 "历史保留周期可配置" requirement is
/// realized as this constant in `0.4.0`; the settings surface (a later
/// iteration) will pass the configured value through the same prune use
/// case, and this constant is the documented default.
///
/// The unit is the `time` crate's `Duration` because it feeds the prune use
/// case's clock arithmetic (`OffsetDateTime::checked_sub`).
pub(crate) const TELEMETRY_RETENTION: time::Duration = time::Duration::days(7);

/// The record seam the sampling loop drives.
///
/// # Why a seam
///
/// Exactly like the scheduler's `OperationDriver`: the loop only needs
/// "sample one endpoint now" and "prune history older than the retention",
/// and must never interpret the use case's verdicts itself. The seam keeps
/// the loop testable with scripted fakes and erases the sampling error
/// vocabulary into one opaque failure that the loop records and moves on
/// from.
pub(crate) trait TelemetryDriver: Send + Sync {
    /// The driver's controlled failure type; only its `Display` is used.
    type Error: Error + Send + Sync + 'static;

    /// Samples one endpoint's current metric values into the store.
    fn sample_endpoint(
        &self,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<EndpointSampling, Self::Error>>;

    /// Prunes every sample older than the retention window.
    fn prune_history(
        &self,
        retention: time::Duration,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

/// The application sampling use case behind the driver seam.
impl<Reader, Store, Time> TelemetryDriver for TelemetrySampler<Reader, Store, Time>
where
    Reader: MetricReportReader,
    Store: TelemetryRepository,
    Time: Clock,
{
    type Error = TelemetrySamplerError<Reader::Error, Store::Error>;

    fn sample_endpoint(
        &self,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<EndpointSampling, Self::Error>> {
        Box::pin(async move { TelemetrySampler::sample_endpoint(self, endpoint_id, now).await })
    }

    fn prune_history(
        &self,
        retention: time::Duration,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move { TelemetrySampler::prune_history(self, retention).await })
    }
}

/// The enrolled-endpoint listing seam of the sampling loop.
///
/// The loop re-lists every tick — unlike the event listeners' startup sweep —
/// so an endpoint enrolled mid-run is sampled from the next tick on.
pub(crate) trait EndpointLister: Send + Sync {
    /// The listing's controlled failure type; only its `Display` is used.
    type Error: Error + Send + Sync + 'static;

    /// Lists the ids of every enrolled endpoint.
    fn list_enrolled_endpoints(&self) -> BoundaryFuture<'_, Result<Vec<EndpointId>, Self::Error>>;
}

/// Runs the sampling loop until the stop signal, sweeping once per interval.
///
/// The loop mirrors the scheduling loop's §7.8 shape: the stop signal is
/// observed while waiting for the next tick and before starting a sweep, the
/// in-flight sweep finishes before the loop exits (structured drain), and a
/// failed sweep is recorded and retried on the next tick. The caller passes
/// the retention — the loop's only product constant besides the interval —
/// so tests can drive the cadence fast and the runtime owns the policy.
pub(crate) async fn run<Driver, Lister, Time>(
    mut stop: StopWatch,
    driver: &Driver,
    lister: &Lister,
    interval: Duration,
    retention: time::Duration,
    clock: Time,
) where
    Driver: TelemetryDriver,
    Lister: EndpointLister,
    Time: Clock,
{
    let mut ticker = tokio::time::interval(interval);
    // Ticks never burst: if one sweep outlasts the interval, the next sweep
    // starts as soon as possible after it instead of piling up. Nothing is
    // skipped — every sweep re-lists and re-samples every endpoint.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            () = stop.stopped() => return,
            _ = ticker.tick() => {
                // The stop may have landed while the interval arm was ready
                // (`select!` picks a ready arm at random): a signalled loop
                // must not start new work, so the sweep is skipped.
                if stop.has_stopped() {
                    return;
                }
                // One instant per sweep: every endpoint sampled by the tick
                // records the same observation time, like the scheduler's
                // shared sweep instant.
                let now = clock.now();
                run_tick(driver, lister, retention, now).await;
            }
        }
    }
}

/// One sweep of the sampling loop: list, sample every endpoint, prune.
///
/// # Failure isolation
///
/// One endpoint's failure never interrupts the sweep: it is recorded and the
/// next endpoint runs. Only the listing failure aborts the sweep — without a
/// listing there is no work to dispatch — and the loop retries the whole
/// sweep on the next tick. The prune runs after the sampling pass
/// regardless of per-endpoint failures, so a tick that sampled nothing still
/// enforces the retention bound.
async fn run_tick<Driver, Lister>(
    driver: &Driver,
    lister: &Lister,
    retention: time::Duration,
    now: OffsetDateTime,
) where
    Driver: TelemetryDriver,
    Lister: EndpointLister,
{
    let endpoints = match lister.list_enrolled_endpoints().await {
        Ok(endpoints) => endpoints,
        Err(error) => {
            tracing::error!("telemetry sampling sweep could not list enrolled endpoints: {error}");
            return;
        }
    };
    for endpoint_id in endpoints {
        if let Err(error) = driver.sample_endpoint(endpoint_id, now).await {
            tracing::error!("telemetry sampling failed for endpoint {endpoint_id}: {error}");
        }
    }
    if let Err(error) = driver.prune_history(retention).await {
        tracing::error!("telemetry history pruning failed: {error}");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        error::Error,
        fmt,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration as StdDuration,
    };

    use time::OffsetDateTime;
    use tokio::sync::Notify;

    use crate::scheduler::StopSignal;

    use super::*;

    /// A fast production-shaped cadence for tests.
    const FAST_INTERVAL: Duration = Duration::from_millis(1);

    /// One recorded driver call, in exact order.
    #[derive(Clone, Debug, Eq, PartialEq)]
    enum DriverCall {
        Sample(EndpointId),
        Prune,
    }

    /// Scripted driver recording every call, with per-endpoint failures and
    /// an optional one-shot sample gate.
    #[derive(Clone, Debug, Default)]
    struct FakeDriver {
        calls: Arc<Mutex<Vec<DriverCall>>>,
        failures: Arc<Mutex<HashMap<EndpointId, usize>>>,
        gate: Option<Arc<Notify>>,
    }

    impl FakeDriver {
        /// Marks every sample of `endpoint_id` to fail `times` times.
        fn fail_samples_of(&self, endpoint_id: EndpointId, times: usize) {
            self.failures
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(endpoint_id, times);
        }

        /// Builds a driver whose first sample blocks until the gate fires.
        fn gated() -> (Self, Arc<Notify>) {
            let gate = Arc::new(Notify::new());
            let driver = Self {
                gate: Some(Arc::clone(&gate)),
                ..Self::default()
            };
            (driver, gate)
        }

        fn calls(&self) -> Vec<DriverCall> {
            self.calls
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }
    }

    impl TelemetryDriver for FakeDriver {
        type Error = MockError;

        fn sample_endpoint(
            &self,
            endpoint_id: EndpointId,
            _now: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<EndpointSampling, Self::Error>> {
            Box::pin(async move {
                // The call is recorded before the gate blocks, so a recorded
                // sample that never completes is exactly the in-flight one.
                self.calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(DriverCall::Sample(endpoint_id));
                if let Some(gate) = &self.gate {
                    // The release future is registered before the sample
                    // blocks, so a release fired while the sample is in
                    // flight is never lost.
                    let released = gate.notified();
                    released.await;
                }
                let mut failures = self
                    .failures
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let remaining = failures.get(&endpoint_id).copied().unwrap_or(0);
                if remaining > 0 {
                    if remaining == 1 {
                        failures.remove(&endpoint_id);
                    } else {
                        failures.insert(endpoint_id, remaining - 1);
                    }
                    return Err(MockError::Store);
                }
                Ok(EndpointSampling::new(1, 1))
            })
        }

        fn prune_history(
            &self,
            _retention: time::Duration,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(DriverCall::Prune);
                Ok(())
            })
        }
    }

    /// Scripted endpoint listing, with a shared listing-failure flag so the
    /// test can flip it while the loop task holds its clone.
    #[derive(Clone, Debug, Default)]
    struct FakeLister {
        endpoints: Arc<Mutex<Vec<EndpointId>>>,
        fail_listing: Arc<AtomicBool>,
    }

    impl FakeLister {
        fn with_endpoints(endpoints: Vec<EndpointId>) -> Self {
            Self {
                endpoints: Arc::new(Mutex::new(endpoints)),
                fail_listing: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    impl EndpointLister for FakeLister {
        type Error = MockError;

        fn list_enrolled_endpoints(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointId>, Self::Error>> {
            Box::pin(async move {
                if self.fail_listing.load(Ordering::Relaxed) {
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
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::Store => "mock driver failed",
                Self::Lock => "mock state is unavailable",
            })
        }
    }

    impl Error for MockError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    async fn join_with_timeout(task: tokio::task::JoinHandle<()>) -> Result<(), Box<dyn Error>> {
        tokio::time::timeout(StdDuration::from_secs(2), task)
            .await
            .map_err(|_| std::io::Error::other("the sampler did not stop"))?
            .map_err(|join_error| std::io::Error::other(join_error.to_string()))?;
        Ok(())
    }

    #[tokio::test]
    async fn every_tick_lists_samples_every_endpoint_then_prunes() -> Result<(), Box<dyn Error>> {
        let first = EndpointId::generate();
        let second = EndpointId::generate();
        let driver = FakeDriver::default();
        let lister = FakeLister::with_endpoints(vec![first, second]);
        let loop_driver = driver.clone();
        let loop_lister = lister.clone();
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_driver,
                &loop_lister,
                FAST_INTERVAL,
                TELEMETRY_RETENTION,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        });
        // Let at least two full sweeps land, then stop.
        for _ in 0..200 {
            if driver
                .calls()
                .iter()
                .filter(|call| **call == DriverCall::Prune)
                .count()
                >= 2
            {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        stop_signal.signal();
        join_with_timeout(task).await?;

        let calls = driver.calls();
        assert!(
            calls
                .iter()
                .filter(|call| **call == DriverCall::Prune)
                .count()
                >= 2,
            "the loop must sweep repeatedly"
        );
        // Every sweep runs list → sample(each endpoint) → prune, in order.
        let mut cursor = calls.as_slice();
        while let Some(rest) = cursor.strip_prefix(&[
            DriverCall::Sample(first),
            DriverCall::Sample(second),
            DriverCall::Prune,
        ]) {
            cursor = rest;
        }
        assert!(
            cursor.is_empty(),
            "the sweep order must be sample(s) then prune: {calls:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn one_failed_endpoint_does_not_affect_the_others() -> Result<(), Box<dyn Error>> {
        let doomed = EndpointId::generate();
        let healthy = EndpointId::generate();
        let driver = FakeDriver::default();
        driver.fail_samples_of(doomed, 1);
        let lister = FakeLister::with_endpoints(vec![doomed, healthy]);
        let loop_driver = driver.clone();
        let loop_lister = lister.clone();
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_driver,
                &loop_lister,
                FAST_INTERVAL,
                TELEMETRY_RETENTION,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        });
        // Wait until the healthy endpoint was sampled after the doomed one
        // failed, then stop.
        for _ in 0..200 {
            if driver.calls().contains(&DriverCall::Sample(healthy)) {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        stop_signal.signal();
        join_with_timeout(task).await?;

        let calls = driver.calls();
        assert!(
            calls.contains(&DriverCall::Sample(healthy)),
            "the healthy endpoint must be sampled despite the doomed one's failure"
        );
        assert!(
            calls.contains(&DriverCall::Prune),
            "the prune must run despite the per-endpoint failure"
        );
        Ok(())
    }

    #[tokio::test]
    async fn stop_during_an_in_flight_sample_finishes_the_sample_first()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let (driver, gate) = FakeDriver::gated();
        let lister = FakeLister::with_endpoints(vec![endpoint_id]);
        let loop_driver = driver.clone();
        let loop_lister = lister.clone();
        let (stop_signal, stop_watch) = StopSignal::new();

        let mut task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_driver,
                &loop_lister,
                FAST_INTERVAL,
                TELEMETRY_RETENTION,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        });
        // Wait until the sample is in flight: the driver records the call
        // before blocking on the gate, so a recorded sample that never
        // completes is exactly the in-flight one.
        for _ in 0..200 {
            if driver.calls().contains(&DriverCall::Sample(endpoint_id)) {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            driver.calls().contains(&DriverCall::Sample(endpoint_id)),
            "the first sample never started"
        );
        stop_signal.signal();
        // While the sample is still blocked, the loop must not exit (§7.8
        // structured drain: the in-flight sweep finishes first).
        assert!(
            tokio::time::timeout(StdDuration::from_millis(80), &mut task)
                .await
                .is_err(),
            "the loop exited while its sample was still being recorded"
        );
        gate.notify_one();
        join_with_timeout(task).await?;
        // The blocked sample ran to completion, the sweep finished its prune,
        // and no further sweep started after the stop signal (the tick-arm
        // guard of `run`).
        assert_eq!(
            driver.calls(),
            [DriverCall::Sample(endpoint_id), DriverCall::Prune,],
            "the in-flight sample must complete and the sweep must finish"
        );
        Ok(())
    }

    // std's `Duration` has no minutes constructor; the sixty-second spelling
    // mirrors the production constant's unit.
    #[allow(clippy::duration_suboptimal_units)]
    #[tokio::test]
    async fn loop_exits_immediately_when_stopped_during_the_wait() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let driver = FakeDriver::default();
        let lister = FakeLister::with_endpoints(vec![endpoint_id]);
        let loop_driver = driver.clone();
        let loop_lister = lister.clone();
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_driver,
                &loop_lister,
                StdDuration::from_secs(60),
                TELEMETRY_RETENTION,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        });
        // The first tick fires immediately (one sweep), then the loop sleeps
        // for sixty seconds: stop it during that wait.
        for _ in 0..200 {
            if driver.calls().contains(&DriverCall::Prune) {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        assert!(
            driver.calls().contains(&DriverCall::Prune),
            "the first sweep never ran"
        );
        stop_signal.signal();
        join_with_timeout(task).await?;
        // Exactly one sweep ran; the wait was cancelled, not waited out.
        assert_eq!(
            driver
                .calls()
                .iter()
                .filter(|call| **call == DriverCall::Prune)
                .count(),
            1,
            "no sweep may start after the stop"
        );
        Ok(())
    }

    #[tokio::test]
    async fn failed_listing_skips_the_whole_sweep_and_retries_later() -> Result<(), Box<dyn Error>>
    {
        let endpoint_id = EndpointId::generate();
        let driver = FakeDriver::default();
        let lister = FakeLister::with_endpoints(vec![endpoint_id]);
        lister.fail_listing.store(true, Ordering::Relaxed);
        let loop_driver = driver.clone();
        let loop_lister = lister.clone();
        let (stop_signal, stop_watch) = StopSignal::new();

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_driver,
                &loop_lister,
                FAST_INTERVAL,
                TELEMETRY_RETENTION,
                FixedClock(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        });
        // Let several sweeps land while the listing fails.
        tokio::time::sleep(StdDuration::from_millis(20)).await;
        assert!(
            driver.calls().is_empty(),
            "a sweep without a listing must not sample or prune: {:?}",
            driver.calls()
        );
        // The listing recovers: the very next sweep must dispatch normally.
        lister.fail_listing.store(false, Ordering::Relaxed);
        for _ in 0..200 {
            if driver.calls().contains(&DriverCall::Sample(endpoint_id)) {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        stop_signal.signal();
        join_with_timeout(task).await?;
        assert!(
            driver.calls().contains(&DriverCall::Sample(endpoint_id)),
            "the recovered listing must dispatch the sweep"
        );
        Ok(())
    }
}
