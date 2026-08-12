//! The §14.4 telemetry sampling loop (design sections 14.4 and 7.8).
//!
//! One background task ticks every [`TELEMETRY_SAMPLE_INTERVAL`]. Each tick
//! re-lists the enrolled endpoints (so an endpoint enrolled mid-run is
//! picked up by the next tick, unlike the event listeners' startup sweep),
//! samples every endpoint through the [`TelemetryDriver`] seam — the
//! application [`TelemetrySampler`] use case over the stored-snapshot reader
//! — and prunes the history older than the configured retention
//! ([`TelemetryRetention`], default seven days) through the same seam. The
//! listing failure aborts only the sweep, never the loop: the next tick
//! retries.
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
//! # Why the retention is a product option
//!
//! Design §14.4 requires the history retention to be configurable (历史保留
//! 周期可配置). The configuration surface is the
//! `--telemetry-retention-days` option of the `run` and `service` CLI
//! subcommands (default 7 days, validated 1–365 by [`TelemetryRetention`]);
//! the settings page of a later iteration will pass the same value through
//! the same path.
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

use std::{error::Error, fmt, time::Duration};

use rutilus_application::{
    BoundaryFuture, Clock, EndpointSampling, MetricReportReader, TelemetryRepository,
    TelemetrySampler, TelemetrySamplerError,
};
use rutilus_domain::EndpointId;
use time::OffsetDateTime;
use tracing::instrument;

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

/// The validated telemetry history retention window (design §14.4: 历史保留
/// 周期可配置).
///
/// One window is a whole number of days; the prune cutoff is `now - days`
/// (the application use case subtracts the window from the product clock).
/// The value is validated at the product boundary, so the runtime and the
/// loop can assume a sane window and the CLI rejects the rest at parse time.
///
/// # Why the default is seven days
///
/// A week of history at the sixty-second cadence is 10,080 samples per
/// series — enough to see a trend across a maintenance cycle while keeping
/// the `SQLite` store small. The `--telemetry-retention-days` option
/// defaults to this window, and the CLI help documents the default.
///
/// # Why the window is bounded
///
/// At least one day: a zero-day window would make the first prune tick
/// erase the entire history — the §14.4 bounded-history promise inverted.
/// At most 365 days: a year at the sixty-second cadence is 525,600 samples
/// per series, and the §14.4 "不把产品变成通用时序数据库" promise keeps the
/// store bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryRetention {
    days: u16,
}

impl TelemetryRetention {
    /// The smallest valid window: one day.
    pub const MIN_DAYS: u16 = 1;
    /// The largest valid window: one year.
    pub const MAX_DAYS: u16 = 365;
    /// The default window: seven days (the pre-configuration product
    /// constant).
    pub const DEFAULT_DAYS: u16 = 7;

    /// Validates one retention window in days.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryRetentionError::OutOfRange`] when `days` lies
    /// outside the validated `MIN_DAYS..=MAX_DAYS` window.
    pub fn try_new(days: u16) -> Result<Self, TelemetryRetentionError> {
        if !(Self::MIN_DAYS..=Self::MAX_DAYS).contains(&days) {
            return Err(TelemetryRetentionError::OutOfRange { days });
        }
        Ok(Self { days })
    }

    /// The window in whole days.
    #[must_use]
    pub const fn days(self) -> u16 {
        self.days
    }

    /// The window as the `time` crate duration the prune use case consumes.
    ///
    /// The unit is the `time` crate's `Duration` because it feeds the prune
    /// use case's clock arithmetic (`OffsetDateTime::checked_sub`).
    #[must_use]
    pub const fn as_duration(self) -> time::Duration {
        time::Duration::days(self.days as i64)
    }
}

impl Default for TelemetryRetention {
    /// The seven-day product default.
    ///
    /// `DEFAULT_DAYS` lies inside the validated window — asserted by the
    /// unit test below — so the default needs no fallible path; `try_new`
    /// guards every other construction.
    fn default() -> Self {
        Self {
            days: Self::DEFAULT_DAYS,
        }
    }
}

impl std::str::FromStr for TelemetryRetention {
    type Err = TelemetryRetentionError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let days = text
            .parse::<u16>()
            .map_err(|_| TelemetryRetentionError::NotANumber {
                value: text.to_owned(),
            })?;
        Self::try_new(days)
    }
}

/// Why one retention value cannot be a telemetry history window.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TelemetryRetentionError {
    /// The value is not a whole number of days.
    NotANumber { value: String },
    /// The value lies outside the validated day window.
    OutOfRange { days: u16 },
}

impl fmt::Display for TelemetryRetentionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotANumber { value } => write!(
                formatter,
                "telemetry retention must be a whole number of days, got \"{value}\""
            ),
            Self::OutOfRange { days } => write!(
                formatter,
                "telemetry retention must be between {} and {} days, got {days}",
                TelemetryRetention::MIN_DAYS,
                TelemetryRetention::MAX_DAYS,
            ),
        }
    }
}

impl Error for TelemetryRetentionError {}

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
/// the retention — the runtime's configured policy, defaulting to
/// [`TelemetryRetention::default`] — so tests can drive the cadence fast and
/// the runtime owns the policy.
#[instrument(skip_all, fields(interval = ?interval))]
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
        str::FromStr as _,
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
        prune_retentions: Arc<Mutex<Vec<time::Duration>>>,
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

        fn prune_retentions(&self) -> Vec<time::Duration> {
            self.prune_retentions
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
            retention: time::Duration,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(DriverCall::Prune);
                self.prune_retentions
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(retention);
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
                TelemetryRetention::default().as_duration(),
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
                TelemetryRetention::default().as_duration(),
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
                TelemetryRetention::default().as_duration(),
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
                TelemetryRetention::default().as_duration(),
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
                TelemetryRetention::default().as_duration(),
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

    #[tokio::test]
    async fn prune_uses_the_retention_the_runtime_configured() -> Result<(), Box<dyn Error>> {
        // The configuration surface (the run CLI option) ends at the
        // loop's `retention` parameter; this test pins that the loop hands
        // the configured window to the prune verbatim, so a configured
        // retention changes the prune cutoff exactly as configured.
        let driver = FakeDriver::default();
        let lister = FakeLister::with_endpoints(Vec::new());
        let loop_driver = driver.clone();
        let loop_lister = lister.clone();
        let (stop_signal, stop_watch) = StopSignal::new();
        let configured = TelemetryRetention::try_new(3)?;

        let task = tokio::spawn(async move {
            run(
                stop_watch,
                &loop_driver,
                &loop_lister,
                FAST_INTERVAL,
                configured.as_duration(),
                FixedClock(OffsetDateTime::UNIX_EPOCH),
            )
            .await;
        });
        for _ in 0..200 {
            if !driver.prune_retentions().is_empty() {
                break;
            }
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
        stop_signal.signal();
        join_with_timeout(task).await?;

        let retentions = driver.prune_retentions();
        assert!(
            !retentions.is_empty(),
            "the configured retention must reach the prune"
        );
        assert!(
            retentions
                .iter()
                .all(|retention| *retention == time::Duration::days(3)),
            "every prune must carry the configured retention: {retentions:?}"
        );
        Ok(())
    }

    #[test]
    fn retention_defaults_to_the_seven_day_product_window() -> Result<(), Box<dyn Error>> {
        let retention = TelemetryRetention::default();
        assert_eq!(retention.days(), TelemetryRetention::DEFAULT_DAYS);
        assert_eq!(retention.as_duration(), time::Duration::days(7));
        assert_eq!(
            retention,
            TelemetryRetention::try_new(7)?,
            "the default must lie inside the validated window"
        );
        Ok(())
    }

    #[test]
    fn retention_rejects_windows_that_would_erase_or_unbound_history() {
        // Zero days makes the first prune tick erase the whole history
        // (cutoff = now); more than a year unbounds the store — both invert
        // the §14.4 bounded-history promise.
        assert!(matches!(
            TelemetryRetention::try_new(0),
            Err(TelemetryRetentionError::OutOfRange { days: 0 })
        ));
        assert!(matches!(
            TelemetryRetention::try_new(366),
            Err(TelemetryRetentionError::OutOfRange { days: 366 })
        ));
        assert!(TelemetryRetention::try_new(1).is_ok());
        assert!(TelemetryRetention::try_new(365).is_ok());
    }

    #[test]
    fn retention_cli_text_must_be_whole_days_within_the_window() -> Result<(), Box<dyn Error>> {
        // The CLI surface parses through `FromStr`; clap rejects the
        // failures with the error's message.
        assert_eq!(
            TelemetryRetention::from_str("30")?,
            TelemetryRetention::try_new(30)?
        );
        assert!(matches!(
            TelemetryRetention::from_str("abc"),
            Err(TelemetryRetentionError::NotANumber { .. })
        ));
        assert!(matches!(
            TelemetryRetention::from_str("-1"),
            Err(TelemetryRetentionError::NotANumber { .. })
        ));
        assert!(matches!(
            TelemetryRetention::from_str("0"),
            Err(TelemetryRetentionError::OutOfRange { .. })
        ));
        assert!(matches!(
            TelemetryRetention::from_str("366"),
            Err(TelemetryRetentionError::OutOfRange { .. })
        ));
        assert_eq!(
            TelemetryRetentionError::OutOfRange { days: 0 }.to_string(),
            "telemetry retention must be between 1 and 365 days, got 0"
        );
        Ok(())
    }
}
