//! The §14.4 telemetry sampling use case: current values and bounded history.
//!
//! # The sample-source decision: stored snapshots, not live gateway reads
//!
//! Sampling is a periodic, product-controlled action (design §14.4: 采样器
//! 节奏由产品控制), and every metric reading already lands in the endpoint's
//! latest complete resource Generation through the refresh pipeline. Reading
//! the *stored* `MetricReport` values through the
//! [`MetricReportSnapshotReader`] therefore costs one store query per tick,
//! while reading live through the Redfish gateway would open an authenticated
//! Session per endpoint per tick (design §11.2 Session 策略) for data the
//! refresh already captured. The trade-off is explicit: the sampling cadence
//! follows the refresh cadence, so a reading that arrived between two
//! refreshes is captured at the next refresh, not sampled on its own clock.
//! The refresh is the product's only gateway read path for telemetry values,
//! exactly like the event listeners are the only gateway stream path (§14.4).
//!
//! # Series identity in the 0.4.0 snapshot contract
//!
//! A telemetry *series* is one metric value of one `MetricReport` of one
//! endpoint (the domain `TelemetrySeries` doc): the persistence key is
//! `(endpoint_id, series_key)`, where the series key carries the report's
//! identity joined with the metric's `MetricId`. The 0.4.0 snapshot contract
//! projects each `MetricReport` reading as a `Timestamp`/`MetricValue` pair
//! and deliberately keeps the per-entry `MetricId` out of the strictly
//! projectable field set (see the infra projection), so the sampler keys
//! each series on the report identity alone — the report's Redfish `Id`, the
//! last `@odata.id` segment. A series therefore has one timeline per report
//! in 0.4.0; the metric dimension joins the key, without touching
//! persistence or delivery layers, once the snapshot contract projects
//! `MetricId`.
//!
//! # Reading-value filtering
//!
//! The DMTF schema types `MetricValue` as `Edm.String`, so a reading can
//! carry text that is not a number (the projection's own docs name boolean
//! and array representations). The reader therefore parses every reading and
//! keeps only the finite `f64` values; the boundary constructor
//! [`MetricReportValues::try_new`] then enforces the same rules on whatever
//! a future reader yields. The domain `TelemetrySample` constructor rejects
//! non-finite values as the final defense inside the sampling path itself
//! (NaN 拒绝在域层), so a non-finite value cannot exist anywhere in the
//! persisted history.
//!
//! # The product clock and the BMC clock
//!
//! Samples are stamped with the product clock — the `now` the sampling loop
//! passes to [`TelemetrySampler::sample_endpoint`] — because ordering,
//! bounded history, and retention pruning are product-time cuts (the domain
//! `TelemetrySample` doc). The BMC's own `MetricValue.Timestamp` rides along
//! as optional display metadata ([`MetricReportReading::bmc_timestamp`]),
//! exactly like the events model keeps the BMC's `EventTimestamp` beside the
//! product receive time.
//!
//! # The monotonic sampling guard
//!
//! The product clock is a wall clock, so it can regress (NTP correction,
//! wall-clock drift). A sample stamped with a regressed instant would sit
//! out of order inside the series timeline — the newest-first projection and
//! the retention prune are product-time cuts, so a regressed row would
//! interleave into the middle of the history instead of extending it. The
//! sampler therefore guards the stamp: every `now` must be at least the
//! previous accepted one (equal instants are the same sweep and stay
//! allowed), and a regressed instant is refused with the classified
//! [`TelemetrySamplerError::ClockRollback`] — the `CutoffUnderflow` style:
//! the use case surfaces the wall-clock anomaly as a controlled failure and
//! the sampling loop records it, instead of silently stamping history with a
//! time that never existed.
//!
//! A regressed clock can persist across many sweeps, and every refused sweep
//! would otherwise storm the operational log with one identical error per
//! endpoint. The use case therefore tracks consecutive refusals: each
//! refusal is still refused with the same classification and the same
//! monotonic semantics, but every refusing call returns its
//! consecutive-refusal verdict with its result — whether the refusal
//! repeats the one before it — so the sampling loop can log the first
//! refusal as an error and every repeat as a warn that the refusal persists
//! until the clock catches up. The verdict is decided in the same critical
//! section that records the refusal (W3N-4): the API allows concurrent
//! callers, and the verdict is per call, never per caller — a concurrent
//! caller's intervening refusal or success can never change the verdict a
//! caller reads for its own call. The
//! [`TelemetrySamplerError::CutoffUnderflow`] refusal of the prune gets the
//! same consecutive-refusal treatment.

use std::{
    error::Error,
    fmt,
    num::NonZeroU64,
    str::FromStr as _,
    sync::{Mutex, PoisonError},
};

use rutilus_domain::{
    EndpointId, NonFiniteSampleValue, ResourceFeature, SeriesKey, SeriesKeyError, TelemetrySample,
    TelemetrySeries, TelemetrySeriesId,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{
    BoundaryFuture, Clock, CoreResourceDetails, EndpointInventoryRepository,
    EndpointResourceInventoryQuery, EndpointResourceInventoryQueryError,
};

/// The §14.4 sample source: the current `MetricReport` values of one
/// endpoint.
///
/// The boundary deliberately takes the endpoint id only — never an address,
/// credential, or gateway handle — so the sampling use case cannot reach
/// into the identity or transport layer (design §7.2). The 0.4.0
/// implementation reads the *stored* refresh Generation (see the module
/// doc); a later iteration could back the same boundary with a live gateway
/// read without touching the use case.
pub trait MetricReportReader: Send + Sync {
    /// The boundary's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Reads every current metric series of one endpoint with its readings.
    fn read_metric_reports(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<MetricReportValues>, Self::Error>>;
}

impl<Reader> MetricReportReader for &Reader
where
    Reader: MetricReportReader + ?Sized,
{
    type Error = Reader::Error;

    fn read_metric_reports(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<MetricReportValues>, Self::Error>> {
        Reader::read_metric_reports(*self, endpoint_id)
    }
}

/// One timestamped reading of one metric series.
///
/// `bmc_timestamp` optionally preserves the BMC's own
/// `MetricValue.Timestamp` as display metadata; the sample's ordering and
/// retention time is the product clock, supplied by the sampler. The value
/// stays a plain `f64`; finiteness is enforced by the containing
/// [`MetricReportValues::try_new`], so an invalid reading cannot be
/// constructed into a series.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MetricReportReading {
    bmc_timestamp: Option<OffsetDateTime>,
    value: f64,
}

impl MetricReportReading {
    /// Creates one reading; finiteness is validated by
    /// [`MetricReportValues::try_new`].
    #[must_use]
    pub const fn new(bmc_timestamp: Option<OffsetDateTime>, value: f64) -> Self {
        Self {
            bmc_timestamp,
            value,
        }
    }

    /// The BMC's own `MetricValue.Timestamp`, when the report carried one.
    #[must_use]
    pub const fn bmc_timestamp(&self) -> Option<OffsetDateTime> {
        self.bmc_timestamp
    }

    /// The reading's numeric value.
    #[must_use]
    pub const fn value(&self) -> f64 {
        self.value
    }
}

/// One metric series and the readings extracted from an endpoint's current
/// `MetricReport` snapshots (§14.4).
///
/// The [`SeriesKey`] is the domain-validated series identity (see the module
/// doc for the 0.4.0 identity: the report's Redfish `Id`), and the readings
/// carry the values the sampler turns into persisted samples.
///
/// `PartialEq` (not `Eq`) because the readings carry `f64` values.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricReportValues {
    series_key: SeriesKey,
    readings: Vec<MetricReportReading>,
}

impl MetricReportValues {
    /// Validates one extracted metric series before it crosses into the
    /// sampling use case.
    ///
    /// The readings must be non-empty — an empty series is not a series —
    /// and every reading value must be finite. The finiteness rule is the
    /// sampler's side of the "NaN 拒绝在域层" guarantee: the reader boundary
    /// filters non-numeric `MetricValue` text, this constructor closes the
    /// boundary, and the domain `TelemetrySample` constructor backs it
    /// inside the sampling path. The series key is already a validated
    /// [`SeriesKey`] by type.
    ///
    /// # Errors
    ///
    /// Returns [`MetricReportValuesError`] for an empty reading set or a
    /// non-finite reading value.
    pub fn try_new(
        series_key: SeriesKey,
        readings: Vec<MetricReportReading>,
    ) -> Result<Self, MetricReportValuesError> {
        if readings.is_empty() {
            return Err(MetricReportValuesError::NoReadings);
        }
        if let Some(reading) = readings.iter().find(|reading| !reading.value.is_finite()) {
            return Err(MetricReportValuesError::NonFiniteReading {
                value: reading.value(),
            });
        }
        Ok(Self {
            series_key,
            readings,
        })
    }

    /// The stable product key of the series.
    #[must_use]
    pub fn series_key(&self) -> &SeriesKey {
        &self.series_key
    }

    /// The readings in the order the report carried them.
    #[must_use]
    pub fn readings(&self) -> &[MetricReportReading] {
        &self.readings
    }
}

/// Why one extracted metric series cannot cross the sampling boundary.
///
/// `PartialEq` (not `Eq`) because the non-finite variant carries the
/// offending `f64` value.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum MetricReportValuesError {
    NoReadings,
    NonFiniteReading { value: f64 },
}

impl fmt::Display for MetricReportValuesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoReadings => {
                formatter.write_str("metric series must carry at least one reading")
            }
            Self::NonFiniteReading { value } => {
                write!(
                    formatter,
                    "metric reading value {value} is not a finite number"
                )
            }
        }
    }
}

impl Error for MetricReportValuesError {}

/// The §14.4 sample source over the stored refresh Generation.
///
/// Reads one endpoint's latest complete resource Generation through the
/// [`EndpointResourceInventoryQuery`] projection — the same strict decode
/// the console inventory uses, so the sampler and the console can never
/// disagree about a stored payload — and extracts every `MetricReport`
/// series with its readings. A report whose snapshots predate the 0.4.0
/// value-array projection (only `MetricValuesCount` persisted) simply
/// contributes no readings, and an entry whose `MetricValue` text is not a
/// finite number (the DMTF `Edm.String` typing allows booleans and arrays)
/// is skipped in isolation, so one glitched reading cannot poison the whole
/// endpoint's sampling. Entries without a `Timestamp` are still valid
/// readings: the BMC clock is display metadata, never a sampling
/// prerequisite (see the module doc).
pub struct MetricReportSnapshotReader<Repository> {
    repository: Repository,
}

impl<Repository> MetricReportSnapshotReader<Repository>
where
    Repository: EndpointInventoryRepository,
{
    #[must_use]
    pub const fn new(repository: Repository) -> Self {
        Self { repository }
    }
}

impl<Repository> MetricReportReader for MetricReportSnapshotReader<Repository>
where
    Repository: EndpointInventoryRepository,
{
    type Error = MetricReportReadError<Repository::Error>;

    fn read_metric_reports(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<MetricReportValues>, Self::Error>> {
        Box::pin(async move {
            let inventory = EndpointResourceInventoryQuery::new(&self.repository, endpoint_id)
                .execute()
                .await
                .map_err(MetricReportReadError::Inventory)?
                .ok_or(MetricReportReadError::UnknownEndpoint { endpoint_id })?;
            let mut reports = Vec::new();
            for resource in inventory.resources() {
                if resource.feature() != ResourceFeature::MetricReport {
                    continue;
                }
                let CoreResourceDetails::MetricReport { metric_values, .. } = resource.details()
                else {
                    // The projection pairs the feature with its variant by
                    // construction; a mismatch would be a programming defect,
                    // and skipping keeps one incoherent payload from failing
                    // the endpoint.
                    continue;
                };
                let Some(values) = metric_values else {
                    // A snapshot from before the 0.4.0 value-array projection
                    // carries only the derived count: nothing to sample.
                    continue;
                };
                let mut readings = Vec::new();
                for value in values {
                    let Some(text) = value.value() else {
                        continue;
                    };
                    let Ok(number) = f64::from_str(text) else {
                        continue;
                    };
                    if !number.is_finite() {
                        continue;
                    }
                    readings.push(MetricReportReading::new(value.timestamp(), number));
                }
                if readings.is_empty() {
                    continue;
                }
                let series_key = SeriesKey::parse(resource.common().id()).map_err(|source| {
                    MetricReportReadError::Projection {
                        endpoint_id,
                        source,
                    }
                })?;
                reports.push(MetricReportValues::try_new(series_key, readings).map_err(
                    |source| MetricReportReadError::Readings {
                        endpoint_id,
                        source,
                    },
                )?);
            }
            Ok(reports)
        })
    }
}

/// A controlled failure while reading one endpoint's stored metric values.
#[derive(Debug, Error)]
pub enum MetricReportReadError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    #[error("endpoint {endpoint_id} is not a managed endpoint")]
    UnknownEndpoint { endpoint_id: EndpointId },
    #[error("failed to load the resource inventory: {0}")]
    Inventory(#[source] EndpointResourceInventoryQueryError<RepositoryError>),
    #[error("stored metric report of endpoint {endpoint_id} carries an invalid series: {source}")]
    Projection {
        endpoint_id: EndpointId,
        #[source]
        source: SeriesKeyError,
    },
    #[error("stored metric report of endpoint {endpoint_id} carries invalid readings: {source}")]
    Readings {
        endpoint_id: EndpointId,
        #[source]
        source: MetricReportValuesError,
    },
}

/// The §14.4 persistence boundary of the telemetry lifecycle.
///
/// The boundary exposes exactly five operations: upsert one series
/// (create-or-return by endpoint and key), append one sample, list the
/// series of one endpoint, list one series' bounded newest-first samples,
/// and prune everything older than a cutoff. There is intentionally no
/// update or delete of individual samples — a sample is immutable once
/// persisted, and history shrinks only through the bounded retention prune.
///
/// The signatures mirror the `SqliteStore` telemetry methods; the
/// delivery-layer projections (`list_series` across endpoints, the current
/// value of a series) compose these primitives.
pub trait TelemetryRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Creates the series row for one endpoint metric key, or returns the
    /// existing row — the create-or-return is atomic so concurrent ticks
    /// cannot duplicate a series.
    fn upsert_series<'a>(
        &'a self,
        endpoint_id: EndpointId,
        series_key: &'a SeriesKey,
    ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>>;

    /// Persists one sample; the domain sample constructor has already
    /// rejected non-finite values (NaN 拒绝在域层).
    fn append_sample<'a>(
        &'a self,
        sample: &'a TelemetrySample,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Lists every series of every endpoint, by series key.
    ///
    /// The product's current-value surface (§14.4) is one series inventory
    /// across endpoints — the same shape the console renders — so the
    /// boundary merges the per-endpoint store listings instead of leaking
    /// the endpoint loop into the delivery layer.
    fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>>;

    /// Lists one series' samples, newest first, bounded by `limit`.
    fn list_samples(
        &self,
        series_id: TelemetrySeriesId,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>>;

    /// Deletes every sample older than the cutoff, then rewrites the
    /// affected series' sample counts — the bounded-retention shrink of
    /// §14.4 (历史保留周期可配置).
    fn prune_before(&self, cutoff: OffsetDateTime) -> BoundaryFuture<'_, Result<(), Self::Error>>;
}

impl<Repository> TelemetryRepository for &Repository
where
    Repository: TelemetryRepository + ?Sized,
{
    type Error = Repository::Error;

    fn upsert_series<'a>(
        &'a self,
        endpoint_id: EndpointId,
        series_key: &'a SeriesKey,
    ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>> {
        Repository::upsert_series(*self, endpoint_id, series_key)
    }

    fn append_sample<'a>(
        &'a self,
        sample: &'a TelemetrySample,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::append_sample(*self, sample)
    }

    fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
        Repository::list_series(*self)
    }

    fn list_samples(
        &self,
        series_id: TelemetrySeriesId,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
        Repository::list_samples(*self, series_id, limit)
    }

    fn prune_before(&self, cutoff: OffsetDateTime) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Repository::prune_before(*self, cutoff)
    }
}

/// The §14.4 sampling use case: move current values into bounded history.
///
/// Generic over the sample-source boundary, the telemetry repository, and
/// the product clock; the use case decides the *what* (which values become
/// samples), never the *when* — the background loop owns the cadence.
///
/// The use case is the product-time guard of the sampling path: it tracks
/// the last accepted sampling instant and refuses a regressed one (see the
/// module doc's monotonic-guard section), so the persisted timeline can
/// never contain an out-of-order row written by this path.
pub struct TelemetrySampler<Reader, Store, Time> {
    reader: Reader,
    store: Store,
    clock: Time,
    /// The last sampling instant this use case accepted, for the monotonic
    /// stamp guard. A `Mutex` because the boundary methods take `&self`; the
    /// lock is held only for the compare-and-store of one tick instant.
    last_sample_instant: Mutex<Option<OffsetDateTime>>,
    /// The consecutive-refusal dedupe state of the monotonic guard (see the
    /// module doc): the refusal that persists across sweeps is reported once,
    /// and every refusing call returns its verdict (W3N-4) so the sampling
    /// loop can downgrade its logging instead of storming the log. The lock
    /// is held only for the compare-and-store of one call's continuation
    /// bits.
    refusals: Mutex<RefusalState>,
}

/// One refused monotonic-guard call, with its consecutive-refusal verdict
/// (W3N-4): the refusal error and whether it repeats the refusal of the
/// call before it — decided in the same critical section as the refusal
/// record, so a concurrent caller can never change it.
type RefusalOutcome<ReaderError, StoreError> =
    (TelemetrySamplerError<ReaderError, StoreError>, bool);

/// The kind of one monotonic-guard refusal, for the consecutive-refusal
/// dedupe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefusalKind {
    /// [`TelemetrySamplerError::ClockRollback`]: a regressed sampling
    /// instant refused by [`TelemetrySampler::accept_instant`].
    ClockRollback,
    /// [`TelemetrySamplerError::CutoffUnderflow`]: a prune cutoff predating
    /// the `OffsetDateTime` range.
    CutoffUnderflow,
}

/// The consecutive-refusal dedupe state of the monotonic guard, one bit per
/// refusal site.
///
/// A refusal "continues" when the immediately previous call at the same site
/// was refused too — the same clock anomaly persisting across sweeps. A call
/// at the other site neither continues nor breaks the chain: the sample
/// path's refusals and the prune path's underflows are independent conditions
/// that each clear only when their own site succeeds again.
///
/// The verdict of one refusal — whether it repeats the one before it — is
/// deliberately NOT stored here (W3N-4): [`TelemetrySampler::note_refusal`]
/// decides it inside the same critical section that records the
/// continuation and returns it with the refusing call's result, so a
/// concurrent caller's intervening refusal or success can never change the
/// verdict a caller reads for its own call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RefusalState {
    /// The previous sampling call was also refused by the rollback guard.
    rollback_continued: bool,
    /// The previous prune call also underflowed the retention cutoff.
    underflow_continued: bool,
}

impl<Reader, Store, Time> TelemetrySampler<Reader, Store, Time>
where
    Reader: MetricReportReader,
    Store: TelemetryRepository,
    Time: Clock,
{
    #[must_use]
    pub const fn new(reader: Reader, store: Store, clock: Time) -> Self {
        Self {
            reader,
            store,
            clock,
            last_sample_instant: Mutex::new(None),
            refusals: Mutex::new(RefusalState {
                rollback_continued: false,
                underflow_continued: false,
            }),
        }
    }

    /// Samples one endpoint's current metric values into the store.
    ///
    /// Every series is upserted (create-or-return, so repeated ticks extend
    /// one timeline) and every reading appended as a sample stamped with the
    /// product clock's `now` — the caller's tick instant, so the loop's
    /// shared sweep time stamps all readings of the sweep and tests stay
    /// deterministic. The BMC's own `MetricValue.Timestamp` rides along as
    /// display metadata when the report carried one. An endpoint without
    /// stored `MetricReport` values — never refreshed, or its reports
    /// predating the 0.4.0 value projection — samples zero series without
    /// error.
    ///
    /// The stamp is guarded monotonically (see the module doc): an instant
    /// below the previous accepted one is refused before any series is
    /// touched, so a wall-clock rollback can never append a regressed row
    /// into the bounded history — the newest-first projection and the
    /// retention prune stay honest product-time cuts. Equal instants are
    /// the same sweep and stay allowed.
    ///
    /// # Returns
    ///
    /// The sampling result and the consecutive-refusal verdict of the call
    /// (W3N-4): `true` only when the returned failure is a
    /// [`TelemetrySamplerError::ClockRollback`] that repeats the refusal of
    /// the call before it. `false` for an accepted call, a failure that is
    /// not a clock refusal, and the first refusal of an anomaly — so the
    /// sampling loop can log the first refusal as an error and each repeat
    /// as a warn. The verdict is decided in the same critical section that
    /// records the refusal, so a concurrent caller's intervening refusal or
    /// success can never change it between the refusal and this read.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetrySamplerError::Read`] when the sample source fails,
    /// [`TelemetrySamplerError::Upsert`] when a series cannot be recorded,
    /// [`TelemetrySamplerError::Append`] when a sample cannot be recorded,
    /// and [`TelemetrySamplerError::ClockRollback`] when `now` regresses
    /// below the previous accepted instant. Per-endpoint failure isolation
    /// is the caller's job, exactly like the event-listener sink failures:
    /// one endpoint's failed tick never stops the others.
    pub async fn sample_endpoint(
        &self,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> (
        Result<EndpointSampling, TelemetrySamplerError<Reader::Error, Store::Error>>,
        bool,
    ) {
        let result = match self.accept_instant(now) {
            Err((error, repeated)) => return (Err(error), repeated),
            Ok(()) => self.sample_accepted(endpoint_id, now).await,
        };
        (result, false)
    }

    /// The sampling pass of one accepted instant: read, upsert, append.
    async fn sample_accepted(
        &self,
        endpoint_id: EndpointId,
        now: OffsetDateTime,
    ) -> Result<EndpointSampling, TelemetrySamplerError<Reader::Error, Store::Error>> {
        let reports = self
            .reader
            .read_metric_reports(endpoint_id)
            .await
            .map_err(|source| TelemetrySamplerError::Read {
                endpoint_id,
                source,
            })?;
        let mut series_sampled = 0_usize;
        let mut samples_appended = 0_usize;
        for report in reports {
            let series_key = report.series_key().clone();
            let series = self
                .store
                .upsert_series(endpoint_id, &series_key)
                .await
                .map_err(|source| TelemetrySamplerError::Upsert {
                    endpoint_id,
                    series_key: series_key.clone(),
                    source,
                })?;
            series_sampled += 1;
            for reading in report.readings() {
                let mut sample =
                    TelemetrySample::new(series.id(), now, reading.value()).map_err(|source| {
                        TelemetrySamplerError::NonFiniteValue {
                            endpoint_id,
                            series_key: series_key.clone(),
                            source,
                        }
                    })?;
                if let Some(bmc_timestamp) = reading.bmc_timestamp() {
                    sample = sample.with_bmc_timestamp(bmc_timestamp);
                }
                self.store.append_sample(&sample).await.map_err(|source| {
                    TelemetrySamplerError::Append {
                        endpoint_id,
                        series_key: series_key.clone(),
                        source,
                    }
                })?;
                samples_appended += 1;
            }
        }
        Ok(EndpointSampling::new(series_sampled, samples_appended))
    }

    /// Accepts one sampling instant under the monotonic stamp guard, or
    /// refuses the tick with [`TelemetrySamplerError::ClockRollback`] when
    /// `now` regresses below the previous accepted instant. A refusal
    /// returns its consecutive-refusal verdict beside the error (W3N-4):
    /// whether it repeats the refusal of the call before it, decided in the
    /// same critical section that records the refusal.
    ///
    /// The lock is held only for this compare-and-store: the helper is
    /// synchronous, so the guard never spans an await point.
    fn accept_instant(
        &self,
        now: OffsetDateTime,
    ) -> Result<(), RefusalOutcome<Reader::Error, Store::Error>> {
        let mut last_instant = self
            .last_sample_instant
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(previous) = *last_instant
            && now < previous
        {
            // A regressed product clock (NTP correction, wall-clock drift):
            // appending samples stamped with the regressed instant would
            // interleave out-of-order rows into the series timeline.
            // Refusing the tick — the `CutoffUnderflow` style: a classified
            // failure the sampling loop records — keeps the history
            // monotonic without falsifying any stamp. The refusal and its
            // verdict are recorded in one critical section before it
            // returns.
            let repeated = self.note_refusal(RefusalKind::ClockRollback);
            return Err((
                TelemetrySamplerError::ClockRollback { previous, now },
                repeated,
            ));
        }
        *last_instant = Some(now);
        // The clock is sane again: the rollback chain clears and the next
        // refusal is a fresh condition.
        self.clear_refusal(RefusalKind::ClockRollback);
        Ok(())
    }

    /// Records one monotonic-guard refusal for the consecutive-refusal
    /// dedupe and returns this refusal's verdict: whether it repeated the
    /// refusal of the call before it at the same site, so the sampling loop
    /// downgrades its logging until the clock catches up.
    ///
    /// The verdict is decided and recorded in the same critical section as
    /// the continuation bit (W3N-4): the returned value is this refusal's
    /// own verdict, never a verdict a concurrent caller's intervening
    /// refusal or success wrote afterwards.
    fn note_refusal(&self, kind: RefusalKind) -> bool {
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        let continued = match kind {
            RefusalKind::ClockRollback => &mut refusals.rollback_continued,
            RefusalKind::CutoffUnderflow => &mut refusals.underflow_continued,
        };
        let repeated = *continued;
        *continued = true;
        repeated
    }

    /// Records that the call at one monotonic-guard site succeeded: the
    /// condition is over, so the next refusal of that kind is fresh again.
    ///
    /// A call at the other site leaves the chain untouched — the rollback
    /// chain survives a successful prune and the underflow chain survives a
    /// successful sampling, because each site's anomaly clears only when
    /// that site proves the clock sane again.
    fn clear_refusal(&self, kind: RefusalKind) {
        let mut refusals = self.refusals.lock().unwrap_or_else(PoisonError::into_inner);
        match kind {
            RefusalKind::ClockRollback => refusals.rollback_continued = false,
            RefusalKind::CutoffUnderflow => refusals.underflow_continued = false,
        }
    }

    /// Prunes every sample older than the retention window (design §14.4:
    /// 历史保留周期可配置 — the window is a use-case parameter here; the
    /// product's configuration surface lands with the settings iteration).
    ///
    /// The cutoff is derived from the injected clock, so the loop passes
    /// only the retention and the tests pin the clock.
    ///
    /// # Returns
    ///
    /// The prune result and the consecutive-refusal verdict of the call
    /// (W3N-4), exactly like [`Self::sample_endpoint`]: `true` only when
    /// the returned failure is a [`TelemetrySamplerError::CutoffUnderflow`]
    /// that repeats the underflow of the call before it.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetrySamplerError::CutoffUnderflow`] when the clock
    /// predates the retention window, and [`TelemetrySamplerError::Prune`]
    /// when the prune fails.
    pub async fn prune_history(
        &self,
        retention: time::Duration,
    ) -> (
        Result<(), TelemetrySamplerError<Reader::Error, Store::Error>>,
        bool,
    ) {
        let Some(cutoff) = self.clock.now().checked_sub(retention) else {
            // The `CutoffUnderflow` refusal gets the same
            // consecutive-refusal treatment as the rollback guard: the
            // clock predates the retention window, the prune cannot cut
            // any history, and the verdict — whether the underflow repeats
            // the one before it — is decided in the same critical section
            // as the refusal record, for the loop's downgraded logging
            // until the clock recovers.
            let repeated = self.note_refusal(RefusalKind::CutoffUnderflow);
            return (Err(TelemetrySamplerError::CutoffUnderflow), repeated);
        };
        // The cutoff computed: the clock is sane again, so the underflow
        // chain clears even if the store call below fails — a store failure
        // is not a clock anomaly.
        self.clear_refusal(RefusalKind::CutoffUnderflow);
        let result = self
            .store
            .prune_before(cutoff)
            .await
            .map_err(TelemetrySamplerError::Prune);
        (result, false)
    }
}

/// The outcome of one endpoint sampling tick.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointSampling {
    series_sampled: usize,
    samples_appended: usize,
}

impl EndpointSampling {
    #[must_use]
    pub const fn new(series_sampled: usize, samples_appended: usize) -> Self {
        Self {
            series_sampled,
            samples_appended,
        }
    }

    #[must_use]
    pub const fn series_sampled(&self) -> usize {
        self.series_sampled
    }

    #[must_use]
    pub const fn samples_appended(&self) -> usize {
        self.samples_appended
    }
}

/// A controlled failure while sampling one endpoint's telemetry.
#[derive(Debug, Error)]
pub enum TelemetrySamplerError<ReaderError, StoreError>
where
    ReaderError: Error + 'static,
    StoreError: Error + 'static,
{
    #[error("metric report values of endpoint {endpoint_id} could not be read: {source}")]
    Read {
        endpoint_id: EndpointId,
        #[source]
        source: ReaderError,
    },
    #[error("metric series {series_key} of endpoint {endpoint_id} could not be recorded: {source}")]
    Upsert {
        endpoint_id: EndpointId,
        series_key: SeriesKey,
        #[source]
        source: StoreError,
    },
    #[error(
        "metric sample of series {series_key} of endpoint {endpoint_id} could not be recorded: {source}"
    )]
    Append {
        endpoint_id: EndpointId,
        series_key: SeriesKey,
        #[source]
        source: StoreError,
    },
    #[error(
        "metric value of series {series_key} of endpoint {endpoint_id} is not finite: {source}"
    )]
    NonFiniteValue {
        endpoint_id: EndpointId,
        series_key: SeriesKey,
        #[source]
        source: NonFiniteSampleValue,
    },
    #[error("telemetry history could not be pruned: {0}")]
    Prune(#[source] StoreError),
    #[error("the product clock predates the telemetry retention window")]
    CutoffUnderflow,
    #[error(
        "the product clock regressed from {previous} to {now}; refusing a non-monotonic sample instant"
    )]
    ClockRollback {
        previous: OffsetDateTime,
        now: OffsetDateTime,
    },
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fmt,
        num::NonZeroU64,
        sync::{Arc, Mutex, PoisonError},
    };

    use rutilus_domain::{
        CredentialId, Endpoint, EndpointAddress, EndpointDisplayName, RefreshGeneration,
        ResourceId, ResourceODataId, ResourceSnapshot, ResourceSnapshotPayload, TlsCertificate,
        TlsTrust,
    };
    use time::{Duration, OffsetDateTime, PrimitiveDateTime};

    use super::*;
    use crate::EndpointInventoryItem;

    const OBSERVED_AT: OffsetDateTime = OffsetDateTime::UNIX_EPOCH;

    /// One deterministic instant, days after the epoch; its RFC 3339 string
    /// is spelled out in the payload fixtures.
    fn instant(days: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::days(days)
    }

    /// The earliest representable product-clock instant: subtracting any
    /// positive retention underflows the `OffsetDateTime` range, so the
    /// prune refuses with `CutoffUnderflow`.
    fn earliest_instant() -> OffsetDateTime {
        PrimitiveDateTime::MIN.assume_utc()
    }

    fn endpoint() -> Result<Endpoint, Box<dyn Error>> {
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Telemetry sampling BMC")?,
            EndpointAddress::parse("https://192.0.2.90")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"telemetry sampling certificate".to_vec())?,
                trusted_at: OffsetDateTime::UNIX_EPOCH,
            },
            CredentialId::generate(),
            OffsetDateTime::UNIX_EPOCH,
            OffsetDateTime::UNIX_EPOCH,
        )?)
    }

    fn snapshot(
        endpoint_id: EndpointId,
        feature: ResourceFeature,
        odata_id: &str,
        payload: &str,
        observed_at: OffsetDateTime,
        generation: RefreshGeneration,
    ) -> Result<ResourceSnapshot, Box<dyn Error>> {
        Ok(ResourceSnapshot::new(
            ResourceId::generate(),
            endpoint_id,
            feature,
            ResourceODataId::parse(odata_id)?,
            ResourceSnapshotPayload::parse(payload)?,
            observed_at,
            generation,
        ))
    }

    /// One inventory item carrying a Service Root and the given report
    /// payloads, satisfying the complete-Generation invariants of
    /// [`EndpointInventoryItem::try_new`].
    fn inventory_with_reports(
        endpoint: &Endpoint,
        reports: &[(String, String)],
    ) -> Result<EndpointInventoryItem, Box<dyn Error>> {
        let endpoint_id = endpoint.id();
        let generation = RefreshGeneration::new(9)?;
        let mut resources = vec![snapshot(
            endpoint_id,
            ResourceFeature::ServiceRoot,
            "/redfish/v1",
            r#"{"Id":"RootService","Name":"Root","Vendor":"Vendor A","Product":"BMC","RedfishVersion":"1.20.0"}"#,
            OBSERVED_AT,
            generation,
        )?];
        for (index, (_, payload)) in reports.iter().enumerate() {
            resources.push(snapshot(
                endpoint_id,
                ResourceFeature::MetricReport,
                &format!("/redfish/v1/TelemetryService/MetricReports/{index}"),
                payload,
                OBSERVED_AT,
                generation,
            )?);
        }
        Ok(EndpointInventoryItem::try_new(endpoint.clone(), resources)?)
    }

    /// The stored `MetricReport` payload of one report, mirroring exactly what
    /// the infra projection writes from `0.4.0`: the derived count plus the
    /// `MetricValue` text of every entry. An entry without a `Timestamp`
    /// omits the key entirely — the strict decoder refuses a malformed
    /// timestamp, and the infra projection omits absent values.
    fn report_payload(id: &str, values: &[(Option<&str>, &str)]) -> serde_json::Value {
        let entries = values
            .iter()
            .map(|(timestamp, value)| match timestamp {
                Some(timestamp) => serde_json::json!({
                    "Timestamp": timestamp,
                    "MetricValue": value,
                }),
                None => serde_json::json!({
                    "MetricValue": value,
                }),
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "Id": id,
            "Name": id,
            "Description": id,
            "MetricValuesCount": values.len(),
            "MetricValues": entries,
        })
    }

    #[test]
    fn series_boundary_rejects_non_finite_and_empty_readings() -> Result<(), Box<dyn Error>> {
        let key = SeriesKey::parse("PowerMetrics")?;
        let valid = MetricReportReading::new(Some(OBSERVED_AT), 42.0);
        let series = MetricReportValues::try_new(key.clone(), vec![valid])?;
        assert_eq!(series.series_key(), &key);
        assert_eq!(series.readings().len(), 1);

        // The NaN 拒绝 contract of the sampling boundary: a non-finite value
        // must never cross into the store.
        assert!(matches!(
            MetricReportValues::try_new(
                key.clone(),
                vec![MetricReportReading::new(Some(OBSERVED_AT), f64::NAN)],
            ),
            Err(MetricReportValuesError::NonFiniteReading { .. })
        ));
        assert!(matches!(
            MetricReportValues::try_new(
                key.clone(),
                vec![MetricReportReading::new(Some(OBSERVED_AT), f64::INFINITY)],
            ),
            Err(MetricReportValuesError::NonFiniteReading { .. })
        ));
        assert!(matches!(
            MetricReportValues::try_new(key, Vec::new()),
            Err(MetricReportValuesError::NoReadings)
        ));
        assert_eq!(
            MetricReportValuesError::NonFiniteReading { value: f64::NAN }.to_string(),
            "metric reading value NaN is not a finite number"
        );
        Ok(())
    }

    // The asserted values are exact decimal literals parsed from the fixture
    // text; `f64` equality is exact here, not approximate.
    #[allow(clippy::float_cmp)]
    #[tokio::test]
    async fn reader_extracts_every_report_with_finite_readings() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let power = report_payload(
            "PowerMetrics",
            &[
                (Some("1970-04-11T00:00:00Z"), "100"),
                (Some("1970-04-12T00:00:00Z"), "94"),
            ],
        );
        // A second report with one glitched reading (a boolean `MetricValue`
        // is legal per the DMTF `Edm.String` typing) must be isolated to its
        // valid entries. Every entry carries a `Timestamp` in the 0.4.0
        // contract: the strict snapshot decoder refuses a missing timestamp,
        // so a timestamp-less reading cannot reach the reader.
        let temperature = report_payload(
            "ThermalMetrics",
            &[
                (Some("1970-04-13T00:00:00Z"), "true"),
                (Some("1970-04-14T00:00:00Z"), "32.5"),
            ],
        );
        let item = inventory_with_reports(
            &endpoint,
            &[
                ("PowerMetrics".to_owned(), power.to_string()),
                ("ThermalMetrics".to_owned(), temperature.to_string()),
            ],
        )?;
        let reader = MetricReportSnapshotReader::new(MockInventoryRepository::new(vec![item]));

        let reports = reader.read_metric_reports(endpoint_id).await?;

        assert_eq!(reports.len(), 2);
        assert_eq!(reports[0].series_key().as_str(), "PowerMetrics");
        assert_eq!(reports[0].readings().len(), 2);
        assert_eq!(reports[0].readings()[0].value(), 100.0);
        assert_eq!(reports[0].readings()[0].bmc_timestamp(), Some(instant(100)));
        assert_eq!(reports[0].readings()[1].value(), 94.0);
        assert_eq!(reports[0].readings()[1].bmc_timestamp(), Some(instant(101)));
        // The glitched entry is skipped; the valid entry survives.
        assert_eq!(reports[1].series_key().as_str(), "ThermalMetrics");
        assert_eq!(reports[1].readings().len(), 1);
        assert_eq!(reports[1].readings()[0].value(), 32.5);
        assert_eq!(reports[1].readings()[0].bmc_timestamp(), Some(instant(103)));
        Ok(())
    }

    #[tokio::test]
    async fn reader_skips_snapshots_without_the_0_4_0_value_array() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        // A 0.2.0-era snapshot carries only the derived count: the strict
        // decoder reads `MetricValues` as `None` and the reader contributes
        // nothing, so old stores are sampled as empty instead of failing.
        let legacy = r#"{"Id":"PowerMetrics","Name":"Power Metrics","MetricValuesCount":12}"#;
        let item =
            inventory_with_reports(&endpoint, &[("PowerMetrics".to_owned(), legacy.to_owned())])?;
        let reader = MetricReportSnapshotReader::new(MockInventoryRepository::new(vec![item]));

        let reports = reader.read_metric_reports(endpoint_id).await?;

        assert!(reports.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn reader_reports_unknown_endpoints_and_inventory_failures() -> Result<(), Box<dyn Error>>
    {
        let unknown = EndpointId::generate();
        let reader = MetricReportSnapshotReader::new(MockInventoryRepository::new(Vec::new()));
        assert!(matches!(
            reader.read_metric_reports(unknown).await,
            Err(MetricReportReadError::UnknownEndpoint { .. })
        ));

        let reader = MetricReportSnapshotReader::new(MockInventoryRepository::failing());
        assert!(matches!(
            reader.read_metric_reports(unknown).await,
            Err(MetricReportReadError::Inventory(_))
        ));
        Ok(())
    }

    // The asserted values are exact decimal literals parsed from the fixture
    // text; `f64` equality is exact here, not approximate.
    #[allow(clippy::float_cmp)]
    #[tokio::test]
    async fn sampler_upserts_series_and_appends_every_reading() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let first_series = MetricReportValues::try_new(
            SeriesKey::parse("PowerMetrics")?,
            vec![
                MetricReportReading::new(Some(OBSERVED_AT + Duration::MINUTE), 100.0),
                MetricReportReading::new(None, 94.0),
            ],
        )?;
        let second_series = MetricReportValues::try_new(
            SeriesKey::parse("ThermalMetrics")?,
            vec![MetricReportReading::new(
                Some(OBSERVED_AT + Duration::MINUTE * 3),
                32.5,
            )],
        )?;
        let reader = FakeReader::with_reports(vec![first_series, second_series]);
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(reader, &store, FixedClock(OBSERVED_AT));

        let (sampling_result, verdict) = sampler.sample_endpoint(endpoint_id, OBSERVED_AT).await;
        let sampling = sampling_result?;
        assert!(
            !verdict,
            "an accepted call never carries a repeated-refusal verdict"
        );

        assert_eq!(sampling.series_sampled(), 2);
        assert_eq!(sampling.samples_appended(), 3);
        let recorded = store.samples();
        assert_eq!(recorded.len(), 3);
        // Every reading becomes a sample stamped with the sweep instant; the
        // BMC timestamp rides along as metadata only when the report carried
        // one, and both readings of one report belong to one series while
        // the second report is a distinct series.
        assert_eq!(recorded[0].1, OBSERVED_AT);
        assert_eq!(recorded[0].2, Some(OBSERVED_AT + Duration::MINUTE));
        assert_eq!(recorded[0].3, 100.0);
        assert_eq!(recorded[1].1, OBSERVED_AT);
        assert_eq!(recorded[1].2, None);
        assert_eq!(recorded[1].3, 94.0);
        assert_eq!(
            recorded[0].0, recorded[1].0,
            "both readings of one report are one series"
        );
        assert_eq!(recorded[2].1, OBSERVED_AT);
        assert_eq!(recorded[2].2, Some(OBSERVED_AT + Duration::MINUTE * 3));
        assert_eq!(recorded[2].3, 32.5);
        assert_ne!(
            recorded[1].0, recorded[2].0,
            "the second report is a distinct series"
        );
        assert_eq!(
            store.upserts(),
            [
                (endpoint_id, "PowerMetrics".to_owned()),
                (endpoint_id, "ThermalMetrics".to_owned()),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn sampler_samples_an_endpoint_without_reports_as_zero() -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(
            FakeReader::with_reports(Vec::new()),
            &store,
            FixedClock(OBSERVED_AT),
        );

        let (sampling_result, verdict) = sampler.sample_endpoint(endpoint_id, OBSERVED_AT).await;
        let sampling = sampling_result?;
        assert!(!verdict);

        assert_eq!(sampling, EndpointSampling::new(0, 0));
        assert!(store.upserts().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_clock_rollback_is_refused_and_history_stays_monotonic() -> Result<(), Box<dyn Error>>
    {
        // The monotonic stamp guard: a product-clock rollback (NTP
        // correction, wall-clock drift) between ticks must refuse the
        // regressed sweep — the `CutoffUnderflow` style, a classified
        // failure the sampling loop records — so a regressed row can never
        // interleave into the newest-first projection. Equal instants (the
        // other endpoints of one sweep) and forward ticks sample normally.
        let endpoint_id = EndpointId::generate();
        let series = MetricReportValues::try_new(
            SeriesKey::parse("PowerMetrics")?,
            vec![MetricReportReading::new(None, 100.0)],
        )?;
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(
            FakeReader::with_reports(vec![series]),
            &store,
            FixedClock(instant(30)),
        );

        sampler.sample_endpoint(endpoint_id, instant(30)).await.0?;
        let (result, verdict) = sampler.sample_endpoint(endpoint_id, instant(10)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("a regressed tick must be refused").into());
        };
        assert!(
            !verdict,
            "the first refusal of a regression is a fresh condition"
        );
        assert!(matches!(
            error,
            TelemetrySamplerError::ClockRollback { previous, now }
                if previous == instant(30) && now == instant(10)
        ));
        assert_eq!(
            error.to_string(),
            format!(
                "the product clock regressed from {} to {}; refusing a non-monotonic sample instant",
                instant(30),
                instant(10)
            )
        );
        // The regressed tick appended nothing: the recorded history holds
        // only the monotonic instant, so the newest-first projection cannot
        // contain an out-of-order row.
        let recorded = store.samples();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].1, instant(30));

        // Equal instants are one sweep, not a rollback; a forward tick
        // samples again — the guard refuses only regressions.
        sampler.sample_endpoint(endpoint_id, instant(30)).await.0?;
        sampler.sample_endpoint(endpoint_id, instant(31)).await.0?;
        let recorded = store.samples();
        assert_eq!(recorded.len(), 3);
        let instants = recorded.iter().map(|sample| sample.1).collect::<Vec<_>>();
        assert!(
            instants.windows(2).all(|pair| pair[0] <= pair[1]),
            "the appended history must stay non-decreasing in product time"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sustained_rollback_refusals_are_deduplicated_until_the_clock_recovers()
    -> Result<(), Box<dyn Error>> {
        // A product clock that stays regressed refuses every sweep, and the
        // consecutive-refusal verdict lets the loop log the first refusal as
        // an error and each repeat as a warn — one error, not an unbounded
        // per-endpoint-per-sweep storm. A refusal that the clock recovers
        // from is over; a fresh regression after recovery is new again.
        let endpoint_id = EndpointId::generate();
        let series = MetricReportValues::try_new(
            SeriesKey::parse("PowerMetrics")?,
            vec![MetricReportReading::new(None, 100.0)],
        )?;
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(
            FakeReader::with_reports(vec![series]),
            &store,
            FixedClock(instant(30)),
        );

        sampler.sample_endpoint(endpoint_id, instant(30)).await.0?;
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, instant(10)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the regressed tick must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::ClockRollback { .. }));
        assert!(
            !repeated,
            "the first refusal of a regression is a fresh condition"
        );
        // The clock stays regressed: the next sweep's refusal repeats the
        // previous one — the condition persists across sweeps.
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, instant(10)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the regressed tick must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::ClockRollback { .. }));
        assert!(repeated);
        // A prune between the refusals neither continues nor breaks the
        // rollback chain: the clock is still regressed below the accepted
        // instant, so the next refusal is still a repeat.
        sampler.prune_history(time::Duration::days(7)).await.0?;
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, instant(10)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the regressed tick must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::ClockRollback { .. }));
        assert!(repeated);
        // The clock catches up (a forward tick past the accepted instant):
        // the guard accepts again and the chain clears — the accepted call
        // itself never carries a repeated-refusal verdict.
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, instant(31)).await;
        assert!(result.is_ok() && !repeated);
        // A fresh regression after the recovery is a new condition again.
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, instant(20)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the regressed tick must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::ClockRollback { .. }));
        assert!(!repeated);
        Ok(())
    }

    #[tokio::test]
    async fn sustained_cutoff_underflows_are_deduplicated_until_the_clock_recovers()
    -> Result<(), Box<dyn Error>> {
        // The `CutoffUnderflow` refusal gets the same consecutive-refusal
        // treatment as the rollback guard: a clock that keeps predating the
        // retention window refuses every prune, the first refusal is a fresh
        // condition, and each repeat is flagged until the clock recovers.
        let clock = MovableClock::at(earliest_instant());
        let store = RecordingStore::new();
        let sampler =
            TelemetrySampler::new(FakeReader::with_reports(Vec::new()), &store, clock.clone());

        let (result, repeated) = sampler.prune_history(time::Duration::days(7)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the underflow must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::CutoffUnderflow));
        assert!(!repeated, "the first underflow is a fresh condition");
        // A sampling call between the prunes neither continues nor breaks
        // the underflow chain: the sample is accepted (no accepted instant
        // precedes it — the underflow guard belongs to the prune), the
        // clock still predates the retention window, and the next prune's
        // underflow is still a repeat.
        let (result, repeated) = sampler
            .sample_endpoint(EndpointId::generate(), earliest_instant())
            .await;
        assert!(result.is_ok() && !repeated);
        let (result, repeated) = sampler.prune_history(time::Duration::days(7)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the underflow must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::CutoffUnderflow));
        assert!(repeated);
        // The clock recovers: the cutoff computes again and the chain
        // clears — the accepted prune itself never carries a
        // repeated-refusal verdict.
        clock.move_to(instant(30));
        let (result, repeated) = sampler.prune_history(time::Duration::days(7)).await;
        assert!(result.is_ok() && !repeated);
        // A fresh underflow after the recovery is a new condition again.
        clock.move_to(earliest_instant());
        let (result, repeated) = sampler.prune_history(time::Duration::days(7)).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("the underflow must be refused").into());
        };
        assert!(matches!(error, TelemetrySamplerError::CutoffUnderflow));
        assert!(!repeated);
        Ok(())
    }

    #[tokio::test]
    async fn interleaved_callers_each_read_their_own_refusal_verdict() -> Result<(), Box<dyn Error>>
    {
        // W3N-4: the refusal verdict travels with the call that refused,
        // decided in the same critical section that records the refusal —
        // so when two callers interleave, each reads the verdict of its own
        // call, never a verdict a concurrent caller wrote afterwards. The
        // pre-fix query API read one shared bit after the call: caller A's
        // first refusal (a fresh condition) followed by caller B's repeat
        // would have shown B's verdict to A — the fresh refusal was
        // mis-logged as a warn, and a persisted anomaly whose chain a
        // concurrent success cleared was mis-logged as a fresh error, the
        // storm the dedupe exists to prevent. The verdict is now per call:
        // A's result carries `false` and B's carries `true`, no matter how
        // the calls interleave.
        let endpoint_id = EndpointId::generate();
        // The sampler owns its store: the refusal path never touches it,
        // and the shared `Arc` must be `'static` for the spawned caller.
        let sampler = Arc::new(TelemetrySampler::new(
            FakeReader::with_reports(Vec::new()),
            RecordingStore::new(),
            FixedClock(instant(30)),
        ));
        // Prime the accepted instant: the two refused calls below both
        // regress from it.
        sampler.sample_endpoint(endpoint_id, instant(30)).await.0?;

        // Caller A refuses first, then holds its result while caller B
        // refuses too — the interleaving that could overwrite a shared
        // verdict bit between A's refusal and A's read.
        let a_started = Arc::new(tokio::sync::Notify::new());
        let release_a = Arc::new(tokio::sync::Notify::new());
        let a_task = {
            let sampler = Arc::clone(&sampler);
            let a_started = Arc::clone(&a_started);
            let release_a = Arc::clone(&release_a);
            tokio::spawn(async move {
                let (result, repeated) = sampler.sample_endpoint(endpoint_id, instant(10)).await;
                // The refusal and its verdict are already in hand here; the
                // task holds them across caller B's intervening call.
                a_started.notify_waiters();
                release_a.notified().await;
                (result, repeated)
            })
        };
        // Wait until A's refusal landed (the waiter is registered before
        // the task runs, so the wake is never missed).
        let entered_wait = a_started.notified();
        entered_wait.await;

        // Caller B refuses now: a repeat of A's refusal.
        let (b_result, b_repeated) = sampler.sample_endpoint(endpoint_id, instant(10)).await;
        assert!(matches!(
            b_result,
            Err(TelemetrySamplerError::ClockRollback { .. })
        ));
        assert!(
            b_repeated,
            "B's refusal repeats A's: the repeat verdict belongs to B's call"
        );

        // A's verdict is its own — a fresh condition — unaffected by B's
        // intervening refusal.
        release_a.notify_one();
        let (a_result, a_repeated) = a_task.await.map_err(std::io::Error::other)?;
        assert!(matches!(
            a_result,
            Err(TelemetrySamplerError::ClockRollback { .. })
        ));
        assert!(
            !a_repeated,
            "A's first refusal stays a fresh condition even though B's repeat landed before A \
             read its result"
        );
        Ok(())
    }

    #[tokio::test]
    async fn sampler_surfaces_source_and_store_failures_with_their_sources()
    -> Result<(), Box<dyn Error>> {
        let endpoint_id = EndpointId::generate();
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(FakeReader::failing(), &store, FixedClock(OBSERVED_AT));
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, OBSERVED_AT).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("sampling must fail").into());
        };
        assert!(matches!(error, TelemetrySamplerError::Read { .. }));
        assert!(error.to_string().contains("could not be read"));
        assert!(
            !repeated,
            "a failure that is not a clock refusal must not be flagged as a repeated refusal"
        );

        let series = MetricReportValues::try_new(
            SeriesKey::parse("PowerMetrics")?,
            vec![MetricReportReading::new(None, 100.0)],
        )?;
        let store = RecordingStore::failing_upserts();
        let sampler = TelemetrySampler::new(
            FakeReader::with_reports(vec![series]),
            &store,
            FixedClock(OBSERVED_AT),
        );
        let (result, repeated) = sampler.sample_endpoint(endpoint_id, OBSERVED_AT).await;
        let Err(error) = result else {
            return Err(std::io::Error::other("sampling must fail").into());
        };
        assert!(
            !repeated,
            "a store failure is not a clock refusal and must not be flagged"
        );
        // The display text is captured before the destructure moves the
        // series key out of the error.
        let display = error.to_string();
        let TelemetrySamplerError::Upsert {
            series_key, source, ..
        } = error
        else {
            return Err(std::io::Error::other("expected an upsert failure").into());
        };
        assert_eq!(series_key.as_str(), "PowerMetrics");
        assert_eq!(source, MockError::Store);
        assert_eq!(
            display,
            format!(
                "metric series PowerMetrics of endpoint {endpoint_id} could not be recorded: mock store failed"
            )
        );
        Ok(())
    }

    #[tokio::test]
    async fn prune_derives_the_cutoff_from_the_clock_and_retention() -> Result<(), Box<dyn Error>> {
        let now = instant(30);
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(
            FakeReader::with_reports(Vec::new()),
            &store,
            FixedClock(now),
        );

        sampler.prune_history(time::Duration::days(7)).await.0?;

        assert_eq!(
            store.prune_cutoffs(),
            vec![now - time::Duration::days(7)],
            "the retention window must be subtracted from the clock instant"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_configured_retention_shifts_the_prune_cutoff() -> Result<(), Box<dyn Error>> {
        // The §14.4 configurability contract: each configured window cuts
        // the history at its own cutoff, so the product's configured value
        // decides what history survives.
        let now = instant(30);
        let store = RecordingStore::new();
        let sampler = TelemetrySampler::new(
            FakeReader::with_reports(Vec::new()),
            &store,
            FixedClock(now),
        );

        sampler.prune_history(time::Duration::days(1)).await.0?;
        sampler.prune_history(time::Duration::days(30)).await.0?;

        assert_eq!(
            store.prune_cutoffs(),
            vec![
                now - time::Duration::days(1),
                now - time::Duration::days(30),
            ],
            "each configured retention must cut the history at its own cutoff"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_clock_jump_forward_moves_the_prune_cutoff_forward() -> Result<(), Box<dyn Error>> {
        // The product clock jumps forward (NTP correction, a missed tick):
        // the next prune derives its cutoff from the new instant, so the
        // retention window always starts at the clock's present, never at a
        // cached past.
        let clock = MovableClock::at(instant(30));
        let store = RecordingStore::new();
        let sampler =
            TelemetrySampler::new(FakeReader::with_reports(Vec::new()), &store, clock.clone());

        sampler.prune_history(time::Duration::days(7)).await.0?;
        clock.move_to(instant(60));
        sampler.prune_history(time::Duration::days(7)).await.0?;

        assert_eq!(
            store.prune_cutoffs(),
            vec![
                instant(30) - time::Duration::days(7),
                instant(60) - time::Duration::days(7),
            ],
            "each prune must subtract the retention from the clock instant at that tick"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_clock_jump_backward_re_derives_the_cutoff_stably() -> Result<(), Box<dyn Error>> {
        // The product clock jumps backward (wall-clock drift): the cutoff is
        // re-derived from the earlier instant — retaining more history than
        // the forward jump would, never a negative window, never a cached
        // stale cutoff — so the prune stays a stable function of the clock at
        // each tick.
        let clock = MovableClock::at(instant(30));
        let store = RecordingStore::new();
        let sampler =
            TelemetrySampler::new(FakeReader::with_reports(Vec::new()), &store, clock.clone());

        sampler.prune_history(time::Duration::days(7)).await.0?;
        clock.move_to(instant(10));
        sampler.prune_history(time::Duration::days(7)).await.0?;
        assert_eq!(
            store.prune_cutoffs(),
            vec![
                instant(30) - time::Duration::days(7),
                instant(10) - time::Duration::days(7),
            ],
            "a backward jump must re-derive the cutoff from the regressed instant"
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Store,
        Lock,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::Store => "mock store failed",
                Self::Lock => "mock state is unavailable",
            })
        }
    }

    impl Error for MockError {}

    #[derive(Clone, Debug, Default)]
    struct MockInventoryRepository {
        items: Arc<Mutex<Vec<EndpointInventoryItem>>>,
        fail_listing: bool,
    }

    impl MockInventoryRepository {
        fn new(items: Vec<EndpointInventoryItem>) -> Self {
            Self {
                items: Arc::new(Mutex::new(items)),
                fail_listing: false,
            }
        }

        fn failing() -> Self {
            Self {
                items: Arc::new(Mutex::new(Vec::new())),
                fail_listing: true,
            }
        }
    }

    impl EndpointInventoryRepository for MockInventoryRepository {
        type Error = MockError;

        fn list_endpoint_inventory(
            &self,
        ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
            Box::pin(async move {
                if self.fail_listing {
                    return Err(MockError::Store);
                }
                self.items
                    .lock()
                    .map(|items| items.clone())
                    .map_err(|_| MockError::Lock)
            })
        }
    }

    #[derive(Clone, Debug, Default)]
    struct FakeReader {
        reports: Arc<Mutex<Vec<MetricReportValues>>>,
        fail_reads: bool,
    }

    impl FakeReader {
        fn with_reports(reports: Vec<MetricReportValues>) -> Self {
            Self {
                reports: Arc::new(Mutex::new(reports)),
                fail_reads: false,
            }
        }

        fn failing() -> Self {
            Self {
                reports: Arc::new(Mutex::new(Vec::new())),
                fail_reads: true,
            }
        }
    }

    impl MetricReportReader for FakeReader {
        type Error = MockError;

        fn read_metric_reports(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Vec<MetricReportValues>, Self::Error>> {
            Box::pin(async move {
                if self.fail_reads {
                    return Err(MockError::Store);
                }
                self.reports
                    .lock()
                    .map(|reports| reports.clone())
                    .map_err(|_| MockError::Lock)
            })
        }
    }

    /// One recorded append, in exact order: the series identity (as its
    /// display text, since the id type stays serialization-free), the product
    /// sampling instant, the optional BMC timestamp, and the value.
    type RecordedSample = (String, OffsetDateTime, Option<OffsetDateTime>, f64);

    /// Records every upsert/append/prune call and serves scripted failures.
    #[derive(Clone, Debug, Default)]
    struct RecordingStore {
        upserts: Arc<Mutex<Vec<(EndpointId, String)>>>,
        samples: Arc<Mutex<Vec<RecordedSample>>>,
        prune_cutoffs: Arc<Mutex<Vec<OffsetDateTime>>>,
        fail_upserts: bool,
    }

    impl RecordingStore {
        fn new() -> Self {
            Self::default()
        }

        fn failing_upserts() -> Self {
            Self {
                fail_upserts: true,
                ..Self::default()
            }
        }

        fn upserts(&self) -> Vec<(EndpointId, String)> {
            self.upserts
                .lock()
                .map(|upserts| upserts.clone())
                .unwrap_or_default()
        }

        fn samples(&self) -> Vec<RecordedSample> {
            self.samples
                .lock()
                .map(|samples| samples.clone())
                .unwrap_or_default()
        }

        fn prune_cutoffs(&self) -> Vec<OffsetDateTime> {
            self.prune_cutoffs
                .lock()
                .map(|cutoffs| cutoffs.clone())
                .unwrap_or_default()
        }
    }

    impl TelemetryRepository for RecordingStore {
        type Error = MockError;

        fn upsert_series<'a>(
            &'a self,
            endpoint_id: EndpointId,
            series_key: &'a SeriesKey,
        ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>> {
            Box::pin(async move {
                if self.fail_upserts {
                    return Err(MockError::Store);
                }
                let series = TelemetrySeries::new(
                    TelemetrySeriesId::generate(),
                    endpoint_id,
                    series_key.clone(),
                );
                self.upserts
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .push((endpoint_id, series_key.to_string()));
                Ok(series)
            })
        }

        fn append_sample<'a>(
            &'a self,
            sample: &'a TelemetrySample,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.samples.lock().map_err(|_| MockError::Lock)?.push((
                    sample.series_id().to_string(),
                    sample.observed_at(),
                    sample.bmc_timestamp(),
                    sample.value(),
                ));
                Ok(())
            })
        }

        fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
            Box::pin(async { Err(MockError::Store) })
        }

        fn list_samples(
            &self,
            _series_id: TelemetrySeriesId,
            _limit: NonZeroU64,
        ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
            Box::pin(async { Err(MockError::Store) })
        }

        fn prune_before(
            &self,
            cutoff: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                self.prune_cutoffs
                    .lock()
                    .map(|mut cutoffs| cutoffs.push(cutoff))
                    .map_err(|_| MockError::Lock)
            })
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    /// A clock the test can move between ticks, modeling the product clock
    /// jumping (NTP correction, wall-clock drift) mid-run.
    #[derive(Clone, Debug)]
    struct MovableClock(Arc<Mutex<OffsetDateTime>>);

    impl MovableClock {
        fn at(now: OffsetDateTime) -> Self {
            Self(Arc::new(Mutex::new(now)))
        }

        fn move_to(&self, now: OffsetDateTime) {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner) = now;
        }
    }

    impl Clock for MovableClock {
        fn now(&self) -> OffsetDateTime {
            *self.0.lock().unwrap_or_else(PoisonError::into_inner)
        }
    }
}
