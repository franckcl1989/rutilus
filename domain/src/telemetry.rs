//! The persisted telemetry model (§9.3 事件和遥测, §14.4 Telemetry).
//!
//! The product is deliberately not a general-purpose time-series database
//! (§14.4 不把产品变成通用时序数据库): it keeps the current value and a
//! bounded history for the metrics it samples, nothing more. The boundary is
//! drawn at the series: **one series is one metric value of one
//! `MetricReport` of one endpoint**. The [`SeriesKey`] carries the report's
//! identity (its Redfish `Id`, the last `@odata.id` segment, for example
//! `PowerMetrics`) joined with the metric's `MetricId` (for example
//! `PowerConsumedWatts`), so the same metric id inside two different reports
//! is two series, never silently merged. Storing whole reports as series
//! would force JSON payloads into the sample rows — a blob store, not
//! readings — and storing raw metric ids without the report identity would
//! let two reports share one history. The scalar-per-series row keeps every
//! sample an `f64` reading and every series bounded by the retention policy.
//!
//! Samples are stamped with the **product clock**, not the BMC's
//! `MetricValue.Timestamp`: [`TelemetrySample::observed_at`] is the time the
//! product's sampler took the reading. The sampler rhythm is
//! product-controlled (§14.4 有界历史 serves product-side trends), the BMC
//! timestamp is an optional Redfish string that may be absent, unparseable,
//! or in a clock far from the product's, and retention pruning is a
//! product-time cut — mixing clocks would make both ordering and pruning
//! ambiguous. The BMC's own `MetricValue.Timestamp` is preserved beside it
//! as optional display metadata ([`TelemetrySample::bmc_timestamp`]),
//! exactly like the events model keeps the BMC's `EventTimestamp` beside
//! the product receive time, so a trend view can show the sensor's own time
//! while ordering and retention stay on the product clock. Unlike events,
//! the BMC timestamp is deliberately not ordered against `observed_at`: it
//! never participates in ordering, dedup, or retention, and refusing
//! readings from BMCs whose clock skews ahead of the product's would drop
//! legitimate data for no ordering benefit.
//!
//! Readings must be finite numbers (§7.6 不伪装): NaN and infinity are not
//! measurements, and a stored one would poison every trend chart and bounded
//! query built on the history. [`TelemetrySample`] refuses them at
//! construction, and persistence re-validates stored values on read, so a
//! corrupt row is reported as corrupt instead of half-read.

use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::EndpointId;

/// The longest [`SeriesKey`] the product records.
///
/// A key is a report identity and a metric id joined by a separator; Redfish
/// `Id` values are short, so 512 Unicode scalar values is a generous bound
/// that still refuses a runaway payload growing the table without limit (the
/// `MessageId` precedent).
const MAX_SERIES_KEY_CHARS: usize = 512;

/// The stable identity of one persisted telemetry series (§9.3, §14.4).
///
/// This is the identity of the `telemetry_series` row — one metric of one
/// `MetricReport` of one endpoint (see the module doc for the identity
/// design). It is the handle the sampler carries to append readings and the
/// key persistence uses to scope the bounded sample history.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TelemetrySeriesId(Uuid);

impl TelemetrySeriesId {
    /// Generates a time-ordered UUID version 7 identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID without changing its value.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the underlying UUID value.
    #[must_use]
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for TelemetrySeriesId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TelemetrySeriesId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// A telemetry series identity as the sampler derives it.
///
/// This is its own type rather than a plain `String` so the §14.4 series
/// identity contract — report identity + metric id, see the module doc — is
/// enforced on the way in: a series never carries an empty or unbounded key,
/// and the unique persistence key `(endpoint_id, series_key)` is therefore
/// always well-formed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SeriesKey(String);

impl SeriesKey {
    /// Validates and normalizes a series key.
    ///
    /// Surrounding whitespace is trimmed (a BMC may pad the value); the
    /// result is the exact key text used for persistence and display.
    ///
    /// # Errors
    ///
    /// Returns [`SeriesKeyError`] for an empty value, a control character,
    /// or a value longer than [`MAX_SERIES_KEY_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, SeriesKeyError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(SeriesKeyError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(SeriesKeyError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_SERIES_KEY_CHARS {
            return Err(SeriesKeyError::TooLong {
                actual,
                maximum: MAX_SERIES_KEY_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SeriesKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for SeriesKey {
    type Err = SeriesKeyError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a telemetry series identity cannot be recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeriesKeyError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for SeriesKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("telemetry series key cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("telemetry series key cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "telemetry series key has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for SeriesKeyError {}

/// One persisted telemetry series (§9.3, §14.4): one metric of one
/// `MetricReport` of one endpoint (see the module doc for the identity
/// design and the "not a time-series database" boundary).
///
/// `sample_count` is the size of the bounded history (§14.4 有界历史) as the
/// persistence maintains it: the persistence `append_sample` increments it,
/// the persistence `prune_before` recomputes it, so the metadata always
/// reflects the rows it describes. The count is a persistence-maintained
/// fact, not a domain computation: creation always starts a series at zero
/// samples, and rehydration accepts whatever consistent count the database
/// stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TelemetrySeries {
    id: TelemetrySeriesId,
    endpoint_id: EndpointId,
    series_key: SeriesKey,
    sample_count: u64,
}

impl TelemetrySeries {
    /// Creates a new, empty series.
    ///
    /// The new series holds no samples yet: `sample_count` starts at zero and
    /// the persistence maintains it from there on.
    #[must_use]
    pub const fn new(
        id: TelemetrySeriesId,
        endpoint_id: EndpointId,
        series_key: SeriesKey,
    ) -> Self {
        Self {
            id,
            endpoint_id,
            series_key,
            sample_count: 0,
        }
    }

    /// Rehydrates a persisted series record.
    ///
    /// This is the persistence loading path, which must accept whatever the
    /// database stored — including the maintained `sample_count`. The
    /// `SeriesKey` is already validated by its own type on the way in, and
    /// the stored count is converted from the database's `i64` at the
    /// persistence boundary (a negative stored count is corrupt there), so
    /// the domain has nothing further to check: a row can never be
    /// rehydrated with a key or count that disagrees with its own fields.
    #[must_use]
    pub const fn from_parts(
        id: TelemetrySeriesId,
        endpoint_id: EndpointId,
        series_key: SeriesKey,
        sample_count: u64,
    ) -> Self {
        Self {
            id,
            endpoint_id,
            series_key,
            sample_count,
        }
    }

    #[must_use]
    pub const fn id(&self) -> TelemetrySeriesId {
        self.id
    }

    /// Returns the endpoint whose `MetricReport` this series samples.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the series identity: report identity + metric id.
    #[must_use]
    pub fn series_key(&self) -> &SeriesKey {
        &self.series_key
    }

    /// Returns the number of samples currently retained for this series.
    #[must_use]
    pub const fn sample_count(&self) -> u64 {
        self.sample_count
    }
}

/// One persisted telemetry reading (§9.3, §14.4): a scalar value sampled
/// from one series at the product's own clock time.
///
/// `observed_at` is the product clock's sampling time — the ordering,
/// bounded-history, and retention key; `bmc_timestamp` optionally preserves
/// the BMC's own `MetricValue.Timestamp` as display metadata beside it (see
/// the module doc for why the two clocks coexist and why the BMC one is not
/// ordered against the product one).
///
/// The value must be a finite number (§7.6 不伪装): NaN and infinity are
/// refused at construction and re-validated on rehydration, so a corrupt
/// stored reading is reported as corrupt rather than half-read.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TelemetrySample {
    series_id: TelemetrySeriesId,
    observed_at: OffsetDateTime,
    bmc_timestamp: Option<OffsetDateTime>,
    value: f64,
}

impl TelemetrySample {
    /// Records a reading the product's sampler took at `observed_at`.
    ///
    /// `observed_at` is the product clock's sampling time, supplied by the
    /// caller exactly like `Operation::apply`'s `now` parameter, so the
    /// domain stays free of clock access. The reading carries no BMC
    /// timestamp; attach one with [`Self::with_bmc_timestamp`] when the
    /// sample source reported it.
    ///
    /// # Errors
    ///
    /// Returns [`NonFiniteSampleValue`] when `value` is NaN or infinite: a
    /// non-finite reading is not a measurement, and recording one would
    /// poison the trend history (§7.6 不伪装).
    pub fn new(
        series_id: TelemetrySeriesId,
        observed_at: OffsetDateTime,
        value: f64,
    ) -> Result<Self, NonFiniteSampleValue> {
        build(series_id, observed_at, None, value)
    }

    /// Attaches the BMC's own `MetricValue.Timestamp` to this reading.
    ///
    /// Display metadata only: it never participates in ordering or
    /// retention (see the module doc).
    #[must_use]
    pub const fn with_bmc_timestamp(mut self, bmc_timestamp: OffsetDateTime) -> Self {
        self.bmc_timestamp = Some(bmc_timestamp);
        self
    }

    /// Rehydrates a persisted sample record.
    ///
    /// This is the persistence loading path, which must accept whatever the
    /// database stored — including the optional BMC timestamp — but only
    /// what is a valid reading. `SQLite` accepts infinite REAL values, so a
    /// stored row with a non-finite value is refused here as corrupt; the
    /// value is re-validated exactly like a fresh sample, and the
    /// persistence maps the refusal into its corrupt row error.
    ///
    /// # Errors
    ///
    /// Returns [`NonFiniteSampleValue`] when the stored value is NaN or
    /// infinite.
    pub fn try_from_parts(
        series_id: TelemetrySeriesId,
        observed_at: OffsetDateTime,
        bmc_timestamp: Option<OffsetDateTime>,
        value: f64,
    ) -> Result<Self, NonFiniteSampleValue> {
        build(series_id, observed_at, bmc_timestamp, value)
    }

    #[must_use]
    pub const fn series_id(&self) -> TelemetrySeriesId {
        self.series_id
    }

    /// Returns when the product's sampler took this reading.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    /// Returns the BMC's own `MetricValue.Timestamp`, when the source
    /// reported one.
    #[must_use]
    pub const fn bmc_timestamp(&self) -> Option<OffsetDateTime> {
        self.bmc_timestamp
    }

    /// Returns the scalar reading.
    #[must_use]
    pub const fn value(&self) -> f64 {
        self.value
    }
}

/// A telemetry reading is not a finite number.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NonFiniteSampleValue;

impl fmt::Display for NonFiniteSampleValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("telemetry sample value must be a finite number")
    }
}

impl Error for NonFiniteSampleValue {}

/// Validates the reading and assembles the sample.
///
/// Both constructors run the same invariant: the value must be finite. A
/// non-finite reading is refused here — never at the persistence layer — so
/// an invalid value cannot exist in the domain at all.
fn build(
    series_id: TelemetrySeriesId,
    observed_at: OffsetDateTime,
    bmc_timestamp: Option<OffsetDateTime>,
    value: f64,
) -> Result<TelemetrySample, NonFiniteSampleValue> {
    if !value.is_finite() {
        return Err(NonFiniteSampleValue);
    }
    Ok(TelemetrySample {
        series_id,
        observed_at,
        bmc_timestamp,
        value,
    })
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use time::OffsetDateTime;

    use super::*;

    #[test]
    fn series_id_round_trips_through_text() -> Result<(), uuid::Error> {
        let original = TelemetrySeriesId::generate();

        assert_eq!(original.into_uuid().get_version_num(), 7);
        assert_eq!(original.to_string().parse::<TelemetrySeriesId>()?, original);
        Ok(())
    }

    #[test]
    fn series_key_validation_normalizes_and_rejects_bad_values() -> Result<(), Box<dyn Error>> {
        let key = SeriesKey::parse("  PowerMetrics/PowerConsumedWatts  ")?;
        assert_eq!(key.as_str(), "PowerMetrics/PowerConsumedWatts");
        assert_eq!("  ".parse::<SeriesKey>(), Err(SeriesKeyError::Empty));
        assert_eq!(
            "PowerMetrics/Power\nConsumedWatts".parse::<SeriesKey>(),
            Err(SeriesKeyError::ControlCharacter)
        );
        assert!(matches!(
            SeriesKey::parse(&"x".repeat(MAX_SERIES_KEY_CHARS + 1)),
            Err(SeriesKeyError::TooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_new_series_starts_with_zero_samples() -> Result<(), Box<dyn Error>> {
        let id = TelemetrySeriesId::generate();
        let endpoint_id = EndpointId::generate();
        let key = SeriesKey::parse("PowerMetrics/PowerConsumedWatts")?;

        let series = TelemetrySeries::new(id, endpoint_id, key.clone());

        assert_eq!(series.id(), id);
        assert_eq!(series.endpoint_id(), endpoint_id);
        assert_eq!(series.series_key(), &key);
        assert_eq!(series.sample_count(), 0);
        Ok(())
    }

    #[test]
    fn rehydration_restores_a_persisted_series_with_its_sample_count() -> Result<(), Box<dyn Error>>
    {
        let id = TelemetrySeriesId::generate();
        let endpoint_id = EndpointId::generate();
        let key = SeriesKey::parse("PowerMetrics/PowerConsumedWatts")?;

        let restored = TelemetrySeries::from_parts(id, endpoint_id, key.clone(), 42);

        assert_eq!(restored.id(), id);
        assert_eq!(restored.endpoint_id(), endpoint_id);
        assert_eq!(restored.series_key(), &key);
        assert_eq!(restored.sample_count(), 42);
        Ok(())
    }

    #[test]
    fn the_same_metric_id_in_different_reports_is_a_different_series() -> Result<(), Box<dyn Error>>
    {
        // §14.4 series identity: the report identity is part of the key, so
        // the same metric id in two reports is two series — two distinct
        // bounded histories, never silently merged.
        let temperature_in_power = SeriesKey::parse("PowerMetrics/Temperature")?;
        let temperature_in_thermal = SeriesKey::parse("ThermalMetrics/Temperature")?;

        assert_ne!(temperature_in_power, temperature_in_thermal);
        assert_eq!(temperature_in_power.as_str(), "PowerMetrics/Temperature");
        Ok(())
    }

    // The compared constants are exactly representable in binary64 and the
    // value round-trips bit-identically, so `==` here is precise, not
    // approximate.
    #[allow(clippy::float_cmp)]
    #[test]
    fn samples_reject_non_finite_values_and_record_finite_readings() -> Result<(), Box<dyn Error>> {
        let series_id = TelemetrySeriesId::generate();
        let observed_at = OffsetDateTime::now_utc();

        // §7.6 不伪装: NaN and infinity are not measurements. Both
        // constructors run the same rule, so a stored non-finite reading is
        // as refused as a fresh one.
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(matches!(
                TelemetrySample::new(series_id, observed_at, value),
                Err(NonFiniteSampleValue)
            ));
            assert!(matches!(
                TelemetrySample::try_from_parts(series_id, observed_at, None, value),
                Err(NonFiniteSampleValue)
            ));
        }

        let sample = TelemetrySample::new(series_id, observed_at, 0.5)?;
        assert_eq!(sample.series_id(), series_id);
        assert_eq!(sample.observed_at(), observed_at);
        assert_eq!(sample.bmc_timestamp(), None);
        assert_eq!(sample.value(), 0.5);
        assert_eq!(
            TelemetrySample::try_from_parts(series_id, observed_at, None, -3.25)?.value(),
            -3.25
        );
        Ok(())
    }

    #[test]
    fn the_bmc_timestamp_is_preserved_as_metadata_and_round_trips_rehydration()
    -> Result<(), Box<dyn Error>> {
        let series_id = TelemetrySeriesId::generate();
        let observed_at = OffsetDateTime::now_utc();
        // The BMC measures before the product samples; a skewed BMC clock
        // may even read later — the metadata is never ordered against the
        // product clock (see the module doc).
        let bmc_reported = observed_at - time::Duration::MINUTE;

        let sample =
            TelemetrySample::new(series_id, observed_at, 21.5)?.with_bmc_timestamp(bmc_reported);
        assert_eq!(sample.bmc_timestamp(), Some(bmc_reported));

        let restored = TelemetrySample::try_from_parts(
            series_id,
            observed_at,
            Some(bmc_reported),
            sample.value(),
        )?;
        assert_eq!(restored, sample);
        Ok(())
    }
}
