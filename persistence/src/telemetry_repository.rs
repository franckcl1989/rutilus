use rutilus_domain::{
    EndpointId, NonFiniteSampleValue, SeriesKey, SeriesKeyError, TelemetrySample, TelemetrySeries,
    TelemetrySeriesId,
};
use rutilus_entity::{telemetry_sample, telemetry_series};
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait, TryInsertResult,
};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::SqliteStore;

impl SqliteStore {
    /// Finds a telemetry series by its unique key or creates it (§14.4).
    ///
    /// The identity is `(endpoint_id, series_key)` — one metric of one
    /// `MetricReport` of one endpoint (the domain `TelemetrySeries` doc).
    /// The operation is idempotent: a series that already exists is returned
    /// unchanged (its `sample_count` included), and a missing one is created
    /// empty. The write gate serializes writers, and the unique index on
    /// `(endpoint_id, series_key)` (migration 000009) is the database-level
    /// backstop, so the find-or-create is atomic — a racing duplicate is
    /// absorbed as a conflict and the winning row is returned, never a
    /// check-then-insert race (the `append_event` dedup discipline).
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryRepositoryError`] when write coordination fails,
    /// `SQLite` rejects the query, or a stored row violates a domain
    /// invariant.
    pub async fn upsert_series(
        &self,
        endpoint_id: EndpointId,
        series_key: SeriesKey,
    ) -> Result<TelemetrySeries, TelemetryRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TelemetryRepositoryError::Coordinate)?;
        let key_text = series_key.to_string();
        let unique = telemetry_series::Column::EndpointId
            .eq(endpoint_id.into_uuid())
            .and(telemetry_series::Column::SeriesKey.eq(&key_text));
        if let Some(model) = telemetry_series::Entity::find()
            .filter(unique.clone())
            .one(&self.database)
            .await
            .map_err(TelemetryRepositoryError::Database)?
        {
            return map_stored_series(&model)
                .map_err(|source| corrupt(TelemetrySeriesId::from_uuid(model.id), source));
        }
        let id = TelemetrySeriesId::generate();
        let inserted = telemetry_series::Entity::insert(telemetry_series::ActiveModel {
            id: Set(id.into_uuid()),
            endpoint_id: Set(endpoint_id.into_uuid()),
            series_key: Set(key_text),
            sample_count: Set(0),
        })
        .on_conflict_do_nothing_on([
            telemetry_series::Column::EndpointId,
            telemetry_series::Column::SeriesKey,
        ])
        .exec(&self.database)
        .await
        .map_err(TelemetryRepositoryError::Database)?;
        match inserted {
            // `Inserted` persisted the new empty series exactly as
            // parameterized, so the domain value is rebuilt from the
            // parameters. `Conflicted` is a racing duplicate absorbed by the
            // unique index — under the write gate it cannot happen, but the
            // winning row is returned rather than the insert failing.
            // `Empty` cannot occur for a single-model insert and exists only
            // for the iterator API; treating it like a conflict keeps the
            // match exhaustive and the result deterministic.
            TryInsertResult::Inserted(_) => Ok(TelemetrySeries::new(id, endpoint_id, series_key)),
            TryInsertResult::Conflicted | TryInsertResult::Empty => {
                let model = telemetry_series::Entity::find()
                    .filter(unique)
                    .one(&self.database)
                    .await
                    .map_err(TelemetryRepositoryError::Database)?
                    .ok_or_else(|| {
                        TelemetryRepositoryError::Database(DbErr::Custom(String::from(
                            "telemetry series disappeared after an upsert conflict",
                        )))
                    })?;
                map_stored_series(&model)
                    .map_err(|source| corrupt(TelemetrySeriesId::from_uuid(model.id), source))
            }
        }
    }

    /// Persists one sampled reading for an existing series (§14.4).
    ///
    /// `sample_count` is maintained here: the append increments the series'
    /// count in the same transaction, so the metadata never silently
    /// disagrees with the rows it describes. The transaction also makes the
    /// existence check atomic — the write gate serializes writers, so a
    /// series cannot be deleted between the check and the insert. A series
    /// must exist before a sample can be appended (see
    /// [`Self::upsert_series`] for the creation entry point): a stale or
    /// mistyped series handle fails loudly instead of silently starting a
    /// new series with a wrong identity.
    ///
    /// The sample is stamped with the product clock by the caller (the
    /// sampler); the BMC's own `MetricValue.Timestamp`, when reported, rides
    /// along as display metadata. See the domain `TelemetrySample` doc for
    /// why the product clock is authoritative.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryRepositoryError::SeriesNotFound`] when no series
    /// has that identity, and the other [`TelemetryRepositoryError`] variants
    /// for coordination or database failures.
    pub async fn append_sample(
        &self,
        sample: &TelemetrySample,
    ) -> Result<(), TelemetryRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TelemetryRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        if telemetry_series::Entity::find_by_id(sample.series_id().into_uuid())
            .one(&transaction)
            .await
            .map_err(TelemetryRepositoryError::Database)?
            .is_none()
        {
            return Err(TelemetryRepositoryError::SeriesNotFound {
                series_id: sample.series_id(),
            });
        }
        telemetry_sample::ActiveModel {
            series_id: Set(sample.series_id().into_uuid()),
            observed_at: Set(sample.observed_at()),
            bmc_timestamp: Set(sample.bmc_timestamp()),
            value: Set(sample.value()),
            ..Default::default()
        }
        .insert(&transaction)
        .await
        .map_err(TelemetryRepositoryError::Database)?;
        telemetry_series::Entity::update_many()
            .col_expr(
                telemetry_series::Column::SampleCount,
                Expr::col(telemetry_series::Column::SampleCount).add(1),
            )
            .filter(telemetry_series::Column::Id.eq(sample.series_id().into_uuid()))
            .exec(&transaction)
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        Ok(())
    }

    /// Lists every telemetry series of one endpoint, by series key.
    ///
    /// The listing is the §14.4 current-value view: each series carries its
    /// `sample_count`, so the caller can show how much bounded history each
    /// metric holds without touching the samples table.
    ///
    /// Each row is rehydrated as a complete domain series, so one corrupt
    /// row poisons the whole listing: the caller must surface the corruption
    /// rather than silently drop an unreadable series (the
    /// `list_recent_events` precedent).
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryRepositoryError`] when the query fails or any
    /// stored series violates domain invariants.
    pub async fn list_series(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<Vec<TelemetrySeries>, TelemetryRepositoryError> {
        let models = telemetry_series::Entity::find()
            .filter(telemetry_series::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .order_by_asc(telemetry_series::Column::SeriesKey)
            .all(&self.database)
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        let mut series = Vec::with_capacity(models.len());
        for model in &models {
            series.push(
                map_stored_series(model)
                    .map_err(|source| corrupt(TelemetrySeriesId::from_uuid(model.id), source))?,
            );
        }
        Ok(series)
    }

    /// Lists the `limit` most recently sampled readings of one series,
    /// newest first.
    ///
    /// The listing is bounded by design (§14.4 有界历史, not an unbounded
    /// scan): the query applies `LIMIT`, so it never returns more than
    /// `limit` rows, and `limit = 0` returns an empty list. Ordering is by
    /// the product sampling time (`observed_at`), with the row identity as a
    /// deterministic tie-break for readings sampled at the same instant.
    ///
    /// Each row is rehydrated as a complete domain sample, so one corrupt
    /// row poisons the whole listing: the caller must surface the
    /// corruption rather than silently drop an unreadable reading.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryRepositoryError`] when the query fails or any
    /// stored reading violates domain invariants.
    pub async fn list_samples(
        &self,
        series_id: TelemetrySeriesId,
        limit: usize,
    ) -> Result<Vec<TelemetrySample>, TelemetryRepositoryError> {
        let models = telemetry_sample::Entity::find()
            .filter(telemetry_sample::Column::SeriesId.eq(series_id.into_uuid()))
            .order_by_desc(telemetry_sample::Column::ObservedAt)
            .order_by_desc(telemetry_sample::Column::Id)
            .limit(limit as u64)
            .all(&self.database)
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        let mut samples = Vec::with_capacity(models.len());
        for model in models {
            let value = model.value;
            let sample = TelemetrySample::try_from_parts(
                series_id,
                model.observed_at,
                model.bmc_timestamp,
                value,
            )
            .map_err(|source| TelemetryRepositoryError::Corrupt {
                series_id,
                source: StoredTelemetryError::NonFiniteValue {
                    stored: value,
                    source,
                },
            })?;
            samples.push(sample);
        }
        Ok(samples)
    }

    /// Deletes every sample observed before `observed_at` and rewrites the
    /// affected series' `sample_count` (§14.4 历史保留周期可配置).
    ///
    /// This is the retention-pruning entry point the sampler calls
    /// periodically with the configured retention cut — for example "delete
    /// everything sampled before 90 days ago". The delete and every count
    /// rewrite commit in one transaction, so a crash mid-prune leaves either
    /// the pre-prune state or the fully pruned state, never a sample table
    /// that disagrees with the series metadata.
    ///
    /// The count is recomputed from the surviving rows rather than
    /// decremented by the deleted count, so any drift between the metadata
    /// and the sample table is repaired by the prune itself. A series whose
    /// samples were all pruned keeps its row and reports zero retained
    /// samples: the series identity is stable for the sampler, only the
    /// history is bounded.
    ///
    /// # Errors
    ///
    /// Returns [`TelemetryRepositoryError`] when write coordination fails or
    /// the transaction is refused by `SQLite`.
    pub async fn prune_before(
        &self,
        observed_at: OffsetDateTime,
    ) -> Result<TelemetryPruneSummary, TelemetryRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TelemetryRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        // The series to rewrite must be gathered before the delete: a series
        // whose every sample is pruned has no surviving rows to identify it
        // afterwards.
        let mut affected: Vec<(Uuid,)> = telemetry_sample::Entity::find()
            .select_only()
            .column(telemetry_sample::Column::SeriesId)
            .filter(telemetry_sample::Column::ObservedAt.lt(observed_at))
            .into_tuple()
            .all(&transaction)
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        affected.sort_unstable();
        affected.dedup();
        let deleted = telemetry_sample::Entity::delete_many()
            .filter(telemetry_sample::Column::ObservedAt.lt(observed_at))
            .exec(&transaction)
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        for (series_id,) in &affected {
            // The count is recomputed from the surviving rows, so the prune
            // repairs any drift between the metadata and the sample table.
            let remaining = telemetry_sample::Entity::find()
                .filter(telemetry_sample::Column::SeriesId.eq(*series_id))
                .count(&transaction)
                .await
                .map_err(TelemetryRepositoryError::Database)?;
            let stored_count = i64::try_from(remaining)
                .map_err(|_| TelemetryRepositoryError::SampleCountOutOfRange(remaining))?;
            telemetry_series::Entity::update_many()
                .col_expr(
                    telemetry_series::Column::SampleCount,
                    Expr::value(stored_count),
                )
                .filter(telemetry_series::Column::Id.eq(*series_id))
                .exec(&transaction)
                .await
                .map_err(TelemetryRepositoryError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(TelemetryRepositoryError::Database)?;
        Ok(TelemetryPruneSummary {
            samples_deleted: deleted.rows_affected,
            series_updated: affected.len() as u64,
        })
    }
}

fn map_stored_series(
    model: &telemetry_series::Model,
) -> Result<TelemetrySeries, StoredTelemetryError> {
    let series_key =
        SeriesKey::parse(&model.series_key).map_err(StoredTelemetryError::InvalidSeriesKey)?;
    let sample_count = u64::try_from(model.sample_count)
        .map_err(|_| StoredTelemetryError::NegativeSampleCount(model.sample_count))?;
    Ok(TelemetrySeries::from_parts(
        TelemetrySeriesId::from_uuid(model.id),
        EndpointId::from_uuid(model.endpoint_id),
        series_key,
        sample_count,
    ))
}

fn corrupt(series_id: TelemetrySeriesId, source: StoredTelemetryError) -> TelemetryRepositoryError {
    TelemetryRepositoryError::Corrupt { series_id, source }
}

/// How many samples [`SqliteStore::prune_before`] removed and from how many
/// series, so the caller can log or audit the retention sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryPruneSummary {
    /// The number of sample rows deleted.
    pub samples_deleted: u64,
    /// The number of series whose `sample_count` was recomputed.
    pub series_updated: u64,
}

/// A controlled failure while reading or writing persisted telemetry.
#[derive(Debug, Error)]
pub enum TelemetryRepositoryError {
    #[error("telemetry write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("telemetry series {series_id} does not exist")]
    SeriesNotFound { series_id: TelemetrySeriesId },
    #[error("telemetry series sample count {0} exceeds the persisted range")]
    SampleCountOutOfRange(u64),
    #[error("stored telemetry row for series {series_id} is invalid: {source}")]
    Corrupt {
        series_id: TelemetrySeriesId,
        #[source]
        source: StoredTelemetryError,
    },
    #[error("telemetry database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why a persisted telemetry row cannot be mapped into a valid domain value.
#[derive(Debug, Error)]
pub enum StoredTelemetryError {
    #[error("stored telemetry sample value is not a finite number ({stored}): {source}")]
    NonFiniteValue {
        stored: f64,
        #[source]
        source: NonFiniteSampleValue,
    },
    #[error("stored telemetry series key is invalid: {0}")]
    InvalidSeriesKey(#[source] SeriesKeyError),
    #[error("stored telemetry series sample count is negative: {0}")]
    NegativeSampleCount(i64),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{EndpointId, SeriesKey, TelemetrySample};
    use sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, EntityTrait, IntoActiveModel,
        PaginatorTrait, QueryFilter, Set,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    /// Upserts a series, appends the given readings to it, and re-upserts so
    /// the returned series reflects the maintained `sample_count`.
    async fn series_with_samples(
        store: &SqliteStore,
        endpoint_id: EndpointId,
        key: &str,
        readings: &[(OffsetDateTime, f64)],
    ) -> Result<TelemetrySeries, Box<dyn Error>> {
        let series = store
            .upsert_series(endpoint_id, SeriesKey::parse(key)?)
            .await?;
        for (observed_at, value) in readings {
            store
                .append_sample(&TelemetrySample::new(series.id(), *observed_at, *value)?)
                .await?;
        }
        store
            .upsert_series(endpoint_id, series.series_key().clone())
            .await
            .map_err(Into::into)
    }

    #[tokio::test]
    async fn upsert_series_is_idempotent_and_scoped_to_the_endpoint() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let key = SeriesKey::parse("PowerMetrics/PowerConsumedWatts")?;

        let first = store.upsert_series(endpoint_id, key.clone()).await?;
        let second = store.upsert_series(endpoint_id, key.clone()).await?;
        assert_eq!(
            first.id(),
            second.id(),
            "the same key on the same endpoint is one series"
        );
        assert_eq!(first.series_key(), &key);
        assert_eq!(first.sample_count(), 0);

        // The same key on a different endpoint is a different series.
        let other_endpoint = store
            .upsert_series(EndpointId::generate(), key.clone())
            .await?;
        assert_ne!(first.id(), other_endpoint.id());

        // An upsert after appends returns the maintained count unchanged.
        store
            .append_sample(&TelemetrySample::new(
                first.id(),
                OffsetDateTime::now_utc(),
                1.5,
            )?)
            .await?;
        let third = store.upsert_series(endpoint_id, key).await?;
        assert_eq!(third.id(), first.id());
        assert_eq!(third.sample_count(), 1);

        let listed = store.list_series(endpoint_id).await?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id(), first.id());
        assert_eq!(
            store.list_series(other_endpoint.endpoint_id()).await?.len(),
            1
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    // The compared constants are exactly representable in binary64 and the
    // values round-trip bit-identically through SQLite REAL, so `==` here is
    // precise, not approximate.
    #[allow(clippy::float_cmp)]
    #[tokio::test]
    async fn appends_are_counted_and_listings_are_bounded_newest_first()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let readings = [
            (base - Duration::seconds(4), 10.0),
            (base - Duration::seconds(3), 11.0),
            (base - Duration::seconds(2), 12.0),
            (base - Duration::seconds(1), 13.0),
            (base, 14.0),
        ];
        let series = series_with_samples(
            &store,
            EndpointId::generate(),
            "PowerMetrics/PowerConsumedWatts",
            &readings,
        )
        .await?;
        assert_eq!(series.sample_count(), 5);

        let stored = store
            .upsert_series(series.endpoint_id(), series.series_key().clone())
            .await?;
        assert_eq!(
            stored.sample_count(),
            5,
            "the persisted count must track the appends"
        );

        let recent = store.list_samples(series.id(), 3).await?;
        assert_eq!(recent.len(), 3, "the listing must respect the limit");
        assert_eq!(
            recent
                .iter()
                .map(TelemetrySample::observed_at)
                .collect::<Vec<_>>(),
            vec![
                base,
                base - Duration::seconds(1),
                base - Duration::seconds(2)
            ],
            "the newest readings must come first"
        );
        assert_eq!(recent[0].value(), 14.0);
        assert_eq!(
            store.list_samples(series.id(), 0).await?.len(),
            0,
            "a zero limit must return an empty listing"
        );
        assert_eq!(
            store.list_samples(series.id(), 100).await?.len(),
            readings.len(),
            "a limit above the table size must return every reading"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn appending_to_an_unknown_series_is_refused() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let series_id = TelemetrySeriesId::generate();
        let sample = TelemetrySample::new(series_id, OffsetDateTime::now_utc(), 1.0)?;

        assert!(matches!(
            store.append_sample(&sample).await,
            Err(TelemetryRepositoryError::SeriesNotFound { series_id: id }) if id == series_id
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn non_finite_readings_are_refused_everywhere() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let series = series_with_samples(
            &store,
            EndpointId::generate(),
            "PowerMetrics/PowerConsumedWatts",
            &[],
        )
        .await?;
        let observed_at = OffsetDateTime::now_utc();

        // The domain refuses NaN and infinity at construction (§7.6 不伪装),
        // so they never reach the persistence layer.
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert!(matches!(
                TelemetrySample::new(series.id(), observed_at, value),
                Err(NonFiniteSampleValue)
            ));
        }

        // A stored infinite reading — which SQLite happily accepts — is
        // corrupt on read, exactly like the stored-severity precedent: it
        // must be surfaced, never silently dropped from a listing.
        telemetry_sample::ActiveModel {
            series_id: Set(series.id().into_uuid()),
            observed_at: Set(observed_at),
            bmc_timestamp: Set(None),
            value: Set(f64::INFINITY),
            ..Default::default()
        }
        .insert(&store.database)
        .await?;
        assert!(matches!(
            store.list_samples(series.id(), 10).await,
            Err(TelemetryRepositoryError::Corrupt {
                source: StoredTelemetryError::NonFiniteValue { stored, .. },
                ..
            }) if stored.is_infinite()
        ));

        // SQLite itself refuses NaN: it stores NaN as NULL, which the
        // NOT NULL column rejects.
        let nan_insert = telemetry_sample::ActiveModel {
            series_id: Set(series.id().into_uuid()),
            observed_at: Set(observed_at),
            bmc_timestamp: Set(None),
            value: Set(f64::NAN),
            ..Default::default()
        }
        .insert(&store.database)
        .await;
        assert!(
            nan_insert.is_err(),
            "SQLite stores NaN as NULL, which NOT NULL must refuse"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_bmc_timestamp_round_trips_with_its_sample() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let series = series_with_samples(
            &store,
            EndpointId::generate(),
            "PowerMetrics/PowerConsumedWatts",
            &[],
        )
        .await?;
        let observed_at = OffsetDateTime::now_utc();
        let bmc_reported = observed_at - Duration::MINUTE;

        let with_bmc =
            TelemetrySample::new(series.id(), observed_at, 42.0)?.with_bmc_timestamp(bmc_reported);
        store.append_sample(&with_bmc).await?;
        let without_bmc = TelemetrySample::new(series.id(), observed_at, 43.0)?;
        store.append_sample(&without_bmc).await?;

        let listed = store.list_samples(series.id(), 10).await?;
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0], without_bmc);
        assert_eq!(listed[1], with_bmc);
        assert_eq!(listed[1].bmc_timestamp(), Some(bmc_reported));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_series_cascades_its_samples() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let series = series_with_samples(
            &store,
            endpoint_id,
            "PowerMetrics/PowerConsumedWatts",
            &[(OffsetDateTime::now_utc(), 1.0)],
        )
        .await?;

        let deleted = telemetry_series::Entity::delete_by_id(series.id().into_uuid())
            .exec(&store.database)
            .await?;
        assert_eq!(deleted.rows_affected, 1);

        let remaining = telemetry_sample::Entity::find()
            .filter(telemetry_sample::Column::SeriesId.eq(series.id().into_uuid()))
            .count(&store.database)
            .await?;
        assert_eq!(
            remaining, 0,
            "the FK cascade must remove the samples with the series"
        );
        assert_eq!(store.list_samples(series.id(), 10).await?.len(), 0);
        assert!(store.list_series(endpoint_id).await?.is_empty());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    // The compared constants are exactly representable in binary64 and the
    // values round-trip bit-identically through SQLite REAL, so `==` here is
    // precise, not approximate.
    #[allow(clippy::float_cmp)]
    #[tokio::test]
    async fn prune_removes_old_samples_and_rewrites_the_series_counts() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let cutoff = OffsetDateTime::now_utc();
        let old = [
            (cutoff - Duration::days(3), 1.0),
            (cutoff - Duration::days(2), 2.0),
            (cutoff - Duration::days(1), 3.0),
        ];
        let fresh = [
            (cutoff + Duration::hours(1), 4.0),
            (cutoff + Duration::hours(2), 5.0),
        ];
        let mut retained_readings = old.to_vec();
        retained_readings.extend_from_slice(&fresh);
        let retained = series_with_samples(
            &store,
            endpoint_id,
            "PowerMetrics/PowerConsumedWatts",
            &retained_readings,
        )
        .await?;
        let drained = series_with_samples(
            &store,
            endpoint_id,
            "ThermalMetrics/Temperature",
            &[(cutoff - Duration::days(4), 40.0)],
        )
        .await?;

        let summary = store.prune_before(cutoff).await?;
        assert_eq!(summary.samples_deleted, 4);
        assert_eq!(summary.series_updated, 2);

        let listed = store.list_samples(retained.id(), 10).await?;
        assert_eq!(listed.len(), 2, "only the fresh readings must survive");
        assert_eq!(listed[0].value(), 5.0);
        assert_eq!(listed[1].value(), 4.0);
        assert_eq!(store.list_samples(drained.id(), 10).await?.len(), 0);

        let stored = store
            .upsert_series(endpoint_id, retained.series_key().clone())
            .await?;
        assert_eq!(
            stored.sample_count(),
            2,
            "prune must rewrite the retained count"
        );
        let stored = store
            .upsert_series(endpoint_id, drained.series_key().clone())
            .await?;
        assert_eq!(
            stored.sample_count(),
            0,
            "a fully drained series reports zero retained samples"
        );

        // A cutoff before every retained reading deletes nothing: the
        // history is already within the retention window.
        let no_op = store.prune_before(cutoff - Duration::days(30)).await?;
        assert_eq!(no_op.samples_deleted, 0);
        assert_eq!(no_op.series_updated, 0);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn a_stored_negative_sample_count_is_corrupt() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let series = store
            .upsert_series(
                endpoint_id,
                SeriesKey::parse("PowerMetrics/PowerConsumedWatts")?,
            )
            .await?;

        // The `ck_telemetry_series_sample_count` CHECK refuses a negative
        // count, so the corrupt row is written on a dedicated
        // single-connection writer with check constraints ignored — exactly
        // what a newer build's row looks like to this build, the upgrade
        // order discipline documented on `find_operation`. One connection
        // executes both the pragma and the update, so the bypass is
        // deterministic.
        let database_path = store.database_path();
        let normalized_path = database_path.to_string_lossy().replace('\\', "/");
        let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
        options.max_connections(1);
        options.sqlx_logging(false);
        let writer = Database::connect(options).await?;
        writer
            .execute_unprepared("PRAGMA ignore_check_constraints = ON")
            .await?;
        let mut stored = telemetry_series::Entity::find_by_id(series.id().into_uuid())
            .one(&writer)
            .await?
            .ok_or("inserted series is missing")?
            .into_active_model();
        stored.sample_count = Set(-1_i64);
        stored.update(&writer).await?;
        writer.close().await?;

        assert!(matches!(
            store.list_series(endpoint_id).await,
            Err(TelemetryRepositoryError::Corrupt {
                series_id: id,
                source: StoredTelemetryError::NegativeSampleCount(-1),
            }) if id == series.id()
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
