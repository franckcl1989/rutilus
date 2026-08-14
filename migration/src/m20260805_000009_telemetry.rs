use sea_orm_migration::prelude::*;

/// The `telemetry_series` and `telemetry_samples` tables from design §9.3
/// 事件和遥测, added with the telemetry milestone (design §14.4 Telemetry).
///
/// A series is one metric value of one `MetricReport` of one endpoint; the
/// samples are the scalar readings the product's sampler takes — the
/// current value and bounded history of §14.4, not a general-purpose
/// time-series database. The unique index on `(endpoint_id, series_key)` is
/// the find-or-create key of the persistence `upsert_series`; the foreign
/// key on `telemetry_samples.series_id` with `ON DELETE CASCADE` ties the
/// history to its series; and the composite index on
/// `(series_id, observed_at)` keeps the bounded newest-first listing and
/// the retention cleanup narrow per series.
///
/// `endpoint_id` deliberately has no foreign key, mirroring `events`
/// (000008): a series row — and with it the retained history — must outlive
/// its endpoint; the retention policy bounds the history, not endpoint
/// deletion.
///
/// `value` is stored with `SQLite` REAL affinity (`double`) and `NOT NULL`:
/// `SQLite` stores NaN as NULL, so a NaN reading is refused by the database,
/// while infinities are accepted by `SQLite` and refused by the domain
/// constructor on the way in (§7.6 不伪装) and re-validated on read.
///
/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default (W9-D-1: the
/// W8-D-1 defect's third recurrence surface). `up` runs four statements (two
/// `CREATE TABLE`s, two `CREATE INDEX`es) and `down` two `DROP TABLE`s that
/// `SQLite` would otherwise auto-commit one by one: a crash between them
/// would leave the migration half-applied while it still records as applied,
/// and the retried run would then fail — `up` with "table already exists"
/// (no `IF NOT EXISTS`), `down` with "no such table" forever, blocking the
/// whole rollback chain. These statements are all legal `SQLite` DDL inside a
/// transaction, so the override costs nothing but the crash-resume guarantee
/// — the same discipline the `m20260814_000003` slice (W8-D-1) and the
/// rebuild migrations already follow.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(TelemetrySeries::Table)
                    .col(
                        ColumnDef::new(TelemetrySeries::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    // Series source, captured without a foreign key so the
                    // record survives endpoint deletion (see the module doc).
                    .col(
                        ColumnDef::new(TelemetrySeries::EndpointId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(TelemetrySeries::SeriesKey).text().not_null())
                    .col(
                        ColumnDef::new(TelemetrySeries::SampleCount)
                            .big_integer()
                            .not_null(),
                    )
                    // The sample count is metadata over the samples table; a
                    // negative value is corruption, refused here and
                    // re-validated on read, so the metadata never silently
                    // disagrees with the rows it describes.
                    .check((
                        "ck_telemetry_series_sample_count",
                        Expr::col(TelemetrySeries::SampleCount).gte(0),
                    ))
                    .to_owned(),
            )
            .await?;

        // The find-or-create key of `upsert_series`: the same endpoint
        // sampling the same metric keeps only one series row. The unique
        // index makes the idempotent upsert atomic — a racing duplicate is
        // refused by the database, never double-inserted by a
        // check-then-insert race.
        manager
            .create_index(
                Index::create()
                    .name("uq_telemetry_series_endpoint_key")
                    .table(TelemetrySeries::Table)
                    .col(TelemetrySeries::EndpointId)
                    .col(TelemetrySeries::SeriesKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(TelemetrySamples::Table)
                    .col(
                        ColumnDef::new(TelemetrySamples::Id)
                            .big_integer()
                            .not_null()
                            .auto_increment()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(TelemetrySamples::SeriesId).uuid().not_null())
                    .col(
                        ColumnDef::new(TelemetrySamples::ObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // The BMC's own `MetricValue.Timestamp` when the source
                    // reported one: display metadata beside the product
                    // clock, never an ordering or retention key (the events
                    // 000008 precedent of keeping both clocks).
                    .col(ColumnDef::new(TelemetrySamples::BmcTimestamp).timestamp_with_time_zone())
                    // `double` renders as REAL on SQLite (FLOAT/DOUBLE/REAL
                    // all get REAL affinity), so readings round-trip as f64.
                    .col(ColumnDef::new(TelemetrySamples::Value).double().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_telemetry_samples_series")
                            .from(TelemetrySamples::Table, TelemetrySamples::SeriesId)
                            .to(TelemetrySeries::Table, TelemetrySeries::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // The bounded newest-first listing (`list_samples`) and the
        // retention cleanup (`prune_before`) both range over one series'
        // samples by observed time; this index keeps those scans narrow
        // instead of touching the whole samples table.
        manager
            .create_index(
                Index::create()
                    .name("ix_telemetry_samples_series_observed_at")
                    .table(TelemetrySamples::Table)
                    .col(TelemetrySamples::SeriesId)
                    .col(TelemetrySamples::ObservedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // The samples table first: its foreign key names the series table,
        // which must exist until every dependent table is gone.
        manager
            .drop_table(Table::drop().table(TelemetrySamples::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(TelemetrySeries::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum TelemetrySeries {
    #[sea_orm(iden = "telemetry_series")]
    Table,
    Id,
    EndpointId,
    SeriesKey,
    SampleCount,
}

#[derive(DeriveIden)]
enum TelemetrySamples {
    #[sea_orm(iden = "telemetry_samples")]
    Table,
    Id,
    SeriesId,
    ObservedAt,
    BmcTimestamp,
    Value,
}
