use std::error::Error;

use rutilus_entity::{telemetry_sample, telemetry_series};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const TELEMETRY_TABLES: [&str; 2] = ["telemetry_series", "telemetry_samples"];

#[tokio::test]
async fn telemetry_migration_preserves_identity_and_retention_invariants()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_telemetry_tables(&database, true).await?;

    let observed_at = OffsetDateTime::now_utc();
    verify_telemetry_constraints(&database, observed_at).await?;

    Migrator::down(&database, None).await?;
    assert_telemetry_tables(&database, false).await?;

    Ok(())
}

// Every §14.4 constraint is spelled out as its own insert-and-assert so a
// failure pinpoints the exact rule (the unique series key, the negative
// count CHECK, the sample FK and cascade, and the NaN refusal), which
// exceeds the pedantic line budget; the domain and persistence crates allow
// the same lint on their exhaustive assertion tests.
// The stored value is compared with `==` on purpose: SQLite REAL and f64
// are the same binary64 format and the constant is exactly representable,
// so the round-trip equality is exact, not approximate.
#[allow(clippy::float_cmp)]
#[allow(clippy::too_many_lines)]
async fn verify_telemetry_constraints(
    database: &DatabaseConnection,
    observed_at: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let endpoint_id = Uuid::now_v7();
    let series_key = String::from("PowerMetrics/PowerConsumedWatts");

    let series_id = Uuid::now_v7();
    telemetry_series::ActiveModel {
        id: Set(series_id),
        endpoint_id: Set(endpoint_id),
        series_key: Set(series_key.clone()),
        sample_count: Set(0),
    }
    .insert(database)
    .await?;
    let stored = telemetry_series::Entity::find_by_id(series_id)
        .one(database)
        .await?
        .ok_or("inserted series is missing")?;
    assert_eq!(stored.endpoint_id, endpoint_id);
    assert_eq!(stored.series_key, series_key);
    assert_eq!(stored.sample_count, 0);

    // The find-or-create key: the same endpoint with the same series key
    // keeps only one row — the second insert must be refused by the unique
    // index. A different endpoint is a different series.
    let duplicate = telemetry_series::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        series_key: Set(series_key.clone()),
        sample_count: Set(0),
    }
    .insert(database)
    .await;
    assert!(
        duplicate.is_err(),
        "the same (endpoint_id, series_key) must be refused as a duplicate"
    );

    let other_endpoint = telemetry_series::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(Uuid::now_v7()),
        series_key: Set(series_key.clone()),
        sample_count: Set(0),
    }
    .insert(database)
    .await;
    assert!(
        other_endpoint.is_ok(),
        "a different endpoint is a new series"
    );

    // A negative sample count is corruption and must be refused by the
    // CHECK constraint, so the metadata can never silently disagree with
    // the samples it describes.
    let negative_count = telemetry_series::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        series_key: Set(String::from("ThermalMetrics/Temperature")),
        sample_count: Set(-1),
    }
    .insert(database)
    .await;
    assert!(
        negative_count.is_err(),
        "a negative sample count must be refused"
    );

    // Samples round-trip their reading exactly as SQLite REAL stores it,
    // with the optional BMC timestamp preserved beside the product clock.
    telemetry_sample::ActiveModel {
        series_id: Set(series_id),
        observed_at: Set(observed_at),
        bmc_timestamp: Set(Some(observed_at - time::Duration::MINUTE)),
        value: Set(42.5),
        ..Default::default()
    }
    .insert(database)
    .await?;
    let reading = telemetry_sample::Entity::find()
        .filter(telemetry_sample::Column::SeriesId.eq(series_id))
        .one(database)
        .await?
        .ok_or("inserted sample is missing")?;
    assert_eq!(reading.series_id, series_id);
    assert_eq!(reading.observed_at, observed_at);
    assert_eq!(
        reading.bmc_timestamp,
        Some(observed_at - time::Duration::MINUTE)
    );
    assert_eq!(reading.value, 42.5);

    // The BMC timestamp is optional: a reading without one stores NULL.
    telemetry_sample::ActiveModel {
        series_id: Set(series_id),
        observed_at: Set(observed_at),
        bmc_timestamp: Set(None),
        value: Set(1.0),
        ..Default::default()
    }
    .insert(database)
    .await?;
    let without_bmc = telemetry_sample::Entity::find()
        .filter(telemetry_sample::Column::SeriesId.eq(series_id))
        .filter(telemetry_sample::Column::BmcTimestamp.is_null())
        .one(database)
        .await?
        .ok_or("inserted sample is missing")?;
    assert_eq!(without_bmc.bmc_timestamp, None);

    // A sample must name an existing series: the foreign key refuses an
    // orphan row even when the domain never would have produced one.
    let orphan = telemetry_sample::ActiveModel {
        series_id: Set(Uuid::now_v7()),
        observed_at: Set(observed_at),
        value: Set(1.0),
        ..Default::default()
    }
    .insert(database)
    .await;
    assert!(orphan.is_err(), "a sample must name an existing series");

    // §7.6 不伪装 at the storage layer: SQLite stores NaN as NULL, so the
    // NOT NULL column refuses a NaN reading that the domain would also
    // have refused.
    let nan_reading = telemetry_sample::ActiveModel {
        series_id: Set(series_id),
        observed_at: Set(observed_at),
        value: Set(f64::NAN),
        ..Default::default()
    }
    .insert(database)
    .await;
    assert!(
        nan_reading.is_err(),
        "SQLite stores NaN as NULL, which NOT NULL must refuse"
    );

    // ON DELETE CASCADE: deleting the series removes its samples with it,
    // atomically — the sampler's "stop tracking" gesture never leaks rows.
    let deleted = telemetry_series::Entity::delete_by_id(series_id)
        .exec(database)
        .await?;
    assert_eq!(deleted.rows_affected, 1);
    let remaining = telemetry_sample::Entity::find()
        .filter(telemetry_sample::Column::SeriesId.eq(series_id))
        .count(database)
        .await?;
    assert_eq!(remaining, 0, "deleting the series must cascade its samples");

    Ok(())
}

async fn assert_telemetry_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in TELEMETRY_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}
