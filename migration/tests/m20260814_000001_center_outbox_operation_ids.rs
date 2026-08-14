use std::error::Error;

use rutilus_entity::{center_outbox, instance};
use rutilus_migration::Migrator;
use sea_orm::sea_query::{Alias, Expr, Query};
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, Set,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const CENTER_OUTBOX_OPERATION_IDS_MIGRATION: &str = "m20260814_000001_center_outbox_operation_ids";

/// The `operation_id` column and its index round-trip through the
/// migration's `up` and `down`, with the envelope rows surviving both
/// directions.
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits atomically on `SQLite`: `down`
/// runs two statements (the index drop, then the column drop) that would
/// otherwise auto-commit one by one, and a crash between them would leave
/// the index gone with the migration still recorded as applied — the
/// retried `down` would fail with "no such index" forever. The round trip
/// below exercises the restart path from a consistent schema in both
/// directions (the crash itself cannot be injected through the framework;
/// the atomicity it pins is what the `use_transaction` override provides).
#[tokio::test]
async fn operation_id_column_and_index_round_trip_with_data_preserved() -> Result<(), Box<dyn Error>>
{
    let (directory, database) = connect().await?;

    // Apply every migration registered before (and including) the
    // center-outbox one: `center_outbox` itself is created by the
    // center-tables slice. The step count derives from the live
    // registration list, so later slices cannot drift the test.
    let steps = migrations_through(CENTER_OUTBOX_OPERATION_IDS_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;

    // Up: the column and the index exist.
    assert!(
        center_outbox_has_column(&database, "operation_id").await?,
        "the up must add the operation_id column"
    );
    assert!(
        index_exists(&database, "ix_center_outbox_instance_operation").await?,
        "the up must create the directed-read index"
    );

    // Seed one envelope and one site instance (the outbox row's foreign key
    // names the instance), so the down below runs against real data.
    let now = OffsetDateTime::now_utc();
    let instance_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(instance_id),
        display_name: Set(String::from("Site One")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let row_id = Uuid::now_v7();
    let operation_id = Uuid::now_v7();
    center_outbox::ActiveModel {
        id: Set(row_id),
        sequence: Set(1),
        instance_id: Set(instance_id),
        payload_json: Set(String::from(
            "RUTC1:0000000000000000000000000000000000000000000000000000000000000000",
        )),
        state: Set(String::from("pending")),
        retry_count: Set(0),
        created_at: Set(now),
        acked_at: Set(None),
        operation_id: Set(Some(operation_id)),
    }
    .insert(&database)
    .await?;

    // Down: exactly this migration rolls back. The index drop and the
    // column drop commit as one unit, so a retried `down` after a crash
    // between them starts from an intact schema instead of failing with
    // "no such index" forever.
    let rollback = rollback_steps_to(CENTER_OUTBOX_OPERATION_IDS_MIGRATION)?;
    Migrator::down(&database, Some(rollback)).await?;
    assert!(
        !index_exists(&database, "ix_center_outbox_instance_operation").await?,
        "the down must drop the index"
    );
    assert!(
        !center_outbox_has_column(&database, "operation_id").await?,
        "the down must drop the column"
    );
    assert_eq!(
        center_outbox_row_count(&database).await?,
        1,
        "the envelope row must survive the down"
    );

    // Up again (the up -> down -> up round trip): the column and the index
    // come back, and the surviving row is untouched — the re-added derived
    // column reads NULL for it.
    Migrator::up(&database, Some(steps)).await?;
    assert!(
        center_outbox_has_column(&database, "operation_id").await?,
        "the re-applied up must add the column again"
    );
    assert!(
        index_exists(&database, "ix_center_outbox_instance_operation").await?,
        "the re-applied up must create the index again"
    );
    assert_eq!(
        center_outbox_row_count(&database).await?,
        1,
        "the round trip must not touch the data"
    );

    drop(database);
    drop(directory);
    Ok(())
}

/// The registration position of the named migration.
fn registration_position(name: &str) -> Result<usize, Box<dyn Error>> {
    Migrator::migrations()
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or_else(|| format!("migration {name} is not registered").into())
}

/// The number of registered migrations through (and including) the named
/// migration.
fn migrations_through(name: &str) -> Result<u32, Box<dyn Error>> {
    Ok(u32::try_from(registration_position(name)? + 1)?)
}

/// The count of applied migrations a rollback must undo to reach the named
/// migration: the framework's `down(Some(n))` rolls back the n newest
/// applied migrations, so the count is the registration tail after the
/// migration — the down-side twin of [`migrations_through`].
fn rollback_steps_to(name: &str) -> Result<u32, Box<dyn Error>> {
    let position = registration_position(name)?;
    Ok(u32::try_from(Migrator::migrations().len() - position)?)
}

/// Whether the live schema has an index with the given name.
async fn index_exists(database: &DatabaseConnection, name: &str) -> Result<bool, Box<dyn Error>> {
    let statement = Query::select()
        .expr(Expr::cust("name"))
        .from(Alias::new("sqlite_master"))
        .cond_where(Expr::cust(format!("type = 'index' AND name = '{name}'")))
        .to_owned();
    Ok(database.query_one(&statement).await?.is_some())
}

/// Whether the live `center_outbox` table DDL names the given column.
async fn center_outbox_has_column(
    database: &DatabaseConnection,
    column: &str,
) -> Result<bool, Box<dyn Error>> {
    let ddl = table_ddl(database, "center_outbox").await?;
    Ok(ddl
        .split_whitespace()
        .any(|word| word.trim_matches('"') == column))
}

/// The `sql` DDL of one table, read from `sqlite_master`.
async fn table_ddl(database: &DatabaseConnection, table: &str) -> Result<String, Box<dyn Error>> {
    let statement = Query::select()
        .expr(Expr::cust("sql"))
        .from(Alias::new("sqlite_master"))
        .cond_where(Expr::cust(format!("type = 'table' AND name = '{table}'")))
        .to_owned();
    let row = database
        .query_one(&statement)
        .await?
        .ok_or_else(|| format!("{table} is not in the live schema"))?;
    Ok(row.try_get_by_index(0)?)
}

/// The number of `center_outbox` rows — the data-preservation probe, read
/// through raw SQL because the entity model names the `operation_id` column
/// the rolled-back table no longer has.
async fn center_outbox_row_count(database: &DatabaseConnection) -> Result<i64, Box<dyn Error>> {
    let statement = Query::select()
        .expr(Expr::cust("COUNT(*) AS row_count"))
        .from(Alias::new("center_outbox"))
        .to_owned();
    let row = database
        .query_one(&statement)
        .await?
        .ok_or_else(|| "center_outbox is not in the live schema".to_owned())?;
    Ok(row.try_get_by_index(0)?)
}

/// Opens one database in a fresh temporary directory.
///
/// The `TempDir` is returned with the connection so it outlives `connect`:
/// dropping it here would unlink the database file while the pool's eager
/// connection still holds it open (the migration tests' shared harness
/// convention).
async fn connect() -> Result<(tempfile::TempDir, DatabaseConnection), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;
    Ok((directory, database))
}
