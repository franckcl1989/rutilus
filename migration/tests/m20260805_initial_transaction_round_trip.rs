//! Round-trip pins for the W9-D-1 fix: the ten oldest multi-statement
//! migrations (`m20260805_000001` through `m20260805_000011`) now override
//! [`MigrationTrait::use_transaction`] so their whole `up` — and the
//! symmetric `down` — commits as one unit on `SQLite`, where the
//! sea-orm-migration runner wraps only `Postgres` by default. Without the
//! override each statement auto-commits one by one, and a crash between two
//! of them leaves the migration half-applied while it still records as
//! applied: the retried run then fails forever — `up` with "table already
//! exists" (no `IF NOT EXISTS`), `down` with "no such table" — blocking the
//! whole rollback chain. The atomicity itself cannot be crash-injected
//! through the framework; what the round trips below pin is the restart path
//! from a consistent schema in both directions, the same shape as the
//! `m20260814_000003_center_outbox_operation_lookup` test.
//!
//! Three representative migrations get the up → down → up round trip:
//! `000001` (the largest — eleven `up` statements and the seven-statement
//! `down` with its `credentials.active_version_id` NULL-out `UPDATE`),
//! `000010` (seven statements across four linked tables), and `000011` (the
//! raw `ALTER TABLE` follow-up whose `down` keeps the `operations` rows —
//! the only one of the ten where `down` preserves data, so it carries the
//! only true data-preservation assertion). The remaining seven migrations
//! (`000003`..`000009`) share the same single-file statement mix and the
//! same override, and every registered migration's `up` and `down` already
//! runs end to end in the full-chain tests (for example
//! `migrations_preserve_storage_invariants`), so the sampling is deliberate:
//! the round trips cover the shapes the full chain cannot isolate — the
//! biggest slice, the widest table group, and the raw-SQL follow-up.
//!
//! The seed rows are written with raw `INSERT` statements instead of the
//! entity models on purpose: the entities model the *current* schema, which
//! carries columns later migrations add (`endpoints.site_id`/`health`,
//! `operations.failure_kind`, ...) that do not exist at the migration points
//! exercised here. Naming the exact 00000X column sets is part of what the
//! round trip verifies.

use std::error::Error;

use rutilus_migration::Migrator;
use sea_orm::sea_query::{Alias, Expr, Query};
use sea_orm::{ConnectOptions, ConnectionTrait, Database, DatabaseConnection};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use uuid::Uuid;

const INITIAL_STORAGE_MIGRATION: &str = "m20260805_000001_initial_storage";
const GROUPS_TAGS_MIGRATION: &str = "m20260805_000010_groups_tags";
const BATCH_OPERATIONS_MIGRATION: &str = "m20260805_000011_batch_operations";

/// The six tables the initial-storage slice creates (000001).
const INITIAL_STORAGE_TABLES: [&str; 6] = [
    "credentials",
    "credential_versions",
    "endpoints",
    "endpoint_addresses",
    "endpoint_trust",
    "endpoint_credentials",
];

/// The four tables the groups-and-tags slice creates (000010).
const GROUPS_TAGS_TABLES: [&str; 4] = ["groups", "group_members", "tags", "endpoint_tags"];

/// A timestamp literal accepted by the `timestamp_with_time_zone` (TEXT)
/// columns; the round trip never reads the values back, only counts rows.
const TS: &str = "2026-08-14T00:00:00Z";

/// A payload literal in the `RUTC1:` ciphertext envelope shape (§9.4), never
/// deserialized by this test.
const ENVELOPE: &str = "RUTC1:0000000000000000000000000000000000000000000000000000000000000000";

/// The largest slice round-trips: `up` creates all six tables, `down` drops
/// them (running the `credentials.active_version_id` NULL-out `UPDATE` that
/// unblocks the `credential_versions` drop under `ON DELETE RESTRICT`
/// against the seeded rows), and the re-applied `up` runs from an intact
/// schema — the restart path after a crash between two auto-committed
/// statements, which would otherwise fail with "table already exists".
#[tokio::test]
async fn initial_storage_transaction_round_trip() -> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;

    // Apply exactly the first registered migration. The step count derives
    // from the live registration list, so later slices cannot drift it.
    let steps = migrations_through(INITIAL_STORAGE_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    for table in INITIAL_STORAGE_TABLES {
        assert!(has_table(&database, table).await?, "up must create {table}");
    }
    assert!(
        index_exists(&database, "uq_credentials_name").await?,
        "the up must create the credentials name index"
    );

    // Seed one row per table, including the credential → version reference
    // the down's NULL-out UPDATE must clear before the version table drops.
    seed_initial_storage_rows(&database, String::from(TS)).await?;

    // Down: exactly the first migration rolls back, as one unit.
    Migrator::down(&database, Some(1)).await?;
    for table in INITIAL_STORAGE_TABLES {
        assert!(
            !has_table(&database, table).await?,
            "down must drop {table}"
        );
    }
    assert!(
        !index_exists(&database, "uq_credentials_name").await?,
        "the down must drop the credentials name index with its table"
    );

    // Up again: the whole slice comes back with no leftover rows — a crash
    // between two auto-committed statements would have left the first tables
    // behind and the re-run would have failed here.
    Migrator::up(&database, Some(steps)).await?;
    for table in INITIAL_STORAGE_TABLES {
        assert!(
            has_table(&database, table).await?,
            "re-up must create {table}"
        );
        assert_eq!(
            row_count(&database, table).await?,
            0,
            "the round trip must not leave rows behind in {table}"
        );
    }

    drop(database);
    drop(directory);
    Ok(())
}

/// The widest table group round-trips: four tables with the
/// group→membership and tag→binding foreign keys, plus the three indexes,
/// all coming back identically after the rollback.
#[tokio::test]
async fn groups_tags_transaction_round_trip() -> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;

    let steps = migrations_through(GROUPS_TAGS_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    for table in GROUPS_TAGS_TABLES {
        assert!(has_table(&database, table).await?, "up must create {table}");
    }
    assert!(
        index_exists(&database, "uq_groups_name").await?,
        "the up must create the groups name index"
    );

    // Seed one group, one membership, one tag, and one binding.
    let now = String::from(TS);
    let group_id = Uuid::now_v7();
    let tag_id = Uuid::now_v7();
    let endpoint_id = Uuid::now_v7();
    database
        .execute_unprepared(&format!(
            "INSERT INTO groups (id, name, created_at, updated_at) \
             VALUES ('{group_id}', 'Lab Racks', '{now}', '{now}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO group_members (group_id, endpoint_id) \
             VALUES ('{group_id}', '{endpoint_id}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO tags (id, name) VALUES ('{tag_id}', 'maintenance')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO endpoint_tags (tag_id, endpoint_id) \
             VALUES ('{tag_id}', '{endpoint_id}')"
        ))
        .await?;

    // Down: exactly the groups-and-tags migration rolls back.
    Migrator::down(&database, Some(1)).await?;
    for table in GROUPS_TAGS_TABLES {
        assert!(
            !has_table(&database, table).await?,
            "down must drop {table}"
        );
    }
    assert!(
        !index_exists(&database, "uq_groups_name").await?,
        "the down must drop the groups name index with its table"
    );

    // Up again: the four tables and the index come back clean.
    Migrator::up(&database, Some(steps)).await?;
    for table in GROUPS_TAGS_TABLES {
        assert!(
            has_table(&database, table).await?,
            "re-up must create {table}"
        );
        assert_eq!(
            row_count(&database, table).await?,
            0,
            "the round trip must not leave rows behind in {table}"
        );
    }
    assert!(
        index_exists(&database, "uq_groups_name").await?,
        "the re-applied up must create the groups name index again"
    );

    drop(database);
    drop(directory);
    Ok(())
}

/// The raw-`ALTER TABLE` follow-up round-trips with a real data-preservation
/// assertion: the migration's `down` drops the `batch_id` column and the
/// `batch_operations` parent, but the child `operations` rows survive —
/// exactly the row set a crash-retried rollback must not lose.
#[tokio::test]
async fn batch_operations_transaction_round_trip() -> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;

    let steps = migrations_through(BATCH_OPERATIONS_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    assert!(
        has_table(&database, "batch_operations").await?,
        "the up must create batch_operations"
    );
    assert!(
        column_exists(&database, "operations", "batch_id").await?,
        "the up must add the operations.batch_id child link"
    );
    assert!(
        index_exists(&database, "ix_operations_batch_id").await?,
        "the up must create the batch id index"
    );

    // Seed the batch parent and one child operation carrying the link.
    let now = String::from(TS);
    let batch_id = Uuid::now_v7();
    let operation_id = Uuid::now_v7();
    database
        .execute_unprepared(&format!(
            "INSERT INTO batch_operations (id, source, command, created_at) \
             VALUES ('{batch_id}', 'standalone', '{ENVELOPE}', '{now}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO operations (id, source, state, command, created_at, updated_at, batch_id) \
             VALUES ('{operation_id}', 'standalone', 'queued', '{ENVELOPE}', '{now}', '{now}', \
             '{batch_id}')"
        ))
        .await?;

    // Down: exactly the batch-operations migration rolls back; the child
    // operation row must survive the column drop.
    Migrator::down(&database, Some(1)).await?;
    assert!(
        !has_table(&database, "batch_operations").await?,
        "the down must drop batch_operations"
    );
    assert!(
        !column_exists(&database, "operations", "batch_id").await?,
        "the down must drop the operations.batch_id child link"
    );
    assert!(
        !index_exists(&database, "ix_operations_batch_id").await?,
        "the down must drop the batch id index"
    );
    assert_eq!(
        row_count(&database, "operations").await?,
        1,
        "the down must keep the child operation rows"
    );

    // Up again: the parent, the child link, and the index come back, and the
    // surviving operation row is untouched — the re-applied up runs against
    // the rows that were present when the crashed run died.
    Migrator::up(&database, Some(steps)).await?;
    assert!(
        has_table(&database, "batch_operations").await?,
        "the re-applied up must create batch_operations again"
    );
    assert!(
        column_exists(&database, "operations", "batch_id").await?,
        "the re-applied up must add the batch_id child link again"
    );
    assert!(
        index_exists(&database, "ix_operations_batch_id").await?,
        "the re-applied up must create the batch id index again"
    );
    assert_eq!(
        row_count(&database, "operations").await?,
        1,
        "the round trip must not touch the child operation rows"
    );
    assert_eq!(
        row_count(&database, "batch_operations").await?,
        0,
        "the re-applied up must create an empty batch_operations table"
    );

    drop(database);
    drop(directory);
    Ok(())
}

/// Seeds one row per initial-storage table (000001 column sets exactly),
/// including the credential → version reference the down's NULL-out `UPDATE`
/// clears.
async fn seed_initial_storage_rows(
    database: &DatabaseConnection,
    now: String,
) -> Result<(), Box<dyn Error>> {
    let credential_id = Uuid::now_v7();
    let version_id = Uuid::now_v7();
    let endpoint_id = Uuid::now_v7();
    let address_id = Uuid::now_v7();
    // The credentials row first (the versions row's foreign key names it),
    // with the active-version link still NULL, then the version, then the
    // link — the two foreign keys point at each other, so the link can only
    // be set after both rows exist.
    database
        .execute_unprepared(&format!(
            "INSERT INTO credentials \
             (id, name, username, active_version_id, created_at, updated_at) \
             VALUES ('{credential_id}', 'lab-admin', 'administrator', NULL, '{now}', '{now}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO credential_versions \
             (id, credential_id, encrypted_secret, nonce, created_at) \
             VALUES ('{version_id}', '{credential_id}', X'0102030405', X'060708090A', '{now}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "UPDATE credentials SET active_version_id = '{version_id}' WHERE id = \
             '{credential_id}'"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO endpoints (id, display_name, created_at, updated_at) \
             VALUES ('{endpoint_id}', 'Round-Trip BMC', '{now}', '{now}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO endpoint_addresses \
             (id, endpoint_id, address, is_active, created_at, retired_at) \
             VALUES ('{address_id}', '{endpoint_id}', 'https://192.0.2.90', 1, '{now}', NULL)"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO endpoint_trust \
             (endpoint_id, trust_mode, certificate_sha256, certificate_der, trusted_at) \
             VALUES ('{endpoint_id}', 'pinned-certificate', X'0A0B0C0D', X'0E0F1011', '{now}')"
        ))
        .await?;
    database
        .execute_unprepared(&format!(
            "INSERT INTO endpoint_credentials (endpoint_id, credential_id, assigned_at) \
             VALUES ('{endpoint_id}', '{credential_id}', '{now}')"
        ))
        .await?;
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

/// Whether the live schema has a table with the given name.
async fn has_table(database: &DatabaseConnection, name: &str) -> Result<bool, Box<dyn Error>> {
    Ok(SchemaManager::new(database).has_table(name).await?)
}

/// Whether the live schema has an index with the given name, read from
/// `sqlite_master` (the `m20260814_000003` test's probe).
async fn index_exists(database: &DatabaseConnection, name: &str) -> Result<bool, Box<dyn Error>> {
    let statement = Query::select()
        .expr(Expr::cust("1"))
        .from(Alias::new("sqlite_master"))
        .cond_where(Expr::cust(format!("type = 'index' AND name = '{name}'")))
        .to_owned();
    Ok(database.query_one(&statement).await?.is_some())
}

/// Whether the live schema has the named column, read from the recorded
/// `CREATE TABLE` text of `sqlite_master`: `ALTER TABLE ... ADD/DROP COLUMN`
/// rewrites that text, so the probe sees the column exactly when the
/// migration's raw follow-up statement is in effect.
async fn column_exists(
    database: &DatabaseConnection,
    table: &str,
    column: &str,
) -> Result<bool, Box<dyn Error>> {
    let statement = Query::select()
        .expr(Expr::cust("1"))
        .from(Alias::new("sqlite_master"))
        .cond_where(Expr::cust(format!(
            "type = 'table' AND name = '{table}' AND sql LIKE '%{column}%'"
        )))
        .to_owned();
    Ok(database.query_one(&statement).await?.is_some())
}

/// The number of rows in a table — the data-preservation probe, read through
/// raw SQL because the entity model may not name every column the table
/// keeps at the migration point exercised.
async fn row_count(database: &DatabaseConnection, table: &str) -> Result<i64, Box<dyn Error>> {
    let statement = Query::select()
        .expr(Expr::cust("COUNT(*) AS row_count"))
        .from(Alias::new(table))
        .to_owned();
    let row = database
        .query_one(&statement)
        .await?
        .ok_or_else(|| format!("{table} is not in the live schema"))?;
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
