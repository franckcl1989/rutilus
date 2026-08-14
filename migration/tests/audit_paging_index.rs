use std::error::Error;

use rutilus_migration::Migrator;
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};
use sea_orm_migration::MigratorTrait;

/// The W7-S-3 / W7-P-4 covering index for the audit-history paging query
/// (`ORDER BY occurred_at DESC, event_sequence DESC, id DESC`) must exist
/// after `up` — registered migrations only — and disappear after `down`.
#[tokio::test]
async fn the_audit_paging_index_exists_after_up_and_is_gone_after_down()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    assert!(
        index_exists(&database, "ix_audit_events_occurred_at_sequence").await?,
        "the paging covering index must exist after `up`"
    );

    Migrator::down(&database, None).await?;
    assert!(
        !index_exists(&database, "ix_audit_events_occurred_at_sequence").await?,
        "the paging covering index must be gone after `down`"
    );
    Ok(())
}

/// Whether `audit_events` carries an index with the given name, read from
/// `PRAGMA index_list` (the `name` column of each row).
async fn index_exists(database: &DatabaseConnection, name: &str) -> Result<bool, Box<dyn Error>> {
    let rows = database
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "PRAGMA index_list(audit_events)",
            vec![],
        ))
        .await?;
    Ok(rows.iter().any(|row| {
        row.try_get_by_index::<String>(1)
            .is_ok_and(|stored| stored == name)
    }))
}
