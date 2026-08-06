use std::error::Error;

use rutilus_entity::{operation, operation_target};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const OPERATION_TABLES: [&str; 2] = ["operations", "operation_targets"];

/// The complete §13.1 state machine, in the codes the domain `OperationState`
/// persists. The database CHECK must accept exactly these and nothing else.
const OPERATION_STATES: [&str; 9] = [
    "queued",
    "validating",
    "running",
    "waiting-remote",
    "verifying",
    "succeeded",
    "failed",
    "unknown",
    "cancelled",
];

#[tokio::test]
async fn operations_migration_preserves_aggregate_invariants() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_operation_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    verify_operation_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_operation_tables(&database, false).await?;

    Ok(())
}

async fn verify_operation_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let operation_id = Uuid::now_v7();
    operation::ActiveModel {
        id: Set(operation_id),
        source: Set(String::from("standalone")),
        state: Set(String::from("queued")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    let first_target_id = Uuid::now_v7();
    for (target_id, endpoint_id) in [
        (first_target_id, Uuid::now_v7()),
        (Uuid::now_v7(), Uuid::now_v7()),
    ] {
        operation_target::ActiveModel {
            operation_id: Set(operation_id),
            target_id: Set(target_id),
            endpoint_id: Set(endpoint_id),
        }
        .insert(database)
        .await?;
    }

    // Every §13.1 state code is accepted by the CHECK constraint, so the
    // recovery scanner can restore any state the domain state machine knows.
    for state in OPERATION_STATES {
        operation::ActiveModel {
            id: Set(Uuid::now_v7()),
            source: Set(String::from("standalone")),
            state: Set(String::from(state)),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(database)
        .await?;
    }

    // A source no product build can classify must be rejected at the
    // database, so rehydration never has to guess an origin.
    let invalid_source = operation::ActiveModel {
        id: Set(Uuid::now_v7()),
        source: Set(String::from("cluster")),
        state: Set(String::from("queued")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(invalid_source.is_err());

    // A state no product build can classify must be rejected at the database.
    let invalid_state = operation::ActiveModel {
        id: Set(Uuid::now_v7()),
        source: Set(String::from("standalone")),
        state: Set(String::from("pending")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(invalid_state.is_err());

    // A target must name an operation that exists.
    let unknown_operation_target = operation_target::ActiveModel {
        operation_id: Set(Uuid::now_v7()),
        target_id: Set(Uuid::now_v7()),
        endpoint_id: Set(Uuid::now_v7()),
    }
    .insert(database)
    .await;
    assert!(unknown_operation_target.is_err());

    // The composite key rejects a repeated target inside one operation.
    let duplicate_target = operation_target::ActiveModel {
        operation_id: Set(operation_id),
        target_id: Set(first_target_id),
        endpoint_id: Set(Uuid::now_v7()),
    }
    .insert(database)
    .await;
    assert!(duplicate_target.is_err());

    // Deleting an operation must cascade to its targets.
    operation::Entity::delete_by_id(operation_id)
        .exec(database)
        .await?;
    assert_eq!(
        operation_target::Entity::find()
            .filter(operation_target::Column::OperationId.eq(operation_id))
            .all(database)
            .await?
            .len(),
        0,
        "deleting an operation must remove its targets"
    );
    Ok(())
}

async fn assert_operation_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in OPERATION_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}
