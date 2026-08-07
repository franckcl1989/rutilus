use std::error::Error;

use rutilus_entity::{operation, remote_task};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const REMOTE_TASK_TABLES: [&str; 1] = ["remote_tasks"];

/// The complete engine `TaskState` code set — the current Redfish DSP0266
/// `TaskState` vocabulary in the product's stable snake-case style. The
/// database CHECK must accept exactly these and nothing else.
const TASK_STATES: [&str; 13] = [
    "new",
    "starting",
    "running",
    "suspended",
    "interrupted",
    "pending",
    "stopping",
    "completed",
    "killed",
    "exception",
    "service",
    "cancelling",
    "cancelled",
];

#[tokio::test]
async fn remote_tasks_migration_preserves_task_invariants() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_remote_task_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    verify_remote_task_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_remote_task_tables(&database, false).await?;

    Ok(())
}

async fn verify_remote_task_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let operation_id = insert_operation(database, now).await?;
    let task_uri = String::from("/redfish/v1/TaskService/Tasks/42");
    let monitor_uri = String::from("/redfish/v1/TaskService/TaskMonitors/42");
    let message = String::from("task started");
    remote_task::ActiveModel {
        operation_id: Set(operation_id),
        endpoint_id: Set(Uuid::now_v7()),
        task_uri: Set(task_uri.clone()),
        task_monitor_uri: Set(Some(monitor_uri.clone())),
        last_state: Set(String::from("running")),
        last_message: Set(Some(message.clone())),
        percent_complete: Set(Some(12)),
        last_checked_at: Set(now),
    }
    .insert(database)
    .await?;
    let stored = remote_task::Entity::find_by_id(operation_id)
        .one(database)
        .await?
        .ok_or("inserted remote task is missing")?;
    assert_eq!(stored.task_uri, task_uri);
    assert_eq!(stored.task_monitor_uri, Some(monitor_uri));
    assert_eq!(stored.last_state, "running");
    assert_eq!(stored.last_message, Some(message));
    assert_eq!(stored.percent_complete, Some(12));
    assert_eq!(stored.last_checked_at, now);

    // Every engine TaskState code is accepted by the CHECK constraint, so
    // the recovery scanner can restore any state the engine understands.
    for state in TASK_STATES {
        let op_id = insert_operation(database, now).await?;
        remote_task::ActiveModel {
            operation_id: Set(op_id),
            endpoint_id: Set(Uuid::now_v7()),
            task_uri: Set(String::from("/redfish/v1/TaskService/Tasks/0")),
            task_monitor_uri: Set(None),
            last_state: Set(String::from(state)),
            last_message: Set(None),
            percent_complete: Set(None),
            last_checked_at: Set(now),
        }
        .insert(database)
        .await?;
    }

    // A state no product build can classify must be rejected at the database.
    let invalid_state = remote_task::ActiveModel {
        operation_id: Set(operation_id),
        endpoint_id: Set(Uuid::now_v7()),
        task_uri: Set(String::from("/redfish/v1/TaskService/Tasks/0")),
        task_monitor_uri: Set(None),
        last_state: Set(String::from("paused")),
        last_message: Set(None),
        percent_complete: Set(None),
        last_checked_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(invalid_state.is_err());

    // A task must belong to an operation that exists.
    let unknown_operation = remote_task::ActiveModel {
        operation_id: Set(Uuid::now_v7()),
        endpoint_id: Set(Uuid::now_v7()),
        task_uri: Set(String::from("/redfish/v1/TaskService/Tasks/0")),
        task_monitor_uri: Set(None),
        last_state: Set(String::from("running")),
        last_message: Set(None),
        percent_complete: Set(None),
        last_checked_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(unknown_operation.is_err());

    // Deleting an operation must cascade to its remote task.
    operation::Entity::delete_by_id(operation_id)
        .exec(database)
        .await?;
    assert_eq!(
        remote_task::Entity::find()
            .filter(remote_task::Column::OperationId.eq(operation_id))
            .all(database)
            .await?
            .len(),
        0,
        "deleting an operation must remove its remote task"
    );
    Ok(())
}

/// Inserts one §13.1-compliant operation row and returns its id.
async fn insert_operation(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<Uuid, Box<dyn Error>> {
    let operation_id = Uuid::now_v7();
    operation::ActiveModel {
        id: Set(operation_id),
        source: Set(String::from("standalone")),
        state: Set(String::from("waiting-remote")),
        command: Set(String::from(r#"{"reset":{"reset_type":"graceful"}}"#)),
        batch_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    Ok(operation_id)
}

async fn assert_remote_task_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in REMOTE_TASK_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}
