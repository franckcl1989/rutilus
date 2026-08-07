use std::error::Error;

use rutilus_entity::{batch_operation, operation};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter, Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const BATCH_TABLES: [&str; 1] = ["batch_operations"];

/// A representative typed-command JSON document (§9.4), mirroring the
/// operations migration test: the migration only guarantees the column stores
/// and returns the text verbatim.
const COMMAND_JSON: &str = r#"{"reset":{"reset_type":"graceful"}}"#;

#[tokio::test]
async fn batch_operations_migration_preserves_parent_and_child_link_invariants()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_batch_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    verify_batch_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_batch_tables(&database, false).await?;

    Ok(())
}

async fn verify_batch_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let batch_id = Uuid::now_v7();
    let command = String::from(COMMAND_JSON);
    batch_operation::ActiveModel {
        id: Set(batch_id),
        source: Set(String::from("standalone")),
        command: Set(command.clone()),
        created_at: Set(now),
    }
    .insert(database)
    .await?;
    let stored_command = batch_operation::Entity::find_by_id(batch_id)
        .one(database)
        .await?
        .ok_or("inserted batch is missing")?
        .command;
    assert_eq!(
        stored_command, command,
        "the command column must store and return the JSON text verbatim"
    );

    // Every §13.1 source code is accepted by the CHECK constraint.
    for source in ["standalone", "site", "center"] {
        batch_operation::ActiveModel {
            id: Set(Uuid::now_v7()),
            source: Set(String::from(source)),
            command: Set(String::from(COMMAND_JSON)),
            created_at: Set(now),
        }
        .insert(database)
        .await?;
    }

    // A source no product build can classify must be rejected at the
    // database, so rehydration never has to guess an origin.
    let invalid_source = batch_operation::ActiveModel {
        id: Set(Uuid::now_v7()),
        source: Set(String::from("cluster")),
        command: Set(String::from(COMMAND_JSON)),
        created_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(invalid_source.is_err());

    // A pre-existing operation stays valid without a batch link: the new
    // column is nullable, so rows written before the migration never break.
    let standalone_operation_id = insert_operation(database, None, now).await?;

    // A batch child links its row to the parent through the nullable column.
    let child_id = insert_operation(database, Some(batch_id), now).await?;
    let linked = operation::Entity::find_by_id(child_id)
        .one(database)
        .await?
        .ok_or("batch child is missing")?;
    assert_eq!(linked.batch_id, Some(batch_id));

    // A child must name a batch that exists (the FK is enforced).
    let unknown_batch_child = insert_operation(database, Some(Uuid::now_v7()), now).await;
    assert!(unknown_batch_child.is_err());

    // Deleting a batch must cascade to its children, while the unlinked
    // operation survives.
    batch_operation::Entity::delete_by_id(batch_id)
        .exec(database)
        .await?;
    assert_eq!(
        operation::Entity::find()
            .filter(operation::Column::BatchId.eq(batch_id))
            .all(database)
            .await?
            .len(),
        0,
        "deleting a batch must remove its children"
    );
    assert!(
        operation::Entity::find_by_id(standalone_operation_id)
            .one(database)
            .await?
            .is_some(),
        "deleting a batch must not touch unlinked operations"
    );
    Ok(())
}

async fn assert_batch_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in BATCH_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    if should_exist {
        return Ok(());
    }
    // After `down` the follow-up ALTER must be fully undone: the operations
    // table can no longer carry a batch link, so a row written with one is
    // refused at the database ("no such column").
    let now = OffsetDateTime::now_utc();
    let link = operation::ActiveModel {
        id: Set(Uuid::now_v7()),
        source: Set(String::from("standalone")),
        state: Set(String::from("queued")),
        command: Set(String::from(COMMAND_JSON)),
        batch_id: Set(Some(Uuid::now_v7())),
        failure_kind: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(link.is_err(), "operations.batch_id must be dropped by down");
    Ok(())
}

/// Inserts one operation row with the given batch link (or none) and returns
/// its id; a rejected row — an unknown batch id (FK) or a missing column
/// after `down` — fails the insert.
async fn insert_operation(
    database: &DatabaseConnection,
    batch_id: Option<Uuid>,
    now: OffsetDateTime,
) -> Result<Uuid, Box<dyn Error>> {
    let operation_id = Uuid::now_v7();
    operation::ActiveModel {
        id: Set(operation_id),
        source: Set(String::from("standalone")),
        state: Set(String::from("queued")),
        command: Set(String::from(COMMAND_JSON)),
        batch_id: Set(batch_id),
        failure_kind: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    Ok(operation_id)
}
