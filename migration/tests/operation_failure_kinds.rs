use std::error::Error;

use rutilus_entity::operation;
use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

/// A representative typed-command JSON document (§9.4), mirroring the other
/// operation migration tests.
const COMMAND_JSON: &str = r#"{"reset":{"reset_type":"graceful"}}"#;

#[tokio::test]
async fn operation_failure_kinds_migration_preserves_the_classification_invariants()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;

    let now = OffsetDateTime::now_utc();
    verify_failure_kind_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    // After `down` the column is fully undone: a row written with a kind is
    // refused at the database ("no such column").
    let after_down = operation::ActiveModel {
        id: Set(Uuid::now_v7()),
        source: Set(String::from("standalone")),
        state: Set(String::from("queued")),
        command: Set(String::from(COMMAND_JSON)),
        batch_id: Set(None),
        failure_kind: Set(Some(String::from("capability-unsupported"))),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await;
    assert!(
        after_down.is_err(),
        "operations.failure_kind must be dropped by down"
    );

    Ok(())
}

async fn verify_failure_kind_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    // A plain operation row stays valid without a classification: the column
    // is nullable, so every row written before the migration never breaks.
    let unclassified_id = insert_operation(database, None, now).await?;
    let unclassified = operation::Entity::find_by_id(unclassified_id)
        .one(database)
        .await?
        .ok_or("unclassified operation is missing")?;
    assert_eq!(
        unclassified.failure_kind, None,
        "an unclassified row must read back NULL"
    );

    // The one kind this build classifies is accepted and round-trips
    // verbatim through the column.
    let classified_id = insert_operation(database, Some("capability-unsupported"), now).await?;
    let classified = operation::Entity::find_by_id(classified_id)
        .one(database)
        .await?
        .ok_or("classified operation is missing")?;
    assert_eq!(
        classified.failure_kind.as_deref(),
        Some("capability-unsupported"),
        "the classification code must store and return verbatim"
    );

    // A code no product build can classify must be rejected at the database,
    // so rehydration never has to guess a kind — the same guard as the state
    // and source CHECK constraints.
    let invalid_kind = insert_operation(database, Some("capability-missing"), now).await;
    assert!(invalid_kind.is_err());

    // Deleting the operation removes the classified row with it; the
    // unclassified row survives.
    operation::Entity::delete_by_id(classified_id)
        .exec(database)
        .await?;
    assert!(
        operation::Entity::find_by_id(classified_id)
            .one(database)
            .await?
            .is_none()
    );
    assert!(
        operation::Entity::find_by_id(unclassified_id)
            .one(database)
            .await?
            .is_some()
    );
    Ok(())
}

/// Inserts one operation row with the given classification (or none) and
/// returns its id; a rejected row — an unknown kind code — fails the insert.
async fn insert_operation(
    database: &DatabaseConnection,
    failure_kind: Option<&str>,
    now: OffsetDateTime,
) -> Result<Uuid, Box<dyn Error>> {
    let operation_id = Uuid::now_v7();
    operation::ActiveModel {
        id: Set(operation_id),
        source: Set(String::from("standalone")),
        state: Set(String::from("queued")),
        command: Set(String::from(COMMAND_JSON)),
        batch_id: Set(None),
        failure_kind: Set(failure_kind.map(str::to_owned)),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    Ok(operation_id)
}
