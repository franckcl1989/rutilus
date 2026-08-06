use std::error::Error;

use rutilus_entity::artifact;
use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const ARTIFACT_TABLES: [&str; 1] = ["artifacts"];

/// The complete §14.3 lifecycle, in the codes the domain `ArtifactState`
/// persists. The database CHECK must accept exactly these and nothing else.
const ARTIFACT_STATES: [&str; 3] = ["uploading", "ready", "failed"];

#[tokio::test]
async fn artifacts_migration_preserves_lifecycle_invariants() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_artifact_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    verify_artifact_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_artifact_tables(&database, false).await?;

    Ok(())
}

async fn verify_artifact_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let artifact_id = Uuid::now_v7();
    let sha256 = String::from("ab").repeat(32);
    artifact::ActiveModel {
        id: Set(artifact_id),
        name: Set(String::from("firmware-2024.2.bin")),
        size_bytes: Set(1024),
        sha256: Set(sha256.clone()),
        state: Set(String::from("uploading")),
        uploaded_bytes: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    let stored = artifact::Entity::find_by_id(artifact_id)
        .one(database)
        .await?
        .ok_or("inserted artifact is missing")?;
    assert_eq!(stored.name, "firmware-2024.2.bin");
    assert_eq!(stored.size_bytes, 1024);
    assert_eq!(stored.sha256, sha256);
    assert_eq!(stored.state, "uploading");
    assert_eq!(stored.uploaded_bytes, 0);
    assert_eq!(stored.created_at, now);
    assert_eq!(stored.updated_at, now);

    // Every §14.3 state code is accepted by the CHECK constraint, so a
    // recovery scan can restore any state the domain state machine knows.
    for state in ARTIFACT_STATES {
        artifact::ActiveModel {
            id: Set(Uuid::now_v7()),
            name: Set(String::from("firmware.bin")),
            size_bytes: Set(1024),
            sha256: Set(sha256.clone()),
            state: Set(String::from(state)),
            uploaded_bytes: Set(1024),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(database)
        .await?;
    }

    // A state no product build can classify must be rejected at the
    // database, so rehydration never has to guess a lifecycle phase.
    let invalid_state = artifact::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("firmware.bin")),
        size_bytes: Set(1024),
        sha256: Set(sha256.clone()),
        state: Set(String::from("paused")),
        uploaded_bytes: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(invalid_state.is_err());

    Ok(())
}

async fn assert_artifact_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in ARTIFACT_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}
