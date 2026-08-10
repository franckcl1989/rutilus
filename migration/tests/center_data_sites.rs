use std::error::Error;

use rutilus_entity::{artifact, endpoint, event, instance};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
    EntityTrait, Set, Statement,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const CENTER_DATA_TABLES: [&str; 3] = ["endpoints", "events", "artifacts"];

#[tokio::test]
async fn center_data_sites_migration_adds_and_drops_the_site_association()
-> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;

    Migrator::up(&database, None).await?;
    for table in CENTER_DATA_TABLES {
        assert!(SchemaManager::new(&database).has_table(table).await?);
    }

    // A site instance, an endpoint projection, an event, and an artifact
    // round-trip with the association columns.
    let now = OffsetDateTime::now_utc();
    let site_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(site_id),
        display_name: Set(String::from("Site One")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let endpoint_id = Uuid::now_v7();
    endpoint::ActiveModel {
        id: Set(endpoint_id),
        display_name: Set(String::from("Rack A PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(Some(site_id)),
        refresh_generation: Set(3),
        health: Set(String::from("ok")),
    }
    .insert(&database)
    .await?;
    event::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        message_id: Set(String::from("ResourceEvent.1.0.ResourceUpdated")),
        severity: Set(String::from("warning")),
        message: Set(None),
        event_timestamp: Set(now),
        observed_at: Set(now),
        dedup_key: Set(String::from("ResourceEvent.1.0.ResourceUpdated\u{1F}1")),
        site_id: Set(Some(site_id)),
    }
    .insert(&database)
    .await?;
    artifact::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("firmware.bin")),
        size_bytes: Set(1024),
        sha256: Set(String::from("ab").repeat(32)),
        state: Set(String::from("uploading")),
        uploaded_bytes: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(Some(site_id)),
    }
    .insert(&database)
    .await?;

    // The endpoint association is a real foreign key: an unknown site is
    // refused, and deleting the site cascades the projection away.
    let unknown = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Stray PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(Some(Uuid::now_v7())),
        refresh_generation: Set(0),
        health: Set(String::from("unknown")),
    }
    .insert(&database)
    .await;
    assert!(
        unknown.is_err(),
        "an unknown site must be refused by the foreign key"
    );
    instance::Entity::delete_by_id(site_id)
        .exec(&database)
        .await?;
    assert!(
        endpoint::Entity::find_by_id(endpoint_id)
            .one(&database)
            .await?
            .is_none(),
        "deleting the site must cascade its endpoint projection"
    );

    // The site-side defaults keep every local row well-formed.
    let local = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Local BMC")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(0),
        health: Set(String::from("unknown")),
    }
    .insert(&database)
    .await?;
    assert_eq!(local.site_id, None);

    Migrator::down(&database, None).await?;
    for table in CENTER_DATA_TABLES {
        assert!(!SchemaManager::new(&database).has_table(table).await?);
    }

    drop(database);
    drop(directory);
    Ok(())
}

// The downgrade assertions spell out each restored table shape, which
// exceeds the pedantic line budget (the migration tests allow the same
// lint on their exhaustive assertion tests).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn center_data_sites_down_restores_the_original_table_shapes() -> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    // Unwind the two 0.7.0 S5 migrations; the down of 000010 must restore
    // the 000009-era shapes.
    Migrator::down(&database, Some(2)).await?;
    let applied = Migrator::get_applied_migrations(&database).await?;
    assert_eq!(applied.len(), 19);
    assert_eq!(
        applied.last().map(sea_orm_migration::Migration::name),
        Some("m20260807_000009_center_tables")
    );

    // The site_id columns are gone: the association inserts are refused
    // and the original shapes work.
    let now = OffsetDateTime::now_utc();
    let site_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(site_id),
        display_name: Set(String::from("Site One")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let scoped = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Rack A PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(Some(site_id)),
        refresh_generation: Set(0),
        health: Set(String::from("unknown")),
    }
    .insert(&database)
    .await;
    assert!(
        scoped.is_err(),
        "the site_id column must be gone after the down"
    );
    let local = endpoint::ActiveModel {
        id: Set(Uuid::now_v7()),
        display_name: Set(String::from("Local BMC")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
        refresh_generation: Set(0),
        health: Set(String::from("unknown")),
    }
    .insert(&database)
    .await;
    assert!(
        local.is_err(),
        "all three added endpoint columns must be gone"
    );

    // The original four-column shape works again, and the events and
    // artifacts tables keep their original CHECKs after the rebuild.
    let endpoint_id = Uuid::now_v7();
    database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO endpoints (id, display_name, created_at, updated_at) \n             VALUES (?, 'Local BMC', ?, ?)",
            vec![endpoint_id.into(), now.into(), now.into()],
        ))
        .await?;
    let original_event = event::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
        message_id: Set(String::from("ResourceEvent.1.0.ResourceUpdated")),
        severity: Set(String::from("warning")),
        message: Set(None),
        event_timestamp: Set(now),
        observed_at: Set(now),
        dedup_key: Set("ResourceEvent.1.0.ResourceUpdated\u{1F}2".to_owned()),
        site_id: Set(None),
    }
    .insert(&database)
    .await;
    assert!(
        original_event.is_err(),
        "the events table still lacks site_id"
    );
    let original_artifact = artifact::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("firmware.bin")),
        size_bytes: Set(1024),
        sha256: Set(String::from("ab").repeat(32)),
        state: Set(String::from("uploading")),
        uploaded_bytes: Set(0),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(None),
    }
    .insert(&database)
    .await;
    assert!(
        original_artifact.is_err(),
        "the artifacts table still lacks site_id"
    );

    // The original events/artifacts CHECKs survived the rebuild: an unknown
    // severity and an unknown state are still refused (the raw inserts drop
    // the site_id column that no longer exists).
    let bad_event = database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO events \
             (id, endpoint_id, message_id, severity, message, event_timestamp, observed_at, dedup_key) \n             VALUES (?, ?, 'Alert.1.0.PowerSupplyFailure', 'informational', NULL, ?, ?, ?)",
            vec![
                Uuid::now_v7().into(),
                endpoint_id.into(),
                now.into(),
                now.into(),
                "Alert.1.0.PowerSupplyFailure\u{1F}3".to_owned().into(),
            ],
        ))
        .await;
    assert!(
        bad_event.is_err(),
        "the events severity CHECK must survive the down"
    );
    let bad_artifact = database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO artifacts \
             (id, name, size_bytes, sha256, state, uploaded_bytes, created_at, updated_at) \n             VALUES (?, 'firmware.bin', 1024, ?, 'paused', 0, ?, ?)",
            vec![
                Uuid::now_v7().into(),
                String::from("ab").repeat(32).into(),
                now.into(),
                now.into(),
            ],
        ))
        .await;
    assert!(
        bad_artifact.is_err(),
        "the artifacts state CHECK must survive the down"
    );

    drop(database);
    drop(directory);
    Ok(())
}

async fn connect() -> Result<(tempfile::TempDir, DatabaseConnection), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;
    Ok((directory, database))
}
