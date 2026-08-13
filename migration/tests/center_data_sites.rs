use std::error::Error;

use rutilus_entity::{
    artifact, credential, endpoint, endpoint_address, endpoint_capability, endpoint_credential,
    endpoint_trust, event, instance, resource, resource_snapshot,
};
use rutilus_migration::Migrator;
use sea_orm::sea_query::{Alias, Expr, Query};
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
    EntityTrait, PaginatorTrait, Set, Statement,
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
    // Seed a parent row and one row in every cascade child of `endpoints`
    // (addresses, TLS trust, credential binding, capability ledger,
    // resource, and snapshot) so the downgrade below runs against real
    // data. The foreign keys are on (the `sqlx` default this harness
    // inherits enables them), so the down of 000010 must rebuild the
    // children alongside `endpoints` — a bare parent drop would silently
    // cascade every child row away.
    let now = OffsetDateTime::now_utc();
    let seed_site_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(seed_site_id),
        display_name: Set(String::from("Site Two")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    let seed_endpoint_id = Uuid::now_v7();
    endpoint::ActiveModel {
        id: Set(seed_endpoint_id),
        display_name: Set(String::from("Rack B PDU")),
        created_at: Set(now),
        updated_at: Set(now),
        site_id: Set(Some(seed_site_id)),
        refresh_generation: Set(1),
        health: Set(String::from("ok")),
    }
    .insert(&database)
    .await?;
    let seed_credential_id = Uuid::now_v7();
    credential::ActiveModel {
        id: Set(seed_credential_id),
        name: Set(String::from("Rack B credential")),
        username: Set(String::from("svc")),
        active_version_id: Set(None),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    endpoint_address::ActiveModel {
        id: Set(Uuid::now_v7()),
        endpoint_id: Set(seed_endpoint_id),
        address: Set(String::from("https://rack-b.example.com")),
        is_active: Set(true),
        created_at: Set(now),
        retired_at: Set(None),
    }
    .insert(&database)
    .await?;
    endpoint_trust::ActiveModel {
        endpoint_id: Set(seed_endpoint_id),
        trust_mode: Set(endpoint_trust::TrustMode::PinnedCertificate),
        certificate_sha256: Set(None),
        certificate_der: Set(None),
        trusted_at: Set(now),
    }
    .insert(&database)
    .await?;
    endpoint_credential::ActiveModel {
        endpoint_id: Set(seed_endpoint_id),
        credential_id: Set(seed_credential_id),
        assigned_at: Set(now),
    }
    .insert(&database)
    .await?;
    endpoint_capability::ActiveModel {
        endpoint_id: Set(seed_endpoint_id),
        capability: Set(String::from("power")),
        state: Set(String::from("supported")),
        observed_at: Set(now),
    }
    .insert(&database)
    .await?;
    let seed_resource_id = Uuid::now_v7();
    resource::ActiveModel {
        id: Set(seed_resource_id),
        endpoint_id: Set(seed_endpoint_id),
        odata_id: Set(String::from("/redfish/v1/Systems/1")),
        feature: Set(String::from("systems")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;
    resource_snapshot::ActiveModel {
        resource_id: Set(seed_resource_id),
        generation: Set(1),
        odata_type: Set(None),
        etag: Set(None),
        typed_payload_json: Set(String::from("{\"id\": 1}")),
        observed_at: Set(now),
    }
    .insert(&database)
    .await?;
    // Unwind every migration registered after the center-tables slice; the
    // down of 000010 must restore the 000009-era shapes. The step count is
    // the registration tail after the named migration, so the test stays
    // correct however later slices extend the registration list.
    let steps = migrations_after("m20260807_000009_center_tables")?;
    Migrator::down(&database, Some(steps)).await?;
    let applied = Migrator::get_applied_migrations(&database).await?;
    let expected_applied =
        u32::try_from(registration_position("m20260807_000009_center_tables")? + 1)?;
    assert_eq!(applied.len(), usize::try_from(expected_applied)?);
    assert_eq!(
        applied.last().map(sea_orm_migration::Migration::name),
        Some("m20260807_000009_center_tables")
    );

    // The six cascade children survive the downgrade with their rows: the
    // down rebuilds them alongside `endpoints` instead of letting the old
    // parent's drop cascade them away (with foreign keys on, the implicit
    // `DELETE FROM endpoints` would silently empty every child — the defect
    // this test pins).
    assert_eq!(
        endpoint_address::Entity::find().count(&database).await?,
        1,
        "the endpoint_addresses row must survive the down"
    );
    assert_eq!(
        endpoint_trust::Entity::find().count(&database).await?,
        1,
        "the endpoint_trust row must survive the down"
    );
    assert_eq!(
        endpoint_credential::Entity::find().count(&database).await?,
        1,
        "the endpoint_credentials row must survive the down"
    );
    assert_eq!(
        endpoint_capability::Entity::find().count(&database).await?,
        1,
        "the endpoint_capabilities row must survive the down"
    );
    assert_eq!(
        resource::Entity::find().count(&database).await?,
        1,
        "the resources row must survive the down"
    );
    assert_eq!(
        resource_snapshot::Entity::find().count(&database).await?,
        1,
        "the resource_snapshots row must survive the down"
    );
    // The `endpoint` model still carries `site_id`, which the down removed,
    // so the endpoint row is counted through raw SQL instead of the entity.
    let statement = Query::select()
        .expr(Expr::cust("COUNT(*) AS row_count"))
        .from(Alias::new("endpoints"))
        .to_owned();
    let row = database
        .query_one(&statement)
        .await?
        .ok_or("endpoints must exist after the rollback")?;
    assert_eq!(
        row.try_get_by_index::<i64>(0)?,
        1,
        "the endpoints row must survive the down rebuild"
    );

    // The site_id columns are gone: the association inserts are refused
    // and the original shapes work.
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

/// The registration position of the named migration.
fn registration_position(name: &str) -> Result<usize, Box<dyn Error>> {
    Migrator::migrations()
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or_else(|| format!("migration {name} is not registered").into())
}

/// The number of registered migrations after the named migration.
fn migrations_after(name: &str) -> Result<u32, Box<dyn Error>> {
    let position = registration_position(name)?;
    Ok(u32::try_from(Migrator::migrations().len() - position - 1)?)
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
