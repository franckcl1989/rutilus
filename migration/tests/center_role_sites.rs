use std::error::Error;

use rutilus_entity::{instance, principal, role_assignment};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
    EntityTrait, Set, Statement,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test]
async fn center_role_sites_migration_scopes_the_roles_to_sites() -> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;

    Migrator::up(&database, None).await?;

    // A principal and a site for the assignments.
    let now = OffsetDateTime::now_utc();
    let principal_id = Uuid::now_v7();
    principal::ActiveModel {
        id: Set(principal_id),
        name: Set(String::from("operator")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    let site_id = Uuid::now_v7();
    instance::ActiveModel {
        id: Set(site_id),
        display_name: Set(String::from("Site One")),
        instance_kind: Set(String::from("site")),
        created_at: Set(now),
    }
    .insert(&database)
    .await?;

    // A site-scoped operator and viewer assignment round-trip (D3).
    role_assignment::ActiveModel {
        principal_id: Set(principal_id),
        role: Set(String::from("operator")),
        assigned_by: Set(None),
        assigned_at: Set(now),
        site_id: Set(Some(site_id)),
    }
    .insert(&database)
    .await?;
    let viewer_id = Uuid::now_v7();
    principal::ActiveModel {
        id: Set(viewer_id),
        name: Set(String::from("viewer")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    role_assignment::ActiveModel {
        principal_id: Set(viewer_id),
        role: Set(String::from("viewer")),
        assigned_by: Set(None),
        assigned_at: Set(now),
        site_id: Set(Some(site_id)),
    }
    .insert(&database)
    .await?;
    // A global assignment (no scope) still works.
    let admin_id = Uuid::now_v7();
    principal::ActiveModel {
        id: Set(admin_id),
        name: Set(String::from("administrator")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    role_assignment::ActiveModel {
        principal_id: Set(admin_id),
        role: Set(String::from("administrator")),
        assigned_by: Set(None),
        assigned_at: Set(now),
        site_id: Set(None),
    }
    .insert(&database)
    .await?;

    // The scope CHECK pins the vocabulary: the administrator's §16.1
    // duties are global, so a site-scoped administrator assignment is
    // refused.
    let scoped_admin = role_assignment::ActiveModel {
        principal_id: Set(admin_id),
        role: Set(String::from("administrator")),
        assigned_by: Set(None),
        assigned_at: Set(now),
        site_id: Set(Some(site_id)),
    }
    .insert(&database)
    .await;
    assert!(
        scoped_admin.is_err(),
        "an administrator assignment must never carry a site scope"
    );

    // The scope is a real foreign key: deleting the site removes its
    // scoped assignments.
    instance::Entity::delete_by_id(site_id)
        .exec(&database)
        .await?;
    let remaining = role_assignment::Entity::find().all(&database).await?;
    assert!(
        remaining.iter().all(|row| row.site_id.is_none()),
        "deleting the site must cascade its scoped assignments"
    );

    Migrator::down(&database, None).await?;
    drop(database);
    drop(directory);
    Ok(())
}

#[tokio::test]
async fn center_role_sites_down_restores_the_unscoped_shape() -> Result<(), Box<dyn Error>> {
    let (directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    // Unwind the feature-list alignment and decode-failure migrations plus
    // the center-role-sites migration; the down of 000010's successor must
    // restore the 000010-era shape.
    Migrator::down(&database, Some(3)).await?;
    let applied = Migrator::get_applied_migrations(&database).await?;
    assert_eq!(
        applied.last().map(sea_orm_migration::Migration::name),
        Some("m20260810_000001_center_data_sites")
    );

    // The site_id column is gone: the scoped insert is refused and the
    // original four-column shape works.
    let now = OffsetDateTime::now_utc();
    let principal_id = Uuid::now_v7();
    principal::ActiveModel {
        id: Set(principal_id),
        name: Set(String::from("operator")),
        state: Set(String::from("enabled")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(&database)
    .await?;
    let scoped = role_assignment::ActiveModel {
        principal_id: Set(principal_id),
        role: Set(String::from("operator")),
        assigned_by: Set(None),
        assigned_at: Set(now),
        site_id: Set(Some(Uuid::now_v7())),
    }
    .insert(&database)
    .await;
    assert!(
        scoped.is_err(),
        "the site_id column must be gone after the down"
    );
    // SeaORM omits `Set(None)` columns from the insert, so the original
    // four-column shape is exercised through a raw statement instead.
    database
        .execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO role_assignments (principal_id, role, assigned_by, assigned_at) \
             VALUES (?, 'operator', NULL, ?)",
            vec![principal_id.into(), now.into()],
        ))
        .await?;

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
