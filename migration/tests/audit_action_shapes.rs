use std::error::Error;

use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_ACTION_SHAPES_MIGRATION: &str = "m20260807_000007_audit_action_shapes";

#[tokio::test]
async fn widened_action_shapes_persist_and_foreign_shapes_are_refused() -> Result<(), Box<dyn Error>>
{
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // Every §16 authentication-slice shape the domain matrix accepts persists
    // and reads back: the authentication lifecycle under `authenticate`, the
    // user-administration actions under `manage-users`, backups and settings
    // under their own permissions, and the `authentication-failed` failure.
    for (action, permission) in [
        ("login", "authenticate"),
        ("logout", "authenticate"),
        ("change-password", "authenticate"),
        ("manage-users", "manage-users"),
        ("manage-sessions", "manage-users"),
        ("manage-totp", "manage-users"),
        ("manage-backups", "manage-backups"),
        ("manage-settings", "manage-site-settings"),
    ] {
        let inserted = insert_action_row(
            &database,
            action,
            permission,
            None,
            "succeeded",
            occurred_at,
        )
        .await?;
        let stored = rutilus_entity::audit_event::Entity::find_by_id(inserted.id)
            .one(&database)
            .await?
            .ok_or("inserted audit row is missing")?;
        assert_eq!(stored.action, action);
        assert_eq!(stored.permission, permission);
        assert_eq!(stored.redfish_operation, "none");
        assert_eq!(stored.parameter_kind, "endpoint-refresh");
    }

    // The authentication-failed failure persists on a failed login.
    let failed = insert_action_row(
        &database,
        "login",
        "authenticate",
        Some("authentication-failed"),
        "failed",
        occurred_at,
    )
    .await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(failed.id)
        .one(&database)
        .await?
        .ok_or("inserted audit row is missing")?;
    assert_eq!(stored.failure.as_deref(), Some("authentication-failed"));

    // A login under a foreign permission is refused: the action CHECK pins
    // the same shapes as the domain consistency matrix.
    let wrong_permission = insert_action_row(
        &database,
        "login",
        "manage-users",
        None,
        "succeeded",
        occurred_at,
    )
    .await;
    assert!(
        wrong_permission.is_err(),
        "a login under manage-users must be refused"
    );
    let unknown_failure = insert_action_row(
        &database,
        "login",
        "authenticate",
        Some("password-expired"),
        "failed",
        occurred_at,
    )
    .await;
    assert!(
        unknown_failure.is_err(),
        "an unknown failure code must be refused"
    );

    // Roll back through the shape migration: the rows written in the new
    // shapes cannot be represented in the restored schema, so they are
    // removed first (the documented restore contract refuses them, exactly
    // like the product-users rollback refuses user-actor rows).
    rutilus_entity::audit_event::Entity::delete_many()
        .exec(&database)
        .await?;
    let steps = rollback_steps_to(AUDIT_ACTION_SHAPES_MIGRATION)?;
    Migrator::down(&database, Some(steps)).await?;

    // The restored schema refuses the widened shapes again.
    let refused = insert_action_row(
        &database,
        "login",
        "authenticate",
        None,
        "succeeded",
        occurred_at,
    )
    .await;
    assert!(
        refused.is_err(),
        "the rolled-back schema must not know the authentication actions"
    );

    Ok(())
}

#[tokio::test]
async fn widened_rebuild_preserves_existing_audit_rows() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Apply every migration before the shape rebuild: the audit table still
    // has the endpoint-management shapes, which the legacy row proves. The
    // step count is the shape migration's own registration position, so the
    // test stays correct however later slices extend the registration list.
    let steps = migrations_before(AUDIT_ACTION_SHAPES_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    let legacy_id = Uuid::now_v7();
    let row = insert_legacy_audit_row(&database, legacy_id).await?;
    assert_eq!(row.action, "enroll-endpoint");

    // The rebuild preserves every legacy row.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(legacy_id)
        .one(&database)
        .await?
        .ok_or("the legacy audit row must survive the rebuild")?;
    assert_eq!(stored.action, "enroll-endpoint");
    assert_eq!(stored.permission, "manage-endpoints");

    Ok(())
}

/// The number of registered migrations before the named migration.
fn migrations_before(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit action shapes migration is not registered")?;
    Ok(u32::try_from(position)?)
}

/// The number of registered migrations to roll back so the named migration
/// is included in the rollback: everything registered after it, plus itself.
fn rollback_steps_to(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit action shapes migration is not registered")?;
    Ok(u32::try_from(migrations.len() - position)?)
}

/// Writes one pre-slice audit row in the endpoint-management product shape,
/// the only shape the table accepts before the widening.
async fn insert_legacy_audit_row(
    database: &DatabaseConnection,
    id: Uuid,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(id),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(1),
        actor: Set(String::from("system")),
        actor_principal_id: Set(None),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("endpoint-address")),
        target_endpoint_id: Set(None),
        target_endpoint_address: Set(Some(String::from("https://192.0.2.90"))),
        parameter_kind: Set(String::from("endpoint-enrollment")),
        credential_id: Set(Some(Uuid::now_v7())),
        trust_mode: Set(Some(String::from("pinned-certificate"))),
        row_count: Set(None),
        permission: Set(String::from("manage-endpoints")),
        action: Set(String::from("enroll-endpoint")),
        redfish_operation: Set(String::from("probe-core-capabilities")),
        outcome: Set(String::from("started")),
        progress: Set(None),
        failure: Set(None),
        verification: Set(None),
        occurred_at: Set(OffsetDateTime::now_utc()),
    }
    .insert(database)
    .await
}

/// Writes one terminal audit row in the §16 authentication-slice product
/// shape.
async fn insert_action_row(
    database: &DatabaseConnection,
    action: &str,
    permission: &str,
    failure: Option<&str>,
    outcome: &str,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(if outcome == "started" { 1 } else { 2 }),
        actor: Set(String::from("user")),
        actor_principal_id: Set(Some(Uuid::now_v7())),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("product")),
        target_endpoint_id: Set(None),
        target_endpoint_address: Set(None),
        parameter_kind: Set(String::from("endpoint-refresh")),
        credential_id: Set(None),
        trust_mode: Set(None),
        row_count: Set(None),
        permission: Set(permission.to_owned()),
        action: Set(action.to_owned()),
        redfish_operation: Set(String::from("none")),
        outcome: Set(outcome.to_owned()),
        progress: Set(None),
        failure: Set(failure.map(str::to_owned)),
        verification: Set(if outcome == "succeeded" {
            Some(String::from("confirmed"))
        } else if outcome == "failed" {
            Some(String::from("rejected"))
        } else {
            None
        }),
        occurred_at: Set(occurred_at),
    }
    .insert(database)
    .await
}

/// Opens one database in a fresh temporary directory.
///
/// The `TempDir` is returned with the connection so it outlives `connect`:
/// dropping it here would unlink the database file while the pool's eager
/// connection still holds it open — harmless on Windows (an open file cannot
/// be deleted), but on Linux the unlink succeeds and the first write
/// statement then fails while creating the rollback journal (the journal
/// open stats the journal path (database path plus "-journal"), which no longer exists, surfacing as
/// `SQLITE_IOERR_FSTAT` / "disk I/O error" on CI).
async fn connect() -> Result<(tempfile::TempDir, DatabaseConnection), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;
    Ok((directory, database))
}
