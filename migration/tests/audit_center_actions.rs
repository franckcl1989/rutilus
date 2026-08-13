use std::error::Error;

use rutilus_migration::Migrator;
use sea_orm::{ActiveModelTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_CENTER_ACTIONS_MIGRATION: &str = "m20260813_000001_audit_center_actions";

// The test walks the full §15.6 audit lifecycle — enroll, bind, dispatch,
// and the foreign-shape refusals — so it exceeds the pedantic line budget
// (same exception as the rebuild migrations' copy steps).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn center_action_shapes_persist_and_foreign_shapes_are_refused() -> Result<(), Box<dyn Error>>
{
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // The three 0.7.0 center-console shapes the domain matrix accepts
    // persist and read back: binding registration and revocation under the
    // product target and the `manage-center-bindings` permission, and the
    // §15.6 dispatch under the endpoint target and the
    // `dispatch-center-operations` permission.
    for (action, permission, target_kind) in [
        ("register-site-binding", "manage-center-bindings", "product"),
        ("revoke-site-binding", "manage-center-bindings", "product"),
        (
            "dispatch-center-operation",
            "dispatch-center-operations",
            "endpoint",
        ),
    ] {
        let inserted = insert_center_row(
            &database,
            action,
            permission,
            target_kind,
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
        assert_eq!(stored.target_kind, target_kind);
        assert_eq!(stored.redfish_operation, "none");
        assert_eq!(stored.parameter_kind, "endpoint-refresh");
        assert_eq!(stored.verification.as_deref(), Some("confirmed"));
    }

    // The two center failure codes persist on failed terminal events.
    for (action, failure) in [
        ("register-site-binding", "center-store-failed"),
        ("dispatch-center-operation", "center-request-refused"),
    ] {
        let failed = insert_center_row(
            &database,
            action,
            if action == "dispatch-center-operation" {
                "dispatch-center-operations"
            } else {
                "manage-center-bindings"
            },
            if action == "dispatch-center-operation" {
                "endpoint"
            } else {
                "product"
            },
            Some(failure),
            "failed",
            occurred_at,
        )
        .await?;
        let stored = rutilus_entity::audit_event::Entity::find_by_id(failed.id)
            .one(&database)
            .await?
            .ok_or("inserted audit row is missing")?;
        assert_eq!(stored.failure.as_deref(), Some(failure));
    }

    // A binding action under a foreign permission is refused: the action
    // CHECK pins the same shapes as the domain consistency matrix.
    let wrong_permission = insert_center_row(
        &database,
        "register-site-binding",
        "manage-users",
        "product",
        None,
        "succeeded",
        occurred_at,
    )
    .await;
    assert!(
        wrong_permission.is_err(),
        "a binding registration under manage-users must be refused"
    );

    // A dispatch is refused when it names a Redfish operation: the center
    // never executes anything, it offers, and the site decides (§15.6).
    let mut wrong_operation = center_row(
        Uuid::now_v7(),
        "dispatch-center-operation",
        "dispatch-center-operations",
        "endpoint",
        None,
        "succeeded",
        occurred_at,
    );
    wrong_operation.redfish_operation = Set(String::from("reset-system"));
    assert!(
        wrong_operation.insert(&database).await.is_err(),
        "a dispatch under a write operation must be refused"
    );

    // A failure code the vocabulary does not know at all is refused.
    let unknown_failure = insert_center_row(
        &database,
        "register-site-binding",
        "manage-center-bindings",
        "product",
        Some("binding-code-expired"),
        "failed",
        occurred_at,
    )
    .await;
    assert!(
        unknown_failure.is_err(),
        "an unknown failure code must be refused"
    );

    // Roll back through the center-shape migration: the rows written in the
    // center shapes cannot be represented in the restored 000008 schema, so
    // they are removed first (the documented restore contract refuses them,
    // exactly like the execution-shape rollback).
    rutilus_entity::audit_event::Entity::delete_many()
        .exec(&database)
        .await?;
    let steps = rollback_steps_to(AUDIT_CENTER_ACTIONS_MIGRATION)?;
    Migrator::down(&database, Some(steps)).await?;

    // The restored 000008 schema refuses the center shapes again, while the
    // execution shape it gained stays accepted.
    let refused = insert_center_row(
        &database,
        "register-site-binding",
        "manage-center-bindings",
        "product",
        None,
        "succeeded",
        occurred_at,
    )
    .await;
    assert!(
        refused.is_err(),
        "the rolled-back schema must not know the center actions"
    );
    let execution = insert_execute_row(&database, "reset-system", occurred_at).await?;
    assert_eq!(execution.action, "execute-operation");
    assert_eq!(execution.permission, "execute-operations");

    Ok(())
}

#[tokio::test]
async fn center_rebuild_preserves_existing_audit_rows() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Apply every migration before the center-shape rebuild: the audit
    // table still has the 000008 shapes, which the legacy row proves. The
    // step count is the center migration's own registration position, so
    // the test stays correct however later slices extend the registration
    // list.
    let steps = migrations_before(AUDIT_CENTER_ACTIONS_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    let row = insert_execute_row(&database, "update-firmware", OffsetDateTime::now_utc()).await?;
    assert_eq!(row.action, "execute-operation");
    assert_eq!(row.verification.as_deref(), Some("confirmed"));

    // The rebuild preserves every legacy row.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(row.id)
        .one(&database)
        .await?
        .ok_or("the legacy audit row must survive the rebuild")?;
    assert_eq!(stored.action, "execute-operation");
    assert_eq!(stored.redfish_operation, "update-firmware");

    Ok(())
}

/// The number of registered migrations before the named migration.
fn migrations_before(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit center actions migration is not registered")?;
    Ok(u32::try_from(position)?)
}

/// The number of registered migrations to roll back so the named migration
/// is included in the rollback: everything registered after it, plus itself.
fn rollback_steps_to(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit center actions migration is not registered")?;
    Ok(u32::try_from(migrations.len() - position)?)
}

/// Writes one terminal audit row in a 0.7.0 center-console shape: the
/// product target for binding management, the endpoint target for the
/// §15.6 dispatch, and the given failure when the outcome is `failed`.
async fn insert_center_row(
    database: &DatabaseConnection,
    action: &str,
    permission: &str,
    target_kind: &str,
    failure: Option<&str>,
    outcome: &str,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    center_row(
        Uuid::now_v7(),
        action,
        permission,
        target_kind,
        failure,
        outcome,
        occurred_at,
    )
    .insert(database)
    .await
}

/// One terminal center-console audit row as an insertable active model.
fn center_row(
    id: Uuid,
    action: &str,
    permission: &str,
    target_kind: &str,
    failure: Option<&str>,
    outcome: &str,
    occurred_at: OffsetDateTime,
) -> rutilus_entity::audit_event::ActiveModel {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(id),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(if outcome == "started" { 1 } else { 2 }),
        actor: Set(String::from("user")),
        actor_principal_id: Set(Some(Uuid::now_v7())),
        origin: Set(String::from("center")),
        target_kind: Set(target_kind.to_owned()),
        target_endpoint_id: Set(if target_kind == "endpoint" {
            Some(Uuid::now_v7())
        } else {
            None
        }),
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
}

/// Writes one terminal audit row in the §16.3 execution shape, the
/// pre-center schema's vocabulary.
async fn insert_execute_row(
    database: &DatabaseConnection,
    redfish_operation: &str,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(2),
        actor: Set(String::from("system")),
        actor_principal_id: Set(None),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("endpoint")),
        target_endpoint_id: Set(Some(Uuid::now_v7())),
        target_endpoint_address: Set(None),
        parameter_kind: Set(String::from("endpoint-refresh")),
        credential_id: Set(None),
        trust_mode: Set(None),
        row_count: Set(None),
        permission: Set(String::from("execute-operations")),
        action: Set(String::from("execute-operation")),
        redfish_operation: Set(redfish_operation.to_owned()),
        outcome: Set(String::from("succeeded")),
        progress: Set(None),
        failure: Set(None),
        verification: Set(Some(String::from("confirmed"))),
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
