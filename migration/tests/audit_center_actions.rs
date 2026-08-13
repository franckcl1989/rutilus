use std::error::Error;

use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait,
    Set,
};
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
    // execution shape it gained stays accepted. The rows go through raw SQL
    // because the entity model names the `target_principal_id` column the
    // restored table no longer has (the product-users rollback's
    // precedent).
    let refused = insert_raw_audit_row(
        &database,
        Uuid::now_v7(),
        "register-site-binding",
        "manage-center-bindings",
        "product",
        None,
        "none",
        "succeeded",
    )
    .await;
    assert!(
        refused.is_err(),
        "the rolled-back schema must not know the center actions"
    );
    insert_raw_audit_row(
        &database,
        Uuid::now_v7(),
        "execute-operation",
        "execute-operations",
        "endpoint",
        Some(Uuid::now_v7()),
        "reset-system",
        "succeeded",
    )
    .await?;

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
    let legacy_id = Uuid::now_v7();
    insert_raw_audit_row(
        &database,
        legacy_id,
        "execute-operation",
        "execute-operations",
        "endpoint",
        Some(Uuid::now_v7()),
        "update-firmware",
        "succeeded",
    )
    .await?;

    // The rebuild preserves every legacy row.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(legacy_id)
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
        target_principal_id: Set(None),
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

/// Writes one terminal audit row through raw SQL — the only way to write to
/// an `audit_events` schema without the `target_principal_id` column, which
/// the entity model names (the product-users rollback's precedent).
#[allow(clippy::too_many_arguments)]
async fn insert_raw_audit_row(
    database: &DatabaseConnection,
    id: Uuid,
    action: &str,
    permission: &str,
    target_kind: &str,
    target_endpoint_id: Option<Uuid>,
    redfish_operation: &str,
    outcome: &str,
) -> Result<(), sea_orm::DbErr> {
    let target_endpoint = match target_endpoint_id {
        Some(target_endpoint_id) => format!("X'{}'", target_endpoint_id.simple()),
        None => String::from("NULL"),
    };
    let verification = if outcome == "succeeded" {
        "'confirmed'"
    } else {
        "'rejected'"
    };
    database
        .execute_unprepared(&format!(
            "INSERT INTO audit_events \
             (id, operation_id, event_sequence, actor, actor_principal_id, origin, \
              target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
              credential_id, trust_mode, row_count, permission, action, redfish_operation, \
              outcome, progress, failure, verification, occurred_at) \
             VALUES (X'{id}', X'{operation_id}', 2, 'system', NULL, 'standalone', \
              '{target_kind}', {target_endpoint}, NULL, 'endpoint-refresh', NULL, NULL, \
              NULL, '{permission}', '{action}', '{redfish_operation}', '{outcome}', NULL, \
              NULL, {verification}, '2026-08-07 12:00:00')",
            id = id.simple(),
            operation_id = Uuid::now_v7().simple(),
        ))
        .await
        .map(|_| ())
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
