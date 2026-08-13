use std::error::Error;

use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait,
    Set,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_EXECUTE_OPERATION_MIGRATION: &str = "m20260807_000008_audit_execute_operation";

/// The fourteen-code §7.5/§11.5/§13.6 execution family, transcribed from the
/// domain consistency matrix: every code an `execute-operation` row may
/// carry, and exactly the codes the widened CHECK accepts.
const EXECUTE_OPERATION_CODES: [&str; 14] = [
    "reset-system",
    "reset-manager",
    "reset-chassis",
    "set-boot-source-override",
    "secure-boot-enable",
    "secure-boot-disable",
    "secure-boot-reset-keys",
    "create-event-subscription",
    "delete-event-subscription",
    "update-firmware",
    "oem-system-config-profile",
    "oem-debug-token",
    "oem-power-smoothing",
    "poll-remote-task",
];

#[tokio::test]
async fn execute_operation_shapes_persist_and_foreign_shapes_are_refused()
-> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // Every write-family code the domain consistency matrix accepts persists
    // and reads back with the full execution shape: the endpoint target, the
    // closest legal parameter summary, the `execute-operations` permission,
    // and the `execute-operation` action.
    for code in EXECUTE_OPERATION_CODES {
        let inserted = insert_execute_row(&database, code, occurred_at).await?;
        let stored = rutilus_entity::audit_event::Entity::find_by_id(inserted.id)
            .one(&database)
            .await?
            .ok_or("inserted audit row is missing")?;
        assert_eq!(stored.action, "execute-operation");
        assert_eq!(stored.permission, "execute-operations");
        assert_eq!(stored.redfish_operation, code);
        assert_eq!(stored.target_kind, "endpoint");
        assert!(stored.target_endpoint_id.is_some());
        assert_eq!(stored.parameter_kind, "endpoint-refresh");
        assert_eq!(stored.verification.as_deref(), Some("confirmed"));
    }

    // A non-write operation code is refused under the execution action: the
    // read and discovery codes belong to their own actions.
    for foreign_code in ["none", "probe-core-capabilities", "read-core-resources"] {
        let refused = insert_execute_row(&database, foreign_code, occurred_at).await;
        assert!(
            refused.is_err(),
            "an execution under {foreign_code} must be refused"
        );
    }

    // An execution under a foreign permission is refused: the action CHECK
    // pins the same shapes as the domain consistency matrix.
    let mut wrong_permission = execute_row(Uuid::now_v7(), "reset-system", occurred_at);
    wrong_permission.permission = Set(String::from("manage-endpoints"));
    assert!(
        wrong_permission.insert(&database).await.is_err(),
        "an execution under manage-endpoints must be refused"
    );

    // An action value the vocabulary does not know at all is refused.
    let mut unknown_action = execute_row(Uuid::now_v7(), "reset-system", occurred_at);
    unknown_action.action = Set(String::from("export-audit"));
    assert!(
        unknown_action.insert(&database).await.is_err(),
        "an unknown action must be refused"
    );

    // Roll back through the execution-shape migration: the rows written in
    // the execution shape cannot be represented in the restored 000007
    // schema, so they are removed first (the documented restore contract
    // refuses them, exactly like the action-shapes rollback).
    rutilus_entity::audit_event::Entity::delete_many()
        .exec(&database)
        .await?;
    let steps = rollback_steps_to(AUDIT_EXECUTE_OPERATION_MIGRATION)?;
    Migrator::down(&database, Some(steps)).await?;

    // The restored 000007 schema refuses the execution shape again, while
    // the authentication shapes it gained stay accepted. The rows go through
    // raw SQL because the entity model names the `target_principal_id`
    // column the restored table no longer has (the product-users rollback's
    // precedent).
    let refused = insert_raw_audit_row(
        &database,
        Uuid::now_v7(),
        "execute-operation",
        "execute-operations",
        "endpoint",
        Some(Uuid::now_v7()),
        "reset-system",
        "succeeded",
    )
    .await;
    assert!(
        refused.is_err(),
        "the rolled-back schema must not know the execution shape"
    );
    insert_raw_audit_row(
        &database,
        Uuid::now_v7(),
        "login",
        "authenticate",
        "product",
        None,
        "none",
        "succeeded",
    )
    .await?;

    Ok(())
}

#[tokio::test]
async fn execute_rebuild_preserves_existing_audit_rows() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Apply every migration before the execution-shape rebuild: the audit
    // table still has the 000007 shapes, which the legacy row proves. The
    // step count is the execution migration's own registration position, so
    // the test stays correct however later slices extend the registration
    // list.
    let steps = migrations_before(AUDIT_EXECUTE_OPERATION_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    let legacy_id = Uuid::now_v7();
    insert_raw_audit_row(
        &database,
        legacy_id,
        "manage-settings",
        "manage-site-settings",
        "product",
        None,
        "none",
        "succeeded",
    )
    .await?;

    // The rebuild preserves every legacy row.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(legacy_id)
        .one(&database)
        .await?
        .ok_or("the legacy audit row must survive the rebuild")?;
    assert_eq!(stored.action, "manage-settings");
    assert_eq!(stored.permission, "manage-site-settings");

    Ok(())
}

/// The number of registered migrations before the named migration.
fn migrations_before(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit execute-operation migration is not registered")?;
    Ok(u32::try_from(position)?)
}

/// The number of registered migrations to roll back so the named migration
/// is included in the rollback: everything registered after it, plus itself.
fn rollback_steps_to(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit execute-operation migration is not registered")?;
    Ok(u32::try_from(migrations.len() - position)?)
}

/// Writes one terminal audit row in the §16.3 execution shape: the endpoint
/// target, the closest legal parameter summary, the `execute-operations`
/// permission, and the given §7.5/§11.5/§13.6 operation code.
async fn insert_execute_row(
    database: &DatabaseConnection,
    redfish_operation: &str,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    execute_row(Uuid::now_v7(), redfish_operation, occurred_at)
        .insert(database)
        .await
}

/// One terminal `execute-operation` row as an insertable active model.
fn execute_row(
    id: Uuid,
    redfish_operation: &str,
    occurred_at: OffsetDateTime,
) -> rutilus_entity::audit_event::ActiveModel {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(id),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(2),
        actor: Set(String::from("system")),
        actor_principal_id: Set(None),
        target_principal_id: Set(None),
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
