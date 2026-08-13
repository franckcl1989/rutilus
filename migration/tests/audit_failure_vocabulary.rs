use std::error::Error;

use rutilus_domain::AuditFailure;
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, QueryFilter, Set,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_FAILURE_VOCABULARY_MIGRATION: &str = "m20260813_000003_audit_failure_vocabulary";

/// The thirteen-code failure vocabulary, in the exact order the 000003
/// migration's `ck_audit_events_outcome` list carries it — the same order as
/// the `AuditFailure` enum in `rutilus-domain`. The test pins the list
/// against the enum in both directions: every domain variant's code is one
/// of these literals, and every literal parses as a domain variant, so a
/// code added on either side without the other fails the test.
const FAILURE_CODES: [&str; 13] = [
    "credential-unavailable",
    "tls-trust-failed",
    "redfish-discovery-failed",
    "endpoint-persistence-failed",
    "core-resource-read-failed",
    "snapshot-persistence-failed",
    "csv-invalid",
    "endpoint-import-row-failed",
    "center-store-failed",
    "center-request-refused",
    "authentication-failed",
    "session-revocation-failed",
    "capability-unsupported",
];

// The test walks the full failure vocabulary and the target-principal
// column, so it exceeds the pedantic line budget (same exception as the
// rebuild migrations' copy steps).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn full_failure_vocabulary_and_target_principal_persist_foreign_shapes_are_refused()
-> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // Direction 1 (domain → schema): every `AuditFailure` variant's stable
    // code is one of the thirteen pinned literals, and each code persists
    // through the real schema on a failed terminal event and reads back.
    for (variant, expected) in [
        (
            AuditFailure::CredentialUnavailable,
            "credential-unavailable",
        ),
        (AuditFailure::TlsTrustFailed, "tls-trust-failed"),
        (
            AuditFailure::RedfishDiscoveryFailed,
            "redfish-discovery-failed",
        ),
        (
            AuditFailure::EndpointPersistenceFailed,
            "endpoint-persistence-failed",
        ),
        (
            AuditFailure::CoreResourceReadFailed,
            "core-resource-read-failed",
        ),
        (
            AuditFailure::SnapshotPersistenceFailed,
            "snapshot-persistence-failed",
        ),
        (AuditFailure::CsvInvalid, "csv-invalid"),
        (
            AuditFailure::EndpointImportRowFailed,
            "endpoint-import-row-failed",
        ),
        (AuditFailure::CenterStoreFailed, "center-store-failed"),
        (AuditFailure::CenterRequestRefused, "center-request-refused"),
        (AuditFailure::AuthenticationFailed, "authentication-failed"),
        (
            AuditFailure::SessionRevocationFailed,
            "session-revocation-failed",
        ),
        (
            AuditFailure::CapabilityUnsupported,
            "capability-unsupported",
        ),
    ] {
        assert_eq!(variant.as_str(), expected);
        let inserted = insert_failed_execute_row(&database, expected, occurred_at).await?;
        let stored = rutilus_entity::audit_event::Entity::find_by_id(inserted.id)
            .one(&database)
            .await?
            .ok_or("inserted audit row is missing")?;
        assert_eq!(stored.failure.as_deref(), Some(expected));
        assert_eq!(stored.verification.as_deref(), Some("rejected"));
    }

    // Direction 2 (schema → domain): every pinned literal is a code the
    // domain vocabulary knows and parses back to itself, so the CHECK
    // cannot widen beyond the domain without the test refusing it.
    for code in FAILURE_CODES {
        assert_eq!(
            code.parse::<AuditFailure>().map(AuditFailure::as_str),
            Ok(code),
            "{code} is in the schema CHECK but not in the domain vocabulary"
        );
    }

    // A failure code the vocabulary does not know at all is refused.
    let unknown = insert_failed_execute_row(&database, "binding-code-expired", occurred_at).await;
    assert!(unknown.is_err(), "an unknown failure code must be refused");

    // The S3-4 target principal persists on a change-password row: the
    // administrator-issued password set records the user whose credential
    // was replaced under the action that names a distinct subject.
    let target_principal_id = Uuid::now_v7();
    let changed =
        insert_change_password_row(&database, Some(target_principal_id), occurred_at).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(changed.id)
        .one(&database)
        .await?
        .ok_or("inserted audit row is missing")?;
    assert_eq!(stored.target_principal_id, Some(target_principal_id));
    assert_eq!(stored.action, "change-password");
    assert!(stored.actor_principal_id.is_some());

    // A target principal under an action that names no subject distinct
    // from its actor is refused: the `ck_audit_events_target_principal`
    // CHECK pins the same shape rule the domain contract states.
    let misplaced = insert_login_with_target_row(&database, occurred_at).await;
    assert!(
        misplaced.is_err(),
        "a target principal under login must be refused"
    );

    Ok(())
}

#[tokio::test]
async fn rebuild_preserves_existing_audit_rows() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Apply every migration before the vocabulary rebuild: the audit table
    // still has the 000001 shapes, which the legacy rows prove — one
    // execution row and one failed center row under an 000001 failure code.
    // The step count is the migration's own registration position, so the
    // test stays correct however later slices extend the registration list.
    let steps = migrations_before(AUDIT_FAILURE_VOCABULARY_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    let execution_id = Uuid::now_v7();
    insert_raw_audit_row(
        &database,
        execution_id,
        "execute-operation",
        "execute-operations",
        "endpoint",
        Some(Uuid::now_v7()),
        "reset-system",
        None,
        "succeeded",
    )
    .await?;
    let center_failure_id = Uuid::now_v7();
    insert_raw_audit_row(
        &database,
        center_failure_id,
        "register-site-binding",
        "manage-center-bindings",
        "product",
        None,
        "none",
        Some("center-request-refused"),
        "failed",
    )
    .await?;

    // The rebuild preserves every legacy row, with the new target column
    // reading NULL.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(execution_id)
        .one(&database)
        .await?
        .ok_or("the legacy execution row must survive the rebuild")?;
    assert_eq!(stored.action, "execute-operation");
    assert_eq!(stored.redfish_operation, "reset-system");
    assert_eq!(stored.target_principal_id, None);
    let stored = rutilus_entity::audit_event::Entity::find_by_id(center_failure_id)
        .one(&database)
        .await?
        .ok_or("the legacy center row must survive the rebuild")?;
    assert_eq!(stored.action, "register-site-binding");
    assert_eq!(stored.failure.as_deref(), Some("center-request-refused"));
    assert_eq!(stored.target_principal_id, None);

    Ok(())
}

#[tokio::test]
async fn down_refuses_unrepresentable_rows_and_restores_the_000001_shapes()
-> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // Rows written in the widened shapes: the two new failure codes and one
    // change-password row carrying a target principal.
    let session_revocation =
        insert_failed_execute_row(&database, "session-revocation-failed", occurred_at).await?;
    let capability =
        insert_failed_execute_row(&database, "capability-unsupported", occurred_at).await?;
    insert_change_password_row(&database, Some(Uuid::now_v7()), occurred_at).await?;
    assert!(
        rutilus_entity::audit_event::Entity::find_by_id(session_revocation.id)
            .one(&database)
            .await?
            .is_some()
    );
    assert!(
        rutilus_entity::audit_event::Entity::find_by_id(capability.id)
            .one(&database)
            .await?
            .is_some()
    );

    // The down refuses the target-principal row: the restored 000001 shape
    // has no column for it, and silently dropping the target would falsify
    // the audit record rather than refuse it.
    let refused_target = Migrator::down(&database, Some(1)).await;
    assert!(
        refused_target.is_err(),
        "the down must refuse rows carrying a target principal"
    );
    rutilus_entity::audit_event::Entity::delete_many()
        .filter(rutilus_entity::audit_event::Column::TargetPrincipalId.is_not_null())
        .exec(&database)
        .await?;

    // Without the target row, the two new failure codes still refuse the
    // down: the restored eleven-code CHECK rejects them during the copy,
    // exactly like the 000001 down refuses its center rows.
    let refused_codes = Migrator::down(&database, Some(1)).await;
    assert!(
        refused_codes.is_err(),
        "the down must refuse rows carrying the new failure codes"
    );
    rutilus_entity::audit_event::Entity::delete_many()
        .exec(&database)
        .await?;
    Migrator::down(&database, Some(1)).await?;

    // The restored 000001 shape refuses the two new codes again while the
    // eleven codes it already knew stay accepted. The rows go through raw
    // SQL because the entity model names the `target_principal_id` column
    // the restored table no longer has (the product-users rollback's
    // precedent).
    for code in ["session-revocation-failed", "capability-unsupported"] {
        let refused = insert_raw_audit_row(
            &database,
            Uuid::now_v7(),
            "execute-operation",
            "execute-operations",
            "endpoint",
            Some(Uuid::now_v7()),
            "reset-system",
            Some(code),
            "failed",
        )
        .await;
        assert!(
            refused.is_err(),
            "the rolled-back schema must not know {code}"
        );
    }
    insert_raw_audit_row(
        &database,
        Uuid::now_v7(),
        "execute-operation",
        "execute-operations",
        "endpoint",
        Some(Uuid::now_v7()),
        "reset-system",
        Some("authentication-failed"),
        "failed",
    )
    .await?;
    // The restored table has no target column at all: an insert that names
    // it is refused by the schema itself.
    let no_column = database
        .execute_unprepared(&format!(
            "INSERT INTO audit_events \
             (id, operation_id, event_sequence, actor, actor_principal_id, \
              target_principal_id, origin, target_kind, target_endpoint_id, \
              target_endpoint_address, parameter_kind, credential_id, trust_mode, \
              row_count, permission, action, redfish_operation, outcome, progress, \
              failure, verification, occurred_at) \
             VALUES ('{id}', '{operation_id}', 2, 'user', '{principal}', \
              '{target}', 'standalone', 'product', NULL, NULL, 'endpoint-refresh', \
              NULL, NULL, NULL, 'authenticate', 'change-password', 'none', \
              'succeeded', NULL, NULL, 'confirmed', '2026-08-07 12:00:00')",
            id = Uuid::now_v7(),
            operation_id = Uuid::now_v7(),
            principal = Uuid::now_v7(),
            target = Uuid::now_v7(),
        ))
        .await;
    assert!(
        no_column.is_err(),
        "the rolled-back schema must have no target_principal_id column"
    );

    Ok(())
}

/// The number of registered migrations before the named migration.
fn migrations_before(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit failure vocabulary migration is not registered")?;
    Ok(u32::try_from(position)?)
}

/// Writes one failed terminal audit row in the §16.3 execution shape with
/// the given failure code.
async fn insert_failed_execute_row(
    database: &DatabaseConnection,
    failure: &str,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
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
        redfish_operation: Set(String::from("reset-system")),
        outcome: Set(String::from("failed")),
        progress: Set(None),
        failure: Set(Some(failure.to_owned())),
        verification: Set(Some(String::from("rejected"))),
        occurred_at: Set(occurred_at),
    }
    .insert(database)
    .await
}

/// Writes one succeeded `change-password` row in the §16.2 authentication
/// shape, optionally naming the principal whose credential was replaced
/// (S3-4).
async fn insert_change_password_row(
    database: &DatabaseConnection,
    target_principal_id: Option<Uuid>,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(2),
        actor: Set(String::from("user")),
        actor_principal_id: Set(Some(Uuid::now_v7())),
        target_principal_id: Set(target_principal_id),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("product")),
        target_endpoint_id: Set(None),
        target_endpoint_address: Set(None),
        parameter_kind: Set(String::from("endpoint-refresh")),
        credential_id: Set(None),
        trust_mode: Set(None),
        row_count: Set(None),
        permission: Set(String::from("authenticate")),
        action: Set(String::from("change-password")),
        redfish_operation: Set(String::from("none")),
        outcome: Set(String::from("succeeded")),
        progress: Set(None),
        failure: Set(None),
        verification: Set(Some(String::from("confirmed"))),
        occurred_at: Set(occurred_at),
    }
    .insert(database)
    .await
}

/// Writes one succeeded `login` row carrying a target principal — the shape
/// the `ck_audit_events_target_principal` CHECK must refuse.
async fn insert_login_with_target_row(
    database: &DatabaseConnection,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    rutilus_entity::audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(2),
        actor: Set(String::from("user")),
        actor_principal_id: Set(Some(Uuid::now_v7())),
        target_principal_id: Set(Some(Uuid::now_v7())),
        origin: Set(String::from("standalone")),
        target_kind: Set(String::from("product")),
        target_endpoint_id: Set(None),
        target_endpoint_address: Set(None),
        parameter_kind: Set(String::from("endpoint-refresh")),
        credential_id: Set(None),
        trust_mode: Set(None),
        row_count: Set(None),
        permission: Set(String::from("authenticate")),
        action: Set(String::from("login")),
        redfish_operation: Set(String::from("none")),
        outcome: Set(String::from("succeeded")),
        progress: Set(None),
        failure: Set(None),
        verification: Set(Some(String::from("confirmed"))),
        occurred_at: Set(occurred_at),
    }
    .insert(database)
    .await
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
    failure: Option<&str>,
    outcome: &str,
) -> Result<(), sea_orm::DbErr> {
    let target_endpoint = match target_endpoint_id {
        Some(target_endpoint_id) => format!("X'{}'", target_endpoint_id.simple()),
        None => String::from("NULL"),
    };
    let failure = match failure {
        Some(code) => format!("'{code}'"),
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
              {failure}, {verification}, '2026-08-07 12:00:00')",
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
