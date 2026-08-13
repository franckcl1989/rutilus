use std::error::Error;

use rutilus_domain::{
    AuditAction, AuditActor, AuditOperationContext, AuditOperationId, AuditParameterSummary,
    AuditRedfishOperation, AuditTarget, DeploymentPosture, EndpointId, ProductPermission,
};
use rutilus_migration::{AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL, Migrator};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, ConnectionTrait, Database, DatabaseConnection,
    EntityTrait, PaginatorTrait, QueryFilter, Set,
};
use sea_orm_migration::MigratorTrait;
use time::OffsetDateTime;
use uuid::Uuid;

const AUDIT_OPERATION_VOCABULARY_MIGRATION: &str = "m20260813_000004_audit_operation_vocabulary";

/// The exhaustive domain-side enumeration of [`AuditRedfishOperation`]: the
/// `match` has no wildcard arm, so adding a variant to the domain enum
/// fails this file's compilation instead of silently leaving the
/// schema-binding expectations stale — the exhaustive-pin style the domain
/// consistency matrix itself uses.
fn pin_redfish_operation_vocabulary(operation: AuditRedfishOperation) {
    use AuditRedfishOperation::{
        ControlUpdate, CreateAccount, CreateEventSubscription, CreateMetricDefinition,
        CreateMetricReportDefinition, DeleteAccount, DeleteEventSubscription,
        DeleteMetricDefinition, DeleteMetricReportDefinition, LogClear, ManagerResetToDefaults,
        None as NoOperation, OemDebugToken, OemPowerSmoothing, OemSystemConfigProfile,
        PollRemoteTask, PowerSupplyReset, ProbeCoreCapabilities, ReadCoreResources, ResetChassis,
        ResetManager, ResetSystem, SecureBootDisable, SecureBootEnable, SecureBootResetKeys,
        SetBootSourceOverride, SetTelemetryEnabled, UpdateAccount, UpdateAccountPassword,
        UpdateAccountUserName, UpdateFirmware, UpdateMetricDefinition,
        UpdateMetricReportDefinition, UpdateServicePatch,
    };
    match operation {
        NoOperation
        | ProbeCoreCapabilities
        | ReadCoreResources
        | CreateAccount
        | UpdateAccount
        | UpdateAccountPassword
        | UpdateAccountUserName
        | DeleteAccount
        | ResetSystem
        | ResetManager
        | ManagerResetToDefaults
        | ResetChassis
        | PowerSupplyReset
        | SetBootSourceOverride
        | SecureBootEnable
        | SecureBootDisable
        | SecureBootResetKeys
        | CreateEventSubscription
        | DeleteEventSubscription
        | LogClear
        | ControlUpdate
        | SetTelemetryEnabled
        | CreateMetricDefinition
        | UpdateMetricDefinition
        | DeleteMetricDefinition
        | CreateMetricReportDefinition
        | UpdateMetricReportDefinition
        | DeleteMetricReportDefinition
        | UpdateFirmware
        | UpdateServicePatch
        | OemSystemConfigProfile
        | OemDebugToken
        | OemPowerSmoothing
        | PollRemoteTask => {}
    }
}

/// Every [`AuditRedfishOperation`] variant, in enum order — the iteration
/// list of the schema-binding tests. [`pin_redfish_operation_vocabulary`]
/// makes the list compile-exhaustive: a variant added to the enum fails the
/// pin's `match` whether or not this list is updated, so the two sides of
/// the binding can never drift silently. The vocabulary holds thirty-four
/// codes: the thirty-one execution codes and the three non-execution codes
/// (`none`, the two discovery reads).
const ALL_REDFISH_OPERATIONS: [AuditRedfishOperation; 34] = [
    AuditRedfishOperation::None,
    AuditRedfishOperation::ProbeCoreCapabilities,
    AuditRedfishOperation::ReadCoreResources,
    AuditRedfishOperation::CreateAccount,
    AuditRedfishOperation::UpdateAccount,
    AuditRedfishOperation::UpdateAccountPassword,
    AuditRedfishOperation::UpdateAccountUserName,
    AuditRedfishOperation::DeleteAccount,
    AuditRedfishOperation::ResetSystem,
    AuditRedfishOperation::ResetManager,
    AuditRedfishOperation::ManagerResetToDefaults,
    AuditRedfishOperation::ResetChassis,
    AuditRedfishOperation::PowerSupplyReset,
    AuditRedfishOperation::SetBootSourceOverride,
    AuditRedfishOperation::SecureBootEnable,
    AuditRedfishOperation::SecureBootDisable,
    AuditRedfishOperation::SecureBootResetKeys,
    AuditRedfishOperation::CreateEventSubscription,
    AuditRedfishOperation::DeleteEventSubscription,
    AuditRedfishOperation::LogClear,
    AuditRedfishOperation::ControlUpdate,
    AuditRedfishOperation::SetTelemetryEnabled,
    AuditRedfishOperation::CreateMetricDefinition,
    AuditRedfishOperation::UpdateMetricDefinition,
    AuditRedfishOperation::DeleteMetricDefinition,
    AuditRedfishOperation::CreateMetricReportDefinition,
    AuditRedfishOperation::UpdateMetricReportDefinition,
    AuditRedfishOperation::DeleteMetricReportDefinition,
    AuditRedfishOperation::UpdateFirmware,
    AuditRedfishOperation::UpdateServicePatch,
    AuditRedfishOperation::OemSystemConfigProfile,
    AuditRedfishOperation::OemDebugToken,
    AuditRedfishOperation::OemPowerSmoothing,
    AuditRedfishOperation::PollRemoteTask,
];

/// Whether the domain consistency matrix accepts the given operation under
/// the §16.3 execution shape.
///
/// The oracle is the real constructor — `AuditOperationContext::try_new`
/// runs the domain's own matrix — so the expected code set is generated by
/// the domain itself, never by a transcription that could drift with it.
fn domain_accepts_execution(operation: AuditRedfishOperation) -> bool {
    AuditOperationContext::try_new(
        AuditOperationId::generate(),
        AuditActor::System,
        DeploymentPosture::Standalone,
        AuditTarget::Endpoint(EndpointId::generate()),
        AuditParameterSummary::EndpointRefresh,
        ProductPermission::ExecuteOperations,
        AuditAction::ExecuteOperation,
        operation,
    )
    .is_ok()
}

/// The codes of one `IN (...)` list inside a `CREATE TABLE` DDL, anchored on
/// the constrained column — the schema side of the domain↔CHECK binding,
/// read from the real DDL instead of a transcribed list, so the test
/// compares the actual CHECK against the actual domain vocabulary.
fn in_list_codes(ddl: &str, anchor: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let marker = format!("{anchor} IN (");
    let start = ddl
        .find(&marker)
        .ok_or_else(|| format!("no `{marker}` list in the DDL"))?
        + marker.len();
    // The list's literals nest no parentheses, so the first `)` closes it.
    let end = ddl[start..]
        .find(')')
        .ok_or_else(|| format!("the `{anchor} IN (` list is not closed"))?
        + start;
    Ok(ddl[start..end]
        .split(',')
        .map(|code| code.trim().trim_matches('\'').to_owned())
        .collect())
}

/// The `CREATE TABLE audit_events` statement of the live schema.
async fn live_audit_events_ddl(database: &DatabaseConnection) -> Result<String, Box<dyn Error>> {
    use sea_orm::sea_query::{Alias, Expr, Query};
    let statement = Query::select()
        .expr(Expr::cust("sql"))
        .from(Alias::new("sqlite_master"))
        .cond_where(Expr::cust("type = 'table' AND name = 'audit_events'"))
        .to_owned();
    let row = database
        .query_one(&statement)
        .await?
        .ok_or("audit_events is not in the live schema")?;
    Ok(row.try_get_by_index(0)?)
}

/// The `redfish_operation IN (...)` codes of the live `audit_events` CHECK.
async fn live_execution_check_codes(
    database: &DatabaseConnection,
) -> Result<Vec<String>, Box<dyn Error>> {
    in_list_codes(&live_audit_events_ddl(database).await?, "redfish_operation")
}

/// The 000003 forward DDL, extracted from the migration source on disk — the
/// shape the 000004 `down` must restore byte for byte. The source walk is
/// relative to `CARGO_MANIFEST_DIR`, the same pattern the static gates use.
fn extract_000003_forward_ddl() -> Result<String, Box<dyn Error>> {
    const MARKER: &str = "const AUDIT_EVENTS_VOCABULARY_DDL: &str = r\"";
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/m20260813_000003_audit_failure_vocabulary.rs"),
    )?;
    let start = source
        .find(MARKER)
        .ok_or("the 000003 forward DDL const is not in the migration source")?
        + MARKER.len();
    // The DDL holds no double quotes (SQL single-quoted literals only), so
    // the raw literal ends at the first `";` after its start.
    let end = source[start..]
        .find("\";")
        .ok_or("the 000003 forward DDL literal is not terminated")?
        + start;
    Ok(source[start..end].to_owned())
}

/// The two rebuild staging names unified — the only difference the 000004
/// `down` may have from the 000003 forward shape — and every whitespace run
/// collapsed to one space, so the comparison is byte-exact on the shape and
/// blind to layout.
fn normalize_staging_ddl(ddl: &str) -> String {
    ddl.replace("audit_events_vocabulary", "audit_events_staging")
        .replace("audit_events_previous", "audit_events_staging")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// The schema-binding test walks the full operation vocabulary in both
// directions and reads the real CHECK out of the live schema, so it exceeds
// the pedantic line budget (same exception as the rebuild migrations' copy
// steps).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn operation_vocabulary_binds_the_domain_matrix_and_persists() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // Direction 1 (domain → schema), generated by the domain itself: every
    // operation variant is inserted under the execution shape, and the
    // schema's accept/reject is compared against the consistency matrix's
    // accept/reject — a code added to either side without the other fails
    // the test, and the comparison cannot be fooled by a stale code list
    // because the expected set comes from the matrix, not from a literal.
    let mut expected_codes: Vec<&str> = Vec::new();
    let mut refused_codes: Vec<&str> = Vec::new();
    for operation in ALL_REDFISH_OPERATIONS {
        pin_redfish_operation_vocabulary(operation);
        let code = operation.as_str();
        let domain_accepts = domain_accepts_execution(operation);
        let inserted = insert_execute_row(&database, code, occurred_at).await;
        match (domain_accepts, inserted) {
            (true, Ok(inserted)) => {
                expected_codes.push(code);
                let stored = rutilus_entity::audit_event::Entity::find_by_id(inserted.id)
                    .one(&database)
                    .await?
                    .ok_or("inserted audit row is missing")?;
                assert_eq!(stored.action, "execute-operation");
                assert_eq!(stored.permission, "execute-operations");
                assert_eq!(stored.redfish_operation, *code);
                assert_eq!(stored.target_kind, "endpoint");
                assert!(stored.target_endpoint_id.is_some());
                assert_eq!(stored.parameter_kind, "endpoint-refresh");
                assert_eq!(stored.verification.as_deref(), Some("confirmed"));
            }
            (false, Err(_)) => refused_codes.push(code),
            (true, Err(error)) => {
                return Err(format!(
                    "the schema refused {code}, which the domain matrix accepts: {error}"
                )
                .into());
            }
            (false, Ok(_)) => {
                return Err(
                    format!("the schema accepted {code}, which the domain matrix refuses").into(),
                );
            }
        }
    }
    // The matrix's execution arm is exactly 31 codes: the thirty §7.5/§14.4
    // write families and the §13.6 poll. The three other operations — the
    // `none` placeholder and the two discovery reads — belong to their own
    // actions, so the schema must refuse them under the execution shape.
    assert_eq!(
        expected_codes.len(),
        31,
        "the domain matrix must accept exactly 31 execution codes"
    );
    assert_eq!(
        refused_codes.len(),
        3,
        "the domain matrix must refuse exactly the three non-execution codes"
    );

    // Direction 2 (schema → domain): the `redfish_operation IN (...)` list
    // of the live CHECK, read from the schema's own DDL, must be exactly the
    // matrix's execution codes — the CHECK cannot carry a code the domain
    // does not accept under the execution shape without the test refusing it.
    let mut expected_sorted = expected_codes.clone();
    expected_sorted.sort_unstable();
    let mut schema_sorted = live_execution_check_codes(&database).await?;
    schema_sorted.sort_unstable();
    assert_eq!(
        expected_sorted, schema_sorted,
        "the live CHECK must accept exactly the domain matrix's execution codes"
    );

    // A code the vocabulary does not know at all is refused under the
    // execution shape.
    for foreign_code in ["firmware-rollback", "remote-firmware-update"] {
        let refused = insert_execute_row(&database, foreign_code, occurred_at).await;
        assert!(
            refused.is_err(),
            "an execution under {foreign_code} must be refused"
        );
    }

    Ok(())
}

#[tokio::test]
async fn operation_rebuild_preserves_existing_audit_rows() -> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;

    // Apply every migration before the operation-vocabulary rebuild: the
    // audit table still has the 000003 shape, which the legacy rows prove —
    // one execution row under an 000003 operation code and one
    // change-password row carrying the S3-4 target principal under the
    // acting administrator's user actor. The step count is the migration's
    // own registration position, so the test stays correct however later
    // slices extend the registration list.
    let steps = migrations_before(AUDIT_OPERATION_VOCABULARY_MIGRATION)?;
    Migrator::up(&database, Some(steps)).await?;
    let occurred_at = OffsetDateTime::now_utc();
    let execution_id = insert_execute_row(&database, "reset-system", occurred_at).await?;
    let target_principal_id = Uuid::now_v7();
    let changed =
        insert_change_password_row(&database, "user", Some(target_principal_id), occurred_at)
            .await?;

    // The rebuild preserves every legacy row: the execution row keeps its
    // operation code, and the change-password row keeps its target
    // principal — the actor rule is satisfied by the real row, so the copy
    // is a pure data-preserving operation.
    Migrator::up(&database, None).await?;
    let stored = rutilus_entity::audit_event::Entity::find_by_id(execution_id.id)
        .one(&database)
        .await?
        .ok_or("the legacy execution row must survive the rebuild")?;
    assert_eq!(stored.action, "execute-operation");
    assert_eq!(stored.redfish_operation, "reset-system");
    let stored = rutilus_entity::audit_event::Entity::find_by_id(changed.id)
        .one(&database)
        .await?
        .ok_or("the legacy change-password row must survive the rebuild")?;
    assert_eq!(stored.action, "change-password");
    assert_eq!(stored.actor, "user");
    assert_eq!(stored.target_principal_id, Some(target_principal_id));

    // The actor rule: a target principal under a non-user actor is refused
    // — the CHECK pins that a target names the principal a `User`-actor
    // action changes (S3-4), never a subject a system or local-operator
    // actor changed.
    let system_actor_target =
        insert_change_password_row(&database, "system", Some(Uuid::now_v7()), occurred_at).await;
    assert!(
        system_actor_target.is_err(),
        "a target principal under a non-user actor must be refused"
    );

    Ok(())
}

// The down test walks the full vocabulary through the refusal and the
// data-preserving copy, so it exceeds the pedantic line budget (same
// exception as the rebuild migrations' copy steps).
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn down_refuses_new_codes_with_migration_context_and_preserves_representable_rows()
-> Result<(), Box<dyn Error>> {
    let (_directory, database) = connect().await?;
    Migrator::up(&database, None).await?;
    let occurred_at = OffsetDateTime::now_utc();

    // One row per domain execution code: the full widened vocabulary.
    // The restored-shape boundary is read from the down DDL itself, so the
    // test's idea of "representable" is the actual restored CHECK.
    let restored_codes = in_list_codes(
        AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL,
        "redfish_operation",
    )?;
    let mut written: Vec<(String, Uuid)> = Vec::new();
    for operation in ALL_REDFISH_OPERATIONS {
        if domain_accepts_execution(operation) {
            let code = operation.as_str();
            let inserted = insert_execute_row(&database, code, occurred_at).await?;
            written.push((code.to_owned(), inserted.id));
        }
    }

    // The down refuses while a widened row remains: the restored 000003
    // shape cannot represent the seventeen later codes. The refusal names
    // the migration and the restored shape — the pre-check's observability
    // convention — so a rolled-back deployment sees why the rollback stops.
    let refused = Migrator::down(&database, Some(1)).await;
    let message = match refused {
        Err(sea_orm::DbErr::Custom(message)) => message,
        Err(other) => return Err(format!("the down must refuse, got: {other}").into()),
        Ok(()) => return Err("the down must refuse rows with the new codes".into()),
    };
    assert!(
        message.contains("000004 down"),
        "the refusal must name the migration, got: {message}"
    );
    assert!(
        message.contains("000003 shape"),
        "the refusal must name the restored shape, got: {message}"
    );

    // Remove the unrepresentable rows — the codes the restored shape does
    // not know — and the down copies everything else: the representable
    // rows survive the rebuild byte for byte.
    let new_codes: Vec<String> = written
        .iter()
        .filter(|(code, _)| !restored_codes.contains(code))
        .map(|(code, _)| code.clone())
        .collect();
    assert_eq!(new_codes.len(), 17, "exactly the seventeen widened codes");
    for (code, id) in &written {
        if new_codes.contains(code) {
            rutilus_entity::audit_event::Entity::delete_by_id(*id)
                .exec(&database)
                .await?;
        }
    }
    Migrator::down(&database, Some(1)).await?;

    // Every restored-shape row reads back with the full execution shape.
    let count = rutilus_entity::audit_event::Entity::find()
        .count(&database)
        .await?;
    assert_eq!(
        count,
        u64::try_from(restored_codes.len())?,
        "the down must keep every representable row"
    );
    for code in &restored_codes {
        let stored = rutilus_entity::audit_event::Entity::find()
            .filter(rutilus_entity::audit_event::Column::RedfishOperation.eq(code))
            .one(&database)
            .await?
            .ok_or_else(|| format!("the restored row for {code} is missing"))?;
        assert_eq!(stored.action, "execute-operation");
        assert_eq!(stored.permission, "execute-operations");
        assert_eq!(stored.redfish_operation, *code);
        assert_eq!(stored.target_kind, "endpoint");
        assert!(stored.target_endpoint_id.is_some());
        assert_eq!(stored.parameter_kind, "endpoint-refresh");
        assert_eq!(stored.verification.as_deref(), Some("confirmed"));
    }

    // The restored 000003 shape refuses the widened codes again while the
    // fourteen codes it already knew stay accepted, and its target-principal
    // CHECK is the action-only 000003 rule (the target column survives the
    // rollback).
    for code in &new_codes {
        let refused = insert_execute_row(&database, code, occurred_at).await;
        assert!(
            refused.is_err(),
            "the rolled-back schema must not know {code}"
        );
    }
    insert_execute_row(&database, "reset-system", occurred_at).await?;
    insert_change_password_row(&database, "user", Some(Uuid::now_v7()), occurred_at).await?;

    Ok(())
}

/// The 000004 `down` must restore the exact 000003 shape: the restored DDL
/// and the 000003 forward DDL are byte-identical once the rebuild staging
/// names are unified and whitespace is laid out, so a future edit of either
/// side (a dropped code, a weakened constraint, a changed column) fails the
/// test instead of silently reshaping a rollback.
#[test]
fn down_restores_the_000003_shape_byte_for_byte() -> Result<(), Box<dyn Error>> {
    let forward = normalize_staging_ddl(&extract_000003_forward_ddl()?);
    let down = normalize_staging_ddl(AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL);
    assert_eq!(
        forward, down,
        "the 000004 down must restore the 000003 shape byte for byte"
    );
    Ok(())
}

/// The number of registered migrations before the named migration.
fn migrations_before(name: &str) -> Result<u32, Box<dyn Error>> {
    let migrations = Migrator::migrations();
    let position = migrations
        .iter()
        .position(|migration| migration.name() == name)
        .ok_or("audit operation vocabulary migration is not registered")?;
    Ok(u32::try_from(position)?)
}

/// Writes one terminal audit row in the §16.3 execution shape: the endpoint
/// target, the closest legal parameter summary, the `execute-operations`
/// permission, and the given operation code.
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

/// Writes one succeeded `change-password` row in the §16.2 authentication
/// shape, with the given actor, optionally naming the principal whose
/// credential was replaced (S3-4).
///
/// The acting principal is derived from the actor per the
/// `ck_audit_events_actor_principal` rule — `user` actors carry one, other
/// actors do not — so a non-user actor row is valid in every other respect
/// and the target-principal rule alone decides its fate.
async fn insert_change_password_row(
    database: &DatabaseConnection,
    actor: &str,
    target_principal_id: Option<Uuid>,
    occurred_at: OffsetDateTime,
) -> Result<rutilus_entity::audit_event::Model, sea_orm::DbErr> {
    let actor_principal_id = (actor == "user").then(Uuid::now_v7);
    rutilus_entity::audit_event::ActiveModel {
        id: Set(Uuid::now_v7()),
        operation_id: Set(Uuid::now_v7()),
        event_sequence: Set(2),
        actor: Set(actor.to_owned()),
        actor_principal_id: Set(actor_principal_id),
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
