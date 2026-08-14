use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Completes the §16.3 `execute-operation` vocabulary of `audit_events` and
/// pins the S3-4 target principal to the `user` actor (V5A-1 / V5A-10).
///
/// # The missing operation codes
///
/// The 000008 rebuild's `ck_audit_events_action` execute-operation arm
/// stopped at the fourteen codes the domain accepted then, and the 000003
/// rebuild carried that list forward unchanged: the five account writes,
/// the manager reset-to-defaults, the chassis power-supply reset, the log
/// clear, the control write, the seven telemetry writes, and the
/// `UpdateService` patch — the §7.5/§14.4 write families the domain has
/// accepted since — are rejected by the schema, so an execution audited
/// under one of those codes (an account create or delete, a
/// factory-defaults wipe, a metric-definition change, a service-patch
/// submission, ...) could not be persisted. This migration extends the arm
/// to the full thirty-one-code domain vocabulary, in the exact order of the
/// [`AuditRedfishOperation`] enum in `rutilus-domain` — the thirty
/// §7.5/§14.4 write families and the §13.6 `poll-remote-task` monitor code
/// — exactly the list the domain consistency matrix accepts under the
/// execution shape, so a persisted row is always one the domain can
/// rehydrate.
///
/// # The actor rule on the target principal
///
/// The 000003 shape's `ck_audit_events_target_principal` pins only the
/// action: a target principal may name the principal a `change-password`
/// action changes (S3-4). The web recorder attaches the target exactly at
/// the administrator-issued password set, under the acting administrator's
/// signed-in session — a `user` actor, per the domain actor vocabulary
/// (`system`, `local-operator`, `user`) — and the domain contract ties the
/// target to a `User`-actor action. The 000004 shape pins the association:
/// a row carrying a target principal must name a `user` actor, so a row can
/// never claim a subject changed by a `system` or `local-operator` actor.
///
/// # The rebuild
///
/// `SQLite` cannot alter a CHECK constraint, so the widening is the same
/// create-copy-drop-rename cycle the 000003 and 000008 migrations used:
/// create `audit_events_operation_vocabulary` with the full widened shape,
/// copy every row, drop the old table, rename the new one into place, and
/// recreate the indexes. Every legacy row satisfies the widened constraint:
/// its operation code is one of the fourteen the 000003 arm already
/// accepted, and its target principal — if any — sits on a `change-password`
/// row the product writes under a `user` actor, so the copy is a pure
/// data-preserving operation, verified by the migration test that inserts
/// rows before the rebuild and reads them back after. The one legacy shape
/// the widened schema cannot represent — a target principal under a
/// `system` or `local-operator` actor, data no product version writes — is
/// refused by an explicit pre-check before the copy, the mirror of the
/// down's refusal, with a message naming the migration and the widened
/// rule. The migration overrides [`MigrationTrait::use_transaction`] so the
/// whole up (and the symmetric down) commits atomically on `SQLite`.
///
/// # Downgrade symmetry
///
/// `down` restores the exact 000003 shape: the fourteen-code
/// execute-operation arm, the thirteen-code failure vocabulary, the target
/// column, and the action-only target-principal CHECK. The rows the widened
/// schema accepted that the restored shape cannot represent are refused,
/// never silently dropped — the documented restore contract of the earlier
/// rebuilds. The seventeen new operation codes are refused by an explicit
/// pre-check before the copy — unlike the 000003 down's failure codes,
/// which the restored CHECK rejects during the copy, the pre-check names
/// the migration in its refusal, so a rolled-back deployment sees why the
/// rollback stops — and every row the restored shape can represent is
/// copied unchanged.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// The rebuild must commit as one unit: a failure halfway would leave
    /// the audit table half-rebuilt with no recorded migration to recover
    /// from.
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_audit_events(manager, RebuildDirection::Forward).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_audit_events(manager, RebuildDirection::Backward).await
    }
}

/// Whether the rebuild moves the audit table forward (the full operation
/// vocabulary and the actor-pinned target principal) or back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildDirection {
    Forward,
    Backward,
}

/// Rebuilds `audit_events` with the full operation vocabulary and the
/// actor-pinned target principal (forward) or restores the 000003 shape
/// (backward).
///
/// All statements run on the migration's transaction (see
/// [`Migration::use_transaction`]), so a failure leaves the old table
/// untouched. The copy steps enumerate every column of both shapes in the
/// insert and select lists, so the function exceeds the pedantic line
/// budget (same exception as the family migrations' rebuilds).
#[allow(clippy::too_many_lines)]
async fn rebuild_audit_events(
    manager: &SchemaManager<'_>,
    direction: RebuildDirection,
) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    if direction == RebuildDirection::Backward {
        // The restored 000003 shape's execute-operation arm stops at the
        // fourteen codes the 000003 migration accepted, so a row carrying
        // one of the seventeen later codes cannot be represented: the down
        // refuses it rather than silently dropping the operation code from
        // the copied row, which would falsify the audit record. The refusal
        // is explicit — the restored CHECK would also reject the copy — so
        // the message can name the migration and the restored shape, the
        // observability convention the 000003 down's target-principal
        // pre-check established.
        let unrepresentable = {
            let statement = Query::select()
                .expr(Expr::col(AuditEventShape::RedfishOperation).count())
                .from(AuditEventShape::Table)
                // Only execution-shape rows can carry the widened codes: the
                // other action arms of the CHECK pin their operation codes
                // ('none', the two discovery reads), so a row carrying one
                // of the seventeen later codes is always an execution row.
                // Restricting the pre-check to the execution shape keeps it
                // exact — an authentication row under `redfish_operation =
                // 'none'` is fully representable in the restored shape.
                .and_where(Expr::col(AuditEventShape::Action).eq("execute-operation"))
                .and_where(
                    Expr::col(AuditEventShape::RedfishOperation)
                        .is_not_in(RESTORED_EXECUTE_OPERATION_CODES),
                )
                .to_owned();
            let row = connection.query_one(&statement).await?.ok_or_else(|| {
                DbErr::Custom(String::from(
                    "the 000004 down could not inspect the audit table",
                ))
            })?;
            row.try_get_by_index::<i64>(0)
                .map_err(|error| DbErr::Custom(error.to_string()))?
        };
        if unrepresentable > 0 {
            return Err(DbErr::Custom(String::from(
                "the 000004 down refuses audit_events rows carrying an operation code \
                 the restored 000003 shape does not accept: the restored \
                 ck_audit_events_action CHECK cannot represent the code; remove the rows \
                 before rolling back",
            )));
        }
    }
    if direction == RebuildDirection::Forward {
        // The widened shape's target-principal rule pins the actor: a row
        // carrying a target principal must name a `user` actor (S3-4), so a
        // legacy row whose target principal sits under a `system` or
        // `local-operator` actor cannot be represented in the widened
        // schema — the widened CHECK would reject the copy mid-way. Like
        // the down's pre-check, the refusal is explicit — the message names
        // the migration and the widened rule, so a deployment that never
        // should have carried such a row sees exactly why the up stops.
        let unrepresentable = {
            let statement = Query::select()
                .expr(Expr::col(AuditEventShape::TargetPrincipalId).count())
                .from(AuditEventShape::Table)
                .and_where(Expr::col(AuditEventShape::Action).eq("change-password"))
                .and_where(Expr::col(AuditEventShape::TargetPrincipalId).is_not_null())
                .and_where(Expr::col(AuditEventShape::Actor).ne("user"))
                .to_owned();
            let row = connection.query_one(&statement).await?.ok_or_else(|| {
                DbErr::Custom(String::from(
                    "the 000004 up could not inspect the audit table",
                ))
            })?;
            row.try_get_by_index::<i64>(0)
                .map_err(|error| DbErr::Custom(error.to_string()))?
        };
        if unrepresentable > 0 {
            return Err(DbErr::Custom(String::from(
                "the 000004 up refuses audit_events rows carrying a target principal \
                 under a non-user actor: the widened ck_audit_events_target_principal \
                 CHECK cannot represent the row; remove the rows before applying",
            )));
        }
        connection
            .execute_unprepared(AUDIT_EVENTS_OPERATION_VOCABULARY_DDL)
            .await?;
        // The copies go through the SeaQuery builder (`INSERT ... SELECT` via
        // `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
        // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
        connection
            .execute(
                &Query::insert()
                    .into_table(AuditEventShape::VocabularyTable)
                    .columns([
                        AuditEventShape::Id,
                        AuditEventShape::OperationId,
                        AuditEventShape::EventSequence,
                        AuditEventShape::Actor,
                        AuditEventShape::ActorPrincipalId,
                        AuditEventShape::TargetPrincipalId,
                        AuditEventShape::Origin,
                        AuditEventShape::TargetKind,
                        AuditEventShape::TargetEndpointId,
                        AuditEventShape::TargetEndpointAddress,
                        AuditEventShape::ParameterKind,
                        AuditEventShape::CredentialId,
                        AuditEventShape::TrustMode,
                        AuditEventShape::RowCount,
                        AuditEventShape::Permission,
                        AuditEventShape::Action,
                        AuditEventShape::RedfishOperation,
                        AuditEventShape::Outcome,
                        AuditEventShape::Progress,
                        AuditEventShape::Failure,
                        AuditEventShape::Verification,
                        AuditEventShape::OccurredAt,
                    ])
                    .select_from(
                        Query::select()
                            .column(AuditEventShape::Id)
                            .column(AuditEventShape::OperationId)
                            .column(AuditEventShape::EventSequence)
                            .column(AuditEventShape::Actor)
                            .column(AuditEventShape::ActorPrincipalId)
                            // The widened shape keeps the target column, so
                            // every legacy target principal is copied as it
                            // is — the actor rule below is satisfied by every
                            // real row (the product writes targets only
                            // under a `user` actor).
                            .column(AuditEventShape::TargetPrincipalId)
                            .column(AuditEventShape::Origin)
                            .column(AuditEventShape::TargetKind)
                            .column(AuditEventShape::TargetEndpointId)
                            .column(AuditEventShape::TargetEndpointAddress)
                            .column(AuditEventShape::ParameterKind)
                            .column(AuditEventShape::CredentialId)
                            .column(AuditEventShape::TrustMode)
                            .column(AuditEventShape::RowCount)
                            .column(AuditEventShape::Permission)
                            .column(AuditEventShape::Action)
                            .column(AuditEventShape::RedfishOperation)
                            .column(AuditEventShape::Outcome)
                            .column(AuditEventShape::Progress)
                            .column(AuditEventShape::Failure)
                            .column(AuditEventShape::Verification)
                            .column(AuditEventShape::OccurredAt)
                            .from(AuditEventShape::Table)
                            .take(),
                    )
                    .map_err(|error| DbErr::Custom(error.to_string()))?
                    .take(),
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE audit_events")
            .await?;
    } else {
        connection
            .execute_unprepared(AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL)
            .await?;
        connection
            .execute(
                &Query::insert()
                    .into_table(AuditEventShape::PreviousTable)
                    .columns([
                        AuditEventShape::Id,
                        AuditEventShape::OperationId,
                        AuditEventShape::EventSequence,
                        AuditEventShape::Actor,
                        AuditEventShape::ActorPrincipalId,
                        AuditEventShape::TargetPrincipalId,
                        AuditEventShape::Origin,
                        AuditEventShape::TargetKind,
                        AuditEventShape::TargetEndpointId,
                        AuditEventShape::TargetEndpointAddress,
                        AuditEventShape::ParameterKind,
                        AuditEventShape::CredentialId,
                        AuditEventShape::TrustMode,
                        AuditEventShape::RowCount,
                        AuditEventShape::Permission,
                        AuditEventShape::Action,
                        AuditEventShape::RedfishOperation,
                        AuditEventShape::Outcome,
                        AuditEventShape::Progress,
                        AuditEventShape::Failure,
                        AuditEventShape::Verification,
                        AuditEventShape::OccurredAt,
                    ])
                    .select_from(
                        Query::select()
                            .column(AuditEventShape::Id)
                            .column(AuditEventShape::OperationId)
                            .column(AuditEventShape::EventSequence)
                            .column(AuditEventShape::Actor)
                            .column(AuditEventShape::ActorPrincipalId)
                            .column(AuditEventShape::TargetPrincipalId)
                            .column(AuditEventShape::Origin)
                            .column(AuditEventShape::TargetKind)
                            .column(AuditEventShape::TargetEndpointId)
                            .column(AuditEventShape::TargetEndpointAddress)
                            .column(AuditEventShape::ParameterKind)
                            .column(AuditEventShape::CredentialId)
                            .column(AuditEventShape::TrustMode)
                            .column(AuditEventShape::RowCount)
                            .column(AuditEventShape::Permission)
                            .column(AuditEventShape::Action)
                            .column(AuditEventShape::RedfishOperation)
                            .column(AuditEventShape::Outcome)
                            .column(AuditEventShape::Progress)
                            .column(AuditEventShape::Failure)
                            .column(AuditEventShape::Verification)
                            .column(AuditEventShape::OccurredAt)
                            .from(AuditEventShape::Table)
                            .take(),
                    )
                    .map_err(|error| DbErr::Custom(error.to_string()))?
                    .take(),
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE audit_events")
            .await?;
    }
    connection
        .execute_unprepared(if direction == RebuildDirection::Forward {
            "ALTER TABLE audit_events_operation_vocabulary RENAME TO audit_events"
        } else {
            "ALTER TABLE audit_events_previous RENAME TO audit_events"
        })
        .await?;
    connection
        .execute_unprepared(
            "CREATE UNIQUE INDEX uq_audit_events_operation_sequence \
             ON audit_events (operation_id, event_sequence)",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE INDEX ix_audit_events_occurred_at ON audit_events (occurred_at)",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE INDEX ix_audit_events_action_occurred_at \
             ON audit_events (action, occurred_at)",
        )
        .await
        .map(|_| ())
}

/// The widened `audit_events` shape: the 000003 columns and constraints plus
/// the full thirty-one-code operation vocabulary and the actor rule on the
/// target principal.
///
/// The operation codes are listed in the exact order of the
/// [`AuditRedfishOperation`] enum in `rutilus-domain` — the same order the
/// domain consistency matrix's execution arm carries — and the migration
/// test pins the list against the enum in both directions, so a domain code
/// added without a schema home fails the test.
const AUDIT_EVENTS_OPERATION_VOCABULARY_DDL: &str = r"
CREATE TABLE audit_events_operation_vocabulary (
    id uuid_text NOT NULL PRIMARY KEY,
    operation_id uuid_text NOT NULL,
    event_sequence integer NOT NULL,
    actor varchar NOT NULL,
    actor_principal_id uuid_text NULL,
    target_principal_id uuid_text NULL,
    origin varchar NOT NULL,
    target_kind varchar NOT NULL,
    target_endpoint_id uuid_text NULL,
    target_endpoint_address varchar NULL,
    parameter_kind varchar NOT NULL,
    credential_id uuid_text NULL,
    trust_mode varchar NULL,
    row_count integer NULL,
    permission varchar NOT NULL,
    action varchar NOT NULL,
    redfish_operation varchar NOT NULL,
    outcome varchar NOT NULL,
    progress varchar NULL,
    failure varchar NULL,
    verification varchar NULL,
    occurred_at timestamp_with_timezone_text NOT NULL,
    CONSTRAINT ck_audit_events_sequence
        CHECK (event_sequence >= 1 AND event_sequence <= 4294967295),
    CONSTRAINT ck_audit_events_actor
        CHECK (actor IN ('system', 'local-operator', 'user')),
    CONSTRAINT ck_audit_events_actor_principal
        CHECK ((actor = 'user') = (actor_principal_id IS NOT NULL)),
    CONSTRAINT ck_audit_events_target_principal
        CHECK (target_principal_id IS NULL OR (action = 'change-password' AND actor = 'user')),
    CONSTRAINT ck_audit_events_origin
        CHECK (origin IN ('standalone', 'site', 'center')),
    CONSTRAINT ck_audit_events_target CHECK (
        (target_kind = 'product'
            AND target_endpoint_id IS NULL
            AND target_endpoint_address IS NULL)
        OR (target_kind = 'endpoint-address'
            AND target_endpoint_id IS NULL
            AND target_endpoint_address IS NOT NULL)
        OR (target_kind = 'endpoint'
            AND target_endpoint_id IS NOT NULL
            AND target_endpoint_address IS NULL)
    ),
    CONSTRAINT ck_audit_events_parameters CHECK (
        (parameter_kind = 'endpoint-enrollment'
            AND credential_id IS NOT NULL
            AND trust_mode IS NOT NULL
            AND trust_mode IN ('system-ca', 'pinned-certificate')
            AND row_count IS NULL)
        OR (parameter_kind = 'endpoint-refresh'
            AND credential_id IS NULL
            AND trust_mode IS NULL
            AND row_count IS NULL)
        OR (parameter_kind = 'csv-endpoint-import'
            AND credential_id IS NULL
            AND trust_mode IS NULL
            AND row_count IS NOT NULL
            AND row_count >= 1
            AND row_count <= 4294967295)
    ),
    CONSTRAINT ck_audit_events_action CHECK (
        (action = 'enroll-endpoint'
            AND target_kind = 'endpoint-address'
            AND parameter_kind = 'endpoint-enrollment'
            AND permission = 'manage-endpoints'
            AND redfish_operation = 'probe-core-capabilities')
        OR (action = 'refresh-endpoint'
            AND target_kind = 'endpoint'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'refresh-endpoints'
            AND redfish_operation = 'read-core-resources')
        OR (action = 'import-endpoints'
            AND target_kind = 'product'
            AND parameter_kind = 'csv-endpoint-import'
            AND permission = 'manage-endpoints'
            AND redfish_operation = 'none')
        OR (action IN ('login', 'logout', 'change-password')
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'authenticate'
            AND redfish_operation = 'none')
        OR (action IN ('manage-users', 'manage-sessions', 'manage-totp')
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-users'
            AND redfish_operation = 'none')
        OR (action = 'manage-backups'
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-backups'
            AND redfish_operation = 'none')
        OR (action = 'manage-settings'
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-site-settings'
            AND redfish_operation = 'none')
        OR (action = 'execute-operation'
            AND target_kind = 'endpoint'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'execute-operations'
            AND redfish_operation IN (
                'create-account',
                'update-account',
                'update-account-password',
                'update-account-user-name',
                'delete-account',
                'reset-system',
                'reset-manager',
                'manager-reset-to-defaults',
                'reset-chassis',
                'power-supply-reset',
                'set-boot-source-override',
                'secure-boot-enable',
                'secure-boot-disable',
                'secure-boot-reset-keys',
                'create-event-subscription',
                'delete-event-subscription',
                'log-clear',
                'control-update',
                'set-telemetry-enabled',
                'create-metric-definition',
                'update-metric-definition',
                'delete-metric-definition',
                'create-metric-report-definition',
                'update-metric-report-definition',
                'delete-metric-report-definition',
                'update-firmware',
                'update-service-patch',
                'oem-system-config-profile',
                'oem-debug-token',
                'oem-power-smoothing',
                'poll-remote-task'
            ))
        OR (action IN ('register-site-binding', 'revoke-site-binding')
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-center-bindings'
            AND redfish_operation = 'none')
        OR (action = 'dispatch-center-operation'
            AND target_kind = 'endpoint'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'dispatch-center-operations'
            AND redfish_operation = 'none')
    ),
    CONSTRAINT ck_audit_events_outcome CHECK (
        (outcome = 'started'
            AND event_sequence = 1
            AND progress IS NULL
            AND failure IS NULL
            AND verification IS NULL)
        OR (outcome = 'progress'
            AND event_sequence > 1
            AND progress IS NOT NULL
            AND (
                (progress = 'endpoint-created' AND action = 'enroll-endpoint')
                OR (progress = 'row-validated' AND action = 'import-endpoints')
            )
            AND failure IS NULL
            AND verification IS NULL)
        OR (outcome = 'succeeded'
            AND event_sequence > 1
            AND progress IS NULL
            AND failure IS NULL
            AND verification IS NOT NULL
            AND verification = 'confirmed')
        OR (outcome = 'failed'
            AND event_sequence > 1
            AND progress IS NULL
            AND failure IS NOT NULL
            AND failure IN (
                'credential-unavailable',
                'tls-trust-failed',
                'redfish-discovery-failed',
                'endpoint-persistence-failed',
                'core-resource-read-failed',
                'snapshot-persistence-failed',
                'csv-invalid',
                'endpoint-import-row-failed',
                'center-store-failed',
                'center-request-refused',
                'authentication-failed',
                'session-revocation-failed',
                'capability-unsupported'
            )
            AND verification IS NOT NULL
            AND verification IN ('rejected', 'inconclusive'))
    )
)
";

/// The 000003 `audit_events` shape restored by `down`: the fourteen-code
/// execute-operation arm, the thirteen-code failure list, the target column
/// with the action-only CHECK, byte for byte the shape the 000003 rebuild
/// created (only the staging table name differs — the migration test in
/// `tests/audit_operation_vocabulary.rs` pins that byte-for-byte identity).
///
/// Exposed as `rutilus_migration::AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL`
/// for that test.
pub const AUDIT_EVENTS_PRE_OPERATION_VOCABULARY_DDL: &str = r"
CREATE TABLE audit_events_previous (
    id uuid_text NOT NULL PRIMARY KEY,
    operation_id uuid_text NOT NULL,
    event_sequence integer NOT NULL,
    actor varchar NOT NULL,
    actor_principal_id uuid_text NULL,
    target_principal_id uuid_text NULL,
    origin varchar NOT NULL,
    target_kind varchar NOT NULL,
    target_endpoint_id uuid_text NULL,
    target_endpoint_address varchar NULL,
    parameter_kind varchar NOT NULL,
    credential_id uuid_text NULL,
    trust_mode varchar NULL,
    row_count integer NULL,
    permission varchar NOT NULL,
    action varchar NOT NULL,
    redfish_operation varchar NOT NULL,
    outcome varchar NOT NULL,
    progress varchar NULL,
    failure varchar NULL,
    verification varchar NULL,
    occurred_at timestamp_with_timezone_text NOT NULL,
    CONSTRAINT ck_audit_events_sequence
        CHECK (event_sequence >= 1 AND event_sequence <= 4294967295),
    CONSTRAINT ck_audit_events_actor
        CHECK (actor IN ('system', 'local-operator', 'user')),
    CONSTRAINT ck_audit_events_actor_principal
        CHECK ((actor = 'user') = (actor_principal_id IS NOT NULL)),
    CONSTRAINT ck_audit_events_target_principal
        CHECK (target_principal_id IS NULL OR action = 'change-password'),
    CONSTRAINT ck_audit_events_origin
        CHECK (origin IN ('standalone', 'site', 'center')),
    CONSTRAINT ck_audit_events_target CHECK (
        (target_kind = 'product'
            AND target_endpoint_id IS NULL
            AND target_endpoint_address IS NULL)
        OR (target_kind = 'endpoint-address'
            AND target_endpoint_id IS NULL
            AND target_endpoint_address IS NOT NULL)
        OR (target_kind = 'endpoint'
            AND target_endpoint_id IS NOT NULL
            AND target_endpoint_address IS NULL)
    ),
    CONSTRAINT ck_audit_events_parameters CHECK (
        (parameter_kind = 'endpoint-enrollment'
            AND credential_id IS NOT NULL
            AND trust_mode IS NOT NULL
            AND trust_mode IN ('system-ca', 'pinned-certificate')
            AND row_count IS NULL)
        OR (parameter_kind = 'endpoint-refresh'
            AND credential_id IS NULL
            AND trust_mode IS NULL
            AND row_count IS NULL)
        OR (parameter_kind = 'csv-endpoint-import'
            AND credential_id IS NULL
            AND trust_mode IS NULL
            AND row_count IS NOT NULL
            AND row_count >= 1
            AND row_count <= 4294967295)
    ),
    CONSTRAINT ck_audit_events_action CHECK (
        (action = 'enroll-endpoint'
            AND target_kind = 'endpoint-address'
            AND parameter_kind = 'endpoint-enrollment'
            AND permission = 'manage-endpoints'
            AND redfish_operation = 'probe-core-capabilities')
        OR (action = 'refresh-endpoint'
            AND target_kind = 'endpoint'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'refresh-endpoints'
            AND redfish_operation = 'read-core-resources')
        OR (action = 'import-endpoints'
            AND target_kind = 'product'
            AND parameter_kind = 'csv-endpoint-import'
            AND permission = 'manage-endpoints'
            AND redfish_operation = 'none')
        OR (action IN ('login', 'logout', 'change-password')
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'authenticate'
            AND redfish_operation = 'none')
        OR (action IN ('manage-users', 'manage-sessions', 'manage-totp')
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-users'
            AND redfish_operation = 'none')
        OR (action = 'manage-backups'
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-backups'
            AND redfish_operation = 'none')
        OR (action = 'manage-settings'
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-site-settings'
            AND redfish_operation = 'none')
        OR (action = 'execute-operation'
            AND target_kind = 'endpoint'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'execute-operations'
            AND redfish_operation IN (
                'reset-system',
                'reset-manager',
                'reset-chassis',
                'set-boot-source-override',
                'secure-boot-enable',
                'secure-boot-disable',
                'secure-boot-reset-keys',
                'create-event-subscription',
                'delete-event-subscription',
                'update-firmware',
                'oem-system-config-profile',
                'oem-debug-token',
                'oem-power-smoothing',
                'poll-remote-task'
            ))
        OR (action IN ('register-site-binding', 'revoke-site-binding')
            AND target_kind = 'product'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'manage-center-bindings'
            AND redfish_operation = 'none')
        OR (action = 'dispatch-center-operation'
            AND target_kind = 'endpoint'
            AND parameter_kind = 'endpoint-refresh'
            AND permission = 'dispatch-center-operations'
            AND redfish_operation = 'none')
    ),
    CONSTRAINT ck_audit_events_outcome CHECK (
        (outcome = 'started'
            AND event_sequence = 1
            AND progress IS NULL
            AND failure IS NULL
            AND verification IS NULL)
        OR (outcome = 'progress'
            AND event_sequence > 1
            AND progress IS NOT NULL
            AND (
                (progress = 'endpoint-created' AND action = 'enroll-endpoint')
                OR (progress = 'row-validated' AND action = 'import-endpoints')
            )
            AND failure IS NULL
            AND verification IS NULL)
        OR (outcome = 'succeeded'
            AND event_sequence > 1
            AND progress IS NULL
            AND failure IS NULL
            AND verification IS NOT NULL
            AND verification = 'confirmed')
        OR (outcome = 'failed'
            AND event_sequence > 1
            AND progress IS NULL
            AND failure IS NOT NULL
            AND failure IN (
                'credential-unavailable',
                'tls-trust-failed',
                'redfish-discovery-failed',
                'endpoint-persistence-failed',
                'core-resource-read-failed',
                'snapshot-persistence-failed',
                'csv-invalid',
                'endpoint-import-row-failed',
                'center-store-failed',
                'center-request-refused',
                'authentication-failed',
                'session-revocation-failed',
                'capability-unsupported'
            )
            AND verification IS NOT NULL
            AND verification IN ('rejected', 'inconclusive'))
    )
)
";

/// The fourteen operation codes the 000003 shape's execute-operation arm
/// accepts — the list the restored shape can represent, and the pre-check's
/// boundary between copyable rows and refused rows.
const RESTORED_EXECUTE_OPERATION_CODES: [&str; 14] = [
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

/// The two `audit_events` shapes the rebuild alternates between, plus the
/// live `audit_events` table the copy reads from; the column variants are
/// shared because both shapes carry the same columns.
#[derive(DeriveIden)]
enum AuditEventShape {
    #[sea_orm(iden = "audit_events")]
    Table,
    #[sea_orm(iden = "audit_events_operation_vocabulary")]
    VocabularyTable,
    #[sea_orm(iden = "audit_events_previous")]
    PreviousTable,
    Id,
    OperationId,
    EventSequence,
    Actor,
    ActorPrincipalId,
    TargetPrincipalId,
    Origin,
    TargetKind,
    TargetEndpointId,
    TargetEndpointAddress,
    ParameterKind,
    CredentialId,
    TrustMode,
    RowCount,
    Permission,
    Action,
    RedfishOperation,
    Outcome,
    Progress,
    Failure,
    Verification,
    OccurredAt,
}
