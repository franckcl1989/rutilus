use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Completes the `audit_events` failure vocabulary and persists the target
/// principal (V4I-1 / V4R-3).
///
/// # The missing failure codes
///
/// The domain has accepted [`AuditFailure::SessionRevocationFailed`] and
/// [`AuditFailure::CapabilityUnsupported`] since the §16.2 session-revocation
/// milestone (B3) and the §13.3 capability pre-flight follow-up (E3-4), but
/// the 000001 rebuild's `ck_audit_events_outcome` failure list stopped at
/// `authentication-failed` — every row carrying either code was rejected by
/// the schema, so a failed password change whose session revocation failed
/// (§16.2) and a refused write whose capability pre-flight failed (§13.3)
/// could not be persisted. This migration extends the failure list to the
/// full domain vocabulary, in the exact order of the `AuditFailure` enum in
/// `rutilus-domain`:
///
/// - `session-revocation-failed` — a password change or administrator-issued
///   password set succeeded, but the mandatory §16.2 session revocation
///   failed; the change is not rolled back, and the audit records which step
///   actually failed (B3). `authentication-failed` would name the wrong
///   fact: the presented credential was accepted; the revocation of the old
///   sessions is the step that failed.
/// - `capability-unsupported` — the §13.3 step 2 capability pre-flight
///   proved the endpoint cannot serve the write: the required capability is
///   not compiled, not advertised, schema-incompatible, or read-only. The
///   refusal is a fact about the endpoint's capability, not about redfish
///   discovery, so it is audited under its own kind (audit follow-up E3-4).
///
/// # The target principal column
///
/// The 000001 shape has no home for the principal a `User`-actor action
/// changes when it names a subject distinct from the actor (S3-4): the
/// administrator-issued password set is audited under the acting
/// administrator as actor and the user whose credential was replaced as the
/// target, and the domain context carries that principal
/// (`AuditOperationContext::with_target_principal`) since the S3-4 slice,
/// yet the web recorder's target was silently dropped at the schema
/// boundary. This migration adds the `target_principal_id` column, and the
/// `ck_audit_events_target_principal` CHECK pins the shape rule the domain
/// contract states: only an action that names a subject distinct from its
/// actor — [`AuditAction::ChangePassword`], the one S3-4 action of the
/// current vocabulary — may carry a target principal. A target under any
/// other action is refused, so a row can never claim a subject the action
/// does not change.
///
/// # The rebuild
///
/// `SQLite` cannot alter a CHECK constraint or add a column with a
/// constraint, so the widening is the same create-copy-drop-rename cycle the
/// 000001 and 000008 migrations used: create `audit_events_vocabulary` with
/// the full widened shape, copy every row, drop the old table, rename the
/// new one into place, and recreate the indexes. Every legacy row satisfies
/// the widened constraint (its failure code is one of the eleven the 000001
/// list already accepted, and its target column is NULL), so the copy is a
/// pure data-preserving operation, verified by the migration test that
/// inserts rows before the rebuild and reads them back after. The migration
/// overrides [`MigrationTrait::use_transaction`] so the whole up (and the
/// symmetric down) commits atomically on `SQLite`.
///
/// # Downgrade symmetry
///
/// `down` restores the exact 000001 shape: the eleven-code failure list and
/// no target column. The rows the widened schema accepted that the restored
/// shape cannot represent are refused, never silently dropped — the
/// documented restore contract of the earlier rebuilds. The two new failure
/// codes are refused by the restored CHECK during the copy (the same
/// mechanism the 000001 down uses for its center rows), and a row carrying a
/// target principal is refused by an explicit pre-check before the copy: the
/// restored shape has no column for the target, and copying the row without
/// it would falsify the audit record rather than refuse it.
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

/// Whether the rebuild moves the audit table forward (the full failure
/// vocabulary and the target-principal column) or back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildDirection {
    Forward,
    Backward,
}

/// Rebuilds `audit_events` with the full failure vocabulary and the
/// target-principal column (forward) or restores the 000001 shapes
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
        // The restored 000001 shape has no `target_principal_id` column, so
        // a row carrying a target principal cannot be represented: the down
        // refuses it rather than silently dropping the target from the
        // copied row, which would falsify the audit record. The refusal is
        // explicit because — unlike the failure-code widening, where the
        // restored CHECK rejects the new codes during the copy — no restored
        // constraint can see a column the restored table does not have.
        let carrying_targets = {
            let statement = Query::select()
                .expr(Expr::col(AuditEventShape::TargetPrincipalId).count())
                .from(AuditEventShape::Table)
                .and_where(Expr::col(AuditEventShape::TargetPrincipalId).is_not_null())
                .to_owned();
            let row = connection.query_one(&statement).await?.ok_or_else(|| {
                DbErr::Custom(String::from(
                    "the 000003 down could not inspect the audit table",
                ))
            })?;
            row.try_get_by_index::<i64>(0)
                .map_err(|error| DbErr::Custom(error.to_string()))?
        };
        if carrying_targets > 0 {
            return Err(DbErr::Custom(String::from(
                "the 000003 down refuses audit_events rows carrying a target principal: \
                 the restored 000001 shape has no column for it; remove the rows before \
                 rolling back",
            )));
        }
    }
    if direction == RebuildDirection::Forward {
        connection
            .execute_unprepared(AUDIT_EVENTS_VOCABULARY_DDL)
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
                            // The new `target_principal_id` column has no
                            // source: every legacy row is copied with the
                            // column NULL, exactly the shape a fresh column
                            // starts in. The NULL literal keeps the select
                            // list aligned with the 22-column insert list —
                            // the `INSERT ... SELECT` pairs the lists
                            // positionally.
                            .expr(Expr::val(None::<String>))
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
            .execute_unprepared(AUDIT_EVENTS_PRE_VOCABULARY_DDL)
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
            "ALTER TABLE audit_events_vocabulary RENAME TO audit_events"
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

/// The widened `audit_events` shape: the 000001 columns plus the
/// `target_principal_id` column and the full thirteen-code failure
/// vocabulary, in the exact order of the `AuditFailure` enum in
/// `rutilus-domain` — the same list the migration test pins code by code,
/// so a domain code added without a schema home fails the test.
const AUDIT_EVENTS_VOCABULARY_DDL: &str = r"
CREATE TABLE audit_events_vocabulary (
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

/// The 000001 `audit_events` shape restored by `down`: the eleven-code
/// failure list and no target column, byte for byte the shape the 000001
/// rebuild created.
const AUDIT_EVENTS_PRE_VOCABULARY_DDL: &str = r"
CREATE TABLE audit_events_previous (
    id uuid_text NOT NULL PRIMARY KEY,
    operation_id uuid_text NOT NULL,
    event_sequence integer NOT NULL,
    actor varchar NOT NULL,
    actor_principal_id uuid_text NULL,
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
                'authentication-failed'
            )
            AND verification IS NOT NULL
            AND verification IN ('rejected', 'inconclusive'))
    )
)
";

/// The two `audit_events` shapes the rebuild alternates between, plus the
/// live `audit_events` table the copy reads from; the column variants are
/// shared because both shapes carry the same columns except the forward
/// shape's `target_principal_id`.
#[derive(DeriveIden)]
enum AuditEventShape {
    #[sea_orm(iden = "audit_events")]
    Table,
    #[sea_orm(iden = "audit_events_vocabulary")]
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
