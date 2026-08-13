use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Permits the 0.7.0 center-console audit shapes in `audit_events` (D4-1).
///
/// # The missing shapes
///
/// The 000008 slice widened `ck_audit_events_action` with the
/// `execute-operation` shape, but the center console actions had no schema
/// home: the domain has accepted [`AuditAction::RegisterSiteBinding`],
/// [`AuditAction::RevokeSiteBinding`], and
/// [`AuditAction::DispatchCenterOperation`] since the center milestone (the
/// §15.6/§16 audit follow-up F3), and the center web handlers record exactly
/// those shapes (the `audit` recorder assertions in `web/src/lib.rs`), yet
/// the CHECK pinned only the endpoint-management, authentication,
/// user-management, and execution actions. Every center audit row was
/// rejected by the schema, so no center binding or dispatch audit could
/// persist.
///
/// # The widened shapes
///
/// This migration extends `ck_audit_events_action` with exactly the shapes
/// the domain consistency matrix accepts for the three center actions
/// (`AuditOperationContext::try_new_with_actor_principal` in
/// `rutilus-domain`), mirroring the arm pattern the 000007/000008 shapes
/// used:
///
/// - `action IN ('register-site-binding', 'revoke-site-binding')` — binding
///   management is a center-wide action with no endpoint target: target
///   `product`, parameter `endpoint-refresh` (the closest legal summary,
///   exactly as the authentication shapes use it), permission
///   `manage-center-bindings`, and `redfish_operation = 'none'`;
/// - `action = 'dispatch-center-operation'` — a §15.6 dispatch targets the
///   projected endpoint that receives the command on the site, exactly like
///   the edge's `ExecuteOperation` targets the managed endpoint: target
///   `endpoint` (the `ck_audit_events_target` CHECK pins the paired endpoint
///   id), parameter `endpoint-refresh`, permission
///   `dispatch-center-operations`, and `redfish_operation = 'none'` — the
///   center never executes anything, it offers, and the site decides (§15.6).
///
/// `ck_audit_events_outcome` gains `center-store-failed` and
/// `center-request-refused` in its failure list: a center write that could
/// not be completed because the center store failed, and a §15.6 dispatch
/// refused by the center (unknown endpoint, endpoint outside the site,
/// unknown target, undecodable command, or the persisted role re-check).
///
/// # The rebuild
///
/// `SQLite` cannot alter a CHECK constraint, so the widening is the same
/// create-copy-drop-rename cycle the 000007 and 000008 migrations used:
/// create `audit_events_center` with the full widened shape, copy every
/// row, drop the old table, rename the new one into place, and recreate the
/// indexes. Every legacy row satisfies the widened constraint (it was
/// written under the narrower shapes), so the copy is a pure
/// data-preserving operation, verified by the migration test that inserts
/// rows before the rebuild and reads them back after. The migration
/// overrides [`MigrationTrait::use_transaction`] so the whole up (and the
/// symmetric down) commits atomically on `SQLite`; the down restores the
/// 000008 shape and refuses only rows written in the center shapes, which
/// cannot be represented in the old schema.
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

/// Whether the rebuild moves the audit table forward (center shapes) or
/// back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildDirection {
    Forward,
    Backward,
}

/// Rebuilds `audit_events` with the center action and failure CHECKs
/// (forward) or restores the 000008 shapes (backward).
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
    if direction == RebuildDirection::Forward {
        connection
            .execute_unprepared(AUDIT_EVENTS_CENTER_DDL)
            .await?;
        // The copies go through the SeaQuery builder (`INSERT ... SELECT` via
        // `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
        // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
        connection
            .execute(
                &Query::insert()
                    .into_table(AuditEventShape::CenterTable)
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
    } else {
        connection
            .execute_unprepared(AUDIT_EVENTS_PRE_CENTER_DDL)
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
            "ALTER TABLE audit_events_center RENAME TO audit_events"
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

/// The widened `audit_events` shape: the 000008 columns plus the three
/// 0.7.0 center-console action arms and the two center failure codes. The
/// arms are transcribed from the domain consistency matrix
/// (`AuditOperationContext::try_new_with_actor_principal` in
/// `rutilus-domain`): the binding management actions with the product
/// target, the closest legal parameter summary, the
/// `manage-center-bindings` permission, and no Redfish operation; the
/// dispatch with the endpoint target, the `dispatch-center-operations`
/// permission, and no Redfish operation — the center never executes
/// anything, it offers, and the site decides (§15.6).
const AUDIT_EVENTS_CENTER_DDL: &str = r"
CREATE TABLE audit_events_center (
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

/// The 000008 `audit_events` shape restored by `down`.
const AUDIT_EVENTS_PRE_CENTER_DDL: &str = r"
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
                'authentication-failed'
            )
            AND verification IS NOT NULL
            AND verification IN ('rejected', 'inconclusive'))
    )
)
";

/// The two `audit_events` shapes the rebuild alternates between, plus the
/// live `audit_events` table the copy reads from; the column variants are
/// shared because both shapes carry the same columns.
#[derive(DeriveIden)]
enum AuditEventShape {
    #[sea_orm(iden = "audit_events")]
    Table,
    #[sea_orm(iden = "audit_events_center")]
    CenterTable,
    #[sea_orm(iden = "audit_events_previous")]
    PreviousTable,
    Id,
    OperationId,
    EventSequence,
    Actor,
    ActorPrincipalId,
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
