use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Permits the §16.3 `execute-operation` audit shape in `audit_events`.
///
/// # The missing shape
///
/// The 000007 slice widened `ck_audit_events_action` with the eight
/// §16.2/§16.1 authentication and user-management shapes, but the operation
/// execution vocabulary still had no schema home: the domain has accepted
/// [`AuditAction::ExecuteOperation`] with a §7.5 write operation type or
/// [`AuditRedfishOperation::PollRemoteTask`] since the operation milestone,
/// and the executor records exactly that shape
/// (`operation_audit_context` in `application`), yet the CHECK pinned only
/// the endpoint-management and authentication actions. Every operation
/// execution audit row — `action = 'execute-operation'`,
/// `permission = 'execute-operations'`, `target_kind = 'endpoint'`,
/// `parameter_kind = 'endpoint-refresh'`, and one of the write-family
/// `redfish_operation` codes — was rejected by the schema, so no write
/// operation audit could persist.
///
/// # The widened shape
///
/// This migration extends `ck_audit_events_action` with exactly the shape
/// the domain consistency matrix accepts for an execution, mirroring the
/// arm pattern the 000007 authentication shapes used:
///
/// - `action = 'execute-operation'` — targets the endpoint that receives
///   the write (`target_kind = 'endpoint'`, the `ck_audit_events_target`
///   CHECK pins the paired endpoint id), parameter `endpoint-refresh` (the
///   closest legal summary the domain documents until an
///   operation-scoped summary lands with its persistence projection),
///   permission `execute-operations`, and `redfish_operation` in the
///   fourteen-code write family the domain accepts: the ten §7.5 write
///   families compiled in [`crate::RedfishCommand`], the three §11.5 OEM
///   faces (`oem-system-config-profile`, `oem-debug-token`,
///   `oem-power-smoothing`), and the §13.6 `poll-remote-task` monitor code.
///
/// The outcome CHECK is unchanged: an execution starts, succeeds, or fails
/// through the existing `started` / `succeeded` / `failed` shapes, and it
/// never records a progress milestone.
///
/// # The rebuild
///
/// `SQLite` cannot alter a CHECK constraint, so the widening is the same
/// create-copy-drop-rename cycle the 000007 and 000005 migrations used:
/// create `audit_events_execute` with the full widened shape, copy every
/// row, drop the old table, rename the new one into place, and recreate the
/// indexes. Every legacy row satisfies the widened constraint (it was
/// written under the narrower shapes), so the copy is a pure
/// data-preserving operation, verified by the migration test that inserts
/// rows before the rebuild and reads them back after. The migration
/// overrides [`MigrationTrait::use_transaction`] so the whole up (and the
/// symmetric down) commits atomically on `SQLite`; the down restores the
/// 000007 shape and refuses only rows written in the execution shape, which
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

/// Whether the rebuild moves the audit table forward (execution shape) or
/// back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildDirection {
    Forward,
    Backward,
}

/// Rebuilds `audit_events` with the execution action CHECK (forward) or
/// restores the 000007 shapes (backward).
///
/// All statements run on the migration's transaction (see
/// [`Migration::use_transaction`]), so a failure leaves the old table
/// untouched.
async fn rebuild_audit_events(
    manager: &SchemaManager<'_>,
    direction: RebuildDirection,
) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    if direction == RebuildDirection::Forward {
        connection
            .execute_unprepared(AUDIT_EVENTS_EXECUTE_DDL)
            .await?;
        connection
            .execute_unprepared(
                "INSERT INTO audit_events_execute \
                 (id, operation_id, event_sequence, actor, actor_principal_id, origin, \
                  target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
                  credential_id, trust_mode, row_count, permission, action, redfish_operation, \
                  outcome, progress, failure, verification, occurred_at) \
                 SELECT id, operation_id, event_sequence, actor, actor_principal_id, origin, \
                  target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
                  credential_id, trust_mode, row_count, permission, action, redfish_operation, \
                  outcome, progress, failure, verification, occurred_at \
                 FROM audit_events",
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE audit_events")
            .await?;
    } else {
        connection
            .execute_unprepared(AUDIT_EVENTS_PRE_EXECUTE_DDL)
            .await?;
        connection
            .execute_unprepared(
                "INSERT INTO audit_events_previous \
                 (id, operation_id, event_sequence, actor, actor_principal_id, origin, \
                  target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
                  credential_id, trust_mode, row_count, permission, action, redfish_operation, \
                  outcome, progress, failure, verification, occurred_at) \
                 SELECT id, operation_id, event_sequence, actor, actor_principal_id, origin, \
                  target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
                  credential_id, trust_mode, row_count, permission, action, redfish_operation, \
                  outcome, progress, failure, verification, occurred_at \
                 FROM audit_events",
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE audit_events")
            .await?;
    }
    connection
        .execute_unprepared(if direction == RebuildDirection::Forward {
            "ALTER TABLE audit_events_execute RENAME TO audit_events"
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

/// The widened `audit_events` shape: the 000007 columns plus the
/// `execute-operation` action arm. The arm is transcribed from the domain
/// consistency matrix (`AuditOperationContext::try_new_with_actor_principal`
/// in `rutilus-domain`): the execution action, the endpoint target, the
/// closest legal parameter summary, the `execute-operations` permission,
/// and the fourteen write-family operation codes the domain accepts —
/// `redfish_operation` `IN (...)` is exactly the domain's exhaustive match
/// list, so a persisted row is always one the domain can rehydrate.
const AUDIT_EVENTS_EXECUTE_DDL: &str = r"
CREATE TABLE audit_events_execute (
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

/// The 000007 `audit_events` shape restored by `down`.
const AUDIT_EVENTS_PRE_EXECUTE_DDL: &str = r"
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
