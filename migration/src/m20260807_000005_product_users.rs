use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// The product user and authentication schema (§16 产品用户和权限) and the
/// `audit_events` actor widening.
///
/// # The six product-user tables
///
/// - `principals` — one row per product user (§16.1): a globally unique,
///   normalized-lowercase `name` (the unique index is the atomic duplicate
///   refusal behind the persistence `create_principal`, and a CHECK pins the
///   normalization so the column can never hold a non-lowercase name), and an
///   `enabled`/`disabled` state. Disabling is the soft-off switch: the
///   account stops signing in and its sessions are revoked, while its rows
///   stay intact.
/// - `password_credentials` — the principal's Argon2id password (§16.2).
///   The `principal_id` primary key means one password per principal; the
///   salt and hash are stored as separate blobs under a `hash_format` code
///   that the CHECK pins to `argon2id-1`, so a persisted row's columns can
///   never silently change meaning. The row cascades away with its principal.
/// - `totp_authenticators` — the optional TOTP second factor (§16.2). The
///   secret column stores the Master-Key-encrypted XChaCha20-Poly1305
///   ciphertext blob (the 24-byte nonce followed by the ciphertext, written
///   through `security::encrypt_credential`): the plaintext secret never
///   reaches the database, and the persistence read path decrypts the blob
///   back to the 20-byte plaintext before the domain rehydration validates
///   it. The state CHECK pins `provisioning`/`active`, and the algorithm,
///   digits, and period columns are pinned to the product's single RFC 6238
///   shape (`sha1`, 6, 30) so a row always carries its full verification
///   contract. The per-principal index keeps the sign-in lookup from
///   scanning the whole table.
/// - `sessions` — one row per sign-in (§16.2). Only the SHA-256 hashes of
///   the bearer token and the CSRF token are stored (unique token hash: the
///   lookup key at every authenticated request), with the lifecycle times.
///   Revocation is the soft write — `revoked_at` is set, the row is never
///   physically deleted — so session history stays auditable.
/// - `role_assignments` — the principal's single role (§16.1): the
///   `principal_id` primary key means one role per principal, the CHECK pins
///   the three §16.1 roles, and the `assigned_by` foreign key preserves the
///   assignment fact when the assigning principal is deleted by nulling the
///   reference instead of cascading the assignment away.
/// - `bootstrap_codes` — the first-startup one-time code (§16.2). Only the
///   SHA-256 hash is stored. Consumption sets `used_at` and `used_by`; the
///   code row belongs to its principal (the `used_by` foreign key cascades
///   with it).
///
/// # The `audit_events` rebuild
///
/// `SQLite` cannot alter a CHECK constraint, so widening the actor vocabulary
/// to `('system', 'local-operator', 'user')` and adding the nullable
/// `actor_principal_id` column — the pair pinned by the new CHECK
/// `(actor = 'user') = (actor_principal_id IS NOT NULL)` — is a whole-table
/// rebuild: create `audit_events_new` with the full 0.6 shape, copy every
/// row with a NULL principal id, drop the old table, rename the new one into
/// place, and recreate the indexes. Every legacy row satisfies the new
/// constraints (its actor is `system` or `local-operator` with no principal
/// id), so the copy is a pure data-preserving operation, verified by the
/// migration test that inserts rows before the rebuild and reads them back
/// after. The migration overrides [`MigrationTrait::use_transaction`] so the
/// whole up (and the symmetric down) commits atomically on `SQLite`; the down
/// restores the pre-0.6 shape and refuses only rows a `user` actor wrote
/// after the rebuild, which cannot be represented in the old schema.
///
/// # The `000004` sequence gap
///
/// No `m20260807_000004` migration exists: the slot is unused. `SeaORM`
/// applies migrations by their registration order in [`crate::Migrator`],
/// not by file-name order, so the gap has no functional effect.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// The six-table creation and the audit rebuild must commit as one unit:
    /// a failure halfway would leave the audit table half-rebuilt with no
    /// recorded migration to recover from.
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_principals(manager).await?;
        create_password_credentials(manager).await?;
        create_totp_authenticators(manager).await?;
        create_sessions(manager).await?;
        create_role_assignments(manager).await?;
        create_bootstrap_codes(manager).await?;
        rebuild_audit_events(manager, RebuildDirection::Forward).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse creation order: every dependent table first, because the
        // foreign keys name the principals table, which must exist until
        // every dependent table is gone.
        manager
            .drop_table(Table::drop().table(BootstrapCode::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RoleAssignment::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Session::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(TotpAuthenticator::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(PasswordCredential::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Principal::Table).to_owned())
            .await?;
        rebuild_audit_events(manager, RebuildDirection::Backward).await
    }
}

async fn create_principals(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Principal::Table)
                .col(
                    ColumnDef::new(Principal::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(Principal::Name).string_len(64).not_null())
                .col(ColumnDef::new(Principal::State).string().not_null())
                .col(
                    ColumnDef::new(Principal::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Principal::UpdatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_principals_state",
                    Expr::col(Principal::State).is_in(["enabled", "disabled"]),
                ))
                // The domain stores every name already normalized; this CHECK
                // pins that invariant at the schema so the column can never
                // silently hold a non-lowercase name.
                .check((
                    "ck_principals_name_lowercase",
                    Expr::col(Principal::Name).eq(Func::lower(Expr::col(Principal::Name))),
                ))
                .to_owned(),
        )
        .await?;

    // The operator-facing principal identity: the persistence
    // `create_principal` collision refusal is this index, atomic instead of
    // a check-then-insert race.
    manager
        .create_index(
            Index::create()
                .name("uq_principals_name")
                .table(Principal::Table)
                .col(Principal::Name)
                .unique()
                .to_owned(),
        )
        .await
}

async fn create_password_credentials(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(PasswordCredential::Table)
                .col(
                    ColumnDef::new(PasswordCredential::PrincipalId)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(PasswordCredential::HashFormat)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(PasswordCredential::Salt).binary().not_null())
                .col(ColumnDef::new(PasswordCredential::Hash).binary().not_null())
                .col(
                    ColumnDef::new(PasswordCredential::ChangedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_password_credentials_hash_format",
                    Expr::col(PasswordCredential::HashFormat).is_in(["argon2id-1"]),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_password_credentials_principal")
                        .from(PasswordCredential::Table, PasswordCredential::PrincipalId)
                        .to(Principal::Table, Principal::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await
}

async fn create_totp_authenticators(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(TotpAuthenticator::Table)
                .col(
                    ColumnDef::new(TotpAuthenticator::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(TotpAuthenticator::PrincipalId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(TotpAuthenticator::Secret)
                        .binary()
                        .not_null(),
                )
                .col(ColumnDef::new(TotpAuthenticator::State).string().not_null())
                .col(
                    ColumnDef::new(TotpAuthenticator::Algorithm)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(TotpAuthenticator::Digits)
                        .integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(TotpAuthenticator::Period)
                        .integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(TotpAuthenticator::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(TotpAuthenticator::ActivatedAt).timestamp_with_time_zone())
                .col(ColumnDef::new(TotpAuthenticator::LastUsedStep).big_integer())
                .check((
                    "ck_totp_authenticators_state",
                    Expr::col(TotpAuthenticator::State).is_in(["provisioning", "active"]),
                ))
                .check((
                    "ck_totp_authenticators_algorithm",
                    Expr::col(TotpAuthenticator::Algorithm).is_in(["sha1"]),
                ))
                .check((
                    "ck_totp_authenticators_digits",
                    Expr::col(TotpAuthenticator::Digits).eq(6),
                ))
                .check((
                    "ck_totp_authenticators_period",
                    Expr::col(TotpAuthenticator::Period).eq(30),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_totp_authenticators_principal")
                        .from(TotpAuthenticator::Table, TotpAuthenticator::PrincipalId)
                        .to(Principal::Table, Principal::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("ix_totp_authenticators_principal")
                .table(TotpAuthenticator::Table)
                .col(TotpAuthenticator::PrincipalId)
                .to_owned(),
        )
        .await
}

async fn create_sessions(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Session::Table)
                .col(ColumnDef::new(Session::Id).uuid().not_null().primary_key())
                .col(ColumnDef::new(Session::PrincipalId).uuid().not_null())
                .col(ColumnDef::new(Session::TokenHash).binary().not_null())
                .col(ColumnDef::new(Session::CsrfHash).binary().not_null())
                .col(
                    ColumnDef::new(Session::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Session::LastUsedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(Session::ExpiresAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(Session::RevokedAt).timestamp_with_time_zone())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_sessions_principal")
                        .from(Session::Table, Session::PrincipalId)
                        .to(Principal::Table, Principal::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    // The token hash is the lookup key of every authenticated request: the
    // unique index makes the collision refusal atomic and the lookup
    // indexed. The per-principal index keeps revocations and listings
    // (batch `revoked_at` writes) from scanning the whole table.
    manager
        .create_index(
            Index::create()
                .name("uq_sessions_token_hash")
                .table(Session::Table)
                .col(Session::TokenHash)
                .unique()
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("ix_sessions_principal")
                .table(Session::Table)
                .col(Session::PrincipalId)
                .to_owned(),
        )
        .await
}

async fn create_role_assignments(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(RoleAssignment::Table)
                .col(
                    ColumnDef::new(RoleAssignment::PrincipalId)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(RoleAssignment::Role).string().not_null())
                .col(ColumnDef::new(RoleAssignment::AssignedBy).uuid())
                .col(
                    ColumnDef::new(RoleAssignment::AssignedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .check((
                    "ck_role_assignments_role",
                    Expr::col(RoleAssignment::Role).is_in(["administrator", "operator", "viewer"]),
                ))
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_role_assignments_principal")
                        .from(RoleAssignment::Table, RoleAssignment::PrincipalId)
                        .to(Principal::Table, Principal::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_role_assignments_assigner")
                        .from(RoleAssignment::Table, RoleAssignment::AssignedBy)
                        .to(Principal::Table, Principal::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::SetNull),
                )
                .to_owned(),
        )
        .await
}

async fn create_bootstrap_codes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(BootstrapCode::Table)
                .col(
                    ColumnDef::new(BootstrapCode::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(BootstrapCode::CodeHash).binary().not_null())
                .col(
                    ColumnDef::new(BootstrapCode::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .col(ColumnDef::new(BootstrapCode::UsedAt).timestamp_with_time_zone())
                .col(ColumnDef::new(BootstrapCode::UsedBy).uuid())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_bootstrap_codes_principal")
                        .from(BootstrapCode::Table, BootstrapCode::UsedBy)
                        .to(Principal::Table, Principal::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await
}

/// Whether the rebuild moves the audit table forward (0.6 shape) or back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildDirection {
    Forward,
    Backward,
}

/// Rebuilds `audit_events` to add `actor_principal_id` and widen the actor
/// CHECK (forward) or restores the pre-0.6 shape (backward).
///
/// `SQLite` cannot add or widen a CHECK on an existing table, so the shape
/// change is a create-copy-drop-rename cycle with the indexes recreated
/// after the rename. All statements run on the migration's transaction (see
/// [`Migration::use_transaction`]), so a failure leaves the old table
/// untouched.
async fn rebuild_audit_events(
    manager: &SchemaManager<'_>,
    direction: RebuildDirection,
) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    if direction == RebuildDirection::Forward {
        connection.execute_unprepared(AUDIT_EVENTS_NEW_DDL).await?;
        connection
            .execute_unprepared(
                "INSERT INTO audit_events_new \
                 (id, operation_id, event_sequence, actor, actor_principal_id, origin, \
                  target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
                  credential_id, trust_mode, row_count, permission, action, redfish_operation, \
                  outcome, progress, failure, verification, occurred_at) \
                 SELECT id, operation_id, event_sequence, actor, NULL, origin, \
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
            .execute_unprepared(AUDIT_EVENTS_ORIGINAL_DDL)
            .await?;
        connection
            .execute_unprepared(
                "INSERT INTO audit_events_old \
                 (id, operation_id, event_sequence, actor, origin, \
                  target_kind, target_endpoint_id, target_endpoint_address, parameter_kind, \
                  credential_id, trust_mode, row_count, permission, action, redfish_operation, \
                  outcome, progress, failure, verification, occurred_at) \
                 SELECT id, operation_id, event_sequence, actor, origin, \
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
            "ALTER TABLE audit_events_new RENAME TO audit_events"
        } else {
            "ALTER TABLE audit_events_old RENAME TO audit_events"
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

/// The 0.6 `audit_events` shape: the original columns plus the nullable
/// `actor_principal_id`, the actor CHECK widened to the product user, and
/// the pairing CHECK tying the two together.
const AUDIT_EVENTS_NEW_DDL: &str = r"
CREATE TABLE audit_events_new (
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
                'endpoint-import-row-failed'
            )
            AND verification IS NOT NULL
            AND verification IN ('rejected', 'inconclusive'))
    )
)
";

/// The pre-0.6 `audit_events` shape restored by `down`.
const AUDIT_EVENTS_ORIGINAL_DDL: &str = r"
CREATE TABLE audit_events_old (
    id uuid_text NOT NULL PRIMARY KEY,
    operation_id uuid_text NOT NULL,
    event_sequence integer NOT NULL,
    actor varchar NOT NULL,
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
        CHECK (actor IN ('system', 'local-operator')),
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
                'endpoint-import-row-failed'
            )
            AND verification IS NOT NULL
            AND verification IN ('rejected', 'inconclusive'))
    )
)
";

#[derive(DeriveIden)]
enum Principal {
    #[sea_orm(iden = "principals")]
    Table,
    Id,
    Name,
    State,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum PasswordCredential {
    #[sea_orm(iden = "password_credentials")]
    Table,
    PrincipalId,
    HashFormat,
    Salt,
    Hash,
    ChangedAt,
}

#[derive(DeriveIden)]
enum TotpAuthenticator {
    #[sea_orm(iden = "totp_authenticators")]
    Table,
    Id,
    PrincipalId,
    Secret,
    State,
    Algorithm,
    Digits,
    Period,
    CreatedAt,
    ActivatedAt,
    LastUsedStep,
}

#[derive(DeriveIden)]
enum Session {
    #[sea_orm(iden = "sessions")]
    Table,
    Id,
    PrincipalId,
    TokenHash,
    CsrfHash,
    CreatedAt,
    LastUsedAt,
    ExpiresAt,
    RevokedAt,
}

#[derive(DeriveIden)]
enum RoleAssignment {
    #[sea_orm(iden = "role_assignments")]
    Table,
    PrincipalId,
    Role,
    AssignedBy,
    AssignedAt,
}

#[derive(DeriveIden)]
enum BootstrapCode {
    #[sea_orm(iden = "bootstrap_codes")]
    Table,
    Id,
    CodeHash,
    CreatedAt,
    UsedAt,
    UsedBy,
}
