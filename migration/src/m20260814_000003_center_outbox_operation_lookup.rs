use sea_orm_migration::prelude::*;

/// Adds the cross-instance `operation_id` lookup index and the endpoint
/// routing index of the dispatch scans (W7-E-3, W7-P-1).
///
/// # The `center_outbox` operation lookup (W7-E-3)
///
/// The R6-E-01 unknown-outcome refusal confirms an `Unknown` operation's
/// offer through the directed read over the plaintext `operation_id`
/// column. The confirmation used to address the request's own site only;
/// after an endpoint re-home the offer lives in the *original* site's
/// queue, so the confirmation must address any instance — a lookup the
/// `(instance_id, operation_id)` index cannot serve. The single-column
/// `ix_center_outbox_operation` index serves the cross-instance lookup,
/// and — `SQLite` indexes NULL keys, so `IS NULL` is an index range scan —
/// the NULL-existence gates of the lazy pre-migration backfill (W7-P-2)
/// ride it too.
///
/// # The `operation_targets` endpoint routing (W7-P-1)
///
/// The center dispatch's idempotency scan lists operations by candidate
/// state and filtered the endpoint in memory, so every scan listed (and
/// decrypted — one `XChaCha20` envelope per row) the whole global operation
/// table. The scan now drives the endpoint-scoped read
/// (`list_operations_for_endpoint`) through this index: the endpoint's
/// operation ids first, then the operations by id. The table's composite
/// primary key is `(operation_id, target_id)`, so `endpoint_id` alone had
/// no index and every scan walked the whole table.
///
/// # Downgrade symmetry
///
/// `down` drops both indexes; no table and no row changes, so the single
/// index-only `down` is never constrained by the child-first drop
/// discipline (no foreign key pair to order).
///
/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default. `up` runs
/// two `CREATE INDEX` statements and `down` two `DROP INDEX` statements that
/// `SQLite` would otherwise auto-commit one by one: a crash between them
/// would leave the migration half-applied while it still records as applied,
/// and the retried run would then fail — `up` with "index already exists"
/// (no `IF NOT EXISTS`), `down` with "no such index" forever, blocking the
/// whole rollback chain. `CREATE INDEX` and `DROP INDEX` are both legal
/// `SQLite` DDL inside a transaction, so the override costs nothing but the
/// crash-resume guarantee — the same discipline the `m20260814_000001`
/// slice (W7-D-7) and the rebuild migrations already follow.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .name("ix_center_outbox_operation")
                    .table(CenterOutbox::Table)
                    .col(CenterOutbox::OperationId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name("ix_operation_targets_endpoint")
                    .table(OperationTargets::Table)
                    .col(OperationTargets::EndpointId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared("DROP INDEX ix_center_outbox_operation")
            .await?;
        connection
            .execute_unprepared("DROP INDEX ix_operation_targets_endpoint")
            .await
            .map(|_| ())
    }
}

#[derive(DeriveIden)]
enum CenterOutbox {
    #[sea_orm(iden = "center_outbox")]
    Table,
    OperationId,
}

#[derive(DeriveIden)]
enum OperationTargets {
    #[sea_orm(iden = "operation_targets")]
    Table,
    EndpointId,
}
