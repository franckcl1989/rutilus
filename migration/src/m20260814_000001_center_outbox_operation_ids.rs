use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Adds the plaintext `operation_id` column to `center_outbox` (R6-E-04).
///
/// # Why a plaintext column
///
/// The center's durable outbox holds exactly the §15.6 operation offers,
/// and every repair read of an offer — the dispatch retry's fall-through,
/// the V5E-1 reply-site fallback, the tracking view's offer facts — had to
/// decrypt and parse the whole queue (or a bounded window) to find one
/// operation's rows. The `operation_id` is not a secret: it already rides
/// in the clear inside the envelope the payload column protects, and on the
/// wire. A plaintext column therefore adds no disclosure surface — it only
/// lets the reads and the ack-time pruning address one operation's rows
/// directly, without the O(N) decryption of the whole queue.
///
/// The column is deliberately nullable and unconstrained: rows that are not
/// offers (the site-side content queue) carry `NULL`, and the value is
/// always written by the repository from the same payload it stores, so the
/// column agrees with the decrypted envelope by construction. Rows written
/// before this migration carry `NULL`; the repository's directed read
/// backfills them lazily from the payload on first access, so a pre-migration
/// acknowledged offer can never be mistaken for a never-enqueued record.
///
/// # Downgrade symmetry
///
/// `down` drops the index and the column; every row survives (the column
/// was derived data). The single-table `down` is never constrained by the
/// child-first drop discipline (no foreign key pair to order).
///
/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default. `down`
/// runs two statements (the index drop, then the column drop) that `SQLite`
/// would otherwise auto-commit one by one: a crash between them would leave
/// the index dropped while the migration still records as applied, and the
/// retried `down` would then fail with "no such index" forever. `DROP
/// INDEX`, `DROP COLUMN`, `ADD COLUMN`, and `CREATE INDEX` are all legal
/// `SQLite` DDL inside a transaction, so the override costs nothing but the
/// crash-resume guarantee — the same discipline the rebuild migrations
/// (000007/000008 and the `m20260813_00000x` slices) already follow.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(CenterOutbox::Table)
                    .add_column(ColumnDef::new(CenterOutbox::OperationId).uuid().null())
                    .to_owned(),
            )
            .await?;
        // The directed reads — one operation's newest row, and the ack-time
        // pruning of its retired rows — filter on the column; the index
        // keeps them off a full table scan.
        manager
            .create_index(
                Index::create()
                    .name("ix_center_outbox_instance_operation")
                    .table(CenterOutbox::Table)
                    .col(CenterOutbox::InstanceId)
                    .col(CenterOutbox::OperationId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared("DROP INDEX ix_center_outbox_instance_operation")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE center_outbox DROP COLUMN operation_id")
            .await
            .map(|_| ())
    }
}

#[derive(DeriveIden)]
enum CenterOutbox {
    #[sea_orm(iden = "center_outbox")]
    Table,
    InstanceId,
    OperationId,
}
