use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// The `batch_operations` parent table and the `operations.batch_id` child
/// link, added with the 0.5.0 batch submission slice (design §13.7).
///
/// A batch submission becomes one `batch_operations` row (the submission
/// facts only: origin, typed command, acceptance time — deliberately no
/// target list and no state, because the targets are a fact of the child
/// operations and the batch state is derived from them) plus one ordinary
/// single-target `operations` row per submitted endpoint. The child link is
/// `operations.batch_id`, a nullable foreign key with `ON DELETE CASCADE`,
/// so deleting a batch removes its children exactly like the `remote_tasks`
/// precedent (migration 000006): the child is part of the batch aggregate.
///
/// # Why the child link is a follow-up `ALTER TABLE`
///
/// The `operations` table ships with migration 000005, whose doc records the
/// rule that its schema evolves through follow-up `ALTER TABLE` statements —
/// this migration is that follow-up. `SQLite` cannot add a foreign key to an
/// existing table through `ADD CONSTRAINT` (sea-query refuses it), so the
/// nullable column is added with its `REFERENCES` clause inline in one raw
/// `ALTER TABLE ... ADD COLUMN` statement; the index is added with the
/// regular schema API afterwards.
///
/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default (W9-D-1: the
/// W8-D-1 defect's third recurrence surface). `up` runs three statements (one
/// `CREATE TABLE`, the raw `ALTER TABLE ... ADD COLUMN` with its inline
/// `REFERENCES`, one `CREATE INDEX`) and `down` three (one `DROP INDEX`, the
/// `ALTER TABLE` column drop, one `DROP TABLE`) that `SQLite` would otherwise
/// auto-commit one by one: a crash between them would leave the migration
/// half-applied while it still records as applied, and the retried run would
/// then fail — `up` with "table already exists" (no `IF NOT EXISTS`), `down`
/// with "no such table" forever, blocking the whole rollback chain. These
/// statements are all legal `SQLite` DDL inside a transaction, so the
/// override costs nothing but the crash-resume guarantee — the same
/// discipline the `m20260814_000003` slice (W8-D-1) and the rebuild
/// migrations already follow.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(BatchOperation::Table)
                    .col(
                        ColumnDef::new(BatchOperation::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(BatchOperation::Source).string().not_null())
                    // The typed write command as serde JSON (§9.4
                    // `TypedPayloadJson` rule), exactly like
                    // `operations.command`: deliberately no CHECK, because the
                    // command is a JSON document of an open, versioned type
                    // that only the repository deserializes through the
                    // domain type.
                    .col(ColumnDef::new(BatchOperation::Command).text().not_null())
                    .col(
                        ColumnDef::new(BatchOperation::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // The full §13.1 source set, mirroring the
                    // `operations.source` CHECK precedent: the database
                    // refuses a code the product cannot classify, so
                    // rehydrated batches always carry a source this build
                    // understands.
                    .check((
                        "ck_batch_operations_source",
                        Expr::col(BatchOperation::Source).is_in(["standalone", "site", "center"]),
                    ))
                    .to_owned(),
            )
            .await?;

        // The child link, added to the shipped `operations` table as a
        // follow-up ALTER (see the module doc). The REFERENCES clause must
        // live in the ADD COLUMN: SQLite cannot add a foreign key to an
        // existing table any other way, and the raw statement is the only
        // SQLite-valid rendering of that clause.
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE operations ADD COLUMN batch_id uuid_text NULL \
                 REFERENCES batch_operations(id) ON DELETE CASCADE",
            )
            .await?;

        // Batch reporting (§13.7): list one batch's children and cascade
        // their deletion without scanning the whole operations table.
        manager
            .create_index(
                Index::create()
                    .name("ix_operations_batch_id")
                    .table(Operation::Table)
                    .col(Operation::BatchId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("ix_operations_batch_id")
                    .table(Operation::Table)
                    .to_owned(),
            )
            .await?;
        // Dropping the column removes its inline REFERENCES clause with it;
        // SQLite exposes no separate way to drop the constraint.
        manager
            .alter_table(
                Table::alter()
                    .table(Operation::Table)
                    .drop_column(Operation::BatchId)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(BatchOperation::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum BatchOperation {
    #[sea_orm(iden = "batch_operations")]
    Table,
    Id,
    Source,
    Command,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Operation {
    #[sea_orm(iden = "operations")]
    Table,
    BatchId,
}
