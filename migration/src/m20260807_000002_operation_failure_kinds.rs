use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Adds the optional `operations.failure_kind` classification column, the
/// data foundation of the §13.7 batch "unsupported" outcome bucket.
///
/// A `Failed` operation carries a kind only when the product can prove *why*
/// it failed in product vocabulary; this slice's sole kind,
/// `capability-unsupported`, is written by the executor's capability
/// pre-flight refusal path (§13.3 step 2) before the `Failed` transition.
/// The column is nullable: every operation that was never classified — every
/// success, every in-flight row, and every unclassified failure — stores
/// `NULL`.
///
/// # Why the CHECK lives inline in the raw `ADD COLUMN`
///
/// The `operations` table ships with migration 000005, whose doc records the
/// rule that its schema evolves through follow-up `ALTER TABLE` statements —
/// this migration is that follow-up. `SQLite` cannot add a CHECK constraint
/// to an existing table through `ADD CONSTRAINT`, so the allow-list is a
/// column-level constraint written inline in one raw `ALTER TABLE ...
/// ADD COLUMN` statement, exactly like the `batch_id` `REFERENCES` clause
/// (migration 000011). `NULL` passes the CHECK (an absent classification is
/// not a classification), and the `IN` list keeps the vocabulary open for
/// later slices to extend with new kinds without a table rebuild.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "ALTER TABLE operations ADD COLUMN failure_kind text NULL \
                 CHECK (failure_kind IN ('capability-unsupported'))",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(Operation::Table)
                    .drop_column(Operation::FailureKind)
                    .to_owned(),
            )
            .await
    }
}

#[derive(DeriveIden)]
enum Operation {
    #[sea_orm(iden = "operations")]
    Table,
    FailureKind,
}
