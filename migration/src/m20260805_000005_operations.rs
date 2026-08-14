use sea_orm_migration::prelude::*;

/// The `operations` and `operation_targets` tables from design §9.3 任务组.
///
/// This migration creates only the operation aggregate itself. The step
/// execution tables (`operation_steps`, `remote_tasks`) and the event log
/// (`operation_events`) are deliberately deferred to the execution-flow
/// milestone, because nothing in this milestone runs or observes a step.
///
/// Revision note: the `command` column was added to this pre-release
/// migration in place (the same way `resource_snapshots` was revised for its
/// feature-code CHECK before 0.2.0 shipped — the audit confirmed that is
/// acceptable before any release, because no database can already exist). An
/// already-published migration would instead need a follow-up `ALTER TABLE`,
/// which is how future schema additions to this table must be shipped.
///
/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default (W9-D-1:
/// the W8-D-1 defect's third recurrence surface). `up` runs three statements
/// (two `CREATE TABLE`s, one `CREATE INDEX`) and `down` two `DROP TABLE`s
/// that `SQLite` would otherwise auto-commit one by one: a crash between
/// them would leave the migration half-applied while it still records as
/// applied, and the retried run would then fail — `up` with "table already
/// exists" (no `IF NOT EXISTS`), `down` with "no such table" forever,
/// blocking the whole rollback chain. These statements are all legal
/// `SQLite` DDL inside a transaction, so the override costs nothing but the
/// crash-resume guarantee — the same discipline the `m20260814_000003` slice
/// (W8-D-1) and the rebuild migrations already follow.
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
                    .table(Operation::Table)
                    .col(
                        ColumnDef::new(Operation::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(Operation::Source).string().not_null())
                    .col(ColumnDef::new(Operation::State).string().not_null())
                    // The typed write command as serde JSON (§9.4
                    // `TypedPayloadJson` rule). Deliberately no CHECK: the
                    // command is a JSON document of an open, versioned type
                    // that only the repository deserializes through the
                    // domain type — the database never parses it, exactly like
                    // `resource_snapshots.typed_payload_json`.
                    .col(ColumnDef::new(Operation::Command).text().not_null())
                    .col(
                        ColumnDef::new(Operation::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Operation::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // The full §13.1 source set. The database refuses a code
                    // the product cannot classify, mirroring the audit_events
                    // origin CHECK precedent, so rehydrated operations always
                    // carry a source this build understands.
                    .check((
                        "ck_operations_source",
                        Expr::col(Operation::Source).is_in(["standalone", "site", "center"]),
                    ))
                    // The full §13.1 state machine. The database refuses a
                    // code the product cannot classify, mirroring the
                    // endpoint_capabilities state CHECK precedent, so a
                    // recovery scan can never hand an unknown code to the
                    // domain state machine.
                    .check((
                        "ck_operations_state",
                        Expr::col(Operation::State).is_in([
                            "queued",
                            "validating",
                            "running",
                            "waiting-remote",
                            "verifying",
                            "succeeded",
                            "failed",
                            "unknown",
                            "cancelled",
                        ]),
                    ))
                    .to_owned(),
            )
            .await?;

        // Recovery scan (§13.6): find every interrupted operation by state
        // (WaitingRemote first) without scanning the whole table.
        manager
            .create_index(
                Index::create()
                    .name("ix_operations_state")
                    .table(Operation::Table)
                    .col(Operation::State)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(OperationTarget::Table)
                    .col(
                        ColumnDef::new(OperationTarget::OperationId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(OperationTarget::TargetId).uuid().not_null())
                    // Routing hint captured at creation time; deliberately no
                    // foreign key: operations outlive their endpoints for
                    // audit and recovery, so deleting an endpoint must never
                    // cascade operation history away.
                    .col(
                        ColumnDef::new(OperationTarget::EndpointId)
                            .uuid()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(OperationTarget::OperationId)
                            .col(OperationTarget::TargetId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_operation_targets_operation")
                            .from(OperationTarget::Table, OperationTarget::OperationId)
                            .to(Operation::Table, Operation::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(OperationTarget::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Operation::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Operation {
    #[sea_orm(iden = "operations")]
    Table,
    Id,
    Source,
    State,
    Command,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum OperationTarget {
    #[sea_orm(iden = "operation_targets")]
    Table,
    OperationId,
    TargetId,
    EndpointId,
}
