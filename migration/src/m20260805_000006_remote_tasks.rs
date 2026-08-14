use sea_orm_migration::prelude::*;

/// The `remote_tasks` table from design §9.3 任务组, added with the
/// execution-flow milestone (design §13.6).
///
/// Each row is one Redfish asynchronous Task the product is monitoring for an
/// operation in `WaitingRemote`: the Task and `TaskMonitor` URIs to poll, the
/// endpoint that accepted the Task, and the last observed progress values.
/// The `operation_id` primary key makes the task part of the operation
/// aggregate — deleting the operation cascades the task away — while
/// `endpoint_id` deliberately has no foreign key, mirroring
/// `operation_targets`: the record must survive endpoint deletion for
/// recovery.
///
/// The `last_state` CHECK constraint refuses a `TaskState` code this build
/// cannot classify, mirroring the `operations.state` and
/// `endpoint_capabilities.state` precedents, so a restart recovery scan can
/// never hand an unknown code to the engine's `RemoteTaskState`.
///
/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default (W9-D-1: the
/// W8-D-1 defect's third recurrence surface). `up` runs two statements (one
/// `CREATE TABLE`, one `CREATE INDEX`) and `down` one `DROP TABLE` that
/// `SQLite` would otherwise auto-commit one by one: a crash between them
/// would leave the migration half-applied while it still records as applied,
/// and the retried run would then fail — `up` with "table already exists"
/// (no `IF NOT EXISTS`), `down` with "no such table" forever, blocking the
/// whole rollback chain. These statements are all legal `SQLite` DDL inside a
/// transaction, so the override costs nothing but the crash-resume guarantee
/// — the same discipline the `m20260814_000003` slice (W8-D-1) and the
/// rebuild migrations already follow.
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
                    .table(RemoteTask::Table)
                    .col(
                        ColumnDef::new(RemoteTask::OperationId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    // Routing hint captured at creation time; deliberately no
                    // foreign key, exactly like operation_targets.endpoint_id:
                    // a task record must outlive its endpoint for the §13.6
                    // recovery scan.
                    .col(ColumnDef::new(RemoteTask::EndpointId).uuid().not_null())
                    .col(ColumnDef::new(RemoteTask::TaskUri).text().not_null())
                    .col(ColumnDef::new(RemoteTask::TaskMonitorUri).text())
                    .col(ColumnDef::new(RemoteTask::LastState).string().not_null())
                    .col(ColumnDef::new(RemoteTask::LastMessage).text())
                    .col(ColumnDef::new(RemoteTask::PercentComplete).integer())
                    .col(
                        ColumnDef::new(RemoteTask::LastCheckedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // The full engine TaskState code set: the current Redfish
                    // DSP0266 TaskState vocabulary in the product's stable
                    // snake-case style. The database refuses a code the
                    // product cannot classify, so rehydrated tasks always
                    // carry a state this build understands.
                    .check((
                        "ck_remote_tasks_state",
                        Expr::col(RemoteTask::LastState).is_in([
                            "new",
                            "starting",
                            "running",
                            "suspended",
                            "interrupted",
                            "pending",
                            "stopping",
                            "completed",
                            "killed",
                            "exception",
                            "service",
                            "cancelling",
                            "cancelled",
                        ]),
                    ))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_remote_tasks_operation")
                            .from(RemoteTask::Table, RemoteTask::OperationId)
                            .to(Operation::Table, Operation::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Recovery scan (§13.6): find the tasks still worth re-polling by
        // their last observed state without scanning the whole table.
        manager
            .create_index(
                Index::create()
                    .name("ix_remote_tasks_state")
                    .table(RemoteTask::Table)
                    .col(RemoteTask::LastState)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(RemoteTask::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Operation {
    #[sea_orm(iden = "operations")]
    Table,
    Id,
}

#[derive(DeriveIden)]
enum RemoteTask {
    #[sea_orm(iden = "remote_tasks")]
    Table,
    OperationId,
    EndpointId,
    TaskUri,
    TaskMonitorUri,
    LastState,
    LastMessage,
    PercentComplete,
    LastCheckedAt,
}
