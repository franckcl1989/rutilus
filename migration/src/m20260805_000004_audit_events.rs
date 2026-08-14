use sea_orm_migration::prelude::*;

/// # Why the whole migration commits atomically
///
/// The migration overrides [`MigrationTrait::use_transaction`] so the whole
/// `up` — and the symmetric `down` — commits as one unit on `SQLite`, where
/// the sea-orm-migration runner wraps only `Postgres` by default (W9-D-1: the
/// W8-D-1 defect's third recurrence surface). `up` runs four statements (one
/// `CREATE TABLE`, three `CREATE INDEX`es) and `down` one `DROP TABLE` that
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
                    .table(AuditEvent::Table)
                    .col(
                        ColumnDef::new(AuditEvent::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(AuditEvent::OperationId).uuid().not_null())
                    .col(
                        ColumnDef::new(AuditEvent::EventSequence)
                            .big_integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditEvent::Actor).string().not_null())
                    .col(ColumnDef::new(AuditEvent::Origin).string().not_null())
                    .col(ColumnDef::new(AuditEvent::TargetKind).string().not_null())
                    .col(ColumnDef::new(AuditEvent::TargetEndpointId).uuid())
                    .col(ColumnDef::new(AuditEvent::TargetEndpointAddress).string())
                    .col(
                        ColumnDef::new(AuditEvent::ParameterKind)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditEvent::CredentialId).uuid())
                    .col(ColumnDef::new(AuditEvent::TrustMode).string())
                    .col(ColumnDef::new(AuditEvent::RowCount).big_integer())
                    .col(ColumnDef::new(AuditEvent::Permission).string().not_null())
                    .col(ColumnDef::new(AuditEvent::Action).string().not_null())
                    .col(
                        ColumnDef::new(AuditEvent::RedfishOperation)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(AuditEvent::Outcome).string().not_null())
                    .col(ColumnDef::new(AuditEvent::Progress).string())
                    .col(ColumnDef::new(AuditEvent::Failure).string())
                    .col(ColumnDef::new(AuditEvent::Verification).string())
                    .col(
                        ColumnDef::new(AuditEvent::OccurredAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .check((
                        "ck_audit_events_sequence",
                        Expr::col(AuditEvent::EventSequence)
                            .gte(1)
                            .and(Expr::col(AuditEvent::EventSequence).lte(i64::from(u32::MAX))),
                    ))
                    .check((
                        "ck_audit_events_actor",
                        Expr::col(AuditEvent::Actor).is_in(["system", "local-operator"]),
                    ))
                    .check((
                        "ck_audit_events_origin",
                        Expr::col(AuditEvent::Origin).is_in(["standalone", "site", "center"]),
                    ))
                    .check(("ck_audit_events_target", target_shape()))
                    .check(("ck_audit_events_parameters", parameter_shape()))
                    .check(("ck_audit_events_action", action_shape()))
                    .check(("ck_audit_events_outcome", outcome_shape()))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_audit_events_operation_sequence")
                    .table(AuditEvent::Table)
                    .col(AuditEvent::OperationId)
                    .col(AuditEvent::EventSequence)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ix_audit_events_occurred_at")
                    .table(AuditEvent::Table)
                    .col(AuditEvent::OccurredAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ix_audit_events_action_occurred_at")
                    .table(AuditEvent::Table)
                    .col(AuditEvent::Action)
                    .col(AuditEvent::OccurredAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditEvent::Table).to_owned())
            .await
    }
}

fn target_shape() -> SimpleExpr {
    Expr::col(AuditEvent::TargetKind)
        .eq("product")
        .and(Expr::col(AuditEvent::TargetEndpointId).is_null())
        .and(Expr::col(AuditEvent::TargetEndpointAddress).is_null())
        .or(Expr::col(AuditEvent::TargetKind)
            .eq("endpoint-address")
            .and(Expr::col(AuditEvent::TargetEndpointId).is_null())
            .and(Expr::col(AuditEvent::TargetEndpointAddress).is_not_null()))
        .or(Expr::col(AuditEvent::TargetKind)
            .eq("endpoint")
            .and(Expr::col(AuditEvent::TargetEndpointId).is_not_null())
            .and(Expr::col(AuditEvent::TargetEndpointAddress).is_null()))
}

fn parameter_shape() -> SimpleExpr {
    Expr::col(AuditEvent::ParameterKind)
        .eq("endpoint-enrollment")
        .and(Expr::col(AuditEvent::CredentialId).is_not_null())
        .and(Expr::col(AuditEvent::TrustMode).is_not_null())
        .and(Expr::col(AuditEvent::TrustMode).is_in(["system-ca", "pinned-certificate"]))
        .and(Expr::col(AuditEvent::RowCount).is_null())
        .or(Expr::col(AuditEvent::ParameterKind)
            .eq("endpoint-refresh")
            .and(Expr::col(AuditEvent::CredentialId).is_null())
            .and(Expr::col(AuditEvent::TrustMode).is_null())
            .and(Expr::col(AuditEvent::RowCount).is_null()))
        .or(Expr::col(AuditEvent::ParameterKind)
            .eq("csv-endpoint-import")
            .and(Expr::col(AuditEvent::CredentialId).is_null())
            .and(Expr::col(AuditEvent::TrustMode).is_null())
            .and(Expr::col(AuditEvent::RowCount).is_not_null())
            .and(Expr::col(AuditEvent::RowCount).gte(1))
            .and(Expr::col(AuditEvent::RowCount).lte(i64::from(u32::MAX))))
}

fn action_shape() -> SimpleExpr {
    Expr::col(AuditEvent::Action)
        .eq("enroll-endpoint")
        .and(Expr::col(AuditEvent::TargetKind).eq("endpoint-address"))
        .and(Expr::col(AuditEvent::ParameterKind).eq("endpoint-enrollment"))
        .and(Expr::col(AuditEvent::Permission).eq("manage-endpoints"))
        .and(Expr::col(AuditEvent::RedfishOperation).eq("probe-core-capabilities"))
        .or(Expr::col(AuditEvent::Action)
            .eq("refresh-endpoint")
            .and(Expr::col(AuditEvent::TargetKind).eq("endpoint"))
            .and(Expr::col(AuditEvent::ParameterKind).eq("endpoint-refresh"))
            .and(Expr::col(AuditEvent::Permission).eq("refresh-endpoints"))
            .and(Expr::col(AuditEvent::RedfishOperation).eq("read-core-resources")))
        .or(Expr::col(AuditEvent::Action)
            .eq("import-endpoints")
            .and(Expr::col(AuditEvent::TargetKind).eq("product"))
            .and(Expr::col(AuditEvent::ParameterKind).eq("csv-endpoint-import"))
            .and(Expr::col(AuditEvent::Permission).eq("manage-endpoints"))
            .and(Expr::col(AuditEvent::RedfishOperation).eq("none")))
}

fn outcome_shape() -> SimpleExpr {
    Expr::col(AuditEvent::Outcome)
        .eq("started")
        .and(Expr::col(AuditEvent::EventSequence).eq(1))
        .and(Expr::col(AuditEvent::Progress).is_null())
        .and(Expr::col(AuditEvent::Failure).is_null())
        .and(Expr::col(AuditEvent::Verification).is_null())
        .or(Expr::col(AuditEvent::Outcome)
            .eq("progress")
            .and(Expr::col(AuditEvent::EventSequence).gt(1))
            .and(Expr::col(AuditEvent::Progress).is_not_null())
            .and(progress_shape())
            .and(Expr::col(AuditEvent::Failure).is_null())
            .and(Expr::col(AuditEvent::Verification).is_null()))
        .or(Expr::col(AuditEvent::Outcome)
            .eq("succeeded")
            .and(Expr::col(AuditEvent::EventSequence).gt(1))
            .and(Expr::col(AuditEvent::Progress).is_null())
            .and(Expr::col(AuditEvent::Failure).is_null())
            .and(Expr::col(AuditEvent::Verification).is_not_null())
            .and(Expr::col(AuditEvent::Verification).eq("confirmed")))
        .or(Expr::col(AuditEvent::Outcome)
            .eq("failed")
            .and(Expr::col(AuditEvent::EventSequence).gt(1))
            .and(Expr::col(AuditEvent::Progress).is_null())
            .and(Expr::col(AuditEvent::Failure).is_not_null())
            .and(Expr::col(AuditEvent::Failure).is_in([
                "credential-unavailable",
                "tls-trust-failed",
                "redfish-discovery-failed",
                "endpoint-persistence-failed",
                "core-resource-read-failed",
                "snapshot-persistence-failed",
                "csv-invalid",
                "endpoint-import-row-failed",
            ]))
            .and(Expr::col(AuditEvent::Verification).is_not_null())
            .and(Expr::col(AuditEvent::Verification).is_in(["rejected", "inconclusive"])))
}

fn progress_shape() -> SimpleExpr {
    Expr::col(AuditEvent::Progress)
        .eq("endpoint-created")
        .and(Expr::col(AuditEvent::Action).eq("enroll-endpoint"))
        .or(Expr::col(AuditEvent::Progress)
            .eq("row-validated")
            .and(Expr::col(AuditEvent::Action).eq("import-endpoints")))
}

#[derive(DeriveIden)]
enum AuditEvent {
    #[sea_orm(iden = "audit_events")]
    Table,
    Id,
    OperationId,
    EventSequence,
    Actor,
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
