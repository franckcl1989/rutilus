use sea_orm_migration::prelude::*;

/// Creates the §12.4 member decode-failure table.
///
/// The table is the persistence sibling of `resource_snapshots`: one row per
/// member whose typed Schema decoding failed during one endpoint refresh
/// Generation, keyed by `endpoint_id + generation + odata_uri` so a complete
/// Generation replays without ambiguity and a Generation can never carry a
/// duplicated record. Rows are written inside the same transaction as the
/// Generation's snapshots and are retained per Generation exactly like the
/// snapshots (§9.5: a failed refresh keeps the last complete snapshot — and
/// the last Generation's records — as one intact whole; the diagnostics query
/// reads the latest Generation).
///
/// The `ck_resource_decode_failures_feature` check mirrors the
/// `ck_resources_feature` allow-list of the `resources` table exactly (the
/// two tables persist the same closed feature surface), so the two
/// allow-lists must stay in lockstep when a future migration extends either.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    // The table builder spells out every column, key, and constraint, which
    // exceeds the pedantic line budget (the rebuild migrations allow the same
    // lint on their exhaustive builders).
    #[allow(clippy::too_many_lines)]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(ResourceDecodeFailure::Table)
                    .col(
                        ColumnDef::new(ResourceDecodeFailure::EndpointId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ResourceDecodeFailure::Generation)
                            .big_integer()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ResourceDecodeFailure::OdataUri)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ResourceDecodeFailure::OdataType).string())
                    .col(
                        ColumnDef::new(ResourceDecodeFailure::Feature)
                            .string()
                            .not_null(),
                    )
                    .col(ColumnDef::new(ResourceDecodeFailure::OemNamespace).string())
                    .col(
                        ColumnDef::new(ResourceDecodeFailure::ErrorSummary)
                            .text()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(ResourceDecodeFailure::ExtendedInfoJson)
                            .text()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(ResourceDecodeFailure::EndpointId)
                            .col(ResourceDecodeFailure::Generation)
                            .col(ResourceDecodeFailure::OdataUri),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_resource_decode_failures_endpoint")
                            .from(
                                ResourceDecodeFailure::Table,
                                ResourceDecodeFailure::EndpointId,
                            )
                            .to(Endpoint::Table, Endpoint::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .check((
                        "ck_resource_decode_failures_generation",
                        Expr::col(ResourceDecodeFailure::Generation).gte(1),
                    ))
                    .check((
                        "ck_resource_decode_failures_feature",
                        Expr::col(ResourceDecodeFailure::Feature).is_in([
                            "service-root",
                            "systems",
                            "chassis",
                            "managers",
                            "dell-attributes",
                            "supermicro-sys-lockdown",
                            "supermicro-kcs-interface",
                            "nvidia-system-config-profile",
                            "nvidia-power-compliance",
                            "nvidia-managed-entity",
                            "processors",
                            "memory",
                            "storages",
                            "network-adapters",
                            "ethernet-interfaces",
                            "accounts",
                            "bios",
                            "boot-options",
                            "secure-boot",
                            "power",
                            "thermal",
                            "sensors",
                            "controls",
                            "log-services",
                            "manager-network-protocol",
                            "host-interfaces",
                            "pcie-devices",
                            "assembly",
                            "software-inventory",
                            "event-service",
                            "event-subscription",
                            "telemetry-service",
                            "metric-definition",
                            "metric-report",
                            "task-service",
                            "task",
                        ]),
                    ))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ResourceDecodeFailure::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Endpoint {
    #[sea_orm(iden = "endpoints")]
    Table,
    Id,
}

#[derive(DeriveIden)]
enum ResourceDecodeFailure {
    #[sea_orm(iden = "resource_decode_failures")]
    Table,
    EndpointId,
    Generation,
    OdataUri,
    OdataType,
    Feature,
    OemNamespace,
    ErrorSummary,
    ExtendedInfoJson,
}
