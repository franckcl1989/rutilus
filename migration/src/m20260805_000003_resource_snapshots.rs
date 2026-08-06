use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_resource_table(manager).await?;
        create_resource_snapshot_table(manager).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(ResourceSnapshot::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Resource::Table).to_owned())
            .await
    }
}

/// Creates the stable `resources` identity table with its feature allow-list.
///
/// The `ck_resources_feature` check keeps the persisted feature codes
/// closed while the product code strings stay forward-extensible per §2.1.
async fn create_resource_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(Resource::Table)
                .col(ColumnDef::new(Resource::Id).uuid().not_null().primary_key())
                .col(ColumnDef::new(Resource::EndpointId).uuid().not_null())
                .col(ColumnDef::new(Resource::OdataId).string().not_null())
                .col(ColumnDef::new(Resource::Feature).string().not_null())
                .col(
                    ColumnDef::new(Resource::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_resources_endpoint")
                        .from(Resource::Table, Resource::EndpointId)
                        .to(Endpoint::Table, Endpoint::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .check((
                    "ck_resources_feature",
                    Expr::col(Resource::Feature).is_in([
                        "service-root",
                        "systems",
                        "chassis",
                        "managers",
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
                    ]),
                ))
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("uq_resources_endpoint_odata_id")
                .table(Resource::Table)
                .col(Resource::EndpointId)
                .col(Resource::OdataId)
                .unique()
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .name("ix_resources_endpoint_feature")
                .table(Resource::Table)
                .col(Resource::EndpointId)
                .col(Resource::Feature)
                .to_owned(),
        )
        .await
}

/// Creates the immutable per-Generation snapshot table chained to
/// `resources`; every row keeps one positive Generation and one observation
/// time so a complete Generation can be replayed without ambiguity.
async fn create_resource_snapshot_table(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(ResourceSnapshot::Table)
                .col(
                    ColumnDef::new(ResourceSnapshot::ResourceId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceSnapshot::Generation)
                        .big_integer()
                        .not_null(),
                )
                .col(ColumnDef::new(ResourceSnapshot::OdataType).string())
                .col(ColumnDef::new(ResourceSnapshot::Etag).string())
                .col(
                    ColumnDef::new(ResourceSnapshot::TypedPayloadJson)
                        .text()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceSnapshot::ObservedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(ResourceSnapshot::ResourceId)
                        .col(ResourceSnapshot::Generation),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_resource_snapshots_resource")
                        .from(ResourceSnapshot::Table, ResourceSnapshot::ResourceId)
                        .to(Resource::Table, Resource::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .check((
                    "ck_resource_snapshots_generation",
                    Expr::col(ResourceSnapshot::Generation).gte(1),
                ))
                .to_owned(),
        )
        .await
}

#[derive(DeriveIden)]
enum Endpoint {
    #[sea_orm(iden = "endpoints")]
    Table,
    Id,
}

#[derive(DeriveIden)]
enum Resource {
    #[sea_orm(iden = "resources")]
    Table,
    Id,
    EndpointId,
    OdataId,
    Feature,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ResourceSnapshot {
    #[sea_orm(iden = "resource_snapshots")]
    Table,
    ResourceId,
    Generation,
    OdataType,
    Etag,
    TypedPayloadJson,
    ObservedAt,
}
