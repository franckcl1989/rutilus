use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(EndpointCapability::Table)
                    .col(
                        ColumnDef::new(EndpointCapability::EndpointId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EndpointCapability::Capability)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EndpointCapability::State)
                            .string()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(EndpointCapability::ObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .primary_key(
                        Index::create()
                            .col(EndpointCapability::EndpointId)
                            .col(EndpointCapability::Capability),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoint_capabilities_endpoint")
                            .from(EndpointCapability::Table, EndpointCapability::EndpointId)
                            .to(Endpoint::Table, Endpoint::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .check((
                        "ck_endpoint_capabilities_state",
                        Expr::col(EndpointCapability::State).is_in([
                            "supported",
                            "read-only",
                            "unauthorized",
                            "temporarily-unavailable",
                            "schema-incompatible",
                            "not-advertised",
                            "not-compiled",
                        ]),
                    ))
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(EndpointCapability::Table).to_owned())
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
enum EndpointCapability {
    #[sea_orm(iden = "endpoint_capabilities")]
    Table,
    EndpointId,
    Capability,
    State,
    ObservedAt,
}
