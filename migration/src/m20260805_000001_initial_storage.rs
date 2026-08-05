use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    #[allow(
        clippy::too_many_lines,
        reason = "the initial schema is reviewed as one order-sensitive migration"
    )]
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(CredentialVersion::Table)
                    .col(uuid_primary_key(CredentialVersion::Id))
                    .col(
                        ColumnDef::new(CredentialVersion::CredentialId)
                            .uuid()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(CredentialVersion::EncryptedSecret)
                            .binary()
                            .not_null(),
                    )
                    .col(ColumnDef::new(CredentialVersion::Nonce).binary().not_null())
                    .col(timestamp(CredentialVersion::CreatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_credential_versions_credential")
                            .from(CredentialVersion::Table, CredentialVersion::CredentialId)
                            .to(Credential::Table, Credential::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_credential_versions_owner_id")
                    .table(CredentialVersion::Table)
                    .col(CredentialVersion::CredentialId)
                    .col(CredentialVersion::Id)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Credential::Table)
                    .col(uuid_primary_key(Credential::Id))
                    .col(ColumnDef::new(Credential::Name).string().not_null())
                    .col(ColumnDef::new(Credential::Username).string().not_null())
                    .col(ColumnDef::new(Credential::ActiveVersionId).uuid())
                    .col(timestamp(Credential::CreatedAt))
                    .col(timestamp(Credential::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_credentials_active_version")
                            .from_tbl(Credential::Table)
                            .from_col(Credential::Id)
                            .from_col(Credential::ActiveVersionId)
                            .to_tbl(CredentialVersion::Table)
                            .to_col(CredentialVersion::CredentialId)
                            .to_col(CredentialVersion::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_credentials_name")
                    .table(Credential::Table)
                    .col(Credential::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("ix_credential_versions_credential_created")
                    .table(CredentialVersion::Table)
                    .col(CredentialVersion::CredentialId)
                    .col(CredentialVersion::CreatedAt)
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Endpoint::Table)
                    .col(uuid_primary_key(Endpoint::Id))
                    .col(ColumnDef::new(Endpoint::DisplayName).string().not_null())
                    .col(timestamp(Endpoint::CreatedAt))
                    .col(timestamp(Endpoint::UpdatedAt))
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EndpointAddress::Table)
                    .col(uuid_primary_key(EndpointAddress::Id))
                    .col(
                        ColumnDef::new(EndpointAddress::EndpointId)
                            .uuid()
                            .not_null(),
                    )
                    .col(ColumnDef::new(EndpointAddress::Address).string().not_null())
                    .col(
                        ColumnDef::new(EndpointAddress::IsActive)
                            .boolean()
                            .not_null(),
                    )
                    .col(timestamp(EndpointAddress::CreatedAt))
                    .col(ColumnDef::new(EndpointAddress::RetiredAt).timestamp_with_time_zone())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoint_addresses_endpoint")
                            .from(EndpointAddress::Table, EndpointAddress::EndpointId)
                            .to(Endpoint::Table, Endpoint::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_endpoint_addresses_address")
                    .table(EndpointAddress::Table)
                    .col(EndpointAddress::Address)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("uq_endpoint_addresses_active")
                    .table(EndpointAddress::Table)
                    .col(EndpointAddress::EndpointId)
                    .and_where(Expr::col(EndpointAddress::IsActive).eq(true))
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EndpointTrust::Table)
                    .col(
                        ColumnDef::new(EndpointTrust::EndpointId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(ColumnDef::new(EndpointTrust::TrustMode).string().not_null())
                    .col(ColumnDef::new(EndpointTrust::CertificateSha256).binary())
                    .col(ColumnDef::new(EndpointTrust::CertificateDer).binary())
                    .col(timestamp(EndpointTrust::TrustedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoint_trust_endpoint")
                            .from(EndpointTrust::Table, EndpointTrust::EndpointId)
                            .to(Endpoint::Table, Endpoint::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EndpointCredential::Table)
                    .col(
                        ColumnDef::new(EndpointCredential::EndpointId)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(EndpointCredential::CredentialId)
                            .uuid()
                            .not_null(),
                    )
                    .col(timestamp(EndpointCredential::AssignedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoint_credentials_endpoint")
                            .from(EndpointCredential::Table, EndpointCredential::EndpointId)
                            .to(Endpoint::Table, Endpoint::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoint_credentials_credential")
                            .from(EndpointCredential::Table, EndpointCredential::CredentialId)
                            .to(Credential::Table, Credential::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Restrict),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(EndpointCredential::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(EndpointTrust::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(EndpointAddress::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Endpoint::Table).to_owned())
            .await?;
        manager
            .execute(
                Query::update()
                    .table(Credential::Table)
                    .value(Credential::ActiveVersionId, Value::Uuid(None))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(CredentialVersion::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Credential::Table).to_owned())
            .await
    }
}

fn uuid_primary_key<T>(column: T) -> ColumnDef
where
    T: IntoIden,
{
    let mut definition = ColumnDef::new(column);
    definition.uuid().not_null().primary_key();
    definition
}

fn timestamp<T>(column: T) -> ColumnDef
where
    T: IntoIden,
{
    let mut definition = ColumnDef::new(column);
    definition.timestamp_with_time_zone().not_null();
    definition
}

#[derive(DeriveIden)]
enum Credential {
    #[sea_orm(iden = "credentials")]
    Table,
    Id,
    Name,
    Username,
    ActiveVersionId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum CredentialVersion {
    #[sea_orm(iden = "credential_versions")]
    Table,
    Id,
    CredentialId,
    EncryptedSecret,
    Nonce,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Endpoint {
    #[sea_orm(iden = "endpoints")]
    Table,
    Id,
    DisplayName,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum EndpointAddress {
    #[sea_orm(iden = "endpoint_addresses")]
    Table,
    Id,
    EndpointId,
    Address,
    IsActive,
    CreatedAt,
    RetiredAt,
}

#[derive(DeriveIden)]
enum EndpointTrust {
    #[sea_orm(iden = "endpoint_trust")]
    Table,
    EndpointId,
    TrustMode,
    CertificateSha256,
    CertificateDer,
    TrustedAt,
}

#[derive(DeriveIden)]
enum EndpointCredential {
    #[sea_orm(iden = "endpoint_credentials")]
    Table,
    EndpointId,
    CredentialId,
    AssignedAt,
}
