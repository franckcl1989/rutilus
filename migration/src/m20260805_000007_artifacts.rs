use sea_orm_migration::prelude::*;

/// The `artifacts` table from design §9.3 制品组, added with the
/// firmware-update milestone (design §14.3, §0.4.0).
///
/// Each row is the manifest of one uploaded firmware file; the file bytes
/// themselves are stored outside the database under the product data
/// directory, at the deterministic path the persistence layer derives from
/// the artifact identity. The row is authoritative for resume and recovery:
/// `uploaded_bytes` is the exact resume offset after an interrupted upload
/// (§0.4.0 大文件断点和进度), and the `state` CHECK constraint refuses a code
/// this build cannot classify — mirroring the `operations.state` precedent —
/// so a recovery scan can never hand an unknown code to the domain
/// `ArtifactState`.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Artifact::Table)
                    .col(ColumnDef::new(Artifact::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Artifact::Name).text().not_null())
                    // The declared size and the received count are SQLite
                    // INTEGER (signed 64-bit); the domain `u64` is mapped by
                    // the repository, which refuses values the column cannot
                    // hold.
                    .col(ColumnDef::new(Artifact::SizeBytes).integer().not_null())
                    // The canonical lowercase 64-hex digest. Stored verbatim;
                    // the domain `Sha256Hex` type validates and normalizes it
                    // on the way in and re-validates on the way out.
                    .col(ColumnDef::new(Artifact::Sha256).text().not_null())
                    .col(ColumnDef::new(Artifact::State).string().not_null())
                    .col(ColumnDef::new(Artifact::UploadedBytes).integer().not_null())
                    .col(
                        ColumnDef::new(Artifact::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Artifact::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    // The full §14.3 lifecycle. The database refuses a code
                    // the product cannot classify, mirroring the
                    // operations.state CHECK precedent, so a recovery scan
                    // can never hand an unknown code to the domain
                    // `ArtifactState`.
                    .check((
                        "ck_artifacts_state",
                        Expr::col(Artifact::State).is_in(["uploading", "ready", "failed"]),
                    ))
                    .to_owned(),
            )
            .await?;

        // Recovery scan (§0.4.0): find every interrupted upload by its
        // lifecycle phase without scanning the whole table, and let the
        // artifact inventory filter by phase cheaply.
        manager
            .create_index(
                Index::create()
                    .name("ix_artifacts_state")
                    .table(Artifact::Table)
                    .col(Artifact::State)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Artifact::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Artifact {
    #[sea_orm(iden = "artifacts")]
    Table,
    Id,
    Name,
    SizeBytes,
    Sha256,
    State,
    UploadedBytes,
    CreatedAt,
    UpdatedAt,
}
