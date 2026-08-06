use sea_orm::entity::prelude::*;

/// One persisted firmware artifact (§9.3, §14.3).
///
/// Each row is the manifest of one uploaded firmware file: the declared size,
/// the SHA-256 digest the complete file must match, and how many bytes have
/// been received so far. The file bytes never live in the database — the
/// persistence layer derives the on-disk path from the artifact identity and
/// the product data directory, and the application upload use case performs
/// the file I/O (§7.8).
///
/// `state` is a stable product code (domain `ArtifactState`): the migration
/// enforces the three-code set with a CHECK constraint, so a recovery scan
/// can never hand an unknown code to the domain. `sha256` is the canonical
/// lowercase 64-hex digest; the domain `Sha256Hex` type validates and
/// normalizes it, and the database stores it verbatim. `size_bytes` and
/// `uploaded_bytes` are `SQLite` `INTEGER` columns (signed 64-bit), mapped
/// to the domain `u64` by the repository.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "artifacts")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The normalized manifest label.
    pub name: String,
    /// The declared file size in bytes.
    pub size_bytes: i64,
    /// The canonical lowercase hex SHA-256 digest the complete file must match.
    pub sha256: String,
    /// The stable lifecycle code: `uploading`, `ready`, or `failed`.
    pub state: String,
    /// Bytes received so far; the resume offset for an interrupted upload.
    pub uploaded_bytes: i64,
    /// When the manifest was declared.
    pub created_at: TimeDateTimeWithTimeZone,
    /// When progress or state last changed; `created_at` until the first
    /// write.
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
