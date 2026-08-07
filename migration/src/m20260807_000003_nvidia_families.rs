use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Extends the `ck_resources_feature` allow-list with the 0.5.0 NVIDIA
/// power-compliance (`nvidia-power-compliance`) and managed-entity
/// (`nvidia-managed-entity`) family codes.
///
/// # Why this is a rebuild, not an in-place edit
///
/// Migration 000005 records the product rule that a shipped migration is
/// never edited in place; a schema evolution ships as a follow-up migration.
/// The Dell/Supermicro families landed by editing 000003's allow-list before
/// that rule was recorded; from the NVIDIA family on, every new resource
/// family code extends the allow-list through a follow-up migration like this
/// one.
///
/// # Why the tables are rebuilt
///
/// `SQLite` has no `ALTER TABLE ... DROP CONSTRAINT`, so replacing a
/// CHECK constraint requires the standard `SQLite` table-rebuild procedure. The
/// `resources` table is the parent of `resource_snapshots` (whose foreign key
/// cascades on delete), so dropping it in place would cascade-delete every
/// stored snapshot; the rebuild therefore re-creates both tables — `resources`
/// and `resource_snapshots` are exactly the two tables involved, because
/// nothing else references either — copies every row, drops the old pair, and
/// renames the new pair into place. With the child dropped first, the
/// cascade that fires when the old `resources` table is dropped can only
/// touch rows that were already copied, so the rebuild is safe under any
/// `foreign_keys` setting and needs no per-connection `PRAGMA` (a PRAGMA
/// would only affect one pooled connection anyway).
///
/// The rebuilt tables are byte-identical in shape to the 000003 originals
/// (same columns, foreign keys, and index definitions), so the rebuild is
/// purely an allow-list replacement: the unique
/// `uq_resources_endpoint_odata_id` and the `ix_resources_endpoint_feature`
/// indexes are recreated after the rename because `SQLite` index names are
/// database-global and the new tables must not collide with the old ones
/// before the drop.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_resource_tables_with(manager, FEATURE_ALLOW_LIST_WITH_POWER_FAMILIES).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_resource_tables_with(manager, FEATURE_ALLOW_LIST_BEFORE_POWER_FAMILIES).await
    }
}

/// The 000001 allow-list (the 000003 list plus the 0.5.0 NVIDIA
/// system-config-profile code) plus the 0.5.0 NVIDIA power-compliance and
/// managed-entity codes.
const FEATURE_ALLOW_LIST_WITH_POWER_FAMILIES: &[&str] = &[
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
];

/// The exact 000001 allow-list (the 000003 list plus the system-config-profile
/// code), used by `down` to restore the previous constraint shape: the two new
/// NVIDIA codes become unparseable again.
const FEATURE_ALLOW_LIST_BEFORE_POWER_FAMILIES: &[&str] = &[
    "service-root",
    "systems",
    "chassis",
    "managers",
    "dell-attributes",
    "supermicro-sys-lockdown",
    "supermicro-kcs-interface",
    "nvidia-system-config-profile",
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
];

/// Rebuilds `resources` and `resource_snapshots` under the given feature
/// allow-list (see the module doc for the rebuild procedure). The rebuild
/// steps exceed the pedantic line budget because both tables are recreated
/// with their full column, key, and constraint sets before the copy, drop,
/// and rename phases.
#[allow(clippy::too_many_lines)]
async fn create_resource_tables_with(
    manager: &SchemaManager<'_>,
    feature_codes: &[&str],
) -> Result<(), DbErr> {
    // The whole rebuild runs on one dedicated transaction connection. SQLite
    // keeps a per-connection cache of the schema, and when consecutive DDL
    // statements (the DROP and the RENAME, or the DROP and the index
    // recreation) land on different connections of the store's pool (the
    // store pools up to four connections), a later statement can still see
    // the pre-DDL schema in the stale cache and refuse with "there is
    // already another table or index with this name" or "index ... already
    // exists". A single transaction pins every statement of the rebuild to
    // one connection, so the schema each DDL step changes is exactly the
    // schema the next step sees, and the rebuild is robust under the pooled
    // settings. (A single connection never hits this; the migration tests
    // pin the pooled behavior through the store's own open path.)
    let rebuild = manager.begin().await?;
    rebuild
        .create_table(
            Table::create()
                .table(ResourceNew::Table)
                .col(
                    ColumnDef::new(ResourceNew::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(ResourceNew::EndpointId).uuid().not_null())
                .col(ColumnDef::new(ResourceNew::OdataId).string().not_null())
                .col(ColumnDef::new(ResourceNew::Feature).string().not_null())
                .col(
                    ColumnDef::new(ResourceNew::CreatedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_resources_endpoint")
                        .from(ResourceNew::Table, ResourceNew::EndpointId)
                        .to(Endpoint::Table, Endpoint::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .check((
                    "ck_resources_feature",
                    Expr::col(ResourceNew::Feature).is_in(feature_codes.iter().copied()),
                ))
                .to_owned(),
        )
        .await?;

    rebuild
        .create_table(
            Table::create()
                .table(ResourceSnapshotNew::Table)
                .col(
                    ColumnDef::new(ResourceSnapshotNew::ResourceId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceSnapshotNew::Generation)
                        .big_integer()
                        .not_null(),
                )
                .col(ColumnDef::new(ResourceSnapshotNew::OdataType).string())
                .col(ColumnDef::new(ResourceSnapshotNew::Etag).string())
                .col(
                    ColumnDef::new(ResourceSnapshotNew::TypedPayloadJson)
                        .text()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceSnapshotNew::ObservedAt)
                        .timestamp_with_time_zone()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(ResourceSnapshotNew::ResourceId)
                        .col(ResourceSnapshotNew::Generation),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_resource_snapshots_resource")
                        .from(ResourceSnapshotNew::Table, ResourceSnapshotNew::ResourceId)
                        .to(ResourceNew::Table, ResourceNew::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .check((
                    "ck_resource_snapshots_generation",
                    Expr::col(ResourceSnapshotNew::Generation).gte(1),
                ))
                .to_owned(),
        )
        .await?;

    rebuild
        .get_connection()
        .execute_unprepared(
            "INSERT INTO resources_new (id, endpoint_id, odata_id, feature, created_at) \
                 SELECT id, endpoint_id, odata_id, feature, created_at FROM resources",
        )
        .await?;
    rebuild
        .get_connection()
        .execute_unprepared(
            "INSERT INTO resource_snapshots_new \
                 (resource_id, generation, odata_type, etag, typed_payload_json, observed_at) \
                 SELECT resource_id, generation, odata_type, etag, typed_payload_json, observed_at \
                 FROM resource_snapshots",
        )
        .await?;
    // The child is dropped first, so the cascade that fires when the old
    // parent is dropped can only reach rows that were already copied.
    rebuild
        .get_connection()
        .execute_unprepared("DROP TABLE resource_snapshots")
        .await?;
    rebuild
        .get_connection()
        .execute_unprepared("DROP TABLE resources")
        .await?;
    // Renaming the parent first repoints the child's foreign key at the
    // new table (SQLite rewrites references on rename), so the child
    // rename afterwards only changes its own name.
    rebuild
        .get_connection()
        .execute_unprepared("ALTER TABLE resources_new RENAME TO resources")
        .await?;
    rebuild
        .get_connection()
        .execute_unprepared("ALTER TABLE resource_snapshots_new RENAME TO resource_snapshots")
        .await?;

    rebuild
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

    rebuild
        .create_index(
            Index::create()
                .name("ix_resources_endpoint_feature")
                .table(Resource::Table)
                .col(Resource::EndpointId)
                .col(Resource::Feature)
                .to_owned(),
        )
        .await?;
    rebuild.commit().await
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
    EndpointId,
    OdataId,
    Feature,
}

#[derive(DeriveIden)]
enum ResourceNew {
    #[sea_orm(iden = "resources_new")]
    Table,
    Id,
    EndpointId,
    OdataId,
    Feature,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ResourceSnapshotNew {
    #[sea_orm(iden = "resource_snapshots_new")]
    Table,
    ResourceId,
    Generation,
    OdataType,
    Etag,
    TypedPayloadJson,
    ObservedAt,
}
