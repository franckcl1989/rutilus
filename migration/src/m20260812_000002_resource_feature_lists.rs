use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Aligns both persisted feature allow-lists with the domain
/// `ResourceFeature` inventory.
///
/// The audit found the two CHECK constraints diverging from the domain enum:
/// `ck_resources_feature` allows 37 of the 47 domain codes (missing the ten
/// `ami-service-root`, `ami-config-bmc`, `hpe-ilo-service-ext`, `hpe-manager`,
/// `liteon-power-supply`, `delta-power-supply`, `power-equipment`,
/// `power-supplies`, `network-device-functions`, and `environment-metrics`
/// families), and `ck_resource_decode_failures_feature` allows only 36 — its
/// 000012 comment claimed it mirrors the `resources` allow-list exactly, but
/// the list was copied from the pre-Lenovo shape, so `lenovo-security-service`
/// and the same ten codes are missing. A refresh that decodes one of these
/// families writes a feature code the constraint rejects, so `SQLite` refuses
/// the row and the whole Generation transaction rolls back — the refresh
/// fails.
///
/// Both tables must therefore allow exactly the domain enum's 47 codes and
/// nothing else. The lists below are copied from the `as_str()` surface of
/// `rutilus_domain::ResourceFeature` and are pinned to it by the migration
/// test (`tests/resource_feature_lists.rs`), which compares the lists
/// character-for-character against the domain enum's full code set: a future
/// family addition or a constraint change on either side fails that test, so
/// the constraint cannot drift from the enum again.
///
/// # Why the tables are rebuilt
///
/// `SQLite` has no `ALTER TABLE ... DROP CONSTRAINT`, so replacing a CHECK
/// constraint requires the standard `SQLite` table-rebuild procedure. The
/// `resources` table is the parent of `resource_snapshots` (whose foreign key
/// cascades on delete), so dropping it in place would cascade-delete every
/// stored snapshot; the rebuild therefore re-creates both tables — `resources`
/// and `resource_snapshots` are exactly the two tables involved, because
/// nothing else references either — copies every row, drops the old pair, and
/// renames the new pair into place (the procedure 000003 and 000006
/// established). `resource_decode_failures` is a leaf table (only its own
/// endpoint foreign key, no children), so it is rebuilt the same way on its
/// own. With children dropped before their parents, the cascade that fires
/// when an old parent is dropped can only touch rows that were already
/// copied, so the rebuilds are safe under any `foreign_keys` setting and need
/// no per-connection `PRAGMA` (a PRAGMA would only affect one pooled
/// connection anyway).
///
/// The rebuilt tables are byte-identical in shape to their originals (same
/// columns, foreign keys, primary keys, and index definitions), so the
/// rebuild is purely an allow-list replacement: the unique
/// `uq_resources_endpoint_odata_id` and the `ix_resources_endpoint_feature`
/// indexes are recreated after the rename because `SQLite` index names are
/// database-global and the new tables must not collide with the old ones
/// before the drop.
///
/// # Downgrade symmetry
///
/// `down` restores the exact pre-migration constraint shapes: the 37-code
/// `resources` list and the 36-code `resource_decode_failures` list. Rows
/// stored under the newly allow-listed codes cannot be represented by the
/// restored constraints, so a downgrade must remove them first — exactly what
/// a real downgrade must do with rows that only the newer schema can hold
/// (the 000003 and 000006 downgrades have the same property).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_resource_tables_with(manager, DOMAIN_FEATURE_CODES).await?;
        rebuild_decode_failures_with(manager, DOMAIN_FEATURE_CODES).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_resource_tables_with(manager, RESOURCE_CODES_BEFORE_ALIGNMENT).await?;
        rebuild_decode_failures_with(manager, DECODE_FAILURE_CODES_BEFORE_ALIGNMENT).await
    }
}

/// The complete `rutilus_domain::ResourceFeature` code inventory — all 47
/// domain codes in enum declaration order (the OEM read-surface families
/// first, then the §2.1 families), so both rebuilt constraints allow exactly
/// the domain surface and nothing else.
const DOMAIN_FEATURE_CODES: &[&str] = &[
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
    "lenovo-security-service",
    "ami-service-root",
    "ami-config-bmc",
    "hpe-ilo-service-ext",
    "hpe-manager",
    "liteon-power-supply",
    "delta-power-supply",
    "processors",
    "memory",
    "storages",
    "network-adapters",
    "network-device-functions",
    "ethernet-interfaces",
    "accounts",
    "bios",
    "boot-options",
    "secure-boot",
    "power",
    "power-equipment",
    "power-supplies",
    "thermal",
    "sensors",
    "controls",
    "environment-metrics",
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

/// The exact 000006 `resources` allow-list (37 codes), restored by `down`:
/// the ten OEM and standard families added here become unparseable again.
const RESOURCE_CODES_BEFORE_ALIGNMENT: &[&str] = &[
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
    "lenovo-security-service",
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

/// The exact 000012 `resource_decode_failures` allow-list (36 codes), restored
/// by `down`: `lenovo-security-service` and the ten codes above become
/// unparseable again.
const DECODE_FAILURE_CODES_BEFORE_ALIGNMENT: &[&str] = &[
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

    // The copy statements go through the SeaQuery builder (`INSERT ... SELECT`
    // via `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
    // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
    rebuild
        .get_connection()
        .execute(
            &Query::insert()
                .into_table(ResourceNew::Table)
                .columns([
                    ResourceNew::Id,
                    ResourceNew::EndpointId,
                    ResourceNew::OdataId,
                    ResourceNew::Feature,
                    ResourceNew::CreatedAt,
                ])
                .select_from(
                    Query::select()
                        .column(Resource::Id)
                        .column(Resource::EndpointId)
                        .column(Resource::OdataId)
                        .column(Resource::Feature)
                        .column(Resource::CreatedAt)
                        .from(Resource::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;
    rebuild
        .get_connection()
        .execute(
            &Query::insert()
                .into_table(ResourceSnapshotNew::Table)
                .columns([
                    ResourceSnapshotNew::ResourceId,
                    ResourceSnapshotNew::Generation,
                    ResourceSnapshotNew::OdataType,
                    ResourceSnapshotNew::Etag,
                    ResourceSnapshotNew::TypedPayloadJson,
                    ResourceSnapshotNew::ObservedAt,
                ])
                .select_from(
                    Query::select()
                        .column(ResourceSnapshot::ResourceId)
                        .column(ResourceSnapshot::Generation)
                        .column(ResourceSnapshot::OdataType)
                        .column(ResourceSnapshot::Etag)
                        .column(ResourceSnapshot::TypedPayloadJson)
                        .column(ResourceSnapshot::ObservedAt)
                        .from(ResourceSnapshot::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
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

/// Rebuilds `resource_decode_failures` under the given feature allow-list
/// (see the module doc for the rebuild procedure). The table is a leaf (only
/// its own endpoint foreign key, no children), so it is rebuilt on its own:
/// create the new table, copy every row, drop the old one, and rename the
/// new one into place.
#[allow(clippy::too_many_lines)]
async fn rebuild_decode_failures_with(
    manager: &SchemaManager<'_>,
    feature_codes: &[&str],
) -> Result<(), DbErr> {
    // The rebuild runs on one dedicated transaction connection for the same
    // reason as the resources rebuild: a single transaction pins every DDL
    // statement to one connection, so each step sees exactly the schema the
    // previous step changed, and the rebuild is robust under the pooled
    // settings.
    let rebuild = manager.begin().await?;
    rebuild
        .create_table(
            Table::create()
                .table(ResourceDecodeFailureNew::Table)
                .col(
                    ColumnDef::new(ResourceDecodeFailureNew::EndpointId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceDecodeFailureNew::Generation)
                        .big_integer()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceDecodeFailureNew::OdataUri)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(ResourceDecodeFailureNew::OdataType).string())
                .col(
                    ColumnDef::new(ResourceDecodeFailureNew::Feature)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(ResourceDecodeFailureNew::OemNamespace).string())
                .col(
                    ColumnDef::new(ResourceDecodeFailureNew::ErrorSummary)
                        .text()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ResourceDecodeFailureNew::ExtendedInfoJson)
                        .text()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .col(ResourceDecodeFailureNew::EndpointId)
                        .col(ResourceDecodeFailureNew::Generation)
                        .col(ResourceDecodeFailureNew::OdataUri),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk_resource_decode_failures_endpoint")
                        .from(
                            ResourceDecodeFailureNew::Table,
                            ResourceDecodeFailureNew::EndpointId,
                        )
                        .to(Endpoint::Table, Endpoint::Id)
                        .on_update(ForeignKeyAction::Cascade)
                        .on_delete(ForeignKeyAction::Cascade),
                )
                .check((
                    "ck_resource_decode_failures_generation",
                    Expr::col(ResourceDecodeFailureNew::Generation).gte(1),
                ))
                .check((
                    "ck_resource_decode_failures_feature",
                    Expr::col(ResourceDecodeFailureNew::Feature)
                        .is_in(feature_codes.iter().copied()),
                ))
                .to_owned(),
        )
        .await?;

    // The copy statement goes through the SeaQuery builder (`INSERT ... SELECT`
    // via `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
    // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
    rebuild
        .get_connection()
        .execute(
            &Query::insert()
                .into_table(ResourceDecodeFailureNew::Table)
                .columns([
                    ResourceDecodeFailureNew::EndpointId,
                    ResourceDecodeFailureNew::Generation,
                    ResourceDecodeFailureNew::OdataUri,
                    ResourceDecodeFailureNew::OdataType,
                    ResourceDecodeFailureNew::Feature,
                    ResourceDecodeFailureNew::OemNamespace,
                    ResourceDecodeFailureNew::ErrorSummary,
                    ResourceDecodeFailureNew::ExtendedInfoJson,
                ])
                .select_from(
                    Query::select()
                        .column(ResourceDecodeFailure::EndpointId)
                        .column(ResourceDecodeFailure::Generation)
                        .column(ResourceDecodeFailure::OdataUri)
                        .column(ResourceDecodeFailure::OdataType)
                        .column(ResourceDecodeFailure::Feature)
                        .column(ResourceDecodeFailure::OemNamespace)
                        .column(ResourceDecodeFailure::ErrorSummary)
                        .column(ResourceDecodeFailure::ExtendedInfoJson)
                        .from(ResourceDecodeFailure::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await?;
    // The leaf table has no children, so dropping it in place cannot cascade
    // into any other table.
    rebuild
        .get_connection()
        .execute_unprepared("DROP TABLE resource_decode_failures")
        .await?;
    rebuild
        .get_connection()
        .execute_unprepared(
            "ALTER TABLE resource_decode_failures_new RENAME TO resource_decode_failures",
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

#[derive(DeriveIden)]
enum ResourceDecodeFailureNew {
    #[sea_orm(iden = "resource_decode_failures_new")]
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
