use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Pins the `endpoints` health-cut and refresh-generation columns to the
/// domain vocabulary (D4-5).
///
/// # The missing CHECKs
///
/// The 000010 slice added `refresh_generation` and `health` to `endpoints`
/// as plain columns (`ALTER TABLE ... ADD COLUMN` with a `DEFAULT`, no
/// constraint), so a malformed row could never be refused. The entity
/// documentation already pins the vocabulary — `health` is `ok`/`unknown`
/// (`rutilus_entity::endpoint`) — and the domain side writes exactly those
/// values: the site creates endpoints with `health = 'unknown'` and
/// `refresh_generation = 0` (the endpoint repositories), the §17 sync
/// reports `unknown` before the first completed refresh and `ok` after it
/// (`application/src/center_sync.rs` `enqueue_endpoint_snapshot`), and the
/// center projects the wire value into the same table. This migration makes
/// the schema enforce the vocabulary:
///
/// - `ck_endpoints_health` — `health IN ('unknown', 'ok')`, the two-value
///   health cut the domain can produce;
/// - `ck_endpoints_refresh_generation` — `refresh_generation >= 0`, the
///   non-negative watermark the domain's `u64` generation projects into the
///   signed `BIGINT` column.
///
/// # The rebuild
///
/// `SQLite` cannot add a CHECK to an existing table, so the constraints
/// require the standard table-rebuild procedure. `endpoints` is the parent
/// of seven `ON DELETE CASCADE` tables — `endpoint_addresses`,
/// `endpoint_trust`, `endpoint_credentials`, `endpoint_capabilities`,
/// `resources` (and through it `resource_snapshots`), and
/// `resource_decode_failures` — so the old parent cannot be dropped the way
/// a leaf table is: with foreign keys on (the production connection and the
/// test harness both enable them), the implicit `DELETE FROM endpoints` the
/// drop runs cascades into every child row and silently empties all seven
/// tables. The children are therefore rebuilt alongside the parent, exactly
/// as the 000010 down rebuilds them (the same eight-table cycle, with the
/// rebuilt foreign keys pointed at the `*_rebuild` tables so the parent drop
/// below cascades into nothing). The rebuilt tables are shape-equivalent to
/// their originals — same columns, foreign keys, primary keys, checks, and
/// index definitions (including the current 47-code `resources` and
/// `resource_decode_failures` allow-lists, unchanged from the 000012
/// alignment) — so the rebuild is purely a CHECK addition. The only
/// difference is the declared types of the string columns: the rebuild DDL
/// spells them `TEXT` where the source migrations used `string()`
/// (`VARCHAR`) — under `SQLite` both resolve to the same TEXT affinity, so
/// the shapes are semantically equivalent. `SQLite` index names are
/// database-global, so the four indexes are recreated after the renames.
///
/// # Downgrade symmetry
///
/// `down` restores the exact pre-migration shape: the same eight-table
/// rebuild with the 000012 `endpoints` (the plain `refresh_generation` and
/// `health` columns without the two CHECKs). Every row the widened schema
/// accepted satisfies the restored shape — the columns are unchanged and
/// the vocabulary was already the domain's — so the downgrade copies
/// everything.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    /// The rebuild must commit as one unit: a failure halfway would leave
    /// the endpoint tables half-rebuilt with no recorded migration to
    /// recover from.
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_endpoints(manager, RebuildDirection::Forward).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        rebuild_endpoints(manager, RebuildDirection::Backward).await
    }
}

/// Whether the rebuild moves `endpoints` forward (the two CHECKs) or back.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebuildDirection {
    Forward,
    Backward,
}

/// Rebuilds `endpoints` and its seven cascade children with the health-cut
/// CHECKs (forward) or the pre-check shape (backward).
///
/// All statements run on the migration's transaction (see
/// [`Migration::use_transaction`]), so a failure leaves the old tables
/// untouched. The copy steps enumerate every column of every table in the
/// insert and select lists, so the function exceeds the pedantic line
/// budget (same exception as the family migrations' rebuilds).
#[allow(clippy::too_many_lines)]
async fn rebuild_endpoints(
    manager: &SchemaManager<'_>,
    direction: RebuildDirection,
) -> Result<(), DbErr> {
    let connection = manager.get_connection();
    // The parent is recreated with (or without) the two CHECKs; the seven
    // children are byte-identical in both directions, with their foreign
    // keys pointed at the staging tables so the parent drop below cascades
    // into nothing.
    if direction == RebuildDirection::Forward {
        connection.execute_unprepared(ENDPOINTS_CHECKED_DDL).await?;
    } else {
        connection
            .execute_unprepared(ENDPOINTS_PRE_CHECK_DDL)
            .await?;
    }
    connection
        .execute_unprepared(ENDPOINT_ADDRESSES_REBUILD_DDL)
        .await?;
    connection
        .execute_unprepared(ENDPOINT_TRUST_REBUILD_DDL)
        .await?;
    connection
        .execute_unprepared(ENDPOINT_CREDENTIALS_REBUILD_DDL)
        .await?;
    connection
        .execute_unprepared(ENDPOINT_CAPABILITIES_REBUILD_DDL)
        .await?;
    connection.execute_unprepared(RESOURCES_REBUILD_DDL).await?;
    connection
        .execute_unprepared(RESOURCE_SNAPSHOTS_REBUILD_DDL)
        .await?;
    connection
        .execute_unprepared(RESOURCE_DECODE_FAILURES_REBUILD_DDL)
        .await?;

    // The copies go through the SeaQuery builder (`INSERT ... SELECT` via
    // `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
    // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
    copy_endpoints(connection, direction).await?;
    copy_endpoint_addresses(connection).await?;
    copy_endpoint_trust(connection).await?;
    copy_endpoint_credentials(connection).await?;
    copy_endpoint_capabilities(connection).await?;
    copy_resources(connection).await?;
    copy_resource_snapshots(connection).await?;
    copy_resource_decode_failures(connection).await?;

    // Children first, deepest dependency first (`resource_snapshots` before
    // `resources`, and `resources` before `endpoints`): with the old
    // children gone, the parent drop below cascades into nothing, so the
    // rebuild is safe under any `foreign_keys` setting.
    connection
        .execute_unprepared("DROP TABLE resource_snapshots")
        .await?;
    connection
        .execute_unprepared("DROP TABLE resources")
        .await?;
    connection
        .execute_unprepared("DROP TABLE resource_decode_failures")
        .await?;
    connection
        .execute_unprepared("DROP TABLE endpoint_credentials")
        .await?;
    connection
        .execute_unprepared("DROP TABLE endpoint_trust")
        .await?;
    connection
        .execute_unprepared("DROP TABLE endpoint_addresses")
        .await?;
    connection
        .execute_unprepared("DROP TABLE endpoint_capabilities")
        .await?;
    connection
        .execute_unprepared("DROP TABLE endpoints")
        .await?;
    // Renaming the parent first repoints the rebuilt children's foreign
    // keys at the live `endpoints` (SQLite rewrites references on rename),
    // so the child renames afterwards only change their own names —
    // `resources` before `resource_snapshots`, whose foreign key names
    // `resources`.
    connection
        .execute_unprepared("ALTER TABLE endpoints_rebuild RENAME TO endpoints")
        .await?;
    connection
        .execute_unprepared("ALTER TABLE resources_rebuild RENAME TO resources")
        .await?;
    connection
        .execute_unprepared("ALTER TABLE resource_snapshots_rebuild RENAME TO resource_snapshots")
        .await?;
    connection
        .execute_unprepared(
            "ALTER TABLE resource_decode_failures_rebuild RENAME TO resource_decode_failures",
        )
        .await?;
    connection
        .execute_unprepared("ALTER TABLE endpoint_addresses_rebuild RENAME TO endpoint_addresses")
        .await?;
    connection
        .execute_unprepared(
            "ALTER TABLE endpoint_credentials_rebuild RENAME TO endpoint_credentials",
        )
        .await?;
    connection
        .execute_unprepared("ALTER TABLE endpoint_trust_rebuild RENAME TO endpoint_trust")
        .await?;
    connection
        .execute_unprepared(
            "ALTER TABLE endpoint_capabilities_rebuild RENAME TO endpoint_capabilities",
        )
        .await?;
    // The rebuilt tables' indexes are recreated after the renames because
    // `SQLite` index names are database-global and the new tables must not
    // collide with the old ones before the drop.
    connection
        .execute_unprepared(
            "CREATE UNIQUE INDEX uq_resources_endpoint_odata_id \
             ON resources (endpoint_id, odata_id)",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE INDEX ix_resources_endpoint_feature ON resources (endpoint_id, feature)",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE UNIQUE INDEX uq_endpoint_addresses_address ON endpoint_addresses (address)",
        )
        .await?;
    connection
        .execute_unprepared(
            "CREATE UNIQUE INDEX uq_endpoint_addresses_active \
             ON endpoint_addresses (endpoint_id) WHERE is_active = true",
        )
        .await
        .map(|_| ())
}

/// Copies every `endpoints` row into the staging table. The select list is
/// the same in both directions (both shapes carry the same columns).
async fn copy_endpoints(
    connection: &SchemaManagerConnection<'_>,
    direction: RebuildDirection,
) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(if direction == RebuildDirection::Forward {
                    EndpointShape::CheckedTable
                } else {
                    EndpointShape::PreCheckTable
                })
                .columns([
                    EndpointShape::Id,
                    EndpointShape::DisplayName,
                    EndpointShape::CreatedAt,
                    EndpointShape::UpdatedAt,
                    EndpointShape::SiteId,
                    EndpointShape::RefreshGeneration,
                    EndpointShape::Health,
                ])
                .select_from(
                    Query::select()
                        .column(EndpointShape::Id)
                        .column(EndpointShape::DisplayName)
                        .column(EndpointShape::CreatedAt)
                        .column(EndpointShape::UpdatedAt)
                        .column(EndpointShape::SiteId)
                        .column(EndpointShape::RefreshGeneration)
                        .column(EndpointShape::Health)
                        .from(EndpointShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_endpoint_addresses(connection: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(EndpointAddressShape::RebuildTable)
                .columns([
                    EndpointAddressShape::Id,
                    EndpointAddressShape::EndpointId,
                    EndpointAddressShape::Address,
                    EndpointAddressShape::IsActive,
                    EndpointAddressShape::CreatedAt,
                    EndpointAddressShape::RetiredAt,
                ])
                .select_from(
                    Query::select()
                        .column(EndpointAddressShape::Id)
                        .column(EndpointAddressShape::EndpointId)
                        .column(EndpointAddressShape::Address)
                        .column(EndpointAddressShape::IsActive)
                        .column(EndpointAddressShape::CreatedAt)
                        .column(EndpointAddressShape::RetiredAt)
                        .from(EndpointAddressShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_endpoint_trust(connection: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(EndpointTrustShape::RebuildTable)
                .columns([
                    EndpointTrustShape::EndpointId,
                    EndpointTrustShape::TrustMode,
                    EndpointTrustShape::CertificateSha256,
                    EndpointTrustShape::CertificateDer,
                    EndpointTrustShape::TrustedAt,
                ])
                .select_from(
                    Query::select()
                        .column(EndpointTrustShape::EndpointId)
                        .column(EndpointTrustShape::TrustMode)
                        .column(EndpointTrustShape::CertificateSha256)
                        .column(EndpointTrustShape::CertificateDer)
                        .column(EndpointTrustShape::TrustedAt)
                        .from(EndpointTrustShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_endpoint_credentials(connection: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(EndpointCredentialShape::RebuildTable)
                .columns([
                    EndpointCredentialShape::EndpointId,
                    EndpointCredentialShape::CredentialId,
                    EndpointCredentialShape::AssignedAt,
                ])
                .select_from(
                    Query::select()
                        .column(EndpointCredentialShape::EndpointId)
                        .column(EndpointCredentialShape::CredentialId)
                        .column(EndpointCredentialShape::AssignedAt)
                        .from(EndpointCredentialShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_endpoint_capabilities(connection: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(EndpointCapabilityShape::RebuildTable)
                .columns([
                    EndpointCapabilityShape::EndpointId,
                    EndpointCapabilityShape::Capability,
                    EndpointCapabilityShape::State,
                    EndpointCapabilityShape::ObservedAt,
                ])
                .select_from(
                    Query::select()
                        .column(EndpointCapabilityShape::EndpointId)
                        .column(EndpointCapabilityShape::Capability)
                        .column(EndpointCapabilityShape::State)
                        .column(EndpointCapabilityShape::ObservedAt)
                        .from(EndpointCapabilityShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_resources(connection: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(ResourceShape::RebuildTable)
                .columns([
                    ResourceShape::Id,
                    ResourceShape::EndpointId,
                    ResourceShape::OdataId,
                    ResourceShape::Feature,
                    ResourceShape::CreatedAt,
                ])
                .select_from(
                    Query::select()
                        .column(ResourceShape::Id)
                        .column(ResourceShape::EndpointId)
                        .column(ResourceShape::OdataId)
                        .column(ResourceShape::Feature)
                        .column(ResourceShape::CreatedAt)
                        .from(ResourceShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_resource_snapshots(connection: &SchemaManagerConnection<'_>) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(ResourceSnapshotShape::RebuildTable)
                .columns([
                    ResourceSnapshotShape::ResourceId,
                    ResourceSnapshotShape::Generation,
                    ResourceSnapshotShape::OdataType,
                    ResourceSnapshotShape::Etag,
                    ResourceSnapshotShape::TypedPayloadJson,
                    ResourceSnapshotShape::ObservedAt,
                ])
                .select_from(
                    Query::select()
                        .column(ResourceSnapshotShape::ResourceId)
                        .column(ResourceSnapshotShape::Generation)
                        .column(ResourceSnapshotShape::OdataType)
                        .column(ResourceSnapshotShape::Etag)
                        .column(ResourceSnapshotShape::TypedPayloadJson)
                        .column(ResourceSnapshotShape::ObservedAt)
                        .from(ResourceSnapshotShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

async fn copy_resource_decode_failures(
    connection: &SchemaManagerConnection<'_>,
) -> Result<(), DbErr> {
    connection
        .execute(
            &Query::insert()
                .into_table(ResourceDecodeFailureShape::RebuildTable)
                .columns([
                    ResourceDecodeFailureShape::EndpointId,
                    ResourceDecodeFailureShape::Generation,
                    ResourceDecodeFailureShape::OdataUri,
                    ResourceDecodeFailureShape::OdataType,
                    ResourceDecodeFailureShape::Feature,
                    ResourceDecodeFailureShape::OemNamespace,
                    ResourceDecodeFailureShape::ErrorSummary,
                    ResourceDecodeFailureShape::ExtendedInfoJson,
                ])
                .select_from(
                    Query::select()
                        .column(ResourceDecodeFailureShape::EndpointId)
                        .column(ResourceDecodeFailureShape::Generation)
                        .column(ResourceDecodeFailureShape::OdataUri)
                        .column(ResourceDecodeFailureShape::OdataType)
                        .column(ResourceDecodeFailureShape::Feature)
                        .column(ResourceDecodeFailureShape::OemNamespace)
                        .column(ResourceDecodeFailureShape::ErrorSummary)
                        .column(ResourceDecodeFailureShape::ExtendedInfoJson)
                        .from(ResourceDecodeFailureShape::Table)
                        .take(),
                )
                .map_err(|error| DbErr::Custom(error.to_string()))?
                .take(),
        )
        .await
        .map(|_| ())
}

/// The current `endpoints` shape plus the two health-cut CHECKs.
const ENDPOINTS_CHECKED_DDL: &str = r"
CREATE TABLE endpoints_rebuild (
    id UUID NOT NULL PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    site_id UUID NULL REFERENCES instances(id) ON DELETE CASCADE,
    refresh_generation BIGINT NOT NULL DEFAULT 0,
    health TEXT NOT NULL DEFAULT 'unknown',
    CONSTRAINT ck_endpoints_health
        CHECK (health IN ('unknown', 'ok')),
    CONSTRAINT ck_endpoints_refresh_generation
        CHECK (refresh_generation >= 0)
)
";

/// The pre-check `endpoints` shape restored by `down`: the 000010/000012
/// columns without the two CHECKs.
const ENDPOINTS_PRE_CHECK_DDL: &str = r"
CREATE TABLE endpoints_rebuild (
    id UUID NOT NULL PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    site_id UUID NULL REFERENCES instances(id) ON DELETE CASCADE,
    refresh_generation BIGINT NOT NULL DEFAULT 0,
    health TEXT NOT NULL DEFAULT 'unknown'
)
";

/// The seven cascade children's staging DDL, identical in both directions,
/// with the foreign keys pointed at the staging tables so the parent drop
/// cascades into nothing. The feature allow-lists are the current 47-code
/// 000012 lists.
const ENDPOINT_ADDRESSES_REBUILD_DDL: &str = r"
CREATE TABLE endpoint_addresses_rebuild (
    id UUID NOT NULL PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    address TEXT NOT NULL,
    is_active BOOLEAN NOT NULL,
    created_at TEXT NOT NULL,
    retired_at TEXT,
    CONSTRAINT fk_endpoint_addresses_endpoint
      FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE
)
";

const ENDPOINT_TRUST_REBUILD_DDL: &str = r"
CREATE TABLE endpoint_trust_rebuild (
    endpoint_id UUID NOT NULL PRIMARY KEY,
    trust_mode TEXT NOT NULL,
    certificate_sha256 BLOB,
    certificate_der BLOB,
    trusted_at TEXT NOT NULL,
    CONSTRAINT fk_endpoint_trust_endpoint
      FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE
)
";

const ENDPOINT_CREDENTIALS_REBUILD_DDL: &str = r"
CREATE TABLE endpoint_credentials_rebuild (
    endpoint_id UUID NOT NULL PRIMARY KEY,
    credential_id UUID NOT NULL,
    assigned_at TEXT NOT NULL,
    CONSTRAINT fk_endpoint_credentials_endpoint
      FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE,
    CONSTRAINT fk_endpoint_credentials_credential
      FOREIGN KEY (credential_id) REFERENCES credentials(id)
      ON UPDATE CASCADE ON DELETE RESTRICT
)
";

const ENDPOINT_CAPABILITIES_REBUILD_DDL: &str = r"
CREATE TABLE endpoint_capabilities_rebuild (
    endpoint_id UUID NOT NULL,
    capability TEXT NOT NULL,
    state TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (endpoint_id, capability),
    CONSTRAINT ck_endpoint_capabilities_state CHECK (
      state IN ('supported', 'read-only', 'unauthorized',
      'temporarily-unavailable', 'schema-incompatible',
      'not-advertised', 'not-compiled')),
    CONSTRAINT fk_endpoint_capabilities_endpoint
      FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE
)
";

const RESOURCES_REBUILD_DDL: &str = r"
CREATE TABLE resources_rebuild (
    id UUID NOT NULL PRIMARY KEY,
    endpoint_id UUID NOT NULL,
    odata_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CONSTRAINT ck_resources_feature CHECK (feature IN (
      'service-root', 'systems', 'chassis', 'managers',
      'dell-attributes', 'supermicro-sys-lockdown',
      'supermicro-kcs-interface', 'nvidia-system-config-profile',
      'nvidia-power-compliance', 'nvidia-managed-entity',
      'lenovo-security-service', 'ami-service-root', 'ami-config-bmc',
      'hpe-ilo-service-ext', 'hpe-manager', 'liteon-power-supply',
      'delta-power-supply', 'processors', 'memory', 'storages',
      'network-adapters', 'network-device-functions',
      'ethernet-interfaces', 'accounts', 'bios', 'boot-options',
      'secure-boot', 'power', 'power-equipment', 'power-supplies',
      'thermal', 'sensors', 'controls', 'environment-metrics',
      'log-services', 'manager-network-protocol', 'host-interfaces',
      'pcie-devices', 'assembly', 'software-inventory',
      'event-service', 'event-subscription', 'telemetry-service',
      'metric-definition', 'metric-report', 'task-service',
      'task')),
    CONSTRAINT fk_resources_endpoint
      FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE
)
";

const RESOURCE_SNAPSHOTS_REBUILD_DDL: &str = r"
CREATE TABLE resource_snapshots_rebuild (
    resource_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    odata_type TEXT,
    etag TEXT,
    typed_payload_json TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (resource_id, generation),
    CONSTRAINT ck_resource_snapshots_generation
      CHECK (generation >= 1),
    CONSTRAINT fk_resource_snapshots_resource
      FOREIGN KEY (resource_id) REFERENCES resources_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE
)
";

const RESOURCE_DECODE_FAILURES_REBUILD_DDL: &str = r"
CREATE TABLE resource_decode_failures_rebuild (
    endpoint_id UUID NOT NULL,
    generation BIGINT NOT NULL,
    odata_uri TEXT NOT NULL,
    odata_type TEXT,
    feature TEXT NOT NULL,
    oem_namespace TEXT,
    error_summary TEXT NOT NULL,
    extended_info_json TEXT NOT NULL,
    PRIMARY KEY (endpoint_id, generation, odata_uri),
    CONSTRAINT ck_resource_decode_failures_generation
      CHECK (generation >= 1),
    CONSTRAINT ck_resource_decode_failures_feature CHECK (feature IN (
      'service-root', 'systems', 'chassis', 'managers',
      'dell-attributes', 'supermicro-sys-lockdown',
      'supermicro-kcs-interface', 'nvidia-system-config-profile',
      'nvidia-power-compliance', 'nvidia-managed-entity',
      'lenovo-security-service', 'ami-service-root', 'ami-config-bmc',
      'hpe-ilo-service-ext', 'hpe-manager', 'liteon-power-supply',
      'delta-power-supply', 'processors', 'memory', 'storages',
      'network-adapters', 'network-device-functions',
      'ethernet-interfaces', 'accounts', 'bios', 'boot-options',
      'secure-boot', 'power', 'power-equipment', 'power-supplies',
      'thermal', 'sensors', 'controls', 'environment-metrics',
      'log-services', 'manager-network-protocol', 'host-interfaces',
      'pcie-devices', 'assembly', 'software-inventory',
      'event-service', 'event-subscription', 'telemetry-service',
      'metric-definition', 'metric-report', 'task-service',
      'task')),
    CONSTRAINT fk_resource_decode_failures_endpoint
      FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id)
      ON UPDATE CASCADE ON DELETE CASCADE
)
";

/// The `endpoints` shapes the rebuild alternates between, plus the live
/// table the copy reads from; the column variants are shared because both
/// shapes carry the same columns.
#[derive(DeriveIden)]
enum EndpointShape {
    #[sea_orm(iden = "endpoints")]
    Table,
    #[sea_orm(iden = "endpoints_rebuild")]
    CheckedTable,
    #[sea_orm(iden = "endpoints_rebuild")]
    PreCheckTable,
    Id,
    DisplayName,
    CreatedAt,
    UpdatedAt,
    SiteId,
    RefreshGeneration,
    Health,
}

#[derive(DeriveIden)]
enum EndpointAddressShape {
    #[sea_orm(iden = "endpoint_addresses")]
    Table,
    #[sea_orm(iden = "endpoint_addresses_rebuild")]
    RebuildTable,
    Id,
    EndpointId,
    Address,
    IsActive,
    CreatedAt,
    RetiredAt,
}

#[derive(DeriveIden)]
enum EndpointTrustShape {
    #[sea_orm(iden = "endpoint_trust")]
    Table,
    #[sea_orm(iden = "endpoint_trust_rebuild")]
    RebuildTable,
    EndpointId,
    TrustMode,
    CertificateSha256,
    CertificateDer,
    TrustedAt,
}

#[derive(DeriveIden)]
enum EndpointCredentialShape {
    #[sea_orm(iden = "endpoint_credentials")]
    Table,
    #[sea_orm(iden = "endpoint_credentials_rebuild")]
    RebuildTable,
    EndpointId,
    CredentialId,
    AssignedAt,
}

#[derive(DeriveIden)]
enum EndpointCapabilityShape {
    #[sea_orm(iden = "endpoint_capabilities")]
    Table,
    #[sea_orm(iden = "endpoint_capabilities_rebuild")]
    RebuildTable,
    EndpointId,
    Capability,
    State,
    ObservedAt,
}

#[derive(DeriveIden)]
enum ResourceShape {
    #[sea_orm(iden = "resources")]
    Table,
    #[sea_orm(iden = "resources_rebuild")]
    RebuildTable,
    Id,
    EndpointId,
    OdataId,
    Feature,
    CreatedAt,
}

#[derive(DeriveIden)]
enum ResourceSnapshotShape {
    #[sea_orm(iden = "resource_snapshots")]
    Table,
    #[sea_orm(iden = "resource_snapshots_rebuild")]
    RebuildTable,
    ResourceId,
    Generation,
    OdataType,
    Etag,
    TypedPayloadJson,
    ObservedAt,
}

#[derive(DeriveIden)]
enum ResourceDecodeFailureShape {
    #[sea_orm(iden = "resource_decode_failures")]
    Table,
    #[sea_orm(iden = "resource_decode_failures_rebuild")]
    RebuildTable,
    EndpointId,
    Generation,
    OdataUri,
    OdataType,
    Feature,
    OemNamespace,
    ErrorSummary,
    ExtendedInfoJson,
}
