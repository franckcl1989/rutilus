use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Adds the center-side site association to the reused §15.5 data tables
/// (0.7.0 S5).
///
/// The center projects the site reports into the same tables the site uses
/// (§9.3 — `endpoints`, `events`, `artifacts`), so every center-side row
/// must name the reporting site. This migration adds the nullable `site_id`
/// column to the three tables and, with it, the endpoint summary columns
/// the §15.5 endpoint view renders (`refresh_generation` and `health`).
///
/// On a site database every row keeps the columns `NULL`/defaulted — the
/// site's own rows have no center association; the columns exist so both
/// deployments share one schema.
///
/// # The foreign key choice
///
/// `endpoints.site_id` names `instances(id)` and cascades on delete: when a
/// registered site is removed from the center, its endpoint projections
/// (and, by the existing cascade, their addresses, trust rows, and
/// resources) go with it. `events.site_id` and `artifacts.site_id` carry
/// no foreign key, mirroring those tables' existing style — `events`
/// deliberately outlives its endpoints, and `artifacts` has no relations.
///
/// `SQLite` supports `ALTER TABLE ... ADD COLUMN` with a `REFERENCES`
/// clause (enforced for new rows), so the columns are added in place; a
/// rebuild is only needed when a CHECK constraint must change (see the
/// role-scoping migration).
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    fn use_transaction(&self) -> Option<bool> {
        Some(true)
    }

    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        connection
            .execute_unprepared(
                "ALTER TABLE endpoints ADD COLUMN site_id UUID NULL \
                 REFERENCES instances(id) ON DELETE CASCADE",
            )
            .await?;
        connection
            .execute_unprepared(
                "ALTER TABLE endpoints ADD COLUMN refresh_generation BIGINT NOT NULL DEFAULT 0",
            )
            .await?;
        connection
            .execute_unprepared(
                "ALTER TABLE endpoints ADD COLUMN health TEXT NOT NULL DEFAULT 'unknown'",
            )
            .await?;
        connection
            .execute_unprepared("ALTER TABLE events ADD COLUMN site_id UUID NULL")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE artifacts ADD COLUMN site_id UUID NULL")
            .await
            .map(|_| ())
    }

    // The down rebuild recreates three tables and copies their rows, so it
    // exceeds the pedantic line budget (same exception as the family
    // migrations' rebuilds).
    #[allow(clippy::too_many_lines)]
    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let connection = manager.get_connection();
        // `SQLite` cannot drop columns in place, so the down direction
        // restores the previous shapes through the standard rebuild
        // procedure (the nvidia-families precedent): create a fresh table
        // with the exact original DDL, copy the rows without the added
        // columns, drop the old table, and rename the new one into place.
        // The indexes are recreated after the rename because `SQLite`
        // index names are database-global and the new tables must not
        // collide with the old ones before the drop.
        //
        // `endpoints` is also the parent of six `ON DELETE CASCADE` tables
        // — `endpoint_addresses`, `endpoint_trust`, `endpoint_credentials`,
        // `endpoint_capabilities`, `resources`, and (through it)
        // `resource_snapshots` — so the old parent cannot be dropped the way
        // `events` and `artifacts` are: with foreign keys on (the production
        // connection and the test harness both enable them), the implicit
        // `DELETE FROM endpoints` the drop runs cascades into every child
        // row and silently empties all six tables. The children are
        // therefore rebuilt alongside the parent, exactly as the
        // family-migration rebuilds (000003/000006/000012) rebuild
        // `resources` with its snapshots, with the rebuilt foreign keys
        // pointed at the `*_rebuild` tables so the parent drop below
        // cascades into nothing.
        connection
            .execute_unprepared(
                "CREATE TABLE endpoints_rebuild (\
                 id UUID NOT NULL PRIMARY KEY,\
                 display_name TEXT NOT NULL,\
                 created_at TEXT NOT NULL,\
                 updated_at TEXT NOT NULL)",
            )
            .await?;
        // The copies go through the SeaQuery builder (`INSERT ... SELECT` via
        // `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
        // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
        connection
            .execute(
                &Query::insert()
                    .into_table(EndpointShape::RebuildTable)
                    .columns([
                        EndpointShape::Id,
                        EndpointShape::DisplayName,
                        EndpointShape::CreatedAt,
                        EndpointShape::UpdatedAt,
                    ])
                    .select_from(
                        Query::select()
                            .column(EndpointShape::Id)
                            .column(EndpointShape::DisplayName)
                            .column(EndpointShape::CreatedAt)
                            .column(EndpointShape::UpdatedAt)
                            .from(EndpointShape::Table)
                            .take(),
                    )
                    .map_err(|error| DbErr::Custom(error.to_string()))?
                    .take(),
            )
            .await?;
        // The six cascade children are recreated with their exact current
        // DDL first, and every row is copied, so the drops below cannot
        // lose anything. The recreated foreign keys name the `*_rebuild`
        // tables (not the old `endpoints`), so the parent drop cannot reach
        // the copies either.
        connection
            .execute_unprepared(
                "CREATE TABLE endpoint_addresses_rebuild (\
                 id UUID NOT NULL PRIMARY KEY,\
                 endpoint_id UUID NOT NULL,\
                 address TEXT NOT NULL,\
                 is_active BOOLEAN NOT NULL,\
                 created_at TEXT NOT NULL,\
                 retired_at TEXT,\
                 CONSTRAINT fk_endpoint_addresses_endpoint \
                   FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id) \
                   ON UPDATE CASCADE ON DELETE CASCADE)",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE TABLE endpoint_trust_rebuild (\
                 endpoint_id UUID NOT NULL PRIMARY KEY,\
                 trust_mode TEXT NOT NULL,\
                 certificate_sha256 BLOB,\
                 certificate_der BLOB,\
                 trusted_at TEXT NOT NULL,\
                 CONSTRAINT fk_endpoint_trust_endpoint \
                   FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id) \
                   ON UPDATE CASCADE ON DELETE CASCADE)",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE TABLE endpoint_credentials_rebuild (\
                 endpoint_id UUID NOT NULL PRIMARY KEY,\
                 credential_id UUID NOT NULL,\
                 assigned_at TEXT NOT NULL,\
                 CONSTRAINT fk_endpoint_credentials_endpoint \
                   FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id) \
                   ON UPDATE CASCADE ON DELETE CASCADE,\
                 CONSTRAINT fk_endpoint_credentials_credential \
                   FOREIGN KEY (credential_id) REFERENCES credentials(id) \
                   ON UPDATE CASCADE ON DELETE RESTRICT)",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE TABLE endpoint_capabilities_rebuild (\
                 endpoint_id UUID NOT NULL,\
                 capability TEXT NOT NULL,\
                 state TEXT NOT NULL,\
                 observed_at TEXT NOT NULL,\
                 PRIMARY KEY (endpoint_id, capability),\
                 CONSTRAINT ck_endpoint_capabilities_state CHECK (\
                   state IN ('supported', 'read-only', 'unauthorized', \
                   'temporarily-unavailable', 'schema-incompatible', \
                   'not-advertised', 'not-compiled')),\
                 CONSTRAINT fk_endpoint_capabilities_endpoint \
                   FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id) \
                   ON UPDATE CASCADE ON DELETE CASCADE)",
            )
            .await?;
        // `resources` and `resource_snapshots` keep the 37-code allow-list
        // the 000012 down restores (the family rebuilds' own downgrades
        // enforce the same list on the rows they copy).
        connection
            .execute_unprepared(
                "CREATE TABLE resources_rebuild (\
                 id UUID NOT NULL PRIMARY KEY,\
                 endpoint_id UUID NOT NULL,\
                 odata_id TEXT NOT NULL,\
                 feature TEXT NOT NULL,\
                 created_at TEXT NOT NULL,\
                 CONSTRAINT ck_resources_feature CHECK (feature IN (\
                   'service-root', 'systems', 'chassis', 'managers', \
                   'dell-attributes', 'supermicro-sys-lockdown', \
                   'supermicro-kcs-interface', 'nvidia-system-config-profile', \
                   'nvidia-power-compliance', 'nvidia-managed-entity', \
                   'lenovo-security-service', 'processors', 'memory', \
                   'storages', 'network-adapters', 'ethernet-interfaces', \
                   'accounts', 'bios', 'boot-options', 'secure-boot', 'power', \
                   'thermal', 'sensors', 'controls', 'log-services', \
                   'manager-network-protocol', 'host-interfaces', \
                   'pcie-devices', 'assembly', 'software-inventory', \
                   'event-service', 'event-subscription', 'telemetry-service', \
                   'metric-definition', 'metric-report', 'task-service', \
                   'task')),\
                 CONSTRAINT fk_resources_endpoint \
                   FOREIGN KEY (endpoint_id) REFERENCES endpoints_rebuild(id) \
                   ON UPDATE CASCADE ON DELETE CASCADE)",
            )
            .await?;
        connection
            .execute_unprepared(
                "CREATE TABLE resource_snapshots_rebuild (\
                 resource_id UUID NOT NULL,\
                 generation BIGINT NOT NULL,\
                 odata_type TEXT,\
                 etag TEXT,\
                 typed_payload_json TEXT NOT NULL,\
                 observed_at TEXT NOT NULL,\
                 PRIMARY KEY (resource_id, generation),\
                 CONSTRAINT ck_resource_snapshots_generation \
                   CHECK (generation >= 1),\
                 CONSTRAINT fk_resource_snapshots_resource \
                   FOREIGN KEY (resource_id) REFERENCES resources_rebuild(id) \
                   ON UPDATE CASCADE ON DELETE CASCADE)",
            )
            .await?;
        // The copies go through the SeaQuery builder (`INSERT ... SELECT` via
        // `select_from`), so the rebuild's raw-SQL surface stays DDL-only —
        // the §7.3 bare-SQL gate in `tests/bare_sql_gate.rs` enforces that.
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
            .await?;
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
            .await?;
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
            .await?;
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
            .await?;
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
            .await?;
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
            .await?;
        // Children first, deepest dependency first (`resource_snapshots`
        // before `resources`, and `resources` before `endpoints`): with the
        // old children gone, the parent drop below cascades into nothing,
        // so the rebuild is safe under any `foreign_keys` setting.
        connection
            .execute_unprepared("DROP TABLE resource_snapshots")
            .await?;
        connection
            .execute_unprepared("DROP TABLE resources")
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
        connection
            .execute_unprepared("ALTER TABLE endpoints_rebuild RENAME TO endpoints")
            .await?;
        // Renaming the parent first repoints the rebuilt children's foreign
        // keys at the live `endpoints` (SQLite rewrites references on
        // rename), so the child renames afterwards only change their own
        // names — `resources` before `resource_snapshots`, whose foreign key
        // names `resources`.
        connection
            .execute_unprepared("ALTER TABLE resources_rebuild RENAME TO resources")
            .await?;
        connection
            .execute_unprepared(
                "ALTER TABLE resource_snapshots_rebuild RENAME TO resource_snapshots",
            )
            .await?;
        connection
            .execute_unprepared(
                "ALTER TABLE endpoint_addresses_rebuild RENAME TO endpoint_addresses",
            )
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
        // The rebuilt tables' indexes are recreated after the renames
        // because `SQLite` index names are database-global and the new
        // tables must not collide with the old ones before the drop.
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
            .await?;

        connection
            .execute_unprepared(
                "CREATE TABLE events_rebuild (\
                 id UUID NOT NULL PRIMARY KEY,\
                 endpoint_id UUID NOT NULL,\
                 message_id TEXT NOT NULL,\
                 severity TEXT NOT NULL,\
                 message TEXT,\
                 event_timestamp TEXT NOT NULL,\
                 observed_at TEXT NOT NULL,\
                 dedup_key TEXT NOT NULL,\
                 CONSTRAINT ck_events_severity CHECK (severity IN ('ok', 'warning', 'critical')))",
            )
            .await?;
        connection
            .execute(
                &Query::insert()
                    .into_table(EventShape::RebuildTable)
                    .columns([
                        EventShape::Id,
                        EventShape::EndpointId,
                        EventShape::MessageId,
                        EventShape::Severity,
                        EventShape::Message,
                        EventShape::EventTimestamp,
                        EventShape::ObservedAt,
                        EventShape::DedupKey,
                    ])
                    .select_from(
                        Query::select()
                            .column(EventShape::Id)
                            .column(EventShape::EndpointId)
                            .column(EventShape::MessageId)
                            .column(EventShape::Severity)
                            .column(EventShape::Message)
                            .column(EventShape::EventTimestamp)
                            .column(EventShape::ObservedAt)
                            .column(EventShape::DedupKey)
                            .from(EventShape::Table)
                            .take(),
                    )
                    .map_err(|error| DbErr::Custom(error.to_string()))?
                    .take(),
            )
            .await?;
        connection.execute_unprepared("DROP TABLE events").await?;
        connection
            .execute_unprepared("ALTER TABLE events_rebuild RENAME TO events")
            .await?;
        connection
            .execute_unprepared(
                "CREATE UNIQUE INDEX uq_events_endpoint_dedup_key \
                 ON events (endpoint_id, dedup_key)",
            )
            .await?;
        connection
            .execute_unprepared("CREATE INDEX ix_events_observed_at ON events (observed_at)")
            .await?;

        connection
            .execute_unprepared(
                "CREATE TABLE artifacts_rebuild (\
                 id UUID NOT NULL PRIMARY KEY,\
                 name TEXT NOT NULL,\
                 size_bytes BIGINT NOT NULL,\
                 sha256 TEXT NOT NULL,\
                 state TEXT NOT NULL,\
                 uploaded_bytes BIGINT NOT NULL,\
                 created_at TEXT NOT NULL,\
                 updated_at TEXT NOT NULL,\
                 CONSTRAINT ck_artifacts_state CHECK (state IN ('uploading', 'ready', 'failed')))",
            )
            .await?;
        connection
            .execute(
                &Query::insert()
                    .into_table(ArtifactShape::RebuildTable)
                    .columns([
                        ArtifactShape::Id,
                        ArtifactShape::Name,
                        ArtifactShape::SizeBytes,
                        ArtifactShape::Sha256,
                        ArtifactShape::State,
                        ArtifactShape::UploadedBytes,
                        ArtifactShape::CreatedAt,
                        ArtifactShape::UpdatedAt,
                    ])
                    .select_from(
                        Query::select()
                            .column(ArtifactShape::Id)
                            .column(ArtifactShape::Name)
                            .column(ArtifactShape::SizeBytes)
                            .column(ArtifactShape::Sha256)
                            .column(ArtifactShape::State)
                            .column(ArtifactShape::UploadedBytes)
                            .column(ArtifactShape::CreatedAt)
                            .column(ArtifactShape::UpdatedAt)
                            .from(ArtifactShape::Table)
                            .take(),
                    )
                    .map_err(|error| DbErr::Custom(error.to_string()))?
                    .take(),
            )
            .await?;
        connection
            .execute_unprepared("DROP TABLE artifacts")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE artifacts_rebuild RENAME TO artifacts")
            .await?;
        connection
            .execute_unprepared("CREATE INDEX ix_artifacts_state ON artifacts (state)")
            .await
            .map(|_| ())
    }
}

/// The three §15.5 data-table shapes the down rebuild restores, each with
/// the live table the copy reads from; the column variants are shared
/// because both shapes carry the same columns.
#[derive(DeriveIden)]
enum EndpointShape {
    #[sea_orm(iden = "endpoints")]
    Table,
    #[sea_orm(iden = "endpoints_rebuild")]
    RebuildTable,
    Id,
    DisplayName,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum EventShape {
    #[sea_orm(iden = "events")]
    Table,
    #[sea_orm(iden = "events_rebuild")]
    RebuildTable,
    Id,
    EndpointId,
    MessageId,
    Severity,
    Message,
    EventTimestamp,
    ObservedAt,
    DedupKey,
}

#[derive(DeriveIden)]
enum ArtifactShape {
    #[sea_orm(iden = "artifacts")]
    Table,
    #[sea_orm(iden = "artifacts_rebuild")]
    RebuildTable,
    Id,
    Name,
    SizeBytes,
    Sha256,
    State,
    UploadedBytes,
    CreatedAt,
    UpdatedAt,
}

/// The six `endpoints` children the down rebuilds alongside their parent,
/// each with the live table the copy reads from and the rebuild table the
/// copy writes to; the column variants are shared because both shapes carry
/// the same columns.
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
