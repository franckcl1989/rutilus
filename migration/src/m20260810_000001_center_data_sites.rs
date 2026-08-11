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
        connection
            .execute_unprepared("DROP TABLE endpoints")
            .await?;
        connection
            .execute_unprepared("ALTER TABLE endpoints_rebuild RENAME TO endpoints")
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
