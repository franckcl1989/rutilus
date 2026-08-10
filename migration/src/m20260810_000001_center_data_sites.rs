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
        connection
            .execute_unprepared(
                "INSERT INTO endpoints_rebuild (id, display_name, created_at, updated_at) \
                 SELECT id, display_name, created_at, updated_at FROM endpoints",
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
            .execute_unprepared(
                "INSERT INTO events_rebuild \
                 (id, endpoint_id, message_id, severity, message, event_timestamp, observed_at, dedup_key) \
                 SELECT id, endpoint_id, message_id, severity, message, event_timestamp, observed_at, dedup_key \
                 FROM events",
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
            .execute_unprepared(
                "INSERT INTO artifacts_rebuild \
                 (id, name, size_bytes, sha256, state, uploaded_bytes, created_at, updated_at) \
                 SELECT id, name, size_bytes, sha256, state, uploaded_bytes, created_at, updated_at \
                 FROM artifacts",
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
