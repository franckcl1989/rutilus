use sea_orm::ConnectionTrait;
use sea_orm_migration::prelude::*;

/// Adds the covering index for the audit-history paging query (W7-S-3 /
/// W7-P-4): `list_recent_audit_events` pages `audit_events` with
/// `ORDER BY occurred_at DESC, event_sequence DESC, id DESC` — the event id
/// is the W7-D-1 tiebreaker that makes the sort a total order. The existing
/// `ix_audit_events_occurred_at` index covers only the first key, so the
/// remaining keys forced a full table scan plus an external sort. This
/// index matches the query's three sort keys exactly — including the
/// tiebreaker — so the query reads the rows in final order directly off the
/// index, newest first, without the scan-and-sort.
///
/// # Downgrade symmetry
///
/// `down` drops the index. The single-statement `down` is never constrained
/// by the child-first drop discipline (no table pair to order), and the raw
/// statements are the `CREATE`/`DROP` DDL the §7.3 bare-SQL boundary allows.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(
                "CREATE INDEX ix_audit_events_occurred_at_sequence \
                 ON audit_events (occurred_at DESC, event_sequence DESC, id DESC)",
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared("DROP INDEX ix_audit_events_occurred_at_sequence")
            .await?;
        Ok(())
    }
}
