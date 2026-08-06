use sea_orm_migration::prelude::*;

/// The `events` table from design §9.3 事件和遥测, added with the Event
/// milestone (design §14.4).
///
/// Each row is one Redfish event the product received — from an
/// `EventService` subscription or from event-log polling — recorded exactly
/// as the BMC
/// reported it: the raw `message_id`, the `severity` (as the domain
/// `EventSeverity` stable code), the original `message` text when present,
/// and the BMC's own `event_timestamp`, beside `observed_at` (the
/// product-side receive time).
///
/// `endpoint_id` records the event's source (§14.4 记录事件来源) and
/// deliberately has no foreign key, mirroring `operation_targets`,
/// `remote_tasks`, and the audit records: an event row must outlive its
/// endpoint, so deleting an endpoint must never cascade the historical event
/// stream away.
///
/// §14.4 去除明显重复 is enforced in the database: the unique index on
/// `(endpoint_id, dedup_key)` means the same endpoint reporting the same
/// message at the same BMC time keeps only the first row, and the
/// persistence `append_event` treats a conflict as an idempotent no-op. The
/// `severity` CHECK constraint refuses a code this build cannot classify —
/// mirroring the `operations.state`, `remote_tasks.last_state`, and
/// `artifacts.state` precedents — so rehydration never has to guess a
/// severity.
#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Event::Table)
                    .col(ColumnDef::new(Event::Id).uuid().not_null().primary_key())
                    // Event source, captured without a foreign key so the
                    // record survives endpoint deletion (see the module doc).
                    .col(ColumnDef::new(Event::EndpointId).uuid().not_null())
                    .col(ColumnDef::new(Event::MessageId).text().not_null())
                    .col(ColumnDef::new(Event::Severity).string().not_null())
                    .col(ColumnDef::new(Event::Message).text())
                    .col(
                        ColumnDef::new(Event::Timestamp)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Event::ObservedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(ColumnDef::new(Event::DedupKey).text().not_null())
                    // The full Event_v1 severity vocabulary in the product's
                    // stable lowercase codes. The database refuses a code the
                    // product cannot classify, so a stored row always maps to
                    // a domain `EventSeverity`.
                    .check((
                        "ck_events_severity",
                        Expr::col(Event::Severity).is_in(["ok", "warning", "critical"]),
                    ))
                    .to_owned(),
            )
            .await?;

        // §14.4 去除明显重复: the same endpoint reporting the same message at
        // the same BMC time keeps only the first row. The unique index makes
        // the idempotent append atomic — a racing duplicate is refused by the
        // database, never double-inserted by a check-then-insert race.
        manager
            .create_index(
                Index::create()
                    .name("uq_events_endpoint_dedup_key")
                    .table(Event::Table)
                    .col(Event::EndpointId)
                    .col(Event::DedupKey)
                    .unique()
                    .to_owned(),
            )
            .await?;

        // The bounded recent-event listing (§14.4 SSE 回放/历史) orders by
        // the product receive time; this index keeps the newest-first query
        // from scanning the whole table.
        manager
            .create_index(
                Index::create()
                    .name("ix_events_observed_at")
                    .table(Event::Table)
                    .col(Event::ObservedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Event::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Event {
    #[sea_orm(iden = "events")]
    Table,
    Id,
    EndpointId,
    MessageId,
    Severity,
    Message,
    /// The BMC's own event timestamp; the iden keeps the column name
    /// `event_timestamp` although the variant is renamed so the enum does
    /// not repeat the `Event` table name in every variant.
    #[sea_orm(iden = "event_timestamp")]
    Timestamp,
    ObservedAt,
    DedupKey,
}
