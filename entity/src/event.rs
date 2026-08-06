use sea_orm::entity::prelude::*;

/// One persisted BMC event (design §9.3 事件和遥测, §14.4 Event).
///
/// The row records the event exactly as the BMC reported it — the raw
/// Redfish `message_id` and `severity` (as the domain's stable codes), the
/// original `message` text when present, and the BMC's own
/// `event_timestamp` — beside `observed_at`, the product-side receive time.
/// A viewer compares the two clocks directly, and the recent listing orders
/// by the product receive time.
///
/// `endpoint_id` is captured as the event's source (§14.4 记录事件来源) and
/// deliberately has no foreign key, mirroring `operation_targets` and
/// `remote_tasks`: an event record must outlive its endpoint, so deleting an
/// endpoint must never cascade the historical event stream away — the same
/// reasoning as the append-only audit records.
///
/// `dedup_key` is the derived combination of `message_id` and
/// `event_timestamp` (see the domain `Event` doc). The unique index on
/// `(endpoint_id, dedup_key)` enforces §14.4 去除明显重复 in the database:
/// the same endpoint reporting the same message at the same BMC time keeps
/// only the first row, so the idempotent append is atomic rather than a
/// check-then-insert race. `severity` is a stable product code; the
/// migration's CHECK constraint refuses a code this build cannot classify,
/// so rehydration never has to guess a severity.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "events")]
pub struct Model {
    /// The immutable identity of this event record.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The endpoint that reported the event; no foreign key (see the
    /// model-level doc).
    pub endpoint_id: Uuid,
    /// The raw Redfish `MessageId`, as the BMC reported it.
    pub message_id: String,
    /// The Redfish event `Severity`, as the domain `EventSeverity` code.
    pub severity: String,
    /// The original Redfish `Message` text, when the BMC provided one.
    pub message: Option<String>,
    /// The BMC's own event timestamp (`EventTimestamp`).
    pub event_timestamp: TimeDateTimeWithTimeZone,
    /// When the product received the event.
    pub observed_at: TimeDateTimeWithTimeZone,
    /// The dedup key: `message_id` + `event_timestamp`, unique per endpoint.
    pub dedup_key: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
