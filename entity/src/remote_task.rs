use sea_orm::entity::prelude::*;

/// One persisted Redfish asynchronous Task (design §13.6).
///
/// When a BMC accepts a write as an asynchronous Task (§13.3 step 8), the
/// product keeps polling the `TaskMonitor` until the outcome is provable. The
/// poll state is persisted here so a process restart can resume monitoring
/// instead of re-executing the write (§13.6: scan `WaitingRemote` operations,
/// re-establish the session, continue reading the Task). Each operation has at
/// most one remote task — the `operation_id` primary key — because the
/// operation lifecycle moves through `WaitingRemote` exactly once.
///
/// `endpoint_id` is captured at creation time as the routing hint for the
/// recovery scan and deliberately has no foreign key, mirroring
/// `operation_targets`: the task record must outlive its endpoint for
/// recovery, so deleting an endpoint must never cascade monitoring state away.
///
/// `last_state` is a stable product code (see the engine's `RemoteTaskState`
/// enum); the migration enforces the allowed code set with a CHECK constraint
/// so the recovery scanner never has to parse a code this build cannot
/// classify — the same discipline as `operations.state` and
/// `endpoint_capabilities.state`. `task_uri`, `task_monitor_uri`,
/// `last_message`, and `percent_complete` are last-observed values, never
/// parsed by the database, exactly like the §9.4 `TypedPayloadJson` rule.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "remote_tasks")]
pub struct Model {
    /// The operation this task belongs to; deleting the operation removes the
    /// task (the remote task is part of the operation aggregate).
    #[sea_orm(primary_key, auto_increment = false)]
    pub operation_id: Uuid,
    /// The endpoint that accepted the Task, captured at creation time as the
    /// recovery routing hint; no foreign key (see the model-level doc).
    pub endpoint_id: Uuid,
    /// The `@odata.id` of the Task resource returned by the BMC.
    pub task_uri: String,
    /// The `TaskMonitor` URI to poll for progress, when the BMC provides one.
    pub task_monitor_uri: Option<String>,
    /// The last observed `TaskState`, as the stable engine code.
    pub last_state: String,
    /// The last observed Task message, when the BMC reported one.
    pub last_message: Option<String>,
    /// The last observed completion percentage (0-100), when provided.
    pub percent_complete: Option<i32>,
    /// When the last observation was recorded, used to bound stale polling.
    pub last_checked_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::operation::Entity",
        from = "Column::OperationId",
        to = "super::operation::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Operation,
}

impl Related<super::operation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Operation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
