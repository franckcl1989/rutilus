use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "audit_events")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub operation_id: Uuid,
    pub event_sequence: i64,
    pub actor: String,
    pub origin: String,
    pub target_kind: String,
    pub target_endpoint_id: Option<Uuid>,
    pub target_endpoint_address: Option<String>,
    pub parameter_kind: String,
    pub credential_id: Option<Uuid>,
    pub trust_mode: Option<String>,
    pub row_count: Option<i64>,
    pub permission: String,
    pub action: String,
    pub redfish_operation: String,
    pub outcome: String,
    pub progress: Option<String>,
    pub failure: Option<String>,
    pub verification: Option<String>,
    pub occurred_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
