use sea_orm::entity::prelude::*;

/// One persisted product Operation (§13.1).
///
/// Every write request becomes a row here before any Redfish call, so the
/// product can resume an interrupted operation after a restart. `source` and
/// `state` are stable product codes (see the domain `OperationSource` and
/// `OperationState` enums); the migration enforces the allowed code sets with
/// CHECK constraints so the recovery scanner never has to parse a code this
/// build cannot classify.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "operations")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub source: String,
    pub state: String,
    /// When the operation was accepted, before any Redfish interaction.
    pub created_at: TimeDateTimeWithTimeZone,
    /// When the state last changed; `created_at` until the first transition.
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::operation_target::Entity")]
    Targets,
}

impl Related<super::operation_target::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Targets.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
