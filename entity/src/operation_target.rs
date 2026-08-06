use sea_orm::entity::prelude::*;

/// One target of a persisted Operation (§13.1).
///
/// A target names the resource on one endpoint the operation acts on. The
/// composite key `(operation_id, target_id)` makes targets a first-class part
/// of the aggregate: they are written and read inside the operation
/// transaction, and deleting the operation removes its targets. `endpoint_id`
/// is captured at creation time as the routing hint for the execution flow;
/// it deliberately has no foreign key so a later endpoint deletion cannot
/// erase operation history (operations outlive their endpoints for audit and
/// recovery).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "operation_targets")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub operation_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub target_id: Uuid,
    pub endpoint_id: Uuid,
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
