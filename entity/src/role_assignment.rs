use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "role_assignments")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub principal_id: Uuid,
    pub role: String,
    pub assigned_by: Option<Uuid>,
    pub assigned_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::principal::Entity",
        from = "Column::PrincipalId",
        to = "super::principal::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Principal,
    #[sea_orm(
        belongs_to = "super::principal::Entity",
        from = "Column::AssignedBy",
        to = "super::principal::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    Assigner,
}

impl Related<super::principal::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Principal.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
