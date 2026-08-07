use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "bootstrap_codes")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub code_hash: Vec<u8>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub used_at: Option<TimeDateTimeWithTimeZone>,
    pub used_by: Option<Uuid>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::principal::Entity",
        from = "Column::UsedBy",
        to = "super::principal::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Principal,
}

impl Related<super::principal::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Principal.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
