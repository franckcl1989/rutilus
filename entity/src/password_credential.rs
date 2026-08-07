use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "password_credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub principal_id: Uuid,
    pub hash_format: String,
    pub salt: Vec<u8>,
    pub hash: Vec<u8>,
    pub changed_at: TimeDateTimeWithTimeZone,
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
}

impl Related<super::principal::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Principal.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
