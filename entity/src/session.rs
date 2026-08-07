use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sessions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub principal_id: Uuid,
    pub token_hash: Vec<u8>,
    pub csrf_hash: Vec<u8>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub last_used_at: TimeDateTimeWithTimeZone,
    pub expires_at: TimeDateTimeWithTimeZone,
    pub revoked_at: Option<TimeDateTimeWithTimeZone>,
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
