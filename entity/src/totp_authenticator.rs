use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "totp_authenticators")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub principal_id: Uuid,
    pub secret: Vec<u8>,
    pub state: String,
    pub algorithm: String,
    pub digits: i64,
    pub period: i64,
    pub created_at: TimeDateTimeWithTimeZone,
    pub activated_at: Option<TimeDateTimeWithTimeZone>,
    pub last_used_step: Option<i64>,
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
