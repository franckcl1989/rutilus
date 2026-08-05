use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "endpoint_addresses")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub address: String,
    pub is_active: bool,
    pub created_at: TimeDateTimeWithTimeZone,
    pub retired_at: Option<TimeDateTimeWithTimeZone>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::endpoint::Entity",
        from = "Column::EndpointId",
        to = "super::endpoint::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Endpoint,
}

impl Related<super::endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Endpoint.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
