use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "resources")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub endpoint_id: Uuid,
    pub odata_id: String,
    pub feature: String,
    pub created_at: TimeDateTimeWithTimeZone,
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
    #[sea_orm(has_many = "super::resource_snapshot::Entity")]
    Snapshots,
}

impl Related<super::endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Endpoint.def()
    }
}

impl Related<super::resource_snapshot::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Snapshots.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
