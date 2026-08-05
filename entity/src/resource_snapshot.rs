use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "resource_snapshots")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub resource_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub generation: i64,
    pub odata_type: Option<String>,
    pub etag: Option<String>,
    pub typed_payload_json: String,
    pub observed_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::resource::Entity",
        from = "Column::ResourceId",
        to = "super::resource::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Resource,
}

impl Related<super::resource::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Resource.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
