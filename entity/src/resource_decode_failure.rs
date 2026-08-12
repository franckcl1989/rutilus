use sea_orm::entity::prelude::*;

/// One member whose typed Schema decoding failed during one refresh
/// Generation (§12.4 decode-error path).
///
/// The row is a sibling of the resource snapshots: the member was skipped as
/// one odd member (§0.2.0), the endpoint and its other resources stay fully
/// usable, and the record keeps the skipped path visible to diagnostics. The
/// primary key anchors one record to exactly one endpoint Generation and one
/// member `@odata.id`, so a complete Generation is replayed without
/// ambiguity and re-committing a Generation can never duplicate a record.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "resource_decode_failures")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub endpoint_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub generation: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub odata_uri: String,
    pub odata_type: Option<String>,
    pub feature: String,
    pub oem_namespace: Option<String>,
    pub error_summary: String,
    pub extended_info_json: String,
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
