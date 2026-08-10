use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "endpoints")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub display_name: String,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
    /// The owning site of a center-side endpoint projection (§15.5); `NULL`
    /// on a site database, where every endpoint is local.
    pub site_id: Option<Uuid>,
    /// The site's refresh-generation watermark of the projection; `0` on a
    /// site database.
    pub refresh_generation: i64,
    /// The health cut of the projection (`ok`/`unknown`); `unknown` on a
    /// site database.
    pub health: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::endpoint_address::Entity")]
    Addresses,
    #[sea_orm(has_one = "super::endpoint_trust::Entity")]
    Trust,
    #[sea_orm(has_one = "super::endpoint_credential::Entity")]
    CredentialBinding,
    #[sea_orm(has_many = "super::resource::Entity")]
    Resources,
}

impl Related<super::endpoint_address::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Addresses.def()
    }
}

impl Related<super::endpoint_trust::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Trust.def()
    }
}

impl Related<super::endpoint_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::CredentialBinding.def()
    }
}

impl Related<super::resource::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Resources.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
