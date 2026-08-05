use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "endpoint_credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub endpoint_id: Uuid,
    pub credential_id: Uuid,
    pub assigned_at: TimeDateTimeWithTimeZone,
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
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Cascade",
        on_delete = "Restrict"
    )]
    Credential,
}

impl Related<super::endpoint::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Endpoint.def()
    }
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
