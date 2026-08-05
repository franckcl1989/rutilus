use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credentials")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub username: String,
    pub active_version_id: Option<Uuid>,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential_version::Entity",
        from = "(Column::Id, Column::ActiveVersionId)",
        to = "(super::credential_version::Column::CredentialId, super::credential_version::Column::Id)",
        on_update = "Cascade",
        on_delete = "Restrict"
    )]
    ActiveVersion,
    #[sea_orm(has_many = "super::credential_version::Entity")]
    Versions,
    #[sea_orm(has_many = "super::endpoint_credential::Entity")]
    EndpointBindings,
}

impl Related<super::credential_version::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Versions.def()
    }
}

impl Related<super::endpoint_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::EndpointBindings.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
