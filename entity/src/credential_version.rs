use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "credential_versions")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub credential_id: Uuid,
    pub encrypted_secret: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::credential::Entity",
        from = "Column::CredentialId",
        to = "super::credential::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Credential,
}

impl Related<super::credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Credential.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
