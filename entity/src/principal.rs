use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "principals")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub name: String,
    pub state: String,
    pub created_at: TimeDateTimeWithTimeZone,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::password_credential::Entity")]
    PasswordCredential,
    #[sea_orm(has_many = "super::totp_authenticator::Entity")]
    TotpAuthenticator,
    #[sea_orm(has_many = "super::session::Entity")]
    Session,
    #[sea_orm(has_many = "super::bootstrap_code::Entity")]
    BootstrapCode,
}

impl Related<super::password_credential::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::PasswordCredential.def()
    }
}

impl Related<super::totp_authenticator::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::TotpAuthenticator.def()
    }
}

impl Related<super::session::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Session.def()
    }
}

impl Related<super::bootstrap_code::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::BootstrapCode.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
