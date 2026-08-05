use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "endpoint_trust")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub endpoint_id: Uuid,
    pub trust_mode: TrustMode,
    pub certificate_sha256: Option<Vec<u8>>,
    pub certificate_der: Option<Vec<u8>>,
    pub trusted_at: TimeDateTimeWithTimeZone,
}

#[derive(Clone, Debug, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::N(32))")]
pub enum TrustMode {
    #[sea_orm(string_value = "system_ca")]
    SystemCa,
    #[sea_orm(string_value = "pinned_certificate")]
    PinnedCertificate,
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
