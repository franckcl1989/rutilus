use sea_orm::entity::prelude::*;

/// One site-to-center binding record of the 0.7.0 center shape (design D2,
/// D6).
///
/// A pending binding carries the SHA-256 hash of the one-time binding code
/// (`binding_code_hash`) and the code's expiry (`expires_at`); binding the
/// site clears both and records `bound_at` and the site certificate
/// fingerprint. `state` is the stable `CenterBindingState` code (`pending`,
/// `bound`, or `revoked`); the migration CHECKs the allow-list and pins the
/// pending/bound/revoked column shape so a row can never silently mean
/// something else.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "center_bindings")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub center_url: String,
    pub binding_code_hash: Option<Vec<u8>>,
    pub site_instance_id: Uuid,
    pub site_cert_fingerprint: Option<String>,
    pub state: String,
    pub bound_at: Option<TimeDateTimeWithTimeZone>,
    pub expires_at: Option<TimeDateTimeWithTimeZone>,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::instance::Entity",
        from = "Column::SiteInstanceId",
        to = "super::instance::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Instance,
}

impl Related<super::instance::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Instance.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
