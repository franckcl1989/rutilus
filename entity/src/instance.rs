use sea_orm::entity::prelude::*;

/// One registered deployment identity of the 0.7.0 center shape (design D6).
///
/// On the center side an `instances` row names one registered site; on the
/// site side the row names the site's own identity — a single-center binding
/// means exactly one row. `instance_kind` is the stable `InstanceKind` code
/// (`site` or `center`); the migration CHECKs the allow-list so the identity
/// rows can never carry a kind this build cannot classify.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "instances")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub display_name: String,
    pub instance_kind: String,
    pub created_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::center_binding::Entity")]
    Bindings,
    #[sea_orm(has_many = "super::center_outbox::Entity")]
    OutboxEntries,
    #[sea_orm(has_many = "super::center_inbox::Entity")]
    InboxEntries,
    #[sea_orm(has_many = "super::sync_cursor::Entity")]
    SyncCursors,
}

impl Related<super::center_binding::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Bindings.def()
    }
}

impl Related<super::center_outbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::OutboxEntries.def()
    }
}

impl Related<super::center_inbox::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::InboxEntries.def()
    }
}

impl Related<super::sync_cursor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::SyncCursors.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
