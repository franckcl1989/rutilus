use sea_orm::entity::prelude::*;

/// One per-instance sync-stream cursor of the 0.7.0 center shape (design §17).
///
/// Each site-to-center sync stream (`endpoint`, `health`, `event`,
/// `artifact`) keeps its own monotonic cursor so a reconnect resumes where
/// the last acknowledged batch ended; the unique `(instance_id, stream)`
/// index makes the upsert atomic. `stream` is the stable `SyncStream` code;
/// the migration CHECKs the allow-list.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sync_cursors")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    pub instance_id: Uuid,
    pub stream: String,
    pub cursor_value: String,
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::instance::Entity",
        from = "Column::InstanceId",
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
