use sea_orm::entity::prelude::*;

/// Binds one tag name to one endpoint (§9.3 组织与标签, §14.2 标签).
///
/// The composite key `(tag_id, endpoint_id)` makes the binding a set: the
/// same endpoint carries the same tag name at most once, and the persistence
/// `assign_tag` idempotency is backed by the primary key (an insert with
/// `ON CONFLICT DO NOTHING` is atomic rather than a check-then-insert race).
/// Deleting the name row removes its bindings via the foreign key cascade.
///
/// `endpoint_id` deliberately has no foreign key, mirroring `group_members`
/// and the event records: a tag may reference an endpoint that is deleted
/// later, and the binding must survive so the tag assignment is never
/// silently lost. Projections against the live endpoint inventory (the §14.2
/// homepage) resolve such rows as deleted endpoints.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "endpoint_tags")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tag_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub endpoint_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::tag::Entity",
        from = "Column::TagId",
        to = "super::tag::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Tag,
}

impl Related<super::tag::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Tag.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
