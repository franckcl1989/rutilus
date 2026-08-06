use sea_orm::entity::prelude::*;

/// One persisted tag name (§9.3 组织与标签, §14.2 标签).
///
/// One row exists per distinct tag name, and `endpoint_tags` binds each name
/// to the endpoints that carry it (endpoint-scoped tags: the pair
/// `(endpoint_id, tag_name)` is the natural key of a tag, per the design
/// decision documented on the domain `Tag`). `name` is globally unique
/// (migration 000010), so the name resolves to exactly one identity and the
/// binding pair `(endpoint_id, tag_name)` is unique by composition of that
/// index with the `endpoint_tags` primary key. A name row is garbage-collected
/// by the persistence `remove_tag` when its last binding is removed, so the
/// table holds exactly the names in use.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "tags")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The normalized operator-facing tag label.
    pub name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::endpoint_tag::Entity")]
    Bindings,
}

impl Related<super::endpoint_tag::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Bindings.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
