use sea_orm::entity::prelude::*;

/// One endpoint member of one static group (§14.2 静态分组).
///
/// The composite key `(group_id, endpoint_id)` makes membership a set: the
/// same endpoint appears at most once per group, and the persistence
/// `add_member` idempotency is backed by the primary key (an insert with
/// `ON CONFLICT DO NOTHING` is atomic rather than a check-then-insert race).
/// Deleting the group removes its membership rows via the foreign key
/// cascade.
///
/// `endpoint_id` deliberately has no foreign key, mirroring
/// `operation_targets`, `events`, and `telemetry_series`: a group may
/// reference an endpoint that is deleted later, and the membership row must
/// survive so the group definition is never silently rewritten. Projections
/// against the live endpoint inventory (the §14.2 homepage) resolve such rows
/// as deleted endpoints.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "group_members")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: Uuid,
    #[sea_orm(primary_key, auto_increment = false)]
    pub endpoint_id: Uuid,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::group::Entity",
        from = "Column::GroupId",
        to = "super::group::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Group,
}

impl Related<super::group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Group.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
