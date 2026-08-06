use sea_orm::entity::prelude::*;

/// One persisted static endpoint group (§9.3 组织与标签, §12.1 分组,
/// §14.2 静态分组).
///
/// Each row is one operator-defined group: the normalized `name` (a domain
/// `GroupName`) and the record times. The membership is not a column — it is
/// the `group_members` rows bound to this row, so a group can grow without
/// rewriting its own record. `name` is globally unique (migration 000010):
/// the name is the operator-facing identity of the group, and the unique
/// index is the atomic duplicate refusal behind the persistence
/// `create_group`.
///
/// §14.2 scopes groups to static membership ("1.0.0 不设计动态规则组和通用
/// 查询语言"): the membership is exactly the stored `group_members` rows and
/// changes only through the persistence `add_member`/`remove_member`.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "groups")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The normalized operator-facing group label.
    pub name: String,
    /// When the group was declared.
    pub created_at: TimeDateTimeWithTimeZone,
    /// When the group or its membership last changed; `created_at` until the
    /// first change.
    pub updated_at: TimeDateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::group_member::Entity")]
    Members,
}

impl Related<super::group_member::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Members.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
