use sea_orm_migration::prelude::*;

/// The `groups`, `group_members`, `tags`, and `endpoint_tags` tables from
/// design §9.3 组织与标签, added with the 0.2 grouping and tagging milestone
/// (§12.1 分组, §14.2 静态分组/标签).
///
/// `groups` is one row per operator-defined static group (§14.2: 1.0.0 does
/// not design dynamic rule groups), with a globally unique `name` — the
/// operator-facing identity, and the atomic duplicate refusal behind the
/// persistence `create_group`. `group_members` holds the static membership:
/// the composite primary key `(group_id, endpoint_id)` makes membership a
/// set, and the foreign key cascades membership away with its group.
/// `endpoint_id` has no foreign key, mirroring `events` (000008) and
/// `telemetry_series` (000009): a group may reference an endpoint that is
/// deleted later, and the membership row must survive so the group definition
/// is never silently rewritten.
///
/// Tags are endpoint-scoped in this milestone: the tagged object is the
/// endpoint (the object the §14.2 homepage tag filter filters); resource-level
/// tags are a later milestone. One `tags` row exists per distinct name —
/// `name` is globally unique — and `endpoint_tags` binds each name row to the
/// endpoints carrying it. The pair `(endpoint_id, tag_name)` is therefore
/// unique by composition: a name maps to exactly one tag id (the unique name
/// index) and each tag id has at most one binding row per endpoint (the
/// composite primary key). The persistence `assign_tag` find-or-creates the
/// name row and binds the endpoint with `ON CONFLICT DO NOTHING`, so tagging
/// is atomic and idempotent without a check-then-insert race. The
/// `endpoint_tags` index on `endpoint_id` keeps the per-endpoint tag listing
/// from scanning the whole table.
#[derive(DeriveMigrationName)]
pub struct Migration;

// The four §9.3 tables with their documented indexes and constraints are
// spelled out table by table so a review pins each schema decision to the
// design reference; the resulting statement count exceeds the pedantic line
// budget, the same trade-off the migration tests document for their
// exhaustive constraint assertions.
#[allow(clippy::too_many_lines)]
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Group::Table)
                    .col(ColumnDef::new(Group::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Group::Name).text().not_null())
                    .col(
                        ColumnDef::new(Group::CreatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Group::UpdatedAt)
                            .timestamp_with_time_zone()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        // The operator-facing group identity: the persistence `create_group`
        // collision refusal is this index, atomic instead of a
        // check-then-insert race.
        manager
            .create_index(
                Index::create()
                    .name("uq_groups_name")
                    .table(Group::Table)
                    .col(Group::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(GroupMember::Table)
                    .col(ColumnDef::new(GroupMember::GroupId).uuid().not_null())
                    .col(ColumnDef::new(GroupMember::EndpointId).uuid().not_null())
                    .primary_key(
                        Index::create()
                            .col(GroupMember::GroupId)
                            .col(GroupMember::EndpointId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_group_members_group")
                            .from(GroupMember::Table, GroupMember::GroupId)
                            .to(Group::Table, Group::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(Tag::Table)
                    .col(ColumnDef::new(Tag::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Tag::Name).text().not_null())
                    .to_owned(),
            )
            .await?;

        // The tag name catalog: one row per distinct name, so `assign_tag`
        // find-or-create is atomic and `(endpoint_id, tag_name)` uniqueness
        // holds by composition with the binding primary key (module doc).
        manager
            .create_index(
                Index::create()
                    .name("uq_tags_name")
                    .table(Tag::Table)
                    .col(Tag::Name)
                    .unique()
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(EndpointTag::Table)
                    .col(ColumnDef::new(EndpointTag::TagId).uuid().not_null())
                    .col(ColumnDef::new(EndpointTag::EndpointId).uuid().not_null())
                    .primary_key(
                        Index::create()
                            .col(EndpointTag::TagId)
                            .col(EndpointTag::EndpointId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk_endpoint_tags_tag")
                            .from(EndpointTag::Table, EndpointTag::TagId)
                            .to(Tag::Table, Tag::Id)
                            .on_update(ForeignKeyAction::Cascade)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // The per-endpoint tag listing (`list_tags_for_endpoint`) scans by
        // endpoint identity; the composite primary key is prefixed by the tag
        // id, so this index keeps that query from scanning the whole table.
        manager
            .create_index(
                Index::create()
                    .name("ix_endpoint_tags_endpoint")
                    .table(EndpointTag::Table)
                    .col(EndpointTag::EndpointId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Reverse creation order: the binding tables first, because their
        // foreign keys name the tables they bind, which must exist until
        // every dependent table is gone.
        manager
            .drop_table(Table::drop().table(EndpointTag::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Tag::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(GroupMember::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Group::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Group {
    #[sea_orm(iden = "groups")]
    Table,
    Id,
    Name,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum GroupMember {
    #[sea_orm(iden = "group_members")]
    Table,
    GroupId,
    EndpointId,
}

#[derive(DeriveIden)]
enum Tag {
    #[sea_orm(iden = "tags")]
    Table,
    Id,
    Name,
}

#[derive(DeriveIden)]
enum EndpointTag {
    #[sea_orm(iden = "endpoint_tags")]
    Table,
    TagId,
    EndpointId,
}
