use std::error::Error;

use rutilus_entity::{endpoint_tag, group, group_member, tag};
use rutilus_migration::Migrator;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter, Set,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};
use time::OffsetDateTime;
use uuid::Uuid;

const GROUPS_TAGS_TABLES: [&str; 4] = ["groups", "group_members", "tags", "endpoint_tags"];

#[tokio::test]
async fn groups_tags_migration_preserves_identity_and_membership_invariants()
-> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let database_path = directory.path().join("rutilus.db");
    let normalized_path = database_path.to_string_lossy().replace('\\', "/");
    let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
    options.max_connections(1);
    let database = Database::connect(options).await?;

    Migrator::up(&database, None).await?;
    Migrator::up(&database, None).await?;
    assert_groups_tags_tables(&database, true).await?;

    let now = OffsetDateTime::now_utc();
    verify_groups_tags_constraints(&database, now).await?;

    Migrator::down(&database, None).await?;
    assert_groups_tags_tables(&database, false).await?;

    Ok(())
}

// Every §9.3/§14.2 constraint is spelled out as its own insert-and-assert so
// a failure pinpoints the exact rule (unique group names, membership set and
// cascade, unique tag names, binding set and cascade), which exceeds the
// pedantic line budget; the domain and persistence crates allow the same lint
// on their exhaustive assertion tests.
#[allow(clippy::too_many_lines)]
async fn verify_groups_tags_constraints(
    database: &DatabaseConnection,
    now: OffsetDateTime,
) -> Result<(), Box<dyn Error>> {
    let group_id = Uuid::now_v7();
    group::ActiveModel {
        id: Set(group_id),
        name: Set(String::from("Lab servers")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await?;
    let stored = group::Entity::find_by_id(group_id)
        .one(database)
        .await?
        .ok_or("inserted group is missing")?;
    assert_eq!(stored.name, "Lab servers");
    assert_eq!(stored.created_at, now);
    assert_eq!(stored.updated_at, now);

    // The operator-facing group identity: a second group under the same name
    // must be refused by the unique index.
    let duplicate_name = group::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("Lab servers")),
        created_at: Set(now),
        updated_at: Set(now),
    }
    .insert(database)
    .await;
    assert!(
        duplicate_name.is_err(),
        "the same group name must be refused as a duplicate"
    );

    // Membership is a set: the composite primary key refuses the same
    // endpoint twice in one group, and the endpoint id has no foreign key, so
    // a group may reference an endpoint that is deleted later and the
    // membership row survives.
    let endpoint_id = Uuid::now_v7();
    group_member::ActiveModel {
        group_id: Set(group_id),
        endpoint_id: Set(endpoint_id),
    }
    .insert(database)
    .await?;
    let duplicate_member = group_member::ActiveModel {
        group_id: Set(group_id),
        endpoint_id: Set(endpoint_id),
    }
    .insert(database)
    .await;
    assert!(
        duplicate_member.is_err(),
        "the same (group_id, endpoint_id) must be refused as a duplicate"
    );

    let other_endpoint = Uuid::now_v7();
    group_member::ActiveModel {
        group_id: Set(group_id),
        endpoint_id: Set(other_endpoint),
    }
    .insert(database)
    .await?;

    // A member must name an existing group: the foreign key refuses an
    // orphan row even when the domain never would have produced one.
    let orphan_member = group_member::ActiveModel {
        group_id: Set(Uuid::now_v7()),
        endpoint_id: Set(other_endpoint),
    }
    .insert(database)
    .await;
    assert!(
        orphan_member.is_err(),
        "a member must name an existing group"
    );

    // ON DELETE CASCADE: deleting the group removes its membership rows with
    // it, atomically — a deleted group never leaks its membership.
    let deleted = group::Entity::delete_by_id(group_id).exec(database).await?;
    assert_eq!(deleted.rows_affected, 1);
    let remaining = group_member::Entity::find()
        .filter(group_member::Column::GroupId.eq(group_id))
        .count(database)
        .await?;
    assert_eq!(remaining, 0, "deleting the group must cascade its members");

    // Tags: one row per distinct name — the tag name catalog.
    let tag_id = Uuid::now_v7();
    tag::ActiveModel {
        id: Set(tag_id),
        name: Set(String::from("production")),
    }
    .insert(database)
    .await?;
    let duplicate_tag = tag::ActiveModel {
        id: Set(Uuid::now_v7()),
        name: Set(String::from("production")),
    }
    .insert(database)
    .await;
    assert!(
        duplicate_tag.is_err(),
        "the same tag name must be refused as a duplicate"
    );

    // A binding must name an existing tag: the foreign key refuses an orphan
    // row even when the domain never would have produced one.
    let orphan_binding = endpoint_tag::ActiveModel {
        tag_id: Set(Uuid::now_v7()),
        endpoint_id: Set(endpoint_id),
    }
    .insert(database)
    .await;
    assert!(
        orphan_binding.is_err(),
        "a binding must name an existing tag"
    );

    // Bindings are a set: the composite primary key refuses the same
    // (tag, endpoint) pair twice, and the endpoint id has no foreign key, so
    // a tag may reference a deleted endpoint and the binding survives.
    endpoint_tag::ActiveModel {
        tag_id: Set(tag_id),
        endpoint_id: Set(endpoint_id),
    }
    .insert(database)
    .await?;
    let duplicate_binding = endpoint_tag::ActiveModel {
        tag_id: Set(tag_id),
        endpoint_id: Set(endpoint_id),
    }
    .insert(database)
    .await;
    assert!(
        duplicate_binding.is_err(),
        "the same (tag_id, endpoint_id) must be refused as a duplicate"
    );
    endpoint_tag::ActiveModel {
        tag_id: Set(tag_id),
        endpoint_id: Set(other_endpoint),
    }
    .insert(database)
    .await?;

    // ON DELETE CASCADE: deleting the tag name row removes its bindings with
    // it, so the tag catalog never leaks stale bindings.
    let deleted = tag::Entity::delete_by_id(tag_id).exec(database).await?;
    assert_eq!(deleted.rows_affected, 1);
    let remaining = endpoint_tag::Entity::find()
        .filter(endpoint_tag::Column::TagId.eq(tag_id))
        .count(database)
        .await?;
    assert_eq!(remaining, 0, "deleting the tag must cascade its bindings");

    Ok(())
}

async fn assert_groups_tags_tables(
    database: &DatabaseConnection,
    should_exist: bool,
) -> Result<(), Box<dyn Error>> {
    let schema = SchemaManager::new(database);
    for table in GROUPS_TAGS_TABLES {
        assert_eq!(
            schema.has_table(table).await?,
            should_exist,
            "table {table}"
        );
    }
    Ok(())
}
