use rutilus_domain::{EndpointId, Tag, TagId, TagName, TagNameError};
use rutilus_entity::{endpoint_tag, tag};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, PaginatorTrait,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Binds `name` to `endpoint_id` (§14.2 标签), idempotently.
    ///
    /// Endpoint-level tags: the pair `(endpoint_id, tag_name)` is the natural
    /// key of a tag, so assigning the same name to the same endpoint twice is
    /// one binding, and assigning the same name to two different endpoints is
    /// two bindings sharing the name row (see the domain `Tag` module doc for
    /// the design decision). The name row is find-or-created and the binding
    /// inserted with `ON CONFLICT DO NOTHING` inside one transaction under
    /// the write gate — the `(endpoint_id, tag_name)` uniqueness is enforced
    /// by the database (migration 000010: the unique name index composed with
    /// the binding primary key), atomically, never by a check-then-insert
    /// race.
    ///
    /// # Errors
    ///
    /// Returns [`TagRepositoryError`] when write coordination fails or the
    /// transaction cannot commit.
    pub async fn assign_tag(
        &self,
        endpoint_id: EndpointId,
        name: &TagName,
    ) -> Result<Tag, TagRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TagRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(TagRepositoryError::Database)?;
        let tag_id = find_or_create_tag(&transaction, name).await?;
        // The fully qualified insert is deliberate: `ActiveModelTrait::insert`
        // would resolve instead of `EntityTrait::insert`, which returns the
        // conflict-handling builder this idempotent write needs.
        endpoint_tag::Entity::insert(endpoint_tag::ActiveModel {
            tag_id: Set(tag_id.into_uuid()),
            endpoint_id: Set(endpoint_id.into_uuid()),
        })
        .on_conflict_do_nothing()
        .exec(&transaction)
        .await
        .map_err(TagRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(TagRepositoryError::Database)?;
        Ok(Tag::new(tag_id, endpoint_id, name.clone()))
    }

    /// Removes the binding of `name` to `endpoint_id` (§14.2 标签),
    /// idempotently.
    ///
    /// A tag that was never assigned to the endpoint — or a name that never
    /// existed — is a no-op: removal converges on "not assigned" from every
    /// input state, the same at-least-once discipline as the group membership
    /// writes. When the removed binding was the name's last one, the name row
    /// is deleted with it in the same transaction, so the `tags` table holds
    /// exactly the names in use and the §14.2 homepage tag filter never lists
    /// a tag that tags nothing.
    ///
    /// # Errors
    ///
    /// Returns [`TagRepositoryError`] when write coordination fails or the
    /// transaction cannot commit.
    pub async fn remove_tag(
        &self,
        endpoint_id: EndpointId,
        name: &TagName,
    ) -> Result<(), TagRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TagRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(TagRepositoryError::Database)?;
        let Some(tag_row) = tag::Entity::find()
            .filter(tag::Column::Name.eq(name.to_string()))
            .one(&transaction)
            .await
            .map_err(TagRepositoryError::Database)?
        else {
            // The name never existed: nothing was ever assigned, so the
            // removal is already complete.
            transaction
                .commit()
                .await
                .map_err(TagRepositoryError::Database)?;
            return Ok(());
        };
        endpoint_tag::Entity::delete_by_id((tag_row.id, endpoint_id.into_uuid()))
            .exec(&transaction)
            .await
            .map_err(TagRepositoryError::Database)?;
        let remaining = endpoint_tag::Entity::find()
            .filter(endpoint_tag::Column::TagId.eq(tag_row.id))
            .count(&transaction)
            .await
            .map_err(TagRepositoryError::Database)?;
        if remaining == 0 {
            tag::Entity::delete_by_id(tag_row.id)
                .exec(&transaction)
                .await
                .map_err(TagRepositoryError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(TagRepositoryError::Database)?;
        Ok(())
    }

    /// Lists every tag bound to one endpoint, in tag-name order.
    ///
    /// The result is ordered by name so the §14.2 homepage tag filter and
    /// per-endpoint tag chips render deterministically. Each stored name is
    /// re-validated through the domain `TagName` on the way out, so one
    /// unreadable row poisons the whole listing — the caller must surface the
    /// corruption rather than silently drop the unreadable tag (the
    /// `list_operations` precedent).
    ///
    /// # Errors
    ///
    /// Returns [`TagRepositoryError`] when the query fails or any stored tag
    /// violates the name invariant.
    pub async fn list_tags_for_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<Vec<Tag>, TagRepositoryError> {
        let bindings = endpoint_tag::Entity::find()
            .filter(endpoint_tag::Column::EndpointId.eq(endpoint_id.into_uuid()))
            .all(&self.database)
            .await
            .map_err(TagRepositoryError::Database)?;
        let mut tags = Vec::with_capacity(bindings.len());
        for binding in bindings {
            let tag_id = TagId::from_uuid(binding.tag_id);
            let Some(tag_row) = tag::Entity::find_by_id(binding.tag_id)
                .one(&self.database)
                .await
                .map_err(TagRepositoryError::Database)?
            else {
                // The foreign key on the binding makes an orphan impossible
                // through the write path; a binding without its name row can
                // only be database corruption and must not half-understood.
                return Err(TagRepositoryError::Corrupt {
                    tag_id,
                    source: StoredTagError::OrphanBinding,
                });
            };
            let name = TagName::parse(&tag_row.name)
                .map_err(StoredTagError::InvalidName)
                .map_err(|source| corrupt(tag_id, source))?;
            tags.push(Tag::new(tag_id, endpoint_id, name));
        }
        tags.sort_by(|left, right| left.name().as_str().cmp(right.name().as_str()));
        Ok(tags)
    }

    /// Lists the endpoints carrying `name`, in endpoint-identity order.
    ///
    /// A name no endpoint carries — or that never existed — is an empty
    /// listing. The result is ordered deterministically so the §14.2
    /// homepage tag filter renders stably.
    ///
    /// # Errors
    ///
    /// Returns [`TagRepositoryError`] when the query fails.
    pub async fn list_endpoints_by_tag(
        &self,
        name: &TagName,
    ) -> Result<Vec<EndpointId>, TagRepositoryError> {
        let Some(tag_row) = tag::Entity::find()
            .filter(tag::Column::Name.eq(name.to_string()))
            .one(&self.database)
            .await
            .map_err(TagRepositoryError::Database)?
        else {
            return Ok(Vec::new());
        };
        let bindings = endpoint_tag::Entity::find()
            .filter(endpoint_tag::Column::TagId.eq(tag_row.id))
            .order_by_asc(endpoint_tag::Column::EndpointId)
            .all(&self.database)
            .await
            .map_err(TagRepositoryError::Database)?;
        Ok(bindings
            .into_iter()
            .map(|binding| EndpointId::from_uuid(binding.endpoint_id))
            .collect())
    }
}

/// Finds the tag name row, creating it when missing.
///
/// The write gate serializes writers, so the check-then-insert inside the
/// caller's transaction is atomic in practice; the unique `tags.name` index
/// (migration 000010) is the backstop that would refuse a racing duplicate.
/// Returns the row's identity.
async fn find_or_create_tag<C>(database: &C, name: &TagName) -> Result<TagId, TagRepositoryError>
where
    C: ConnectionTrait,
{
    let Some(model) = tag::Entity::find()
        .filter(tag::Column::Name.eq(name.to_string()))
        .one(database)
        .await
        .map_err(TagRepositoryError::Database)?
    else {
        let created = tag::ActiveModel {
            id: Set(TagId::generate().into_uuid()),
            name: Set(name.to_string()),
        }
        .insert(database)
        .await
        .map_err(TagRepositoryError::Database)?;
        return Ok(TagId::from_uuid(created.id));
    };
    Ok(TagId::from_uuid(model.id))
}

fn corrupt(tag_id: TagId, source: StoredTagError) -> TagRepositoryError {
    TagRepositoryError::Corrupt { tag_id, source }
}

/// A controlled failure while assigning, removing, or listing tags.
#[derive(Debug, Error)]
pub enum TagRepositoryError {
    #[error("tag write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("stored tag {tag_id} is invalid: {source}")]
    Corrupt {
        tag_id: TagId,
        #[source]
        source: StoredTagError,
    },
    #[error("tag database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted tag data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredTagError {
    #[error("stored tag name is invalid: {0}")]
    InvalidName(#[source] TagNameError),
    #[error("stored binding references a missing tag name row")]
    OrphanBinding,
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use sea_orm::{ActiveModelTrait, ConnectOptions, Database, Set};
    use uuid::Uuid;

    use super::*;
    use crate::SqliteStore;

    #[tokio::test]
    async fn assigning_tags_binds_names_per_endpoint_and_lists_them() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let first_endpoint = EndpointId::generate();
        let second_endpoint = EndpointId::generate();

        let production = store
            .assign_tag(first_endpoint, &TagName::parse("production")?)
            .await?;
        let lab = store
            .assign_tag(first_endpoint, &TagName::parse("lab")?)
            .await?;
        let shared = store
            .assign_tag(second_endpoint, &TagName::parse("production")?)
            .await?;

        // The same name on two endpoints shares the name row while keeping
        // independent bindings (§14.2 endpoint-scoped tags): the binding —
        // not the name row — is the endpoint-tag pair.
        assert_eq!(
            production.id(),
            shared.id(),
            "two endpoints carrying the same name must share the name row"
        );
        assert_ne!(production.endpoint_id(), shared.endpoint_id());
        assert_eq!(production.name(), shared.name());

        let listed = store.list_tags_for_endpoint(first_endpoint).await?;
        assert_eq!(
            listed,
            vec![lab, production],
            "the endpoint's tags must come back in name order"
        );

        let mut expected = vec![first_endpoint, second_endpoint];
        expected.sort();
        assert_eq!(
            store
                .list_endpoints_by_tag(&TagName::parse("production")?)
                .await?,
            expected
        );
        assert!(
            store
                .list_endpoints_by_tag(&TagName::parse("never-assigned")?)
                .await?
                .is_empty(),
            "a name no endpoint carries must be an empty listing"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn assign_tag_is_idempotent_per_endpoint() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let name = TagName::parse("production")?;

        let first = store.assign_tag(endpoint_id, &name).await?;
        let second = store.assign_tag(endpoint_id, &name).await?;
        assert_eq!(
            first, second,
            "re-assigning the same name must return the same binding"
        );
        assert_eq!(
            store.list_tags_for_endpoint(endpoint_id).await?.len(),
            1,
            "re-assigning must not duplicate the binding row"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn remove_tag_is_idempotent() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let name = TagName::parse("production")?;
        store.assign_tag(endpoint_id, &name).await?;

        store.remove_tag(endpoint_id, &name).await?;
        assert!(store.list_tags_for_endpoint(endpoint_id).await?.is_empty());
        // Removing again, or removing a name that was never assigned, is a
        // no-op: removal converges on "not assigned" from every input state.
        store.remove_tag(endpoint_id, &name).await?;
        store
            .remove_tag(endpoint_id, &TagName::parse("never-assigned")?)
            .await?;

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn removing_the_last_binding_removes_the_name_row() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let first_endpoint = EndpointId::generate();
        let second_endpoint = EndpointId::generate();
        let name = TagName::parse("production")?;
        store.assign_tag(first_endpoint, &name).await?;
        store.assign_tag(second_endpoint, &name).await?;

        store.remove_tag(first_endpoint, &name).await?;
        assert_eq!(
            store.list_endpoints_by_tag(&name).await?,
            vec![second_endpoint],
            "the name must survive while any endpoint still carries it"
        );

        store.remove_tag(second_endpoint, &name).await?;
        let stored_names = tag::Entity::find()
            .filter(tag::Column::Name.eq(name.to_string()))
            .all(&store.database)
            .await?;
        assert!(
            stored_names.is_empty(),
            "a name with no bindings left must be removed from the catalog"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn reports_corrupt_stored_names() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();

        // A name row and binding written directly, bypassing the
        // repository's domain validation — exactly what a row written by a
        // bug or a future build would look like. Rehydration must refuse it
        // as a corrupt aggregate.
        let tag_id = Uuid::now_v7();
        tag::ActiveModel {
            id: Set(tag_id),
            name: Set(String::from("bad\nname")),
        }
        .insert(&store.database)
        .await?;
        endpoint_tag::ActiveModel {
            tag_id: Set(tag_id),
            endpoint_id: Set(endpoint_id.into_uuid()),
        }
        .insert(&store.database)
        .await?;

        assert!(matches!(
            store.list_tags_for_endpoint(endpoint_id).await,
            Err(TagRepositoryError::Corrupt {
                source: StoredTagError::InvalidName(_),
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn reports_an_orphan_binding_as_corrupt() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let tag_id = Uuid::now_v7();
        tag::ActiveModel {
            id: Set(tag_id),
            name: Set(String::from("production")),
        }
        .insert(&store.database)
        .await?;
        endpoint_tag::ActiveModel {
            tag_id: Set(tag_id),
            endpoint_id: Set(endpoint_id.into_uuid()),
        }
        .insert(&store.database)
        .await?;

        // The foreign key cascade normally removes the binding with its name
        // row, so an orphan binding can only be written by a bug or a future
        // build — exactly the corruption a read must refuse. The row is
        // produced on a dedicated single-connection writer with foreign keys
        // disabled; one connection executes both the pragma and the delete,
        // so the bypass is deterministic (the `PRAGMA
        // ignore_check_constraints` precedent in the event repository
        // tests).
        //
        // Test-scope exception to the §7.3 bare-SQL ban: the PRAGMA only
        // simulates the foreign-build write above; no production path runs
        // raw SQL (the `tests/bare_sql_gate.rs` gate in the migration crate
        // pins persistence/src to PRAGMA-only).
        let database_path = store.database_path();
        let normalized_path = database_path.to_string_lossy().replace('\\', "/");
        let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
        options.max_connections(1);
        options.sqlx_logging(false);
        let writer = Database::connect(options).await?;
        writer
            .execute_unprepared("PRAGMA foreign_keys = OFF")
            .await?;
        tag::Entity::delete_by_id(tag_id).exec(&writer).await?;
        writer.close().await?;

        assert!(matches!(
            store.list_tags_for_endpoint(endpoint_id).await,
            Err(TagRepositoryError::Corrupt {
                source: StoredTagError::OrphanBinding,
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
