use rutilus_domain::{EndpointId, Group, GroupId, GroupName, GroupNameError, GroupRestoreError};
use rutilus_entity::{group, group_member};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, Set, SqlErr, TransactionTrait, TryInsertResult,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Atomically persists one static group and its membership (§14.2 静态分组).
    ///
    /// The group row and its `group_members` rows commit in one transaction,
    /// so a group can never be persisted without its declared members (or
    /// half of them). Collision handling is deliberate and split:
    ///
    /// - Re-creating a group identity that is already stored is a no-op —
    ///   the stored row is authoritative and never rewritten, mirroring the
    ///   `create_artifact` and `create_operation` at-least-once delivery
    ///   discipline (§15.4).
    /// - Creating a different identity under a name that is already stored is
    ///   refused with [`GroupRepositoryError::NameAlreadyExists`]: the group
    ///   name is the operator-facing identity (§12.1 分组), and silently
    ///   keeping the first group would hide a real collision instead of
    ///   surfacing it for the operator to resolve.
    ///
    /// Both checks run against the unique `groups.name` index (migration
    /// 000010) inside one transaction under the write gate, so the refusal is
    /// atomic rather than a check-then-insert race.
    ///
    /// # Errors
    ///
    /// Returns [`GroupRepositoryError`] when write coordination fails, the
    /// name already belongs to another group, the transaction cannot commit,
    /// or a stored row violates a domain invariant.
    pub async fn create_group(&self, group: &Group) -> Result<(), GroupRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(GroupRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(GroupRepositoryError::Database)?;
        let group_id = group.id();
        if group::Entity::find_by_id(group_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?
            .is_some()
        {
            // The stored row is authoritative and must not be rewritten
            // (mirrors `create_artifact` and `create_operation`).
            transaction
                .commit()
                .await
                .map_err(GroupRepositoryError::Database)?;
            return Ok(());
        }
        group::ActiveModel {
            id: Set(group_id.into_uuid()),
            name: Set(group.name().to_string()),
            created_at: Set(group.created_at()),
            updated_at: Set(group.updated_at()),
        }
        .insert(&transaction)
        .await
        .map_err(map_group_insert_error)?;
        for endpoint_id in group.member_endpoint_ids() {
            group_member::ActiveModel {
                group_id: Set(group_id.into_uuid()),
                endpoint_id: Set(endpoint_id.into_uuid()),
            }
            .insert(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(GroupRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one complete static group by stable identity.
    ///
    /// The membership rows are read inside the same transaction as the group
    /// row and ordered by endpoint identity, so the returned aggregate is a
    /// consistent snapshot whose member order matches the domain canonical
    /// sorted set (see the `Group` module doc) — the group always rehydrates
    /// equal to the value the caller built.
    ///
    /// # Errors
    ///
    /// Returns [`GroupRepositoryError`] when the query fails or the stored
    /// group violates a domain invariant (invalid name or inverted timeline).
    pub async fn find_group(
        &self,
        group_id: GroupId,
    ) -> Result<Option<Group>, GroupRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(GroupRepositoryError::Database)?;
        let Some(model) = group::Entity::find_by_id(group_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(GroupRepositoryError::Database)?;
            return Ok(None);
        };
        let domain = load_group_aggregate(&transaction, &model).await?;
        transaction
            .commit()
            .await
            .map_err(GroupRepositoryError::Database)?;
        Ok(Some(domain))
    }

    /// Lists every static group in creation order with its full membership.
    ///
    /// Results are ordered by creation time and identity, like
    /// `list_credentials`; each group is rehydrated as a complete aggregate,
    /// so one corrupt row poisons the whole listing — the caller must surface
    /// the corruption rather than silently drop the unreadable group (the
    /// `list_operations` precedent).
    ///
    /// # Errors
    ///
    /// Returns [`GroupRepositoryError`] when the query fails or any stored
    /// group violates domain invariants.
    pub async fn list_groups(&self) -> Result<Vec<Group>, GroupRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(GroupRepositoryError::Database)?;
        let models = group::Entity::find()
            .order_by_asc(group::Column::CreatedAt)
            .order_by_asc(group::Column::Id)
            .all(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?;
        let mut groups = Vec::with_capacity(models.len());
        for model in &models {
            groups.push(load_group_aggregate(&transaction, model).await?);
        }
        transaction
            .commit()
            .await
            .map_err(GroupRepositoryError::Database)?;
        Ok(groups)
    }

    /// Adds one endpoint to a static group's membership (§14.2 静态分组).
    ///
    /// The operation is idempotent: adding an endpoint that is already a
    /// member is a no-op — the composite primary key `(group_id, endpoint_id)`
    /// refuses the duplicate row atomically (`ON CONFLICT DO NOTHING`), so a
    /// racing or redelivered membership write converges instead of duplicating
    /// (the §15.4 at-least-once discipline). The membership row commits
    /// together with the group's updated timestamp, so the group record and
    /// its membership never disagree about when the definition changed. The
    /// updated timestamp is the repository clock, taken after the stored one
    /// so the persisted timeline can never regress.
    ///
    /// # Errors
    ///
    /// Returns [`GroupRepositoryError::NotFound`] when the group does not
    /// exist, or [`GroupRepositoryError`] for coordination or database
    /// failures.
    pub async fn add_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> Result<(), GroupRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(GroupRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(GroupRepositoryError::Database)?;
        let model = group::Entity::find_by_id(group_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?
            .ok_or(GroupRepositoryError::NotFound { group_id })?;
        let result = group_member::Entity::insert(group_member::ActiveModel {
            group_id: Set(group_id.into_uuid()),
            endpoint_id: Set(endpoint_id.into_uuid()),
        })
        .on_conflict_do_nothing()
        .exec(&transaction)
        .await
        .map_err(GroupRepositoryError::Database)?;
        // `Inserted` persisted a new membership row; `Conflicted` is a
        // duplicate add — the membership already exists, which is the
        // idempotent success case. `Empty` cannot occur for a single-model
        // insert and exists only for the iterator API; naming it keeps the
        // match exhaustive.
        match result {
            TryInsertResult::Inserted(_) | TryInsertResult::Conflicted | TryInsertResult::Empty => {
            }
        }
        touch_group(&transaction, &model).await?;
        transaction
            .commit()
            .await
            .map_err(GroupRepositoryError::Database)?;
        Ok(())
    }

    /// Removes one endpoint from a static group's membership (§14.2 静态分组).
    ///
    /// Idempotent, mirroring [`Self::add_member`]: removing an endpoint that
    /// is not a member is a no-op — the delete targets the exact
    /// `(group_id, endpoint_id)` row and affects zero or one rows, both of
    /// which converge on the same state. The group must exist, however:
    /// removing from a group that was never created is an error the caller
    /// should surface, not silently absorb.
    ///
    /// # Errors
    ///
    /// Returns [`GroupRepositoryError::NotFound`] when the group does not
    /// exist, or [`GroupRepositoryError`] for coordination or database
    /// failures.
    pub async fn remove_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> Result<(), GroupRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(GroupRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(GroupRepositoryError::Database)?;
        let model = group::Entity::find_by_id(group_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?
            .ok_or(GroupRepositoryError::NotFound { group_id })?;
        group_member::Entity::delete_by_id((group_id.into_uuid(), endpoint_id.into_uuid()))
            .exec(&transaction)
            .await
            .map_err(GroupRepositoryError::Database)?;
        touch_group(&transaction, &model).await?;
        transaction
            .commit()
            .await
            .map_err(GroupRepositoryError::Database)?;
        Ok(())
    }

    /// Deletes one static group and cascades its membership rows away.
    ///
    /// The foreign key on `group_members.group_id` (migration 000010) removes
    /// every membership row with the group in one atomic statement, so a
    /// deleted group can never leave orphan membership behind.
    ///
    /// # Errors
    ///
    /// Returns [`GroupRepositoryError::NotFound`] when the group does not
    /// exist, or [`GroupRepositoryError`] for coordination or database
    /// failures.
    pub async fn delete_group(&self, group_id: GroupId) -> Result<(), GroupRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(GroupRepositoryError::Coordinate)?;
        let deleted = group::Entity::delete_by_id(group_id.into_uuid())
            .exec(&self.database)
            .await
            .map_err(GroupRepositoryError::Database)?;
        if deleted.rows_affected == 0 {
            return Err(GroupRepositoryError::NotFound { group_id });
        }
        Ok(())
    }
}

/// Loads one group's membership and assembles the domain aggregate.
///
/// The stored name is re-validated through the domain `GroupName` on the way
/// out, and the timeline invariant is re-checked by `Group::try_from_parts`,
/// so a row written by a bug or a future build is refused as corrupt instead
/// of half-understood (the rehydration discipline of every aggregate). The
/// membership is loaded ordered by endpoint identity, matching the domain's
/// canonical sorted set.
async fn load_group_aggregate<C>(
    database: &C,
    model: &group::Model,
) -> Result<Group, GroupRepositoryError>
where
    C: ConnectionTrait,
{
    let group_id = GroupId::from_uuid(model.id);
    let name = GroupName::parse(&model.name)
        .map_err(StoredGroupError::InvalidName)
        .map_err(|source| corrupt(group_id, source))?;
    let member_endpoint_ids = group_member::Entity::find()
        .filter(group_member::Column::GroupId.eq(model.id))
        .order_by_asc(group_member::Column::EndpointId)
        .all(database)
        .await
        .map_err(GroupRepositoryError::Database)?
        .into_iter()
        .map(|member| EndpointId::from_uuid(member.endpoint_id))
        .collect();
    Group::try_from_parts(
        group_id,
        name,
        member_endpoint_ids,
        model.created_at,
        model.updated_at,
    )
    .map_err(StoredGroupError::InvalidRestore)
    .map_err(|source| corrupt(group_id, source))
}

/// Bumps one group's `updated_at` to the repository clock.
///
/// The new timestamp is `max(now, stored)`, so a group created with a
/// timestamp in the future (the caller supplies the clock at the boundary,
/// §7.2) never regresses its own timeline. The caller must hold the write
/// gate: this runs inside a transaction.
async fn touch_group<C>(database: &C, model: &group::Model) -> Result<(), GroupRepositoryError>
where
    C: ConnectionTrait,
{
    let changed_at = OffsetDateTime::now_utc().max(model.updated_at);
    let mut active = model.clone().into_active_model();
    active.updated_at = Set(changed_at);
    active
        .update(database)
        .await
        .map_err(GroupRepositoryError::Database)?;
    Ok(())
}

fn map_group_insert_error(error: DbErr) -> GroupRepositoryError {
    if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        // The idempotency check already returned for a stored identity, so a
        // unique violation here can only be the `groups.name` index: the
        // operator-facing identity is taken.
        GroupRepositoryError::NameAlreadyExists
    } else {
        GroupRepositoryError::Database(error)
    }
}

fn corrupt(group_id: GroupId, source: StoredGroupError) -> GroupRepositoryError {
    GroupRepositoryError::Corrupt { group_id, source }
}

/// A controlled failure while creating, reading, or deleting groups.
#[derive(Debug, Error)]
pub enum GroupRepositoryError {
    #[error("group write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("a group with this name already exists")]
    NameAlreadyExists,
    #[error("group {group_id} was not found")]
    NotFound { group_id: GroupId },
    #[error("stored group {group_id} is invalid: {source}")]
    Corrupt {
        group_id: GroupId,
        #[source]
        source: StoredGroupError,
    },
    #[error("group database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted group data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredGroupError {
    #[error("group name is invalid: {0}")]
    InvalidName(#[source] GroupNameError),
    #[error("group record violates a domain invariant: {0}")]
    InvalidRestore(#[source] GroupRestoreError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use sea_orm::{ActiveModelTrait, Set};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    #[tokio::test]
    async fn creates_and_loads_groups_with_their_members() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc() - Duration::SECOND;
        let mut group = group_with_name("Lab servers", base)?;
        let first = EndpointId::generate();
        let second = EndpointId::generate();
        assert!(group.add_member(second));
        assert!(group.add_member(first));

        store.create_group(&group).await?;

        assert_eq!(
            store.find_group(group.id()).await?,
            Some(group.clone()),
            "the stored group must round-trip with its membership"
        );
        assert!(
            store.find_group(GroupId::generate()).await?.is_none(),
            "an unknown id must not match a stored group"
        );
        assert_eq!(
            store.list_groups().await?,
            vec![group],
            "the listing must return the created group"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn repeated_creation_never_rewrites_the_stored_row() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc() - Duration::SECOND;
        let mut group = group_with_name("Lab servers", base)?;
        assert!(group.add_member(EndpointId::generate()));

        store.create_group(&group).await?;
        store.create_group(&group).await?;
        assert_eq!(store.find_group(group.id()).await?, Some(group.clone()));

        // The re-created identity must not resurrect a group that has already
        // moved forward: a fresh writer carrying the same id must not roll
        // back membership the first writer recorded.
        let added = EndpointId::generate();
        store.add_member(group.id(), added).await?;
        store.create_group(&group).await?;
        let stored = store
            .find_group(group.id())
            .await?
            .ok_or("stored group is missing")?;
        assert!(stored.member_endpoint_ids().contains(&added));
        assert!(stored.updated_at() > group.updated_at());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_name_is_refused_and_keeps_the_first_group() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc() - Duration::SECOND;
        let first = group_with_name("Lab servers", base)?;
        store.create_group(&first).await?;

        let collision = group_with_name("Lab servers", base + Duration::SECOND)?;
        assert!(matches!(
            store.create_group(&collision).await,
            Err(GroupRepositoryError::NameAlreadyExists)
        ));
        assert_eq!(
            store.find_group(first.id()).await?,
            Some(first),
            "the refused create must leave the first group untouched"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn add_member_is_idempotent_and_advances_the_update_time() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc() - Duration::seconds(2);
        let group = group_with_name("Lab servers", base)?;
        store.create_group(&group).await?;
        let group_id = group.id();
        let member = EndpointId::generate();

        store.add_member(group_id, member).await?;
        store.add_member(group_id, member).await?;
        let stored = store
            .find_group(group_id)
            .await?
            .ok_or("stored group is missing")?;
        assert_eq!(
            stored.member_endpoint_ids(),
            &[member],
            "a duplicate add must not duplicate the membership row"
        );
        assert!(
            stored.updated_at() > base,
            "adding a member must advance the group's update time"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn add_member_never_regresses_an_update_time_in_the_future() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        // The caller supplies the clock at the boundary (§7.2), so a group
        // can arrive with a creation time in the future of the repository
        // clock (clock skew, a scheduled import). The repository clock must
        // never move the update time backwards past the stored value —
        // `touch_group` takes `max(now, stored)` — or the persisted timeline
        // would regress.
        let future = OffsetDateTime::now_utc() + Duration::days(1);
        let group = group_with_name("Lab servers", future)?;
        store.create_group(&group).await?;
        let group_id = group.id();

        store.add_member(group_id, EndpointId::generate()).await?;
        let stored = store
            .find_group(group_id)
            .await?
            .ok_or("stored group is missing")?;
        assert_eq!(
            stored.updated_at(),
            future,
            "adding a member must not move the update time before the stored value"
        );
        assert_eq!(stored.created_at(), future);
        assert_eq!(
            stored.member_endpoint_ids().len(),
            1,
            "the membership write itself must still take effect"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn add_member_on_an_unknown_group_is_not_found() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let unknown = GroupId::generate();

        assert!(matches!(
            store.add_member(unknown, EndpointId::generate()).await,
            Err(GroupRepositoryError::NotFound { group_id }) if group_id == unknown
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn remove_member_is_idempotent_and_advances_the_update_time() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc() - Duration::seconds(2);
        let mut group = group_with_name("Lab servers", base)?;
        let member = EndpointId::generate();
        let other = EndpointId::generate();
        assert!(group.add_member(member));
        assert!(group.add_member(other));
        store.create_group(&group).await?;
        let group_id = group.id();

        store.remove_member(group_id, member).await?;
        store.remove_member(group_id, member).await?;
        let stored = store
            .find_group(group_id)
            .await?
            .ok_or("stored group is missing")?;
        assert_eq!(
            stored.member_endpoint_ids(),
            &[other],
            "removing an absent member must be a no-op"
        );
        assert!(
            stored.updated_at() > base,
            "removing a member must advance the group's update time"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn remove_member_on_an_unknown_group_is_not_found() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let unknown = GroupId::generate();

        assert!(matches!(
            store.remove_member(unknown, EndpointId::generate()).await,
            Err(GroupRepositoryError::NotFound { group_id }) if group_id == unknown
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_group_cascades_its_membership() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc() - Duration::SECOND;
        let mut group = group_with_name("Lab servers", base)?;
        assert!(group.add_member(EndpointId::generate()));
        store.create_group(&group).await?;
        let group_id = group.id();

        store.delete_group(group_id).await?;
        assert!(store.find_group(group_id).await?.is_none());
        assert_eq!(
            group_member::Entity::find()
                .filter(group_member::Column::GroupId.eq(group_id.into_uuid()))
                .all(&store.database)
                .await?
                .len(),
            0,
            "deleting the group must cascade its membership"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_an_unknown_group_is_not_found() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let unknown = GroupId::generate();

        assert!(matches!(
            store.delete_group(unknown).await,
            Err(GroupRepositoryError::NotFound { group_id }) if group_id == unknown
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn reports_corrupt_stored_rows() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();

        // Every corrupt row is written directly, bypassing the repository's
        // domain validation — exactly what a row written by a bug or a future
        // build would look like. Rehydration must refuse each one as a
        // corrupt aggregate.
        let invalid_name = insert_group_row(&store, "bad\nname", now, now).await?;
        assert!(matches!(
            store.find_group(invalid_name).await,
            Err(GroupRepositoryError::Corrupt {
                group_id,
                source: StoredGroupError::InvalidName(_),
            }) if group_id == invalid_name
        ));

        let inverted_timeline =
            insert_group_row(&store, "inverted", now, now - Duration::SECOND).await?;
        assert!(matches!(
            store.find_group(inverted_timeline).await,
            Err(GroupRepositoryError::Corrupt {
                group_id,
                source: StoredGroupError::InvalidRestore(GroupRestoreError::InvalidTimeline),
            }) if group_id == inverted_timeline
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// Inserts one raw group row directly, bypassing repository validation.
    async fn insert_group_row(
        store: &SqliteStore,
        name: &str,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<GroupId, Box<dyn Error>> {
        let group_id = GroupId::generate();
        group::ActiveModel {
            id: Set(group_id.into_uuid()),
            name: Set(name.to_owned()),
            created_at: Set(created_at),
            updated_at: Set(updated_at),
        }
        .insert(&store.database)
        .await?;
        Ok(group_id)
    }

    fn group_with_name(name: &str, created_at: OffsetDateTime) -> Result<Group, GroupNameError> {
        Ok(Group::new(
            GroupId::generate(),
            GroupName::parse(name)?,
            created_at,
        ))
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
