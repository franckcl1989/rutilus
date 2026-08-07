use rutilus_domain::{
    Principal, PrincipalName, PrincipalRestoreError, PrincipalState, Role, RoleAssignment,
};
use rutilus_entity::{principal, role_assignment};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one new principal (§16.1).
    ///
    /// The normalized name is the principal's identity: the `principals.name`
    /// unique index refuses a second principal under the same name atomically
    /// (no check-then-insert race), which is what makes duplicate refusal
    /// safe under racing sign-ups.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError::DuplicateName`] for an existing
    /// name, and [`PrincipalRepositoryError`] variants for coordination or
    /// database failures.
    pub async fn create_principal(
        &self,
        principal: &Principal,
    ) -> Result<(), PrincipalRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(PrincipalRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(PrincipalRepositoryError::Database)?;
        insert_principal(&transaction, principal).await?;
        transaction
            .commit()
            .await
            .map_err(PrincipalRepositoryError::Database)
    }

    /// Reads one principal by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_principal(
        &self,
        principal_id: rutilus_domain::PrincipalId,
    ) -> Result<Option<Principal>, PrincipalRepositoryError> {
        let Some(model) = principal::Entity::find_by_id(principal_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(PrincipalRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_principal(principal_id, &model).map(Some)
    }

    /// Reads one principal by its normalized name.
    ///
    /// The name is the login key; the unique index makes this lookup the
    /// atomic gate of the sign-in path.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_principal_by_name(
        &self,
        name: &PrincipalName,
    ) -> Result<Option<Principal>, PrincipalRepositoryError> {
        let Some(model) = principal::Entity::find()
            .filter(principal::Column::Name.eq(name.as_str()))
            .one(&self.database)
            .await
            .map_err(PrincipalRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_principal(rutilus_domain::PrincipalId::from_uuid(model.id), &model).map(Some)
    }

    /// Lists every principal in creation order.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants.
    pub async fn list_principals(&self) -> Result<Vec<Principal>, PrincipalRepositoryError> {
        let models = principal::Entity::find()
            .order_by_asc(principal::Column::CreatedAt)
            .order_by_asc(principal::Column::Id)
            .all(&self.database)
            .await
            .map_err(PrincipalRepositoryError::Database)?;
        let mut principals = Vec::with_capacity(models.len());
        for model in models {
            let principal_id = rutilus_domain::PrincipalId::from_uuid(model.id);
            principals.push(map_stored_principal(principal_id, &model)?);
        }
        Ok(principals)
    }

    /// Transitions one principal's enabled/disabled state (§16.1).
    ///
    /// The disabled state is the soft-off switch: the principal stops signing
    /// in and its sessions are revoked separately (see
    /// [`Self::revoke_sessions_for_principal`]); the row stays intact.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError::NotFound`] for an unknown id and
    /// [`PrincipalRepositoryError`] variants for coordination or database
    /// failures.
    pub async fn set_principal_state(
        &self,
        principal_id: rutilus_domain::PrincipalId,
        state: PrincipalState,
        at: OffsetDateTime,
    ) -> Result<(), PrincipalRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(PrincipalRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(PrincipalRepositoryError::Database)?;
        let model = principal::Entity::find_by_id(principal_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(PrincipalRepositoryError::Database)?
            .ok_or(PrincipalRepositoryError::NotFound { principal_id })?;
        let mut active = model.into_active_model();
        active.state = Set(state.as_str().to_owned());
        active.updated_at = Set(at);
        active
            .update(&transaction)
            .await
            .map_err(PrincipalRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(PrincipalRepositoryError::Database)
    }

    /// Assigns (or replaces) one principal's role (§16.1).
    ///
    /// The `role_assignments.principal_id` primary key makes the write a
    /// find-or-replace: one role per principal, no history. The optional
    /// assigner is preserved as `SET NULL` by the schema when the assigning
    /// principal is later deleted.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError`] when the assignment references an
    /// unknown principal or assigner (the foreign keys refuse it) or a
    /// coordination or database failure occurs.
    pub async fn assign_role(
        &self,
        assignment: &RoleAssignment,
    ) -> Result<(), PrincipalRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(PrincipalRepositoryError::Coordinate)?;
        let active = role_assignment::ActiveModel {
            principal_id: Set(assignment.principal_id().into_uuid()),
            role: Set(assignment.role().as_str().to_owned()),
            assigned_by: Set(assignment
                .assigned_by()
                .map(rutilus_domain::PrincipalId::into_uuid)),
            assigned_at: Set(assignment.assigned_at()),
        };
        // One role per principal: the primary key conflict replaces the
        // stored assignment, never duplicates it.
        role_assignment::Entity::insert(active)
            .on_conflict(
                sea_orm::sea_query::OnConflict::columns([role_assignment::Column::PrincipalId])
                    .update_columns([
                        role_assignment::Column::Role,
                        role_assignment::Column::AssignedBy,
                        role_assignment::Column::AssignedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.database)
            .await
            .map_err(PrincipalRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one principal's role assignment.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError`] when the query fails or the
    /// stored role code is unknown to this build.
    pub async fn find_role_assignment(
        &self,
        principal_id: rutilus_domain::PrincipalId,
    ) -> Result<Option<RoleAssignment>, PrincipalRepositoryError> {
        let Some(model) = role_assignment::Entity::find_by_id(principal_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(PrincipalRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_assignment(principal_id, &model).map(Some)
    }

    /// Lists every role assignment, paired with its principal.
    ///
    /// # Errors
    ///
    /// Returns [`PrincipalRepositoryError::CorruptAssignment`] when any
    /// stored role code is unknown to this build.
    pub async fn list_role_assignments(
        &self,
    ) -> Result<Vec<RoleAssignment>, PrincipalRepositoryError> {
        let models = role_assignment::Entity::find()
            .order_by_asc(role_assignment::Column::AssignedAt)
            .all(&self.database)
            .await
            .map_err(PrincipalRepositoryError::Database)?;
        let mut assignments = Vec::with_capacity(models.len());
        for model in models {
            assignments.push(map_stored_assignment(
                rutilus_domain::PrincipalId::from_uuid(model.principal_id),
                &model,
            )?);
        }
        Ok(assignments)
    }
}

async fn insert_principal<C>(
    database: &C,
    domain: &Principal,
) -> Result<(), PrincipalRepositoryError>
where
    C: sea_orm::ConnectionTrait,
{
    principal::ActiveModel {
        id: Set(domain.id().into_uuid()),
        name: Set(domain.name().as_str().to_owned()),
        state: Set(domain.state().as_str().to_owned()),
        created_at: Set(domain.created_at()),
        updated_at: Set(domain.updated_at()),
    }
    .insert(database)
    .await
    .map_err(|error| {
        // The unique name index is the atomic duplicate refusal; the only
        // unique constraint in reach here is `principals.name` (the primary
        // key idempotency has its own pre-check upstream).
        if matches!(
            error.sql_err(),
            Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
        ) {
            PrincipalRepositoryError::DuplicateName {
                name: domain.name().as_str().to_owned(),
            }
        } else {
            PrincipalRepositoryError::Database(error)
        }
    })?;
    Ok(())
}

fn map_stored_principal(
    principal_id: rutilus_domain::PrincipalId,
    model: &principal::Model,
) -> Result<Principal, PrincipalRepositoryError> {
    let name = PrincipalName::parse(&model.name)
        .map_err(StoredPrincipalError::InvalidName)
        .map_err(|source| corrupt(principal_id, source))?;
    let state = model
        .state
        .parse::<PrincipalState>()
        .map_err(StoredPrincipalError::InvalidState)
        .map_err(|source| corrupt(principal_id, source))?;
    Principal::try_from_parts(
        principal_id,
        name,
        state,
        model.created_at,
        model.updated_at,
    )
    .map_err(StoredPrincipalError::InvalidTimeline)
    .map_err(|source| corrupt(principal_id, source))
}

fn map_stored_assignment(
    principal_id: rutilus_domain::PrincipalId,
    model: &role_assignment::Model,
) -> Result<RoleAssignment, PrincipalRepositoryError> {
    let role = model
        .role
        .parse::<Role>()
        .map_err(StoredPrincipalError::InvalidRole)
        .map_err(|source| corrupt_assignment(principal_id, source))?;
    Ok(RoleAssignment::new(
        principal_id,
        role,
        model
            .assigned_by
            .map(rutilus_domain::PrincipalId::from_uuid),
        model.assigned_at,
    ))
}

fn corrupt(
    principal_id: rutilus_domain::PrincipalId,
    source: StoredPrincipalError,
) -> PrincipalRepositoryError {
    PrincipalRepositoryError::Corrupt {
        principal_id,
        source,
    }
}

fn corrupt_assignment(
    principal_id: rutilus_domain::PrincipalId,
    source: StoredPrincipalError,
) -> PrincipalRepositoryError {
    PrincipalRepositoryError::CorruptAssignment {
        principal_id,
        source,
    }
}

/// A controlled failure while creating, reading, or changing principals.
#[derive(Debug, Error)]
pub enum PrincipalRepositoryError {
    #[error("principal write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("principal {principal_id} was not found")]
    NotFound {
        principal_id: rutilus_domain::PrincipalId,
    },
    #[error("a principal named {name} already exists")]
    DuplicateName { name: String },
    #[error("stored principal {principal_id} is invalid: {source}")]
    Corrupt {
        principal_id: rutilus_domain::PrincipalId,
        #[source]
        source: StoredPrincipalError,
    },
    #[error("stored role assignment for {principal_id} is invalid: {source}")]
    CorruptAssignment {
        principal_id: rutilus_domain::PrincipalId,
        #[source]
        source: StoredPrincipalError,
    },
    #[error("principal database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted principal data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredPrincipalError {
    #[error("principal name is invalid: {0}")]
    InvalidName(#[source] rutilus_domain::PrincipalNameError),
    #[error("principal state code is invalid: {0}")]
    InvalidState(#[source] rutilus_domain::PrincipalStateParseError),
    #[error("principal timeline is invalid: {0}")]
    InvalidTimeline(#[source] PrincipalRestoreError),
    #[error("role code is invalid: {0}")]
    InvalidRole(#[source] rutilus_domain::RoleParseError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::PrincipalId;
    use rutilus_entity::{principal, role_assignment};
    use sea_orm::{EntityTrait, Set};
    use time::Duration;
    use uuid::Uuid;

    use super::*;
    use crate::SqliteStore;

    #[tokio::test]
    async fn creates_finds_and_lists_principals() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let admin = Principal::new(
            PrincipalId::generate(),
            PrincipalName::parse("Admin")?,
            base,
        );
        let operator = Principal::new(
            PrincipalId::generate(),
            PrincipalName::parse("operator")?,
            base + Duration::SECOND,
        );
        store.create_principal(&admin).await?;
        store.create_principal(&operator).await?;

        // Names are normalized at the boundary: the stored name is the
        // lowercase form the caller constructed.
        assert_eq!(admin.name().as_str(), "admin");
        assert_eq!(store.find_principal(admin.id()).await?, Some(admin.clone()));
        assert_eq!(
            store.find_principal_by_name(&admin.name().clone()).await?,
            Some(admin.clone())
        );
        assert_eq!(
            store.list_principals().await?,
            vec![admin.clone(), operator.clone()],
            "listing must return every principal in creation order"
        );
        assert!(
            store
                .find_principal(PrincipalId::generate())
                .await?
                .is_none()
        );
        assert!(
            store
                .find_principal_by_name(&PrincipalName::parse("missing")?)
                .await?
                .is_none()
        );
        assert_eq!(store.list_principals().await?.len(), 2);

        // The unique normalized name refuses a duplicate atomically.
        assert!(matches!(
            store
                .create_principal(&Principal::new(
                    PrincipalId::generate(),
                    PrincipalName::parse("admin")?,
                    base,
                ))
                .await,
            Err(PrincipalRepositoryError::DuplicateName { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn state_transitions_round_trip_and_reject_unknown_ids() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let principal = Principal::new(
            PrincipalId::generate(),
            PrincipalName::parse("admin")?,
            created_at,
        );
        store.create_principal(&principal).await?;
        let principal_id = principal.id();

        let disabled_at = created_at + Duration::SECOND;
        store
            .set_principal_state(principal_id, PrincipalState::Disabled, disabled_at)
            .await?;
        let disabled = store
            .find_principal(principal_id)
            .await?
            .ok_or("stored principal is missing")?;
        assert_eq!(disabled.state(), PrincipalState::Disabled);
        assert_eq!(disabled.updated_at(), disabled_at);

        let enabled_at = disabled_at + Duration::SECOND;
        store
            .set_principal_state(principal_id, PrincipalState::Enabled, enabled_at)
            .await?;
        let enabled = store
            .find_principal(principal_id)
            .await?
            .ok_or("stored principal is missing")?;
        assert_eq!(enabled.state(), PrincipalState::Enabled);
        assert_eq!(enabled.updated_at(), enabled_at);

        assert!(matches!(
            store
                .set_principal_state(
                    PrincipalId::generate(),
                    PrincipalState::Disabled,
                    enabled_at
                )
                .await,
            Err(PrincipalRepositoryError::NotFound { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn role_assignments_replace_and_preserve_the_assigner() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let root = Principal::new(PrincipalId::generate(), PrincipalName::parse("root")?, base);
        let admin = Principal::new(
            PrincipalId::generate(),
            PrincipalName::parse("admin")?,
            base + Duration::SECOND,
        );
        store.create_principal(&root).await?;
        store.create_principal(&admin).await?;

        let first = RoleAssignment::new(admin.id(), Role::Operator, Some(root.id()), base);
        store.assign_role(&first).await?;
        assert_eq!(store.find_role_assignment(admin.id()).await?, Some(first));

        // One role per principal: assigning again replaces the row.
        let second = RoleAssignment::new(
            admin.id(),
            Role::Administrator,
            Some(root.id()),
            base + Duration::SECOND,
        );
        store.assign_role(&second).await?;
        assert_eq!(
            store.find_role_assignment(admin.id()).await?,
            Some(second.clone())
        );
        assert_eq!(store.list_role_assignments().await?, vec![second.clone()]);

        // The schema preserves the assignment fact when the assigner is
        // deleted: the assigner reference is nulled, the role stays.
        principal::Entity::delete_by_id(root.id().into_uuid())
            .exec(&store.database)
            .await?;
        let stored = store
            .find_role_assignment(admin.id())
            .await?
            .ok_or("the assignment must survive its assigner")?;
        assert_eq!(stored.role(), Role::Administrator);
        assert_eq!(stored.assigned_by(), None);

        // A role code no product build can classify is refused at the
        // database (the role CHECK); the refused write changes nothing, so
        // the listing still returns exactly the valid assignment.
        let invalid = role_assignment::ActiveModel {
            principal_id: Set(Uuid::now_v7()),
            role: Set(String::from("superuser")),
            assigned_by: Set(None),
            assigned_at: Set(base),
        }
        .insert(&store.database)
        .await;
        assert!(invalid.is_err());
        assert_eq!(
            store.list_role_assignments().await?,
            vec![RoleAssignment::new(
                admin.id(),
                Role::Administrator,
                None,
                base + Duration::SECOND,
            )]
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_stored_principal_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        let principal_id = PrincipalId::generate();

        // A state code no product build can classify is refused at the
        // database (the CHECK constraint); rehydration would refuse it as
        // corrupt.
        let invalid_state = principal::ActiveModel {
            id: Set(principal_id.into_uuid()),
            name: Set(String::from("admin")),
            state: Set(String::from("banned")),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&store.database)
        .await;
        assert!(invalid_state.is_err());

        // An inverted timeline written directly is refused on read.
        principal::ActiveModel {
            id: Set(principal_id.into_uuid()),
            name: Set(String::from("admin")),
            state: Set(String::from("enabled")),
            created_at: Set(now),
            updated_at: Set(now - Duration::SECOND),
        }
        .insert(&store.database)
        .await?;
        assert!(matches!(
            store.find_principal(principal_id).await,
            Err(PrincipalRepositoryError::Corrupt {
                principal_id: id,
                source: StoredPrincipalError::InvalidTimeline(_),
            }) if id == principal_id
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
