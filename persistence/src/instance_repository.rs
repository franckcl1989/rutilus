use rutilus_domain::{InstanceId, InstanceKind, InstanceKindParseError, SiteInstance};
use rutilus_entity::instance;
use sea_orm::{ActiveModelTrait, DbErr, EntityTrait, QueryOrder, Set};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one registered deployment identity (design D6).
    ///
    /// # Errors
    ///
    /// Returns [`InstanceRepositoryError`] when write coordination fails or
    /// the insert fails.
    pub async fn create_instance(
        &self,
        site: &SiteInstance,
    ) -> Result<(), InstanceRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(InstanceRepositoryError::Coordinate)?;
        instance::ActiveModel {
            id: Set(site.id().into_uuid()),
            display_name: Set(site.display_name().to_owned()),
            instance_kind: Set(site.kind().as_str().to_owned()),
            created_at: Set(site.created_at()),
        }
        .insert(&self.database)
        .await
        .map_err(InstanceRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one registered deployment by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`InstanceRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_instance(
        &self,
        instance_id: InstanceId,
    ) -> Result<Option<SiteInstance>, InstanceRepositoryError> {
        let Some(model) = instance::Entity::find_by_id(instance_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(InstanceRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_instance(instance_id, &model).map(Some)
    }

    /// Lists every registered deployment in creation order.
    ///
    /// On the center side this is the registered-site listing (D6); on the
    /// site side it is the site's single identity row. Each row carries its
    /// kind, so the caller filters by deployment semantics.
    ///
    /// # Errors
    ///
    /// Returns [`InstanceRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants.
    pub async fn list_instances(&self) -> Result<Vec<SiteInstance>, InstanceRepositoryError> {
        let models = instance::Entity::find()
            .order_by_asc(instance::Column::CreatedAt)
            .order_by_asc(instance::Column::Id)
            .all(&self.database)
            .await
            .map_err(InstanceRepositoryError::Database)?;
        models
            .iter()
            .map(|model| {
                let instance_id = InstanceId::from_uuid(model.id);
                map_stored_instance(instance_id, model)
            })
            .collect()
    }
}

fn map_stored_instance(
    instance_id: InstanceId,
    model: &instance::Model,
) -> Result<SiteInstance, InstanceRepositoryError> {
    let kind = model
        .instance_kind
        .parse::<InstanceKind>()
        .map_err(StoredInstanceError::InvalidKind)
        .map_err(|source| InstanceRepositoryError::Corrupt {
            instance_id,
            source,
        })?;
    Ok(SiteInstance::new(
        instance_id,
        model.display_name.clone(),
        kind,
        model.created_at,
    ))
}

/// A controlled failure while persisting or reading deployment identities.
#[derive(Debug, Error)]
pub enum InstanceRepositoryError {
    #[error("instance write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("stored instance {instance_id} is invalid: {source}")]
    Corrupt {
        instance_id: InstanceId,
        #[source]
        source: StoredInstanceError,
    },
    #[error("instance database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted instance data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredInstanceError {
    #[error("stored instance kind is invalid: {0}")]
    InvalidKind(#[source] InstanceKindParseError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{InstanceId, InstanceKind, SiteInstance};

    use crate::SqliteStore;

    fn site_instance(now: time::OffsetDateTime, kind: InstanceKind) -> SiteInstance {
        SiteInstance::new(InstanceId::generate(), String::from("Site One"), kind, now)
    }

    #[tokio::test]
    async fn instances_round_trip_through_the_store() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = time::OffsetDateTime::now_utc();

        let site = site_instance(now, InstanceKind::Site);
        let center = site_instance(now, InstanceKind::Center);
        store.create_instance(&site).await?;
        store.create_instance(&center).await?;

        assert_eq!(store.find_instance(site.id()).await?, Some(site.clone()));
        assert_eq!(
            store.find_instance(center.id()).await?,
            Some(center.clone())
        );
        assert_eq!(store.find_instance(InstanceId::generate()).await?, None);

        let listed = store.list_instances().await?;
        assert_eq!(listed.len(), 2);
        assert!(listed.contains(&site));
        assert!(listed.contains(&center));

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
