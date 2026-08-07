use rutilus_domain::{Argon2IdHash, PasswordCredential, PasswordCredentialError, PrincipalId};
use rutilus_entity::password_credential;
use sea_orm::{DbErr, EntityTrait, Set};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Reads the password credential of one principal (§16.2).
    ///
    /// The sign-in path loads the stored `argon2id-1` hash and lets the
    /// domain value object re-derive the comparison, so the plaintext
    /// password never reaches this layer.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordRepositoryError::Corrupt`] when the stored salt or
    /// hash does not match the `argon2id-1` format.
    pub async fn find_password_credential(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Option<PasswordCredential>, PasswordRepositoryError> {
        let Some(model) = password_credential::Entity::find_by_id(principal_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(PasswordRepositoryError::Database)?
        else {
            return Ok(None);
        };
        let hash = Argon2IdHash::from_parts(&model.salt, &model.hash)
            .map_err(StoredPasswordError::InvalidHashParts)
            .map_err(|source| corrupt(principal_id, source))?;
        PasswordCredential::try_from_parts(principal_id, hash, model.changed_at)
            .map_err(StoredPasswordError::InvalidHashParts)
            .map_err(|source| corrupt(principal_id, source))
            .map(Some)
    }

    /// Stores one principal's password credential (§16.2).
    ///
    /// The `principal_id` primary key makes the write a find-or-replace:
    /// one password per principal, and changing it writes a fresh row (a new
    /// salt and hash under `argon2id-1`), never an in-place derivation. The
    /// caller derives the hash; the salt and hash bytes are stored as their
    /// own columns under the format code.
    ///
    /// # Errors
    ///
    /// Returns [`PasswordRepositoryError`] when write coordination fails or
    /// the transaction cannot commit.
    pub async fn save_password_credential(
        &self,
        credential: &PasswordCredential,
    ) -> Result<(), PasswordRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(PasswordRepositoryError::Coordinate)?;
        let active = password_credential::ActiveModel {
            principal_id: Set(credential.principal_id().into_uuid()),
            hash_format: Set(rutilus_domain::ARGON2ID_FORMAT.to_owned()),
            salt: Set(credential.hash().salt().to_vec()),
            hash: Set(credential.hash().hash().to_vec()),
            changed_at: Set(credential.changed_at()),
        };
        // One password per principal: the primary key conflict replaces the
        // stored credential, never duplicates it.
        password_credential::Entity::insert(active)
            .on_conflict(
                sea_orm::sea_query::OnConflict::columns([password_credential::Column::PrincipalId])
                    .update_columns([
                        password_credential::Column::HashFormat,
                        password_credential::Column::Salt,
                        password_credential::Column::Hash,
                        password_credential::Column::ChangedAt,
                    ])
                    .to_owned(),
            )
            .exec(&self.database)
            .await
            .map_err(PasswordRepositoryError::Database)?;
        Ok(())
    }
}

fn corrupt(principal_id: PrincipalId, source: StoredPasswordError) -> PasswordRepositoryError {
    PasswordRepositoryError::Corrupt {
        principal_id,
        source,
    }
}

/// A controlled failure while reading or storing password credentials.
#[derive(Debug, Error)]
pub enum PasswordRepositoryError {
    #[error("password write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("stored password credential for {principal_id} is invalid: {source}")]
    Corrupt {
        principal_id: PrincipalId,
        #[source]
        source: StoredPasswordError,
    },
    #[error("password database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted password data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredPasswordError {
    #[error("stored salt or hash does not match the argon2id-1 format: {0}")]
    InvalidHashParts(#[source] PasswordCredentialError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use sea_orm::ActiveModelTrait;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    #[tokio::test]
    async fn saves_and_loads_one_password_per_principal() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse("admin")?,
            base,
        );
        store.create_principal(&principal).await?;
        let principal_id = principal.id();

        assert!(
            store
                .find_password_credential(principal_id)
                .await?
                .is_none(),
            "a fresh principal has no password"
        );

        let first = credential_for(principal_id, base)?;
        store.save_password_credential(&first).await?;
        assert_eq!(
            store.find_password_credential(principal_id).await?,
            Some(first.clone())
        );

        // Changing the password replaces the row: the same principal reads
        // back the newer credential only.
        let second = credential_for(principal_id, base + Duration::SECOND)?;
        store.save_password_credential(&second).await?;
        let stored = store
            .find_password_credential(principal_id)
            .await?
            .ok_or("the stored credential is missing")?;
        assert_eq!(stored, second);
        assert_ne!(stored, first);
        assert_eq!(stored.changed_at(), base + Duration::SECOND);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_stored_password_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse("admin")?,
            now,
        );
        store.create_principal(&principal).await?;
        let principal_id = principal.id();

        // A truncated hash column is refused on read as corrupt; the format
        // CHECK refuses a foreign format at the database.
        password_credential::ActiveModel {
            principal_id: Set(principal_id.into_uuid()),
            hash_format: Set(rutilus_domain::ARGON2ID_FORMAT.to_owned()),
            salt: Set(vec![0x11; 16]),
            hash: Set(vec![0x22; 31]),
            changed_at: Set(now),
        }
        .insert(&store.database)
        .await?;
        assert!(matches!(
            store.find_password_credential(principal_id).await,
            Err(PasswordRepositoryError::Corrupt {
                source: StoredPasswordError::InvalidHashParts(_),
                ..
            })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    fn credential_for(
        principal_id: PrincipalId,
        changed_at: OffsetDateTime,
    ) -> Result<PasswordCredential, Box<dyn Error>> {
        let hash = Argon2IdHash::from_parts(&[0x11; 16], &[0x22; 32])?;
        Ok(PasswordCredential::try_from_parts(
            principal_id,
            hash,
            changed_at,
        )?)
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
