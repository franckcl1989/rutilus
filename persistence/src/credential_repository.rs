use rutilus_domain::{
    Credential, CredentialId, CredentialName, CredentialNameError, CredentialTimelineError,
    CredentialUsername, CredentialUsernameError, CredentialVersionId,
};
use rutilus_entity::{credential, credential_version};
use rutilus_security::{
    CREDENTIAL_NONCE_LENGTH, CredentialProtectionError, ProtectedCredentialVersion,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, QuerySelect, Set, SqlErr, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

/// A validated credential and its first protected, immutable version.
#[derive(Clone, Debug)]
pub struct NewCredential {
    name: CredentialName,
    username: CredentialUsername,
    protected_secret: ProtectedCredentialVersion,
}

impl NewCredential {
    /// Combines validated metadata with identity-bound protected ciphertext.
    #[must_use]
    pub fn new(
        name: CredentialName,
        username: CredentialUsername,
        protected_secret: ProtectedCredentialVersion,
    ) -> Self {
        Self {
            name,
            username,
            protected_secret,
        }
    }
}

/// Secret-free metadata paired with its active authenticated ciphertext.
#[derive(Clone, Debug)]
pub struct StoredCredential {
    metadata: Credential,
    protected_secret: ProtectedCredentialVersion,
}

impl StoredCredential {
    /// Borrows secret-free credential metadata.
    #[must_use]
    pub const fn metadata(&self) -> &Credential {
        &self.metadata
    }

    /// Borrows the active authenticated ciphertext without exposing plaintext.
    #[must_use]
    pub const fn protected_secret(&self) -> &ProtectedCredentialVersion {
        &self.protected_secret
    }

    /// Separates domain metadata from its active authenticated ciphertext.
    #[must_use]
    pub fn into_parts(self) -> (Credential, ProtectedCredentialVersion) {
        (self.metadata, self.protected_secret)
    }
}

impl SqliteStore {
    /// Atomically creates credential metadata and its first encrypted version.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialRepositoryError`] when write coordination, encryption
    /// metadata, a uniqueness constraint, or a database transaction fails.
    pub async fn create_credential(
        &self,
        new_credential: NewCredential,
    ) -> Result<Credential, CredentialRepositoryError> {
        let NewCredential {
            name,
            username,
            protected_secret,
        } = new_credential;
        let (credential_id, version_id, nonce, ciphertext) = protected_secret.into_parts();
        let now = OffsetDateTime::now_utc();
        let domain = Credential::try_new(
            credential_id,
            name.clone(),
            username.clone(),
            version_id,
            now,
            now,
        )
        .map_err(CredentialRepositoryError::InvalidTimeline)?;
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CredentialRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CredentialRepositoryError::Database)?;

        let persisted = credential::ActiveModel {
            id: Set(credential_id.into_uuid()),
            name: Set(name.to_string()),
            username: Set(username.to_string()),
            active_version_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&transaction)
        .await
        .map_err(map_credential_insert_error)?;
        credential_version::ActiveModel {
            id: Set(version_id.into_uuid()),
            credential_id: Set(credential_id.into_uuid()),
            encrypted_secret: Set(ciphertext),
            nonce: Set(nonce.to_vec()),
            created_at: Set(now),
        }
        .insert(&transaction)
        .await
        .map_err(map_version_insert_error)?;

        let mut persisted = persisted.into_active_model();
        persisted.active_version_id = Set(Some(version_id.into_uuid()));
        persisted
            .update(&transaction)
            .await
            .map_err(CredentialRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(CredentialRepositoryError::Database)?;

        Ok(domain)
    }

    /// Finds secret-free credential metadata by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialRepositoryError`] when the query fails or persisted
    /// metadata violates a domain invariant.
    pub async fn find_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<Credential>, CredentialRepositoryError> {
        let model = credential::Entity::find_by_id(credential_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(CredentialRepositoryError::Database)?;
        model
            .map(|model| map_credential_model(&model))
            .transpose()
            .map_err(|source| CredentialRepositoryError::Corrupt {
                credential_id,
                source,
            })
    }

    /// Finds metadata and the active authenticated ciphertext by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialRepositoryError`] when the query fails or stored
    /// metadata, version linkage, nonce, or ciphertext is invalid.
    pub async fn find_active_credential(
        &self,
        credential_id: CredentialId,
    ) -> Result<Option<StoredCredential>, CredentialRepositoryError> {
        load_active_credential(&self.database, credential_id).await
    }

    /// Lists secret-free credential metadata in creation order, bounded to at
    /// most `limit` credentials.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialRepositoryError::InvalidLimit`] for a zero limit,
    /// [`CredentialRepositoryError::Database`] when the query fails, or
    /// [`CredentialRepositoryError::Corrupt`] when persisted metadata violates
    /// a domain invariant.
    pub async fn list_credentials(
        &self,
        limit: u64,
    ) -> Result<Vec<Credential>, CredentialRepositoryError> {
        if limit == 0 {
            return Err(CredentialRepositoryError::InvalidLimit { limit });
        }
        let models = credential::Entity::find()
            .order_by_asc(credential::Column::CreatedAt)
            .limit(limit)
            .all(&self.database)
            .await
            .map_err(CredentialRepositoryError::Database)?;
        let mut credentials = Vec::with_capacity(models.len());
        for model in &models {
            credentials.push(map_credential_model(model).map_err(|source| {
                CredentialRepositoryError::Corrupt {
                    credential_id: CredentialId::from_uuid(model.id),
                    source,
                }
            })?);
        }
        Ok(credentials)
    }

    /// Appends an immutable encrypted version and atomically makes it active.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialRepositoryError`] when the credential is missing or
    /// corrupt, the version identity already exists, write coordination fails,
    /// or the database transaction cannot commit.
    pub async fn rotate_credential(
        &self,
        protected_secret: ProtectedCredentialVersion,
    ) -> Result<StoredCredential, CredentialRepositoryError> {
        let credential_id = protected_secret.credential_id();
        let version_id = protected_secret.version_id();
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CredentialRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CredentialRepositoryError::Database)?;
        let existing = load_active_credential(&transaction, credential_id)
            .await?
            .ok_or(CredentialRepositoryError::NotFound { credential_id })?;
        let now = OffsetDateTime::now_utc().max(existing.metadata.updated_at());
        let updated = Credential::try_new(
            credential_id,
            existing.metadata.name().clone(),
            existing.metadata.username().clone(),
            version_id,
            existing.metadata.created_at(),
            now,
        )
        .map_err(CredentialRepositoryError::InvalidTimeline)?;
        let persisted_secret = protected_secret.clone();
        let (_, _, nonce, ciphertext) = protected_secret.into_parts();

        credential_version::ActiveModel {
            id: Set(version_id.into_uuid()),
            credential_id: Set(credential_id.into_uuid()),
            encrypted_secret: Set(ciphertext),
            nonce: Set(nonce.to_vec()),
            created_at: Set(now),
        }
        .insert(&transaction)
        .await
        .map_err(map_version_insert_error)?;

        let model = credential::Entity::find_by_id(credential_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CredentialRepositoryError::Database)?
            .ok_or(CredentialRepositoryError::NotFound { credential_id })?;
        let mut model = model.into_active_model();
        model.active_version_id = Set(Some(version_id.into_uuid()));
        model.updated_at = Set(now);
        model
            .update(&transaction)
            .await
            .map_err(CredentialRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(CredentialRepositoryError::Database)?;

        Ok(StoredCredential {
            metadata: updated,
            protected_secret: persisted_secret,
        })
    }
}

async fn load_active_credential<C>(
    database: &C,
    credential_id: CredentialId,
) -> Result<Option<StoredCredential>, CredentialRepositoryError>
where
    C: ConnectionTrait,
{
    let Some(model) = credential::Entity::find_by_id(credential_id.into_uuid())
        .one(database)
        .await
        .map_err(CredentialRepositoryError::Database)?
    else {
        return Ok(None);
    };
    let metadata =
        map_credential_model(&model).map_err(|source| CredentialRepositoryError::Corrupt {
            credential_id,
            source,
        })?;
    let version_id = metadata.active_version_id();
    let version = credential_version::Entity::find_by_id(version_id.into_uuid())
        .filter(credential_version::Column::CredentialId.eq(credential_id.into_uuid()))
        .one(database)
        .await
        .map_err(CredentialRepositoryError::Database)?
        .ok_or_else(|| CredentialRepositoryError::Corrupt {
            credential_id,
            source: StoredCredentialError::ActiveVersionMissing { version_id },
        })?;
    let actual_nonce_length = version.nonce.len();
    let nonce = version
        .nonce
        .try_into()
        .map_err(|_| CredentialRepositoryError::Corrupt {
            credential_id,
            source: StoredCredentialError::InvalidNonceLength {
                actual: actual_nonce_length,
                expected: CREDENTIAL_NONCE_LENGTH,
            },
        })?;
    let protected_secret = ProtectedCredentialVersion::from_parts(
        credential_id,
        version_id,
        nonce,
        version.encrypted_secret,
    )
    .map_err(|source| CredentialRepositoryError::Corrupt {
        credential_id,
        source: StoredCredentialError::InvalidCiphertext(source),
    })?;

    Ok(Some(StoredCredential {
        metadata,
        protected_secret,
    }))
}

fn map_credential_model(model: &credential::Model) -> Result<Credential, StoredCredentialError> {
    let name = CredentialName::parse(&model.name).map_err(StoredCredentialError::InvalidName)?;
    let username = CredentialUsername::parse(&model.username)
        .map_err(StoredCredentialError::InvalidUsername)?;
    let active_version_id = model
        .active_version_id
        .map(CredentialVersionId::from_uuid)
        .ok_or(StoredCredentialError::ActiveVersionNotSelected)?;
    Credential::try_new(
        CredentialId::from_uuid(model.id),
        name,
        username,
        active_version_id,
        model.created_at,
        model.updated_at,
    )
    .map_err(StoredCredentialError::InvalidTimeline)
}

fn map_credential_insert_error(error: DbErr) -> CredentialRepositoryError {
    if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        CredentialRepositoryError::AlreadyExists
    } else {
        CredentialRepositoryError::Database(error)
    }
}

fn map_version_insert_error(error: DbErr) -> CredentialRepositoryError {
    if matches!(error.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        CredentialRepositoryError::VersionAlreadyExists
    } else {
        CredentialRepositoryError::Database(error)
    }
}

/// A controlled failure while creating, reading, or rotating credentials.
#[derive(Debug, Error)]
pub enum CredentialRepositoryError {
    #[error("credential write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("credential identity or name already exists")]
    AlreadyExists,
    #[error("credential version identity already exists")]
    VersionAlreadyExists,
    #[error("credential inventory limit must be positive, not {limit}")]
    InvalidLimit { limit: u64 },
    #[error("credential {credential_id} was not found")]
    NotFound { credential_id: CredentialId },
    #[error("credential timeline is invalid: {0}")]
    InvalidTimeline(#[source] CredentialTimelineError),
    #[error("stored credential {credential_id} is invalid: {source}")]
    Corrupt {
        credential_id: CredentialId,
        #[source]
        source: StoredCredentialError,
    },
    #[error("credential database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted credential data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredCredentialError {
    #[error("credential name is invalid: {0}")]
    InvalidName(#[source] CredentialNameError),
    #[error("credential username is invalid: {0}")]
    InvalidUsername(#[source] CredentialUsernameError),
    #[error("credential has no active encrypted version")]
    ActiveVersionNotSelected,
    #[error("active credential version {version_id} is missing")]
    ActiveVersionMissing { version_id: CredentialVersionId },
    #[error("credential timeline is invalid: {0}")]
    InvalidTimeline(#[source] CredentialTimelineError),
    #[error("credential nonce has {actual} bytes; expected {expected}")]
    InvalidNonceLength { actual: usize, expected: usize },
    #[error("credential ciphertext is invalid: {0}")]
    InvalidCiphertext(#[source] CredentialProtectionError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_entity::credential_version;
    use rutilus_security::{MasterKey, decrypt_credential, encrypt_credential};
    use sea_orm::{ActiveModelTrait, EntityTrait, IntoActiveModel, Set};
    use secrecy::{ExposeSecret, SecretString};

    use super::*;

    #[tokio::test]
    async fn creates_loads_and_rotates_encrypted_credentials() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let key = MasterKey::from_boxed_bytes(Box::new([0x41; 32]));
        let credential_id = CredentialId::generate();
        let first_version_id = CredentialVersionId::generate();
        let first_secret: SecretString = String::from("first secret").into();
        let first_encrypted =
            encrypt_credential(&key, credential_id, first_version_id, &first_secret)?;

        let created = store
            .create_credential(NewCredential::new(
                CredentialName::parse("Lab administrator")?,
                CredentialUsername::parse("administrator")?,
                first_encrypted,
            ))
            .await?;
        assert_eq!(created.id(), credential_id);
        assert_eq!(created.active_version_id(), first_version_id);
        assert_eq!(
            store
                .find_credential(credential_id)
                .await?
                .ok_or("created credential metadata is missing")?,
            created
        );
        assert!(
            store
                .find_credential(CredentialId::generate())
                .await?
                .is_none()
        );

        let loaded = store
            .find_active_credential(credential_id)
            .await?
            .ok_or("created credential is missing")?;
        let decrypted = decrypt_credential(&key, loaded.protected_secret())?;
        assert_eq!(decrypted.expose_secret(), "first secret");

        let second_version_id = CredentialVersionId::generate();
        let second_secret: SecretString = String::from("second secret").into();
        let second_encrypted =
            encrypt_credential(&key, credential_id, second_version_id, &second_secret)?;
        let rotated = store.rotate_credential(second_encrypted).await?;
        assert_eq!(rotated.metadata().active_version_id(), second_version_id);
        let decrypted = decrypt_credential(&key, rotated.protected_secret())?;
        assert_eq!(decrypted.expose_secret(), "second secret");
        assert!(
            credential_version::Entity::find_by_id(first_version_id.into_uuid())
                .one(&store.database)
                .await?
                .is_some()
        );

        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn duplicate_create_rolls_back_without_an_orphan_version() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let key = MasterKey::from_boxed_bytes(Box::new([0x42; 32]));
        let first_id = CredentialId::generate();
        let first_version = CredentialVersionId::generate();
        let secret: SecretString = String::from("secret").into();
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("duplicate label")?,
                CredentialUsername::parse("administrator")?,
                encrypt_credential(&key, first_id, first_version, &secret)?,
            ))
            .await?;

        let duplicate_id = CredentialId::generate();
        let duplicate_version = CredentialVersionId::generate();
        let duplicate = store
            .create_credential(NewCredential::new(
                CredentialName::parse("duplicate label")?,
                CredentialUsername::parse("operator")?,
                encrypt_credential(&key, duplicate_id, duplicate_version, &secret)?,
            ))
            .await;
        assert!(matches!(
            duplicate,
            Err(CredentialRepositoryError::AlreadyExists)
        ));
        assert!(
            credential_version::Entity::find_by_id(duplicate_version.into_uuid())
                .one(&store.database)
                .await?
                .is_none()
        );

        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn missing_rotation_rolls_back_without_an_orphan_version() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let key = MasterKey::from_boxed_bytes(Box::new([0x44; 32]));
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let secret: SecretString = String::from("secret").into();
        let protected = encrypt_credential(&key, credential_id, version_id, &secret)?;

        let rotation = store.rotate_credential(protected).await;
        assert!(matches!(
            rotation,
            Err(CredentialRepositoryError::NotFound {
                credential_id: missing_id
            }) if missing_id == credential_id
        ));
        assert!(
            credential_version::Entity::find_by_id(version_id.into_uuid())
                .one(&store.database)
                .await?
                .is_none()
        );

        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn reports_corrupt_persisted_nonce_without_exposing_ciphertext()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let key = MasterKey::from_boxed_bytes(Box::new([0x43; 32]));
        let credential_id = CredentialId::generate();
        let version_id = CredentialVersionId::generate();
        let secret: SecretString = String::from("secret").into();
        store
            .create_credential(NewCredential::new(
                CredentialName::parse("corruption test")?,
                CredentialUsername::parse("administrator")?,
                encrypt_credential(&key, credential_id, version_id, &secret)?,
            ))
            .await?;

        let model = credential_version::Entity::find_by_id(version_id.into_uuid())
            .one(&store.database)
            .await?
            .ok_or("created version is missing")?;
        let mut model = model.into_active_model();
        model.nonce = Set(vec![0_u8; 3]);
        model.update(&store.database).await?;

        let loaded = store.find_active_credential(credential_id).await;
        assert!(matches!(
            loaded,
            Err(CredentialRepositoryError::Corrupt {
                source: StoredCredentialError::InvalidNonceLength {
                    actual: 3,
                    expected: CREDENTIAL_NONCE_LENGTH
                },
                ..
            })
        ));

        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn lists_secret_free_credentials_in_creation_order_within_a_positive_limit()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let key = MasterKey::from_boxed_bytes(Box::new([0x45; 32]));
        let secret: SecretString = String::from("list secret").into();
        for (name, username) in [
            ("Alpha", "administrator"),
            ("Beta", "operator"),
            ("Gamma", "auditor"),
        ] {
            store
                .create_credential(NewCredential::new(
                    CredentialName::parse(name)?,
                    CredentialUsername::parse(username)?,
                    encrypt_credential(
                        &key,
                        CredentialId::generate(),
                        CredentialVersionId::generate(),
                        &secret,
                    )?,
                ))
                .await?;
        }

        let all = store.list_credentials(10).await?;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].name().as_str(), "Alpha");
        assert_eq!(all[1].name().as_str(), "Beta");
        assert_eq!(all[2].name().as_str(), "Gamma");

        let bounded = store.list_credentials(2).await?;
        assert_eq!(bounded.len(), 2);
        assert_eq!(bounded[0].name().as_str(), "Alpha");
        assert_eq!(bounded[1].name().as_str(), "Beta");

        assert!(matches!(
            store.list_credentials(0).await,
            Err(CredentialRepositoryError::InvalidLimit { limit: 0 })
        ));
        store.close().await?;
        Ok(())
    }
}
