use base64::Engine as _;
use rutilus_domain::{
    BootstrapCode, BootstrapCodeError, BootstrapCodeId, PasswordCredential, PrincipalId, Session,
    TotpAuthenticator,
};
use rutilus_entity::bootstrap_code;
use rutilus_security::{MasterKey, encrypt_credential};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    PaginatorTrait, QueryFilter, Set, TransactionTrait,
};
use secrecy::ExposeSecret as _;
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one new unused bootstrap code (§16.2).
    ///
    /// Only the SHA-256 hash of the code is stored; the raw code is shown to
    /// the operator exactly once by the security crate.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapRepositoryError`] when write coordination fails or
    /// the transaction cannot commit.
    pub async fn create_bootstrap_code(
        &self,
        code: &BootstrapCode,
    ) -> Result<(), BootstrapRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(BootstrapRepositoryError::Coordinate)?;
        bootstrap_code::ActiveModel {
            id: Set(code.id().into_uuid()),
            code_hash: Set(code.code_hash().to_vec()),
            created_at: Set(code.created_at()),
            used_at: Set(code.used_at()),
            used_by: Set(code.used_by().map(PrincipalId::into_uuid)),
        }
        .insert(&self.database)
        .await
        .map_err(BootstrapRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one bootstrap code by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_bootstrap_code(
        &self,
        code_id: BootstrapCodeId,
    ) -> Result<Option<BootstrapCode>, BootstrapRepositoryError> {
        let Some(model) = bootstrap_code::Entity::find_by_id(code_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(BootstrapRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_code(code_id, &model).map(Some)
    }

    /// Reads one bootstrap code by the SHA-256 hash of the presented code.
    ///
    /// The code hash is the claim lookup key: the caller hashes the
    /// presented code and looks the row up by that hash, so a leaked
    /// database never yields a usable claim secret.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_bootstrap_code_by_hash(
        &self,
        code_hash: &[u8; 32],
    ) -> Result<Option<BootstrapCode>, BootstrapRepositoryError> {
        let Some(model) = bootstrap_code::Entity::find()
            .filter(bootstrap_code::Column::CodeHash.eq(code_hash.to_vec()))
            .one(&self.database)
            .await
            .map_err(BootstrapRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_code(BootstrapCodeId::from_uuid(model.id), &model).map(Some)
    }

    /// Reports whether any unconsumed bootstrap code exists.
    ///
    /// This is the first-startup gate of the sign-in policy: while an unused
    /// code exists the initial claim has not happened, and the loopback
    /// console serves without a session (§16.2 "首次启动生成一次性
    /// Bootstrap Code").
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapRepositoryError`] when the query fails.
    pub async fn has_unconsumed_bootstrap_code(&self) -> Result<bool, BootstrapRepositoryError> {
        let count = bootstrap_code::Entity::find()
            .filter(bootstrap_code::Column::UsedAt.is_null())
            .count(&self.database)
            .await
            .map_err(BootstrapRepositoryError::Database)?;
        Ok(count > 0)
    }

    /// Consumes one bootstrap code, enrolls the optional TOTP authenticator,
    /// and opens the first session in one transaction (§16.2 "首次启动生成
    /// 一次性 Bootstrap Code").
    ///
    /// The claim flow — verify the code is unused, mark it used for the
    /// principal, write the initial password credential, enroll the optional
    /// TOTP authenticator (whose secret is Master-Key encrypted before it
    /// reaches the database), and open the sign-in session — commits as a
    /// single transaction, so a code can never be half-consumed: the
    /// unused-check is re-read inside the transaction (never trusted from a
    /// stale read), which makes two racing consumers impossible; the
    /// credential, the authenticator, and the session can never exist
    /// without the code being consumed, and vice versa.
    ///
    /// # Errors
    ///
    /// Returns [`BootstrapRepositoryError::NotFound`] for an unknown code,
    /// [`BootstrapRepositoryError::AlreadyUsed`] when the code was already
    /// consumed, and [`BootstrapRepositoryError`] variants for coordination,
    /// encryption, or database failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn consume_bootstrap_code(
        &self,
        master_key: &MasterKey,
        code_id: BootstrapCodeId,
        used_by: PrincipalId,
        password: &PasswordCredential,
        authenticator: Option<&TotpAuthenticator>,
        session: &Session,
        consumed_at: time::OffsetDateTime,
    ) -> Result<(), BootstrapRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(BootstrapRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(BootstrapRepositoryError::Database)?;
        let model = bootstrap_code::Entity::find_by_id(code_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(BootstrapRepositoryError::Database)?
            .ok_or(BootstrapRepositoryError::NotFound { code_id })?;
        if model.used_at.is_some() {
            return Err(BootstrapRepositoryError::AlreadyUsed { code_id });
        }
        let mut active = model.into_active_model();
        active.used_at = Set(Some(consumed_at));
        active.used_by = Set(Some(used_by.into_uuid()));
        active
            .update(&transaction)
            .await
            .map_err(BootstrapRepositoryError::Database)?;
        insert_password_credential(&transaction, password).await?;
        if let Some(authenticator) = authenticator {
            insert_authenticator(&transaction, master_key, authenticator).await?;
        }
        insert_session(&transaction, session).await?;
        transaction
            .commit()
            .await
            .map_err(BootstrapRepositoryError::Database)
    }
}

async fn insert_password_credential<C>(
    database: &C,
    domain: &PasswordCredential,
) -> Result<(), BootstrapRepositoryError>
where
    C: ConnectionTrait,
{
    rutilus_entity::password_credential::ActiveModel {
        principal_id: Set(domain.principal_id().into_uuid()),
        hash_format: Set(rutilus_domain::ARGON2ID_FORMAT.to_owned()),
        salt: Set(domain.hash().salt().to_vec()),
        hash: Set(domain.hash().hash().to_vec()),
        changed_at: Set(domain.changed_at()),
    }
    .insert(database)
    .await
    .map_err(BootstrapRepositoryError::Database)?;
    Ok(())
}

/// Persists the optional TOTP authenticator of a bootstrap claim with its
/// Master-Key-encrypted secret — the same nonce-and-ciphertext format the
/// TOTP repository writes, so the read path decrypts it identically.
async fn insert_authenticator<C>(
    database: &C,
    master_key: &MasterKey,
    domain: &TotpAuthenticator,
) -> Result<(), BootstrapRepositoryError>
where
    C: ConnectionTrait,
{
    let protected = encrypt_credential(
        master_key,
        rutilus_domain::CredentialId::from_uuid(domain.id().into_uuid()),
        rutilus_domain::CredentialVersionId::from_uuid(domain.id().into_uuid()),
        &base64::engine::general_purpose::STANDARD
            .encode(domain.secret().expose_secret())
            .into(),
    )
    .map_err(BootstrapRepositoryError::Protect)?;
    let (_, _, nonce, ciphertext) = protected.into_parts();
    let mut stored_secret =
        Vec::with_capacity(rutilus_security::CREDENTIAL_NONCE_LENGTH + ciphertext.len());
    stored_secret.extend_from_slice(&nonce);
    stored_secret.extend_from_slice(&ciphertext);
    rutilus_entity::totp_authenticator::ActiveModel {
        id: Set(domain.id().into_uuid()),
        principal_id: Set(domain.principal_id().into_uuid()),
        secret: Set(stored_secret),
        state: Set(domain.state().as_str().to_owned()),
        algorithm: Set(String::from("sha1")),
        digits: Set(i64::from(rutilus_domain::TOTP_DIGITS)),
        period: Set(rutilus_domain::TOTP_PERIOD_SECONDS),
        created_at: Set(domain.created_at()),
        activated_at: Set(domain.activated_at()),
        last_used_step: Set(domain
            .last_used_step()
            .and_then(|step| i64::try_from(step).ok())),
    }
    .insert(database)
    .await
    .map_err(BootstrapRepositoryError::Database)?;
    Ok(())
}

async fn insert_session<C>(database: &C, domain: &Session) -> Result<(), BootstrapRepositoryError>
where
    C: ConnectionTrait,
{
    rutilus_entity::session::ActiveModel {
        id: Set(domain.id().into_uuid()),
        principal_id: Set(domain.principal_id().into_uuid()),
        token_hash: Set(domain.token_hash().to_vec()),
        csrf_hash: Set(domain.csrf_hash().to_vec()),
        created_at: Set(domain.created_at()),
        last_used_at: Set(domain.last_used_at()),
        expires_at: Set(domain.expires_at()),
        revoked_at: Set(domain.revoked_at()),
    }
    .insert(database)
    .await
    .map_err(BootstrapRepositoryError::Database)?;
    Ok(())
}

fn map_stored_code(
    code_id: BootstrapCodeId,
    model: &bootstrap_code::Model,
) -> Result<BootstrapCode, BootstrapRepositoryError> {
    BootstrapCode::try_from_parts(
        code_id,
        &model.code_hash,
        model.created_at,
        model.used_at,
        model.used_by.map(PrincipalId::from_uuid),
    )
    .map_err(StoredBootstrapCodeError::Invalid)
    .map_err(|source| BootstrapRepositoryError::Corrupt { code_id, source })
}

/// A controlled failure while creating or consuming bootstrap codes.
#[derive(Debug, Error)]
pub enum BootstrapRepositoryError {
    #[error("bootstrap code write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("bootstrap code {code_id} was not found")]
    NotFound { code_id: BootstrapCodeId },
    #[error("bootstrap code {code_id} was already consumed")]
    AlreadyUsed { code_id: BootstrapCodeId },
    #[error("stored bootstrap code {code_id} is invalid: {source}")]
    Corrupt {
        code_id: BootstrapCodeId,
        #[source]
        source: StoredBootstrapCodeError,
    },
    #[error("TOTP secret could not be protected: {0}")]
    Protect(#[source] rutilus_security::CredentialProtectionError),
    #[error("bootstrap code database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted bootstrap code data cannot be mapped into valid product
/// types.
#[derive(Debug, Error)]
pub enum StoredBootstrapCodeError {
    #[error("stored bootstrap code is invalid: {0}")]
    Invalid(#[source] BootstrapCodeError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::SessionId;
    use rutilus_entity::session;
    use rutilus_security::MasterKey;
    use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
    use secrecy::SecretBox;
    use time::Duration;

    use super::*;
    use crate::SqliteStore;

    fn test_key() -> MasterKey {
        MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))
    }

    fn code_at(created_at: time::OffsetDateTime) -> BootstrapCode {
        BootstrapCode::new(BootstrapCodeId::generate(), [0x66; 32], created_at)
    }

    fn credential_for(
        principal_id: PrincipalId,
        changed_at: time::OffsetDateTime,
    ) -> Result<PasswordCredential, Box<dyn Error>> {
        let hash = rutilus_domain::Argon2IdHash::from_parts(&[0x11; 16], &[0x22; 32])?;
        Ok(PasswordCredential::try_from_parts(
            principal_id,
            hash,
            changed_at,
        )?)
    }

    fn session_for(principal_id: PrincipalId, created_at: time::OffsetDateTime) -> Session {
        Session::new(
            SessionId::generate(),
            principal_id,
            [0x33; 32],
            [0x44; 32],
            created_at,
            created_at + Duration::hours(8),
        )
    }

    #[tokio::test]
    async fn consume_marks_used_and_writes_credential_and_session_atomically()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let code = code_at(base);
        store.create_bootstrap_code(&code).await?;
        // The claiming principal exists before the consumption: the consume
        // transaction binds the code, the credential, and the session to it.
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse("admin")?,
            base,
        );
        store.create_principal(&principal).await?;
        let principal_id = principal.id();
        let credential = credential_for(principal_id, base)?;
        let session = session_for(principal_id, base);
        let consumed_at = base + Duration::MINUTE;

        store
            .consume_bootstrap_code(
                &test_key(),
                code.id(),
                principal_id,
                &credential,
                None,
                &session,
                consumed_at,
            )
            .await?;

        // The code reads back consumed by the principal.
        let stored_code = store
            .find_bootstrap_code(code.id())
            .await?
            .ok_or("stored bootstrap code is missing")?;
        assert_eq!(stored_code.used_at(), Some(consumed_at));
        assert_eq!(stored_code.used_by(), Some(principal_id));

        // The credential and the session landed with the consumption.
        let stored_credential =
            rutilus_entity::password_credential::Entity::find_by_id(principal_id.into_uuid())
                .one(&store.database)
                .await?
                .ok_or("the consumed credential is missing")?;
        assert_eq!(
            stored_credential.hash_format,
            rutilus_domain::ARGON2ID_FORMAT
        );
        assert_eq!(stored_credential.salt, vec![0x11; 16]);
        assert_eq!(stored_credential.hash, vec![0x22; 32]);
        let stored_session = session::Entity::find()
            .filter(session::Column::PrincipalId.eq(principal_id.into_uuid()))
            .one(&store.database)
            .await?
            .ok_or("the consumed session is missing")?;
        assert_eq!(stored_session.token_hash, vec![0x33; 32]);

        // A second consumption is refused: the code is one-time.
        assert!(matches!(
            store
                .consume_bootstrap_code(
                    &test_key(),
                    code.id(),
                    principal_id,
                    &credential,
                    None,
                    &session,
                    consumed_at + Duration::SECOND,
                )
                .await,
            Err(BootstrapRepositoryError::AlreadyUsed { .. })
        ));
        assert!(matches!(
            store
                .consume_bootstrap_code(
                    &test_key(),
                    BootstrapCodeId::generate(),
                    principal_id,
                    &credential,
                    None,
                    &session,
                    consumed_at,
                )
                .await,
            Err(BootstrapRepositoryError::NotFound { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn failed_consumption_rolls_back_the_whole_claim() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let code = code_at(base);
        store.create_bootstrap_code(&code).await?;
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse("admin")?,
            base,
        );
        store.create_principal(&principal).await?;
        let principal_id = principal.id();
        let credential = credential_for(principal_id, base)?;
        let consumed_at = base + Duration::MINUTE;

        // A session whose token hash is already taken forces the transaction
        // to fail after the code row was updated; the rollback must undo the
        // code consumption too, so the code stays consumable.
        let taken = session_for(principal_id, base);
        store.create_session(&taken).await?;
        let duplicate = Session::new(
            SessionId::generate(),
            principal_id,
            *taken.token_hash(),
            [0x44; 32],
            base,
            base + Duration::hours(8),
        );
        let result = store
            .consume_bootstrap_code(
                &test_key(),
                code.id(),
                principal_id,
                &credential,
                None,
                &duplicate,
                consumed_at,
            )
            .await;
        assert!(
            result.is_err(),
            "the duplicate token hash must fail the claim"
        );

        let stored_code = store
            .find_bootstrap_code(code.id())
            .await?
            .ok_or("stored bootstrap code is missing")?;
        assert_eq!(
            stored_code.used_at(),
            None,
            "a failed claim must leave the code consumable"
        );
        assert_eq!(
            rutilus_entity::password_credential::Entity::find_by_id(principal_id.into_uuid())
                .one(&store.database)
                .await?
                .map(|row| row.hash_format),
            None,
            "a failed claim must not write the credential"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn hash_lookup_and_unconsumed_gate_round_trip() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let code = code_at(base);
        store.create_bootstrap_code(&code).await?;

        assert_eq!(
            store.find_bootstrap_code_by_hash(code.code_hash()).await?,
            Some(code.clone())
        );
        assert!(
            store
                .find_bootstrap_code_by_hash(&[0xee; 32])
                .await?
                .is_none()
        );
        assert!(store.has_unconsumed_bootstrap_code().await?);

        // Consumption is the unconsumed gate: after the claim no code is
        // pending, exactly like the sign-in policy decides.
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse("admin")?,
            base,
        );
        store.create_principal(&principal).await?;
        let credential = credential_for(principal.id(), base)?;
        let session = session_for(principal.id(), base);
        store
            .consume_bootstrap_code(
                &test_key(),
                code.id(),
                principal.id(),
                &credential,
                None,
                &session,
                base,
            )
            .await?;
        assert!(!store.has_unconsumed_bootstrap_code().await?);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn claim_can_enroll_an_activated_totp_authenticator() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let code = code_at(base);
        store.create_bootstrap_code(&code).await?;
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse("admin")?,
            base,
        );
        store.create_principal(&principal).await?;
        let principal_id = principal.id();
        let credential = credential_for(principal_id, base)?;
        let session = session_for(principal_id, base);

        // The optional TOTP authenticator lands with the claim, its secret
        // stored Master-Key-encrypted (never the 20-byte plaintext). The
        // RFC 6238 appendix B SHA-1 vector activates the authenticator: the
        // ASCII RFC test secret at time 59 accepts code 287082.
        let mut authenticator = rutilus_domain::TotpAuthenticator::new(
            rutilus_domain::TotpAuthenticatorId::generate(),
            principal_id,
            SecretBox::new(Box::new(*b"12345678901234567890")),
            time::OffsetDateTime::from_unix_timestamp(0)?,
        );
        authenticator
            .activate("287082", time::OffsetDateTime::from_unix_timestamp(59)?)
            .map_err(|_| "activation code must verify")?;
        store
            .consume_bootstrap_code(
                &test_key(),
                code.id(),
                principal_id,
                &credential,
                Some(&authenticator),
                &session,
                base,
            )
            .await?;

        let stored = store
            .find_totp_authenticator(&test_key(), authenticator.id())
            .await?
            .ok_or("the claimed authenticator is missing")?;
        assert_eq!(stored, authenticator);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_stored_code_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let code_id = BootstrapCodeId::generate();
        let now = time::OffsetDateTime::now_utc();
        let invalid = bootstrap_code::ActiveModel {
            id: Set(code_id.into_uuid()),
            code_hash: Set(vec![0x66; 31]),
            created_at: Set(now),
            used_at: Set(None),
            used_by: Set(None),
        };
        invalid.insert(&store.database).await?;

        assert!(matches!(
            store.find_bootstrap_code(code_id).await,
            Err(BootstrapRepositoryError::Corrupt { .. })
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
