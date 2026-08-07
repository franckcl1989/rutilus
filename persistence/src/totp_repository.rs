use base64::Engine;
use rutilus_domain::{
    PrincipalId, TotpAuthenticator, TotpAuthenticatorId, TotpRestoreError, TotpState,
    TotpStateParseError,
};
use rutilus_entity::totp_authenticator;
use rutilus_security::{
    CREDENTIAL_NONCE_LENGTH, CredentialProtectionError, MasterKey, ProtectedCredentialVersion,
    decrypt_credential, encrypt_credential,
};
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, Condition, DbErr, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use secrecy::ExposeSecret;
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one new (provisioning) TOTP authenticator (§16.2).
    ///
    /// The 20-byte secret is wrapped with the instance master key before it
    /// reaches the database: [`encrypt_credential`] produces an
    /// XChaCha20-Poly1305 ciphertext bound to the authenticator's identity
    /// as associated data, and the `secret` column stores the 24-byte nonce
    /// concatenated with the ciphertext — the format the read path splits
    /// again. The plaintext secret never touches persistence; it only exists
    /// as the domain aggregate's zeroized `SecretBox` while this function
    /// runs.
    ///
    /// # Errors
    ///
    /// Returns [`TotpRepositoryError`] when write coordination fails, the
    /// secret cannot be encrypted, or the transaction cannot commit.
    pub async fn create_totp_authenticator(
        &self,
        master_key: &MasterKey,
        authenticator: &TotpAuthenticator,
    ) -> Result<(), TotpRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TotpRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(TotpRepositoryError::Database)?;
        insert_authenticator(&transaction, master_key, authenticator).await?;
        transaction
            .commit()
            .await
            .map_err(TotpRepositoryError::Database)
    }

    /// Reads one authenticator by stable identity.
    ///
    /// The stored nonce-and-ciphertext is decrypted with the instance master
    /// key and only then rehydrated through
    /// [`TotpAuthenticator::try_from_parts`] — whose exactly-20-bytes rule
    /// can never accept raw ciphertext.
    ///
    /// # Errors
    ///
    /// Returns [`TotpRepositoryError::Corrupt`] when the stored row violates
    /// domain invariants and [`TotpRepositoryError`] variants when the
    /// ciphertext cannot be authenticated or decrypted.
    pub async fn find_totp_authenticator(
        &self,
        master_key: &MasterKey,
        authenticator_id: TotpAuthenticatorId,
    ) -> Result<Option<TotpAuthenticator>, TotpRepositoryError> {
        let Some(model) = totp_authenticator::Entity::find_by_id(authenticator_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(TotpRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_authenticator(master_key, authenticator_id, &model).map(Some)
    }

    /// Lists one principal's authenticators in creation order.
    ///
    /// # Errors
    ///
    /// Returns [`TotpRepositoryError::Corrupt`] when any stored row violates
    /// domain invariants and [`TotpRepositoryError`] variants when a
    /// ciphertext cannot be authenticated or decrypted.
    pub async fn list_totp_authenticators(
        &self,
        master_key: &MasterKey,
        principal_id: PrincipalId,
    ) -> Result<Vec<TotpAuthenticator>, TotpRepositoryError> {
        let models = totp_authenticator::Entity::find()
            .filter(totp_authenticator::Column::PrincipalId.eq(principal_id.into_uuid()))
            .order_by_asc(totp_authenticator::Column::CreatedAt)
            .all(&self.database)
            .await
            .map_err(TotpRepositoryError::Database)?;
        let mut authenticators = Vec::with_capacity(models.len());
        for model in models {
            authenticators.push(map_stored_authenticator(
                master_key,
                TotpAuthenticatorId::from_uuid(model.id),
                &model,
            )?);
        }
        Ok(authenticators)
    }

    /// Records the successful activation of a provisioning authenticator.
    ///
    /// The write is the persistence half of [`TotpAuthenticator::activate`]:
    /// the caller has already verified the presented code through the domain
    /// aggregate, and this method persists the transition and the matched
    /// step atomically. The step update is conditional — it only moves the
    /// recorded step forward — so a racing activation cannot rewind it.
    ///
    /// # Errors
    ///
    /// Returns [`TotpRepositoryError::NotFound`] for an unknown id and
    /// [`TotpRepositoryError`] variants for coordination or database
    /// failures.
    pub async fn activate_totp_authenticator(
        &self,
        authenticator_id: TotpAuthenticatorId,
        activated_at: OffsetDateTime,
        step: u64,
    ) -> Result<(), TotpRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TotpRepositoryError::Coordinate)?;
        let step = i64::try_from(step)
            .map_err(|_| TotpRepositoryError::StepOutOfRange { authenticator_id })?;
        let result = totp_authenticator::Entity::update_many()
            .col_expr(
                totp_authenticator::Column::State,
                Expr::value(TotpState::Active.as_str()),
            )
            .col_expr(
                totp_authenticator::Column::ActivatedAt,
                Expr::value(activated_at),
            )
            .col_expr(totp_authenticator::Column::LastUsedStep, Expr::value(step))
            .filter(totp_authenticator::Column::Id.eq(authenticator_id.into_uuid()))
            // The conditional step guard: a racing sign-in that already
            // recorded a later step must not be rewound by a stale
            // activation.
            .filter(
                Condition::any()
                    .add(totp_authenticator::Column::LastUsedStep.is_null())
                    .add(totp_authenticator::Column::LastUsedStep.lt(step)),
            )
            .exec(&self.database)
            .await
            .map_err(TotpRepositoryError::Database)?;
        if result.rows_affected == 0 {
            return Err(TotpRepositoryError::NotFound { authenticator_id });
        }
        Ok(())
    }

    /// Records the step matched by a successful sign-in verification.
    ///
    /// The update is conditional — the step only moves forward — so two
    /// racing sign-ins that both verified the same code cannot both record
    /// it: the loser updates zero rows and is refused, which is the
    /// persistence half of the domain's anti-replay rule. Returns whether
    /// the step was recorded.
    ///
    /// # Errors
    ///
    /// Returns [`TotpRepositoryError::StepOutOfRange`] for an unrepresentable
    /// step and [`TotpRepositoryError`] variants for coordination or database
    /// failures.
    pub async fn record_totp_step(
        &self,
        authenticator_id: TotpAuthenticatorId,
        step: u64,
    ) -> Result<bool, TotpRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(TotpRepositoryError::Coordinate)?;
        let step = i64::try_from(step)
            .map_err(|_| TotpRepositoryError::StepOutOfRange { authenticator_id })?;
        let result = totp_authenticator::Entity::update_many()
            .col_expr(totp_authenticator::Column::LastUsedStep, Expr::value(step))
            .filter(totp_authenticator::Column::Id.eq(authenticator_id.into_uuid()))
            .filter(
                Condition::any()
                    .add(totp_authenticator::Column::LastUsedStep.is_null())
                    .add(totp_authenticator::Column::LastUsedStep.lt(step)),
            )
            .exec(&self.database)
            .await
            .map_err(TotpRepositoryError::Database)?;
        Ok(result.rows_affected == 1)
    }
}

async fn insert_authenticator<C>(
    database: &C,
    master_key: &MasterKey,
    domain: &TotpAuthenticator,
) -> Result<(), TotpRepositoryError>
where
    C: sea_orm::ConnectionTrait,
{
    let secret = domain.secret();
    // The plaintext never reaches the database: the secret column stores
    // the nonce-and-ciphertext blob the read path splits and decrypts. The
    // ciphertext is bound to the authenticator's identity as associated
    // data, so a blob copied to another row refuses to decrypt.
    let protected = encrypt_credential(
        master_key,
        rutilus_domain::CredentialId::from_uuid(domain.id().into_uuid()),
        rutilus_domain::CredentialVersionId::from_uuid(domain.id().into_uuid()),
        &base64::engine::general_purpose::STANDARD
            .encode(secret.expose_secret())
            .into(),
    )
    .map_err(TotpRepositoryError::Protect)?;
    let (_, _, nonce, ciphertext) = protected.into_parts();
    let mut stored_secret = Vec::with_capacity(CREDENTIAL_NONCE_LENGTH + ciphertext.len());
    stored_secret.extend_from_slice(&nonce);
    stored_secret.extend_from_slice(&ciphertext);
    totp_authenticator::ActiveModel {
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
    .map_err(TotpRepositoryError::Database)?;
    Ok(())
}

/// Rehydrates one authenticator row.
///
/// The stored nonce-and-ciphertext is split, authenticated, and decrypted
/// with the instance master key; the recovered 20-byte secret is passed to
/// [`TotpAuthenticator::try_from_parts`], whose exactly-20-bytes rule
/// matches the plaintext this slice writes.
fn map_stored_authenticator(
    master_key: &MasterKey,
    authenticator_id: TotpAuthenticatorId,
    model: &totp_authenticator::Model,
) -> Result<TotpAuthenticator, TotpRepositoryError> {
    let state = model
        .state
        .parse::<TotpState>()
        .map_err(StoredTotpError::InvalidState)
        .map_err(|source| corrupt(authenticator_id, source))?;
    let last_used_step = model
        .last_used_step
        .map(|step| u64::try_from(step).map_err(|_| StoredTotpError::InvalidStep))
        .transpose()
        .map_err(|source| corrupt(authenticator_id, source))?;
    let secret = decrypt_stored_secret(master_key, authenticator_id, &model.secret)
        .map_err(StoredTotpError::InvalidSecret)
        .map_err(|source| corrupt(authenticator_id, source))?;
    TotpAuthenticator::try_from_parts(
        authenticator_id,
        PrincipalId::from_uuid(model.principal_id),
        &secret,
        state,
        model.created_at,
        model.activated_at,
        last_used_step,
    )
    .map_err(StoredTotpError::InvalidShape)
    .map_err(|source| corrupt(authenticator_id, source))
}

/// Recovers the 20-byte plaintext secret from one stored nonce-and-ciphertext
/// blob.
///
/// The blob layout is the write path's mirror: the 24-byte nonce followed by
/// the ciphertext, authenticated and decrypted under the identity-bound
/// associated data, with the plaintext recovered from its base64 form (the
/// encoding that makes 20 arbitrary bytes a valid credential string).
fn decrypt_stored_secret(
    master_key: &MasterKey,
    authenticator_id: TotpAuthenticatorId,
    stored: &[u8],
) -> Result<Vec<u8>, CredentialProtectionError> {
    if stored.len() < CREDENTIAL_NONCE_LENGTH {
        return Err(CredentialProtectionError::CiphertextTooShort);
    }
    let mut nonce = [0_u8; CREDENTIAL_NONCE_LENGTH];
    nonce.copy_from_slice(&stored[..CREDENTIAL_NONCE_LENGTH]);
    let protected = ProtectedCredentialVersion::from_parts(
        rutilus_domain::CredentialId::from_uuid(authenticator_id.into_uuid()),
        rutilus_domain::CredentialVersionId::from_uuid(authenticator_id.into_uuid()),
        nonce,
        stored[CREDENTIAL_NONCE_LENGTH..].to_vec(),
    )?;
    let plaintext = decrypt_credential(master_key, &protected)?;
    base64::engine::general_purpose::STANDARD
        .decode(plaintext.expose_secret().as_bytes())
        .map_err(|_| CredentialProtectionError::InvalidPlaintextEncoding)
}

fn corrupt(authenticator_id: TotpAuthenticatorId, source: StoredTotpError) -> TotpRepositoryError {
    TotpRepositoryError::Corrupt {
        authenticator_id,
        source,
    }
}

/// A controlled failure while creating or reading TOTP authenticators.
#[derive(Debug, Error)]
pub enum TotpRepositoryError {
    #[error("TOTP write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("TOTP authenticator {authenticator_id} was not found")]
    NotFound {
        authenticator_id: TotpAuthenticatorId,
    },
    #[error("TOTP step {authenticator_id} cannot be represented")]
    StepOutOfRange {
        authenticator_id: TotpAuthenticatorId,
    },
    #[error("TOTP secret could not be protected: {0}")]
    Protect(#[source] CredentialProtectionError),
    #[error("stored TOTP authenticator {authenticator_id} is invalid: {source}")]
    Corrupt {
        authenticator_id: TotpAuthenticatorId,
        #[source]
        source: StoredTotpError,
    },
    #[error("TOTP database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted TOTP data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredTotpError {
    #[error("TOTP state code is invalid: {0}")]
    InvalidState(#[source] TotpStateParseError),
    #[error("TOTP authenticator shape is invalid: {0}")]
    InvalidShape(#[source] TotpRestoreError),
    #[error("stored TOTP step is outside the supported range")]
    InvalidStep,
    #[error("stored TOTP secret cannot be authenticated or decrypted: {0}")]
    InvalidSecret(#[source] CredentialProtectionError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::TOTP_SECRET_LENGTH;
    use rutilus_security::MasterKey;
    use secrecy::SecretBox;
    use time::Duration;

    use super::*;
    use crate::SqliteStore;

    fn test_key() -> MasterKey {
        MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))
    }

    fn provisioning(principal_id: PrincipalId, created_at: OffsetDateTime) -> TotpAuthenticator {
        TotpAuthenticator::new(
            TotpAuthenticatorId::generate(),
            principal_id,
            SecretBox::new(Box::new([0x5a; TOTP_SECRET_LENGTH])),
            created_at,
        )
    }

    async fn stored_principal(
        store: &SqliteStore,
        name: &str,
        created_at: OffsetDateTime,
    ) -> Result<PrincipalId, Box<dyn Error>> {
        let principal = rutilus_domain::Principal::new(
            PrincipalId::generate(),
            rutilus_domain::PrincipalName::parse(name)?,
            created_at,
        );
        store.create_principal(&principal).await?;
        Ok(principal.id())
    }

    #[tokio::test]
    async fn creates_lists_and_activates_authenticators() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let key = test_key();
        let base = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", base).await?;
        let first = provisioning(principal_id, base);
        let second = provisioning(principal_id, base + Duration::SECOND);
        store.create_totp_authenticator(&key, &first).await?;
        store.create_totp_authenticator(&key, &second).await?;

        assert_eq!(
            store.find_totp_authenticator(&key, first.id()).await?,
            Some(first.clone())
        );
        assert_eq!(
            store.list_totp_authenticators(&key, principal_id).await?,
            vec![first.clone(), second],
            "listing must return the authenticators oldest first"
        );
        assert!(
            store
                .list_totp_authenticators(&key, PrincipalId::generate())
                .await?
                .is_empty()
        );

        // The stored secret is the encrypted nonce-and-ciphertext blob, not
        // the 20-byte plaintext.
        let stored = totp_authenticator::Entity::find_by_id(first.id().into_uuid())
            .one(&store.database)
            .await?
            .ok_or("stored authenticator is missing")?;
        assert_ne!(stored.secret, vec![0x5a; TOTP_SECRET_LENGTH]);
        assert!(stored.secret.len() > CREDENTIAL_NONCE_LENGTH);

        // A wrong master key cannot recover the secret.
        let wrong_key = MasterKey::from_boxed_bytes(Box::new([0x6a; 32]));
        assert!(matches!(
            store.find_totp_authenticator(&wrong_key, first.id()).await,
            Err(TotpRepositoryError::Corrupt {
                source: StoredTotpError::InvalidSecret(
                    CredentialProtectionError::AuthenticationFailed
                ),
                ..
            })
        ));

        // The activation transition persists the state, the activation time,
        // and the matched step together.
        let activated_at = base + Duration::MINUTE;
        store
            .activate_totp_authenticator(first.id(), activated_at, 7)
            .await?;
        let active = store
            .find_totp_authenticator(&key, first.id())
            .await?
            .ok_or("stored authenticator is missing")?;
        assert_eq!(active.state(), TotpState::Active);
        assert_eq!(active.activated_at(), Some(activated_at));
        assert_eq!(active.last_used_step(), Some(7));

        // A racing activation with a stale step cannot rewind the recorded
        // step: the conditional update refuses it, so the row stays.
        let result = store
            .activate_totp_authenticator(first.id(), activated_at, 3)
            .await;
        assert!(matches!(result, Err(TotpRepositoryError::NotFound { .. })));
        let still_active = store
            .find_totp_authenticator(&key, first.id())
            .await?
            .ok_or("stored authenticator is missing")?;
        assert_eq!(still_active.last_used_step(), Some(7));

        assert!(matches!(
            store
                .activate_totp_authenticator(TotpAuthenticatorId::generate(), activated_at, 1)
                .await,
            Err(TotpRepositoryError::NotFound { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn step_recording_is_forward_only_under_racing_sign_ins() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let key = test_key();
        let base = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", base).await?;
        let authenticator = provisioning(principal_id, base);
        store
            .create_totp_authenticator(&key, &authenticator)
            .await?;
        store
            .activate_totp_authenticator(authenticator.id(), base, 1)
            .await?;

        // Two racing sign-ins that both verified step 2: exactly one
        // records it, the loser observes zero rows updated.
        assert!(store.record_totp_step(authenticator.id(), 2).await?);
        assert!(!store.record_totp_step(authenticator.id(), 2).await?);
        assert!(!store.record_totp_step(authenticator.id(), 1).await?);
        let stored = store
            .find_totp_authenticator(&key, authenticator.id())
            .await?
            .ok_or("stored authenticator is missing")?;
        assert_eq!(stored.last_used_step(), Some(2));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_stored_totp_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let key = test_key();
        let now = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", now).await?;
        let authenticator_id = TotpAuthenticatorId::generate();

        // A blob too short to carry the nonce and a tampered ciphertext are
        // both refused on read as corrupt.
        let truncated = totp_authenticator::ActiveModel {
            id: Set(authenticator_id.into_uuid()),
            principal_id: Set(principal_id.into_uuid()),
            secret: Set(vec![0x5a; 10]),
            state: Set(String::from("active")),
            algorithm: Set(String::from("sha1")),
            digits: Set(6),
            period: Set(30),
            created_at: Set(now),
            activated_at: Set(None),
            last_used_step: Set(None),
        };
        truncated.insert(&store.database).await?;
        assert!(matches!(
            store.find_totp_authenticator(&key, authenticator_id).await,
            Err(TotpRepositoryError::Corrupt {
                authenticator_id: id,
                source: StoredTotpError::InvalidSecret(
                    CredentialProtectionError::CiphertextTooShort
                ),
            }) if id == authenticator_id
        ));

        // The tampered ciphertext row replaces the truncated one (the
        // primary key is find-or-replace, so no stale row collides).
        totp_authenticator::Entity::delete_by_id(authenticator_id.into_uuid())
            .exec(&store.database)
            .await?;
        let tampered = totp_authenticator::ActiveModel {
            id: Set(authenticator_id.into_uuid()),
            principal_id: Set(principal_id.into_uuid()),
            secret: Set(vec![0x5a; CREDENTIAL_NONCE_LENGTH + 32]),
            state: Set(String::from("active")),
            algorithm: Set(String::from("sha1")),
            digits: Set(6),
            period: Set(30),
            created_at: Set(now),
            activated_at: Set(None),
            last_used_step: Set(None),
        };
        tampered.insert(&store.database).await?;
        assert!(matches!(
            store.find_totp_authenticator(&key, authenticator_id).await,
            Err(TotpRepositoryError::Corrupt {
                authenticator_id: id,
                source: StoredTotpError::InvalidSecret(
                    CredentialProtectionError::AuthenticationFailed
                ),
            }) if id == authenticator_id
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
