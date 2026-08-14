use rutilus_domain::{
    BindingCode, BindingCodeVerificationError, CenterBinding, CenterBindingError, CenterBindingId,
    CenterBindingState, CenterBindingStateParseError, CertificateFingerprint,
    CertificateFingerprintParseError, InstanceId,
};
use rutilus_entity::center_binding;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder,
    Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one new pending binding (design D2, D6).
    ///
    /// The single-center-binding rule is enforced twice: the partial unique
    /// index over active bindings is the atomic refusal, and the in-
    /// transaction re-read reports the collision as a typed error so the
    /// registration flow can answer the operator instead of surfacing a
    /// constraint failure.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::AlreadyActiveBinding`] when
    /// the site already has a pending or bound binding, and
    /// [`CenterBindingRepositoryError`] variants for coordination or
    /// database failures.
    pub async fn create_binding(
        &self,
        binding: &CenterBinding,
    ) -> Result<(), CenterBindingRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterBindingRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterBindingRepositoryError::Database)?;
        if center_binding::Entity::find()
            .filter(
                center_binding::Column::SiteInstanceId.eq(binding.site_instance_id().into_uuid()),
            )
            .filter(center_binding::Column::State.is_in(["pending", "bound"]))
            .one(&transaction)
            .await
            .map_err(CenterBindingRepositoryError::Database)?
            .is_some()
        {
            transaction
                .rollback()
                .await
                .map_err(CenterBindingRepositoryError::Database)?;
            return Err(CenterBindingRepositoryError::AlreadyActiveBinding {
                site_instance_id: binding.site_instance_id(),
            });
        }
        insert_binding(&transaction, binding).await?;
        transaction
            .commit()
            .await
            .map_err(CenterBindingRepositoryError::Database)
    }

    /// Reads one binding by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_binding(
        &self,
        binding_id: CenterBindingId,
    ) -> Result<Option<CenterBinding>, CenterBindingRepositoryError> {
        let Some(model) = center_binding::Entity::find_by_id(binding_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(CenterBindingRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_binding(binding_id, &model).map(Some)
    }

    /// Reads the most recent binding row of one site.
    ///
    /// A revoked binding stays stored as history, so the lookup returns the
    /// latest row and the caller decides by its state.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_binding_by_site(
        &self,
        site_instance_id: InstanceId,
    ) -> Result<Option<CenterBinding>, CenterBindingRepositoryError> {
        let Some(model) = center_binding::Entity::find()
            .filter(center_binding::Column::SiteInstanceId.eq(site_instance_id.into_uuid()))
            .order_by_desc(center_binding::Column::CreatedAt)
            .one(&self.database)
            .await
            .map_err(CenterBindingRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_binding(CenterBindingId::from_uuid(model.id), &model).map(Some)
    }

    /// Matches a presented code hash to its pending registration.
    ///
    /// This is the center-side lookup of the bind flow: the site presents
    /// the code, the center hashes it, and this query finds the pending
    /// binding whose outstanding code matches.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_pending_binding_by_code_hash(
        &self,
        code_hash: &[u8; 32],
    ) -> Result<Option<CenterBinding>, CenterBindingRepositoryError> {
        let Some(model) = center_binding::Entity::find()
            .filter(center_binding::Column::State.eq("pending"))
            .filter(center_binding::Column::BindingCodeHash.eq(code_hash.to_vec()))
            .order_by_asc(center_binding::Column::CreatedAt)
            .one(&self.database)
            .await
            .map_err(CenterBindingRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_binding(CenterBindingId::from_uuid(model.id), &model).map(Some)
    }

    /// Binds the site with its one-time code (design D2).
    ///
    /// The consumption is atomic: the binding row is re-read inside the
    /// transaction (never trusted from a stale read), the pending state,
    /// the short TTL, and the code hash are verified against the domain
    /// `CenterBinding`, and the row is conditionally updated to `bound`
    /// with the code consumed (hash and expiry cleared) and the bind time
    /// and site certificate fingerprint recorded. Two racing consumers can
    /// never both bind, and a presented code can never bind twice.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::NotFound`] for an unknown
    /// binding, [`CenterBindingRepositoryError::NotPending`] when the
    /// binding is not pending, [`CenterBindingRepositoryError::CodeExpired`]
    /// when the outstanding code has expired, and
    /// [`CenterBindingRepositoryError::CodeMismatch`] when the presented
    /// code does not match.
    pub async fn bind_with_code(
        &self,
        binding_id: CenterBindingId,
        code: &BindingCode,
        site_cert_fingerprint: Option<CertificateFingerprint>,
        now: OffsetDateTime,
    ) -> Result<(), CenterBindingRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterBindingRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterBindingRepositoryError::Database)?;
        let model = center_binding::Entity::find_by_id(binding_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(CenterBindingRepositoryError::Database)?
            .ok_or(CenterBindingRepositoryError::NotFound { binding_id })?;
        let binding = map_stored_binding(binding_id, &model)?;
        binding
            .verify_code(code, now)
            .map_err(|error| match error {
                BindingCodeVerificationError::NotPending => {
                    CenterBindingRepositoryError::NotPending { binding_id }
                }
                BindingCodeVerificationError::Expired => CenterBindingRepositoryError::CodeExpired,
                BindingCodeVerificationError::CodeMismatch => {
                    CenterBindingRepositoryError::CodeMismatch
                }
            })?;
        // R6-C-2: the site certificate fingerprint is a one-to-one identity
        // — the session admission resolves a presented certificate by it, so
        // a second *bound* registration carrying the same fingerprint would
        // split the cross-validation between two sites. The recheck runs
        // inside the transaction, and the write gate serializes the binds,
        // so a racing second bind of the same fingerprint is refused after
        // the first commits; a revoked row (state `revoked`) never blocks
        // the same site's re-bind.
        if let Some(fingerprint) = site_cert_fingerprint {
            let competing = center_binding::Entity::find()
                .filter(center_binding::Column::SiteCertFingerprint.eq(fingerprint.to_string()))
                .filter(center_binding::Column::State.eq("bound"))
                .filter(center_binding::Column::Id.ne(binding_id.into_uuid()))
                .one(&transaction)
                .await
                .map_err(CenterBindingRepositoryError::Database)?;
            if competing.is_some() {
                transaction
                    .rollback()
                    .await
                    .map_err(CenterBindingRepositoryError::Database)?;
                return Err(CenterBindingRepositoryError::FingerprintAlreadyBound { fingerprint });
            }
        }
        // The conditional update is the atomic guard: only a row still in
        // `pending` can be bound, so the re-read and the write can never
        // diverge even outside the write gate.
        let update = center_binding::Entity::update_many()
            .filter(center_binding::Column::Id.eq(binding_id.into_uuid()))
            .filter(center_binding::Column::State.eq("pending"))
            .set(center_binding::ActiveModel {
                state: Set(String::from("bound")),
                binding_code_hash: Set(None),
                expires_at: Set(None),
                site_cert_fingerprint: Set(
                    site_cert_fingerprint.map(|fingerprint| fingerprint.to_string())
                ),
                bound_at: Set(Some(now)),
                ..Default::default()
            })
            .exec(&transaction)
            .await
            .map_err(CenterBindingRepositoryError::Database)?;
        if update.rows_affected != 1 {
            transaction
                .rollback()
                .await
                .map_err(CenterBindingRepositoryError::Database)?;
            return Err(CenterBindingRepositoryError::NotPending { binding_id });
        }
        transaction
            .commit()
            .await
            .map_err(CenterBindingRepositoryError::Database)
    }

    /// Reads the most recent binding recorded for one site identity
    /// fingerprint.
    ///
    /// This is the session-admission lookup of the S5 slice: the center
    /// resolves a presented client certificate by the site-identity
    /// fingerprint bound into its private-arc extension. A revoked binding
    /// stays stored as history, and a re-bound site records a newer row
    /// with the same fingerprint, so the lookup returns the latest row and
    /// the caller decides by its state (the S3b cross-validation).
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_binding_by_site_fingerprint(
        &self,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<Option<CenterBinding>, CenterBindingRepositoryError> {
        let Some(model) = center_binding::Entity::find()
            .filter(center_binding::Column::SiteCertFingerprint.eq(site_fingerprint.to_string()))
            .order_by_desc(center_binding::Column::CreatedAt)
            .one(&self.database)
            .await
            .map_err(CenterBindingRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_binding(CenterBindingId::from_uuid(model.id), &model).map(Some)
    }

    /// Revokes a binding (design D6).
    ///
    /// The conditional update makes the write idempotent: a binding that is
    /// already revoked is reported as [`RevokeOutcome::AlreadyRevoked`]
    /// instead of failing, and the outstanding code (if any) is consumed by
    /// the revocation so a revoked binding never leaves a live code behind.
    ///
    /// # Errors
    ///
    /// Returns [`CenterBindingRepositoryError::NotFound`] for an unknown
    /// binding.
    pub async fn revoke_binding(
        &self,
        binding_id: CenterBindingId,
    ) -> Result<RevokeOutcome, CenterBindingRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterBindingRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterBindingRepositoryError::Database)?;
        let update = center_binding::Entity::update_many()
            .filter(center_binding::Column::Id.eq(binding_id.into_uuid()))
            .filter(center_binding::Column::State.ne("revoked"))
            .set(center_binding::ActiveModel {
                state: Set(String::from("revoked")),
                binding_code_hash: Set(None),
                expires_at: Set(None),
                ..Default::default()
            })
            .exec(&transaction)
            .await
            .map_err(CenterBindingRepositoryError::Database)?;
        let outcome = if update.rows_affected == 1 {
            RevokeOutcome::Revoked
        } else {
            if center_binding::Entity::find_by_id(binding_id.into_uuid())
                .one(&transaction)
                .await
                .map_err(CenterBindingRepositoryError::Database)?
                .is_none()
            {
                transaction
                    .rollback()
                    .await
                    .map_err(CenterBindingRepositoryError::Database)?;
                return Err(CenterBindingRepositoryError::NotFound { binding_id });
            }
            RevokeOutcome::AlreadyRevoked
        };
        transaction
            .commit()
            .await
            .map_err(CenterBindingRepositoryError::Database)?;
        Ok(outcome)
    }
}

async fn insert_binding<C>(
    database: &C,
    binding: &CenterBinding,
) -> Result<(), CenterBindingRepositoryError>
where
    C: ConnectionTrait,
{
    center_binding::ActiveModel {
        id: Set(binding.id().into_uuid()),
        center_url: Set(binding.center_url().to_owned()),
        binding_code_hash: Set(binding.binding_code_hash().map(|hash| hash.to_vec())),
        site_instance_id: Set(binding.site_instance_id().into_uuid()),
        site_cert_fingerprint: Set(binding
            .site_cert_fingerprint()
            .map(|fingerprint| fingerprint.to_string())),
        state: Set(binding.state().as_str().to_owned()),
        bound_at: Set(binding.bound_at()),
        expires_at: Set(binding.expires_at()),
        created_at: Set(binding.created_at()),
    }
    .insert(database)
    .await
    .map_err(CenterBindingRepositoryError::Database)?;
    Ok(())
}

fn map_stored_binding(
    binding_id: CenterBindingId,
    model: &center_binding::Model,
) -> Result<CenterBinding, CenterBindingRepositoryError> {
    let fingerprint = model
        .site_cert_fingerprint
        .as_deref()
        .map(str::parse)
        .transpose()
        .map_err(StoredCenterBindingError::InvalidFingerprint)
        .map_err(|source| CenterBindingRepositoryError::Corrupt { binding_id, source })?;
    CenterBinding::try_from_parts(
        binding_id,
        model.center_url.clone(),
        InstanceId::from_uuid(model.site_instance_id),
        model
            .state
            .parse::<CenterBindingState>()
            .map_err(StoredCenterBindingError::InvalidState)
            .map_err(|source| CenterBindingRepositoryError::Corrupt { binding_id, source })?,
        model.binding_code_hash.as_deref(),
        fingerprint,
        model.bound_at,
        model.expires_at,
        model.created_at,
    )
    .map_err(|source| CenterBindingRepositoryError::Corrupt {
        binding_id,
        source: StoredCenterBindingError::Invalid(source),
    })
}

/// The outcome of a binding revocation write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevokeOutcome {
    /// The binding was revoked.
    Revoked,
    /// The binding was already revoked; nothing changed.
    AlreadyRevoked,
}

/// A controlled failure while persisting or consuming site-to-center
/// bindings.
#[derive(Debug, Error)]
pub enum CenterBindingRepositoryError {
    #[error("binding write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("binding {binding_id} was not found")]
    NotFound { binding_id: CenterBindingId },
    #[error("site {site_instance_id} already has an active binding")]
    AlreadyActiveBinding { site_instance_id: InstanceId },
    #[error("binding {binding_id} is not pending")]
    NotPending { binding_id: CenterBindingId },
    #[error("binding code has expired")]
    CodeExpired,
    #[error("binding code does not match the outstanding code")]
    CodeMismatch,
    #[error(
        "the site certificate fingerprint {fingerprint} already belongs to a bound registration"
    )]
    FingerprintAlreadyBound { fingerprint: CertificateFingerprint },
    #[error("stored binding {binding_id} is invalid: {source}")]
    Corrupt {
        binding_id: CenterBindingId,
        #[source]
        source: StoredCenterBindingError,
    },
    #[error("binding database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted binding data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredCenterBindingError {
    #[error("stored binding state is invalid: {0}")]
    InvalidState(#[source] CenterBindingStateParseError),
    #[error("stored certificate fingerprint is invalid: {0}")]
    InvalidFingerprint(#[source] CertificateFingerprintParseError),
    #[error("stored binding is invalid: {0}")]
    Invalid(#[source] CenterBindingError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        BINDING_CODE_TTL, BindingCode, CenterBinding, CenterBindingId, InstanceId, InstanceKind,
        SiteInstance,
    };
    use rutilus_security::generate_binding_code;
    use sea_orm::{ActiveModelTrait, Set};
    use time::Duration;

    use super::*;
    use crate::SqliteStore;

    fn site_instance(now: time::OffsetDateTime) -> SiteInstance {
        SiteInstance::new(
            InstanceId::generate(),
            String::from("Site One"),
            InstanceKind::Site,
            now,
        )
    }

    fn pending_binding(
        site: &SiteInstance,
        code: &BindingCode,
        created_at: time::OffsetDateTime,
    ) -> CenterBinding {
        CenterBinding::new_pending(
            CenterBindingId::generate(),
            String::from("https://center.example"),
            site.id(),
            code,
            created_at + BINDING_CODE_TTL,
            created_at,
        )
    }

    #[tokio::test]
    async fn registration_creates_pending_bindings_and_refuses_a_second_active_one()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let code = generate_binding_code()?;
        let binding = pending_binding(&site, &code, base);

        store.create_binding(&binding).await?;
        let stored = store
            .find_binding(binding.id())
            .await?
            .ok_or("stored binding is missing")?;
        assert_eq!(stored, binding);
        assert_eq!(stored.state(), rutilus_domain::CenterBindingState::Pending);
        assert_eq!(stored.binding_code_hash(), Some(code.hash()));

        // The site lookup returns the pending registration.
        let by_site = store
            .find_binding_by_site(site.id())
            .await?
            .ok_or("the site lookup is missing the binding")?;
        assert_eq!(by_site.id(), binding.id());

        // A second active binding for the same site is refused.
        let second = pending_binding(&site, &generate_binding_code()?, base);
        assert!(matches!(
            store.create_binding(&second).await,
            Err(CenterBindingRepositoryError::AlreadyActiveBinding { .. })
        ));

        // Another site registers independently.
        let other_site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site Two"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&other_site).await?;
        store
            .create_binding(&pending_binding(
                &other_site,
                &generate_binding_code()?,
                base,
            ))
            .await?;

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn bind_consumes_the_one_time_code_atomically() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let code = generate_binding_code()?;
        let binding = pending_binding(&site, &code, base);
        store.create_binding(&binding).await?;

        // The matching code binds the site; the code is consumed.
        store
            .bind_with_code(binding.id(), &code, None, base + Duration::MINUTE)
            .await?;
        let stored = store
            .find_binding(binding.id())
            .await?
            .ok_or("stored binding is missing")?;
        assert_eq!(stored.state(), rutilus_domain::CenterBindingState::Bound);
        assert_eq!(
            stored.binding_code_hash(),
            None,
            "the one-time code must be consumed by the bind"
        );
        assert_eq!(stored.expires_at(), None);
        assert_eq!(stored.bound_at(), Some(base + Duration::MINUTE));

        // A second bind is refused: the code is one-time.
        assert!(matches!(
            store
                .bind_with_code(binding.id(), &code, None, base + Duration::MINUTE)
                .await,
            Err(CenterBindingRepositoryError::NotPending { .. })
        ));
        // An unknown binding is refused.
        assert!(matches!(
            store
                .bind_with_code(CenterBindingId::generate(), &code, None, base)
                .await,
            Err(CenterBindingRepositoryError::NotFound { .. })
        ));

        // A fresh registration accepts the matching code and records the
        // site certificate fingerprint.
        let other_site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site Two"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&other_site).await?;
        let other_code = generate_binding_code()?;
        let other_binding = pending_binding(&other_site, &other_code, base);
        store.create_binding(&other_binding).await?;
        let fingerprint = rutilus_domain::CertificateFingerprint::from_bytes([0x77; 32]);
        store
            .bind_with_code(
                other_binding.id(),
                &other_code,
                Some(fingerprint),
                base + Duration::MINUTE,
            )
            .await?;
        let stored = store
            .find_binding(other_binding.id())
            .await?
            .ok_or("stored binding is missing")?;
        assert_eq!(stored.site_cert_fingerprint(), Some(fingerprint));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_wrong_and_expired_codes() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let code = generate_binding_code()?;
        let binding = pending_binding(&site, &code, base);
        store.create_binding(&binding).await?;

        // A wrong code is refused by hash comparison.
        assert!(matches!(
            store
                .bind_with_code(binding.id(), &generate_binding_code()?, None, base)
                .await,
            Err(CenterBindingRepositoryError::CodeMismatch)
        ));

        // An expired outstanding code is refused.
        let expired_site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site Three"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&expired_site).await?;
        let expired_code = generate_binding_code()?;
        let expired = CenterBinding::new_pending(
            CenterBindingId::generate(),
            String::from("https://center.example"),
            expired_site.id(),
            &expired_code,
            base - Duration::SECOND,
            base - Duration::MINUTE,
        );
        store.create_binding(&expired).await?;
        assert!(matches!(
            store
                .bind_with_code(expired.id(), &expired_code, None, base)
                .await,
            Err(CenterBindingRepositoryError::CodeExpired)
        ));

        // The pending-code-hash lookup matches only the outstanding code.
        let by_hash = store
            .find_pending_binding_by_code_hash(&code.hash())
            .await?
            .ok_or("the code-hash lookup missed the pending binding")?;
        assert_eq!(by_hash.id(), binding.id());
        // The expired row is still pending in the database — expiry is a
        // domain judgment at bind time, so the lookup finds it and the bind
        // refuses it as expired.
        let by_expired_hash = store
            .find_pending_binding_by_code_hash(&expired_code.hash())
            .await?
            .ok_or("the expired binding must still be found by its code hash")?;
        assert_eq!(by_expired_hash.id(), expired.id());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn bind_refuses_a_fingerprint_already_bound_to_another_registration()
    -> Result<(), Box<dyn Error>> {
        // R6-C-2: the site certificate fingerprint is a one-to-one identity
        // — a second *bound* registration carrying the same fingerprint
        // would split the session admission's cross-validation between two
        // sites. The bind rechecks inside the transaction, so the second
        // bind of the same fingerprint is refused even though its own code
        // is valid.
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let fingerprint = rutilus_domain::CertificateFingerprint::from_bytes([0x77; 32]);

        // Site A binds with the fingerprint.
        let site_a = site_instance(base);
        store.create_instance(&site_a).await?;
        let code_a = generate_binding_code()?;
        let binding_a = pending_binding(&site_a, &code_a, base);
        store.create_binding(&binding_a).await?;
        store
            .bind_with_code(
                binding_a.id(),
                &code_a,
                Some(fingerprint),
                base + Duration::MINUTE,
            )
            .await?;

        // Site B presents its own valid code but the same fingerprint: the
        // bind is refused, and B's row stays pending.
        let site_b = site_instance(base + Duration::SECOND);
        store.create_instance(&site_b).await?;
        let code_b = generate_binding_code()?;
        let binding_b = pending_binding(&site_b, &code_b, base + Duration::SECOND);
        store.create_binding(&binding_b).await?;
        assert!(matches!(
            store
                .bind_with_code(binding_b.id(), &code_b, Some(fingerprint), base + Duration::MINUTE)
                .await,
            Err(CenterBindingRepositoryError::FingerprintAlreadyBound { fingerprint: found })
                if found == fingerprint
        ));
        let stored_b = store
            .find_binding(binding_b.id())
            .await?
            .ok_or("binding B is missing")?;
        assert_eq!(
            stored_b.state(),
            rutilus_domain::CenterBindingState::Pending,
            "the refused bind must leave the row pending for a later bind"
        );

        // The re-bind path stays open: after A's revocation, the same
        // fingerprint can bind a fresh registration again.
        store.revoke_binding(binding_a.id()).await?;
        let site_a_again = site_instance(base + Duration::seconds(2));
        store.create_instance(&site_a_again).await?;
        let code_again = generate_binding_code()?;
        let binding_again =
            pending_binding(&site_a_again, &code_again, base + Duration::seconds(2));
        store.create_binding(&binding_again).await?;
        store
            .bind_with_code(
                binding_again.id(),
                &code_again,
                Some(fingerprint),
                base + Duration::seconds(3),
            )
            .await?;

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn revoke_is_idempotent_and_consumes_the_outstanding_code() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let code = generate_binding_code()?;
        let binding = pending_binding(&site, &code, base);
        store.create_binding(&binding).await?;

        assert_eq!(
            store.revoke_binding(binding.id()).await?,
            RevokeOutcome::Revoked
        );
        let stored = store
            .find_binding(binding.id())
            .await?
            .ok_or("stored binding is missing")?;
        assert_eq!(stored.state(), rutilus_domain::CenterBindingState::Revoked);
        assert_eq!(
            stored.binding_code_hash(),
            None,
            "the revocation must consume the outstanding code"
        );
        assert_eq!(
            store.revoke_binding(binding.id()).await?,
            RevokeOutcome::AlreadyRevoked
        );
        assert!(matches!(
            store.revoke_binding(CenterBindingId::generate()).await,
            Err(CenterBindingRepositoryError::NotFound { .. })
        ));

        // After the revocation the site can register again.
        let rebind = pending_binding(&site, &generate_binding_code()?, base + Duration::SECOND);
        store.create_binding(&rebind).await?;

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_stored_binding_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let base = time::OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        // A pending row whose stored code hash is not 32 bytes passes the
        // schema CHECK (it only demands a value) but is corrupt to the
        // domain.
        let binding_id = CenterBindingId::generate();
        let invalid = center_binding::ActiveModel {
            id: Set(binding_id.into_uuid()),
            center_url: Set(String::from("https://center.example")),
            binding_code_hash: Set(Some(vec![0x5a; 31])),
            site_instance_id: Set(site.id().into_uuid()),
            site_cert_fingerprint: Set(None),
            state: Set(String::from("pending")),
            bound_at: Set(None),
            expires_at: Set(Some(base + Duration::MINUTE)),
            created_at: Set(base),
        };
        invalid.insert(&store.database).await?;

        assert!(matches!(
            store.find_binding(binding_id).await,
            Err(CenterBindingRepositoryError::Corrupt { .. })
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
