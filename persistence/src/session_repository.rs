use rutilus_domain::{PrincipalId, Session, SessionError, SessionId, SessionRestoreError};
use rutilus_entity::session;
use sea_orm::sea_query::Expr;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one new session (§16.2).
    ///
    /// Only the SHA-256 hashes of the bearer token and the CSRF token are
    /// stored (the security crate produced them); the raw tokens never reach
    /// this layer.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRepositoryError`] when write coordination fails, the
    /// token hash already belongs to another session, or the transaction
    /// cannot commit.
    pub async fn create_session(&self, session: &Session) -> Result<(), SessionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(SessionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(SessionRepositoryError::Database)?;
        session::ActiveModel {
            id: Set(session.id().into_uuid()),
            principal_id: Set(session.principal_id().into_uuid()),
            token_hash: Set(session.token_hash().to_vec()),
            csrf_hash: Set(session.csrf_hash().to_vec()),
            created_at: Set(session.created_at()),
            last_used_at: Set(session.last_used_at()),
            expires_at: Set(session.expires_at()),
            revoked_at: Set(session.revoked_at()),
        }
        .insert(&transaction)
        .await
        .map_err(|error| {
            if matches!(
                error.sql_err(),
                Some(sea_orm::SqlErr::UniqueConstraintViolation(_))
            ) {
                SessionRepositoryError::TokenHashTaken
            } else {
                SessionRepositoryError::Database(error)
            }
        })?;
        transaction
            .commit()
            .await
            .map_err(SessionRepositoryError::Database)
    }

    /// Reads the session presenting a token hash.
    ///
    /// The token hash is the lookup key of every authenticated request: the
    /// caller hashes the presented token and looks the session up by that
    /// hash, so a leaked database never yields a usable bearer secret. A
    /// revoked or expired session still reads back — the caller decides
    /// through [`Session::is_active`] — so the revocation fact stays
    /// observable.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_session_by_token_hash(
        &self,
        token_hash: &[u8; 32],
    ) -> Result<Option<Session>, SessionRepositoryError> {
        let Some(model) = session::Entity::find()
            .filter(session::Column::TokenHash.eq(token_hash.to_vec()))
            .one(&self.database)
            .await
            .map_err(SessionRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_session(SessionId::from_uuid(model.id), &model).map(Some)
    }

    /// Lists one principal's sessions, oldest first.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants.
    pub async fn list_sessions(
        &self,
        principal_id: PrincipalId,
    ) -> Result<Vec<Session>, SessionRepositoryError> {
        let models = session::Entity::find()
            .filter(session::Column::PrincipalId.eq(principal_id.into_uuid()))
            .order_by_asc(session::Column::CreatedAt)
            .all(&self.database)
            .await
            .map_err(SessionRepositoryError::Database)?;
        let mut sessions = Vec::with_capacity(models.len());
        for model in models {
            sessions.push(map_stored_session(SessionId::from_uuid(model.id), &model)?);
        }
        Ok(sessions)
    }

    /// Records session activity at the persistence boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRepositoryError::NotFound`] for an unknown id,
    /// [`SessionRepositoryError::Corrupt`] for a stored row that violates
    /// domain invariants, and [`SessionRepositoryError::StaleTouch`] when
    /// the activity time would move the last use backwards.
    pub async fn touch_session(
        &self,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> Result<(), SessionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(SessionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(SessionRepositoryError::Database)?;
        let model = session::Entity::find_by_id(session_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(SessionRepositoryError::Database)?
            .ok_or(SessionRepositoryError::NotFound { session_id })?;
        let mut domain = map_stored_session(session_id, &model)?;
        domain
            .touch(at)
            .map_err(|_| SessionRepositoryError::StaleTouch { session_id })?;
        let mut active = active_model(&domain);
        active.last_used_at = Set(at);
        active
            .update(&transaction)
            .await
            .map_err(SessionRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(SessionRepositoryError::Database)
    }

    /// Revokes one session (§16.2).
    ///
    /// Revocation is the soft write: `revoked_at` is set, the row is never
    /// physically deleted, so the session history stays auditable.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRepositoryError::NotFound`] for an unknown id,
    /// [`SessionRepositoryError::AlreadyRevoked`] for a second revocation,
    /// or [`SessionRepositoryError::Corrupt`] for a stored row that violates
    /// domain invariants.
    pub async fn revoke_session(
        &self,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> Result<(), SessionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(SessionRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(SessionRepositoryError::Database)?;
        let model = session::Entity::find_by_id(session_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(SessionRepositoryError::Database)?
            .ok_or(SessionRepositoryError::NotFound { session_id })?;
        let mut domain = map_stored_session(session_id, &model)?;
        match domain.revoke(at) {
            Ok(()) => {}
            Err(SessionError::AlreadyRevoked) => {
                return Err(SessionRepositoryError::AlreadyRevoked { session_id });
            }
            Err(SessionError::InvalidTimeline) => {
                return Err(SessionRepositoryError::Corrupt {
                    session_id,
                    source: StoredSessionError::InvalidTimeline(
                        SessionRestoreError::InvalidTimeline,
                    ),
                });
            }
        }
        let mut active = active_model(&domain);
        active.revoked_at = Set(domain.revoked_at());
        active
            .update(&transaction)
            .await
            .map_err(SessionRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(SessionRepositoryError::Database)
    }

    /// Revokes every active session of one principal (§16.2 "密码或角色变化撤销
    /// 旧 Session").
    ///
    /// The write is one conditional update — `revoked_at` is set only on rows
    /// that are not revoked yet — so a repeated revocation (a password change
    /// followed by a role change) is idempotent and never rewrites an
    /// existing revocation fact. Returns the number of sessions revoked.
    ///
    /// # Errors
    ///
    /// Returns [`SessionRepositoryError`] when write coordination fails or
    /// the update fails.
    pub async fn revoke_sessions_for_principal(
        &self,
        principal_id: PrincipalId,
        at: OffsetDateTime,
    ) -> Result<u64, SessionRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(SessionRepositoryError::Coordinate)?;
        let result = session::Entity::update_many()
            .col_expr(session::Column::RevokedAt, Expr::value(at))
            .filter(session::Column::PrincipalId.eq(principal_id.into_uuid()))
            .filter(session::Column::RevokedAt.is_null())
            .exec(&self.database)
            .await
            .map_err(SessionRepositoryError::Database)?;
        Ok(result.rows_affected)
    }
}

/// Projects a rehydrated session back into its persistence row.
///
/// The rehydrated value is authoritative after a `touch` or `revoke`
/// mutation, so the update writes every column from the domain value (the
/// `ActiveModel` update emits a full-row UPDATE, which is what the soft
/// revocation fact wants).
fn active_model(domain: &Session) -> session::ActiveModel {
    session::ActiveModel {
        id: Set(domain.id().into_uuid()),
        principal_id: Set(domain.principal_id().into_uuid()),
        token_hash: Set(domain.token_hash().to_vec()),
        csrf_hash: Set(domain.csrf_hash().to_vec()),
        created_at: Set(domain.created_at()),
        last_used_at: Set(domain.last_used_at()),
        expires_at: Set(domain.expires_at()),
        revoked_at: Set(domain.revoked_at()),
    }
}

fn map_stored_session(
    session_id: SessionId,
    model: &session::Model,
) -> Result<Session, SessionRepositoryError> {
    let token_hash = <[u8; 32]>::try_from(model.token_hash.as_slice())
        .map_err(|_| StoredSessionError::InvalidTokenHash)
        .map_err(|source| corrupt(session_id, source))?;
    let csrf_hash = <[u8; 32]>::try_from(model.csrf_hash.as_slice())
        .map_err(|_| StoredSessionError::InvalidCsrfHash)
        .map_err(|source| corrupt(session_id, source))?;
    Session::try_from_parts(
        session_id,
        PrincipalId::from_uuid(model.principal_id),
        token_hash,
        csrf_hash,
        model.created_at,
        model.last_used_at,
        model.expires_at,
        model.revoked_at,
    )
    .map_err(StoredSessionError::InvalidTimeline)
    .map_err(|source| corrupt(session_id, source))
}

fn corrupt(session_id: SessionId, source: StoredSessionError) -> SessionRepositoryError {
    SessionRepositoryError::Corrupt { session_id, source }
}

/// A controlled failure while creating, reading, or revoking sessions.
#[derive(Debug, Error)]
pub enum SessionRepositoryError {
    #[error("session write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("session {session_id} was not found")]
    NotFound { session_id: SessionId },
    #[error("the session token hash already belongs to another session")]
    TokenHashTaken,
    #[error("session {session_id} was already revoked")]
    AlreadyRevoked { session_id: SessionId },
    #[error("session {session_id} activity would move its last use backwards")]
    StaleTouch { session_id: SessionId },
    #[error("stored session {session_id} is invalid: {source}")]
    Corrupt {
        session_id: SessionId,
        #[source]
        source: StoredSessionError,
    },
    #[error("session database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted session data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredSessionError {
    #[error("stored session token hash is not exactly 32 bytes")]
    InvalidTokenHash,
    #[error("stored session CSRF hash is not exactly 32 bytes")]
    InvalidCsrfHash,
    #[error("session timeline is invalid: {0}")]
    InvalidTimeline(#[source] SessionRestoreError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use time::Duration;

    use super::*;
    use crate::SqliteStore;

    fn session_for(principal_id: PrincipalId, created_at: OffsetDateTime) -> Session {
        let id = SessionId::generate();
        // A distinct token hash per session: the token hash is unique, so two
        // sessions under the same hash would refuse the second insert.
        let mut token_hash = [0_u8; 32];
        let bytes = *id.into_uuid().as_bytes();
        token_hash[..16].copy_from_slice(&bytes);
        token_hash[16..].copy_from_slice(&bytes);
        Session::new(
            id,
            principal_id,
            token_hash,
            [0x22; 32],
            created_at,
            created_at + Duration::hours(8),
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
    async fn creates_finds_and_lists_sessions_by_token_hash() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", base).await?;
        let first = session_for(principal_id, base);
        let second = session_for(principal_id, base + Duration::SECOND);
        store.create_session(&first).await?;
        store.create_session(&second).await?;

        assert_eq!(
            store.find_session_by_token_hash(first.token_hash()).await?,
            Some(first.clone()),
            "the token hash is the lookup key"
        );
        assert_eq!(
            store.list_sessions(principal_id).await?,
            vec![first.clone(), second],
            "listing must return the sessions oldest first"
        );
        assert!(
            store
                .find_session_by_token_hash(&[0xee; 32])
                .await?
                .is_none()
        );

        // The token hash uniqueness is atomic: the same token cannot sign in
        // twice.
        assert!(matches!(
            store.create_session(&first).await,
            Err(SessionRepositoryError::TokenHashTaken)
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn revoke_is_soft_idempotent_and_batchable() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", base).await?;
        let other = stored_principal(&store, "operator", base).await?;
        let first = session_for(principal_id, base);
        let second = session_for(principal_id, base + Duration::SECOND);
        let third = session_for(principal_id, base + Duration::SECOND * 2);
        let foreign = session_for(other, base);
        for session in [&first, &second, &third, &foreign] {
            store.create_session(session).await?;
        }
        let revoked_at = base + Duration::hours(1);

        // A single session revokes softly: the row stays readable with its
        // revocation fact.
        store.revoke_session(first.id(), revoked_at).await?;
        let revoked = store
            .find_session_by_token_hash(first.token_hash())
            .await?
            .ok_or("a revoked session must still read back")?;
        assert_eq!(revoked.revoked_at(), Some(revoked_at));
        assert!(!revoked.is_active(revoked_at));
        assert!(matches!(
            store
                .revoke_session(first.id(), revoked_at + Duration::SECOND)
                .await,
            Err(SessionRepositoryError::AlreadyRevoked { .. })
        ));

        // The batch revocation touches only the principal's active sessions;
        // a repeated call is idempotent.
        assert_eq!(
            store
                .revoke_sessions_for_principal(principal_id, revoked_at)
                .await?,
            2
        );
        assert_eq!(
            store
                .revoke_sessions_for_principal(principal_id, revoked_at)
                .await?,
            0,
            "a repeated revocation must not rewrite the stored facts"
        );
        for session in [&second, &third] {
            let stored = store
                .find_session_by_token_hash(session.token_hash())
                .await?
                .ok_or("stored session is missing")?;
            assert_eq!(stored.revoked_at(), Some(revoked_at));
        }
        let untouched = store
            .find_session_by_token_hash(foreign.token_hash())
            .await?
            .ok_or("stored session is missing")?;
        assert_eq!(untouched.revoked_at(), None);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn touch_advances_and_rejects_stale_activity() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", base).await?;
        let session = session_for(principal_id, base);
        store.create_session(&session).await?;
        let session_id = session.id();

        let used_at = base + Duration::hours(1);
        store.touch_session(session_id, used_at).await?;
        let stored = store
            .find_session_by_token_hash(session.token_hash())
            .await?
            .ok_or("stored session is missing")?;
        assert_eq!(stored.last_used_at(), used_at);

        assert!(matches!(
            store.touch_session(session_id, base).await,
            Err(SessionRepositoryError::StaleTouch { .. })
        ));
        assert!(matches!(
            store.touch_session(SessionId::generate(), base).await,
            Err(SessionRepositoryError::NotFound { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_stored_session_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        let principal_id = stored_principal(&store, "admin", now).await?;
        let session_id = SessionId::generate();
        let mut model = session::ActiveModel {
            id: Set(session_id.into_uuid()),
            principal_id: Set(principal_id.into_uuid()),
            token_hash: Set(vec![0x11; 32]),
            csrf_hash: Set(vec![0x22; 32]),
            created_at: Set(now),
            last_used_at: Set(now),
            expires_at: Set(now + Duration::hours(8)),
            revoked_at: Set(None),
        };

        // A truncated token hash is refused on read as corrupt. The lookup
        // by hash cannot match the tampered row (the stored hash is only 16
        // bytes), so the listing rehydration is what surfaces it.
        model.token_hash = Set(vec![0x11; 16]);
        model.clone().insert(&store.database).await?;
        assert!(matches!(
            store.list_sessions(principal_id).await,
            Err(SessionRepositoryError::Corrupt {
                session_id: id,
                source: StoredSessionError::InvalidTokenHash,
            }) if id == session_id
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
