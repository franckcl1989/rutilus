use std::path::{Path, PathBuf};

use rutilus_domain::{
    Artifact, ArtifactId, ArtifactName, ArtifactNameError, ArtifactRestoreError, ArtifactState,
    ArtifactStateParseError, Sha256Hex, Sha256HexParseError,
};
use rutilus_entity::artifact;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder,
    Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

/// The fixed subdirectory under the product data directory that holds
/// artifact files. The name is part of the persistence boundary contract:
/// the upload use case creates it (with `spawn_blocking`, §7.8) before the
/// first write.
const ARTIFACT_DIRECTORY_NAME: &str = "artifacts";

/// The fixed file extension appended to the artifact identity. Part of the
/// same path contract as [`ARTIFACT_DIRECTORY_NAME`]; the extension is
/// conventional and does not imply any content format.
const ARTIFACT_FILE_EXTENSION: &str = "bin";

impl SqliteStore {
    /// Atomically persists one artifact manifest.
    ///
    /// The manifest is declared before any byte is transferred (the api
    /// `CreateArtifactRequest` contract), so the row exists while the file is
    /// still being uploaded and carries the resume state. Re-creating an
    /// artifact identity that is already stored is a no-op — the stored row
    /// is authoritative and never rewritten, mirroring the
    /// [`Self::create_operation`] at-least-once delivery discipline: a
    /// duplicate manifest declares the same identity, size, and digest, so
    /// nothing is lost by keeping the first row.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRepositoryError`] when write coordination fails, a
    /// value cannot be stored in the `SQLite` `INTEGER` range, the
    /// transaction cannot commit, or a stored row violates an aggregate
    /// invariant.
    pub async fn create_artifact(
        &self,
        artifact: &Artifact,
    ) -> Result<(), ArtifactRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(ArtifactRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        let artifact_id = artifact.id();
        if artifact::Entity::find_by_id(artifact_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(ArtifactRepositoryError::Database)?
            .is_some()
        {
            // The stored row is authoritative and must not be rewritten
            // (mirrors `create_operation`).
            transaction
                .commit()
                .await
                .map_err(ArtifactRepositoryError::Database)?;
            return Ok(());
        }
        artifact::ActiveModel {
            id: Set(artifact_id.into_uuid()),
            name: Set(artifact.name().to_string()),
            size_bytes: Set(stored_integer(artifact.size_bytes())?),
            sha256: Set(artifact.sha256().as_str().to_owned()),
            state: Set(artifact.state().as_str().to_owned()),
            uploaded_bytes: Set(stored_integer(artifact.uploaded_bytes())?),
            created_at: Set(artifact.created_at()),
            updated_at: Set(artifact.updated_at()),
        }
        .insert(&transaction)
        .await
        .map_err(ArtifactRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one artifact manifest by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRepositoryError`] when the query fails or the stored
    /// row violates a domain invariant.
    pub async fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<Artifact>, ArtifactRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        let Some(model) = artifact::Entity::find_by_id(artifact_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(ArtifactRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(ArtifactRepositoryError::Database)?;
            return Ok(None);
        };
        let domain = map_stored_artifact(artifact_id, &model)?;
        transaction
            .commit()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        Ok(Some(domain))
    }

    /// Lists every artifact in one lifecycle phase, in declaration order.
    ///
    /// The one-phase filter backs the §0.4.0 recovery scan — every upload
    /// still in `Uploading` after a restart is a resume candidate whose
    /// `uploaded_bytes` is the exact offset to continue from — and the
    /// artifact inventory projections. Results are ordered by creation time
    /// and identity so recovery replays in declaration order. Each row is
    /// rehydrated as a complete aggregate, so one corrupt row poisons the
    /// whole listing; recovery must surface that rather than silently drop
    /// the unreadable artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRepositoryError`] when the query fails or any stored
    /// artifact violates domain invariants.
    pub async fn list_artifacts_by_state(
        &self,
        state: ArtifactState,
    ) -> Result<Vec<Artifact>, ArtifactRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        let models = artifact::Entity::find()
            .filter(artifact::Column::State.eq(state.as_str()))
            .order_by_asc(artifact::Column::CreatedAt)
            .order_by_asc(artifact::Column::Id)
            .all(&transaction)
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        let mut artifacts = Vec::with_capacity(models.len());
        for model in &models {
            artifacts.push(map_stored_artifact(ArtifactId::from_uuid(model.id), model)?);
        }
        transaction
            .commit()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        Ok(artifacts)
    }

    /// Persists one progress and state step of an artifact upload (§14.3).
    ///
    /// The uploaded byte count and lifecycle phase change together, exactly
    /// like [`Self::apply_transition`] records one operation step: the
    /// persisted row is re-read inside the transaction and is authoritative,
    /// so the received count can only ever grow (a stale or racing writer is
    /// refused with a regression conflict), can never exceed the declared
    /// size, `Ready` requires the complete byte range, and a terminal row
    /// (`Ready`/`Failed`) can never be reopened — the §0.4.0
    /// "固件上传中断可恢复或明确失败" guarantee: once an upload finished or
    /// failed, no later writer can resurrect it.
    ///
    /// The in-memory legality of the step is the domain lifecycle methods'
    /// decision, which the use case applies before calling this method; this
    /// method protects the persisted row against regressions and races the
    /// domain cannot see.
    ///
    /// `occurred_at` becomes the row's update time, recording exactly when
    /// the step took effect; the caller supplies the clock at the boundary,
    /// keeping the domain free of clock access (§7.2), mirroring
    /// [`Self::apply_transition`].
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactRepositoryError::NotFound`] for an unknown id,
    /// [`ArtifactRepositoryError::TerminalConflict`] when the persisted state
    /// is terminal, [`ArtifactRepositoryError::ProgressRegression`] when the
    /// request moves the byte count backwards,
    /// [`ArtifactRepositoryError::ProgressExceedsSize`] when the request
    /// exceeds the declared size,
    /// [`ArtifactRepositoryError::IncompleteUpload`] when `Ready` is
    /// requested before the byte count is complete, and
    /// [`ArtifactRepositoryError`] variants for coordination or database
    /// failures.
    pub async fn update_artifact(
        &self,
        artifact_id: ArtifactId,
        uploaded_bytes: u64,
        state: ArtifactState,
        occurred_at: OffsetDateTime,
    ) -> Result<(), ArtifactRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(ArtifactRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        let model = artifact::Entity::find_by_id(artifact_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(ArtifactRepositoryError::Database)?
            .ok_or(ArtifactRepositoryError::NotFound { artifact_id })?;
        let current_state = model
            .state
            .parse::<ArtifactState>()
            .map_err(StoredArtifactError::InvalidState)
            .map_err(|source| corrupt(artifact_id, source))?;
        if current_state.is_terminal() {
            return Err(ArtifactRepositoryError::TerminalConflict {
                artifact_id,
                state: current_state,
            });
        }
        let persisted_uploaded = u64::try_from(model.uploaded_bytes)
            .map_err(|_| StoredArtifactError::InvalidUploadedBytes {
                actual: model.uploaded_bytes,
            })
            .map_err(|source| corrupt(artifact_id, source))?;
        let persisted_size = u64::try_from(model.size_bytes)
            .map_err(|_| StoredArtifactError::InvalidSize {
                actual: model.size_bytes,
            })
            .map_err(|source| corrupt(artifact_id, source))?;
        if uploaded_bytes < persisted_uploaded {
            return Err(ArtifactRepositoryError::ProgressRegression {
                artifact_id,
                persisted: persisted_uploaded,
                requested: uploaded_bytes,
            });
        }
        if uploaded_bytes > persisted_size {
            return Err(ArtifactRepositoryError::ProgressExceedsSize {
                artifact_id,
                uploaded: uploaded_bytes,
                size: persisted_size,
            });
        }
        if state == ArtifactState::Ready && uploaded_bytes != persisted_size {
            return Err(ArtifactRepositoryError::IncompleteUpload {
                artifact_id,
                uploaded: uploaded_bytes,
                size: persisted_size,
            });
        }
        let mut active = model.into_active_model();
        active.uploaded_bytes = Set(stored_integer(uploaded_bytes)?);
        active.state = Set(state.as_str().to_owned());
        active.updated_at = Set(occurred_at);
        active
            .update(&transaction)
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(ArtifactRepositoryError::Database)?;
        Ok(())
    }

    /// Returns the deterministic on-disk location of one artifact file.
    ///
    /// The file lives in a fixed `artifacts/` subdirectory of the product
    /// data directory — the directory that contains the `SQLite` database
    /// file — named `<artifact-id>.bin`. The mapping is a pure function of
    /// the identity and the store location, so the same id always yields the
    /// same path, two ids never collide, and the row and its bytes link
    /// without any table of file locations.
    ///
    /// This method performs no I/O: the path is a persistence contract, and
    /// the actual file write and read are the upload use case's job (std
    /// file I/O under `spawn_blocking`, design §7.8), which must create the
    /// directory first.
    #[must_use]
    pub fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
        artifact_file_path(&self.database_path, artifact_id)
    }
}

/// The deterministic on-disk location of one artifact's bytes.
///
/// A pure function of the database location and the artifact identity, so a
/// restore can place the artifact files of a backup package back where the
/// restored database rows expect them.
#[must_use]
pub fn artifact_file_path(database_path: &Path, artifact_id: ArtifactId) -> PathBuf {
    let data_directory = database_path.parent().unwrap_or_else(|| Path::new("."));
    data_directory
        .join(ARTIFACT_DIRECTORY_NAME)
        .join(format!("{artifact_id}.{ARTIFACT_FILE_EXTENSION}"))
}

fn map_stored_artifact(
    artifact_id: ArtifactId,
    model: &artifact::Model,
) -> Result<Artifact, ArtifactRepositoryError> {
    let name = ArtifactName::parse(&model.name)
        .map_err(StoredArtifactError::InvalidName)
        .map_err(|source| corrupt(artifact_id, source))?;
    let sha256 = Sha256Hex::parse(&model.sha256)
        .map_err(StoredArtifactError::InvalidSha256)
        .map_err(|source| corrupt(artifact_id, source))?;
    let state = model
        .state
        .parse::<ArtifactState>()
        .map_err(StoredArtifactError::InvalidState)
        .map_err(|source| corrupt(artifact_id, source))?;
    let size_bytes = u64::try_from(model.size_bytes)
        .map_err(|_| StoredArtifactError::InvalidSize {
            actual: model.size_bytes,
        })
        .map_err(|source| corrupt(artifact_id, source))?;
    let uploaded_bytes = u64::try_from(model.uploaded_bytes)
        .map_err(|_| StoredArtifactError::InvalidUploadedBytes {
            actual: model.uploaded_bytes,
        })
        .map_err(|source| corrupt(artifact_id, source))?;
    Artifact::try_from_parts(
        artifact_id,
        name,
        size_bytes,
        sha256,
        state,
        uploaded_bytes,
        model.created_at,
        model.updated_at,
    )
    .map_err(StoredArtifactError::InvalidRestore)
    .map_err(|source| corrupt(artifact_id, source))
}

fn corrupt(artifact_id: ArtifactId, source: StoredArtifactError) -> ArtifactRepositoryError {
    ArtifactRepositoryError::Corrupt {
        artifact_id,
        source,
    }
}

/// Converts a domain `u64` count into the signed 64-bit range of a `SQLite`
/// `INTEGER` column.
///
/// # Errors
///
/// Returns [`ArtifactRepositoryError::IntegerOutOfRange`] when the value
/// exceeds what the column can hold. Progress never exceeds the declared
/// size and the size is converted first in the write paths, so this is a
/// totality guard for values no realistic upload can produce.
fn stored_integer(value: u64) -> Result<i64, ArtifactRepositoryError> {
    i64::try_from(value).map_err(|_| ArtifactRepositoryError::IntegerOutOfRange { value })
}

/// A controlled failure while creating, reading, or advancing artifacts.
#[derive(Debug, Error)]
pub enum ArtifactRepositoryError {
    #[error("artifact write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("artifact {artifact_id} was not found")]
    NotFound { artifact_id: ArtifactId },
    #[error(
        "artifact {artifact_id} is already in terminal state {state} and cannot be overwritten"
    )]
    TerminalConflict {
        artifact_id: ArtifactId,
        state: ArtifactState,
    },
    #[error("artifact {artifact_id} progress cannot move from {persisted} to {requested} bytes")]
    ProgressRegression {
        artifact_id: ArtifactId,
        persisted: u64,
        requested: u64,
    },
    #[error(
        "artifact {artifact_id} upload of {uploaded} bytes exceeds the declared size of {size} bytes"
    )]
    ProgressExceedsSize {
        artifact_id: ArtifactId,
        uploaded: u64,
        size: u64,
    },
    #[error(
        "artifact {artifact_id} cannot become ready with only {uploaded} of {size} bytes received"
    )]
    IncompleteUpload {
        artifact_id: ArtifactId,
        uploaded: u64,
        size: u64,
    },
    #[error("value {value} cannot be stored in the SQLite INTEGER column")]
    IntegerOutOfRange { value: u64 },
    #[error("stored artifact {artifact_id} is invalid: {source}")]
    Corrupt {
        artifact_id: ArtifactId,
        #[source]
        source: StoredArtifactError,
    },
    #[error("artifact database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted artifact data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredArtifactError {
    #[error("artifact name is invalid: {0}")]
    InvalidName(#[source] ArtifactNameError),
    #[error("artifact SHA-256 digest is invalid: {0}")]
    InvalidSha256(#[source] Sha256HexParseError),
    #[error("artifact state code is invalid: {0}")]
    InvalidState(#[source] ArtifactStateParseError),
    #[error("stored artifact size is negative: {actual}")]
    InvalidSize { actual: i64 },
    #[error("stored artifact progress is negative: {actual}")]
    InvalidUploadedBytes { actual: i64 },
    #[error("artifact record violates a domain invariant: {0}")]
    InvalidRestore(#[source] ArtifactRestoreError),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, ffi::OsStr};

    use rutilus_domain::ArtifactNameError;
    use time::Duration;

    use super::*;
    use crate::SqliteStore;

    #[tokio::test]
    async fn creates_and_loads_artifacts_with_full_metadata() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let artifact = uploading_artifact("firmware-2024.2.bin", 1024, [0xAB; 32], created_at)?;

        store.create_artifact(&artifact).await?;
        assert_eq!(
            store.find_artifact(artifact.id()).await?,
            Some(artifact.clone())
        );
        assert!(store.find_artifact(ArtifactId::generate()).await?.is_none());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn repeated_manifest_declaration_never_rewrites_the_stored_row()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let artifact = uploading_artifact("firmware.bin", 100, [0xAB; 32], created_at)?;

        store.create_artifact(&artifact).await?;
        store.create_artifact(&artifact).await?;
        assert_eq!(
            store.find_artifact(artifact.id()).await?,
            Some(artifact.clone())
        );

        // The re-declared manifest must not resurrect a row that has already
        // moved forward: a fresh writer carrying the same identity must not
        // roll back progress the first writer recorded.
        let progressed_at = created_at + Duration::SECOND;
        store
            .update_artifact(artifact.id(), 60, ArtifactState::Uploading, progressed_at)
            .await?;
        store.create_artifact(&artifact).await?;
        let stored = store
            .find_artifact(artifact.id())
            .await?
            .ok_or("stored artifact is missing")?;
        assert_eq!(stored.uploaded_bytes(), 60);
        assert_eq!(stored.updated_at(), progressed_at);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn lists_artifacts_by_state_in_declaration_order() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let first = uploading_artifact("first.bin", 100, [0x01; 32], base)?;
        let second = uploading_artifact("second.bin", 100, [0x02; 32], base + Duration::SECOND)?;
        let third = uploading_artifact("third.bin", 100, [0x03; 32], base + Duration::SECOND * 2)?;
        for artifact in [&first, &second, &third] {
            store.create_artifact(artifact).await?;
        }
        store
            .update_artifact(
                first.id(),
                100,
                ArtifactState::Ready,
                base + Duration::SECOND,
            )
            .await?;
        store
            .update_artifact(
                second.id(),
                10,
                ArtifactState::Failed,
                base + Duration::SECOND * 2,
            )
            .await?;

        let uploading = store
            .list_artifacts_by_state(ArtifactState::Uploading)
            .await?;
        assert_eq!(
            uploading.iter().map(Artifact::id).collect::<Vec<_>>(),
            vec![third.id()],
            "only the untouched upload remains in Uploading"
        );
        let ready = store.list_artifacts_by_state(ArtifactState::Ready).await?;
        assert_eq!(
            ready.iter().map(Artifact::id).collect::<Vec<_>>(),
            vec![first.id()]
        );
        let failed = store.list_artifacts_by_state(ArtifactState::Failed).await?;
        assert_eq!(
            failed.iter().map(Artifact::id).collect::<Vec<_>>(),
            vec![second.id()]
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn update_records_progress_and_state_with_their_occurred_at() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let artifact = uploading_artifact("firmware.bin", 100, [0xAB; 32], created_at)?;
        store.create_artifact(&artifact).await?;
        let artifact_id = artifact.id();

        let first_at = created_at + Duration::SECOND;
        store
            .update_artifact(artifact_id, 40, ArtifactState::Uploading, first_at)
            .await?;
        let partial = store
            .find_artifact(artifact_id)
            .await?
            .ok_or("partial artifact is missing")?;
        assert_eq!(partial.uploaded_bytes(), 40);
        assert_eq!(partial.state(), ArtifactState::Uploading);
        assert_eq!(partial.updated_at(), first_at);
        assert_eq!(partial.created_at(), created_at);
        assert_eq!(partial.name(), artifact.name());

        let complete_at = first_at + Duration::SECOND;
        store
            .update_artifact(artifact_id, 100, ArtifactState::Uploading, complete_at)
            .await?;
        let ready_at = complete_at + Duration::SECOND;
        store
            .update_artifact(artifact_id, 100, ArtifactState::Ready, ready_at)
            .await?;
        let ready = store
            .find_artifact(artifact_id)
            .await?
            .ok_or("ready artifact is missing")?;
        assert_eq!(ready.uploaded_bytes(), 100);
        assert_eq!(ready.state(), ArtifactState::Ready);
        assert_eq!(ready.updated_at(), ready_at);
        assert_eq!(ready.sha256(), artifact.sha256());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn update_rejects_unknown_ids() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let unknown = ArtifactId::generate();
        assert!(matches!(
            store
                .update_artifact(unknown, 0, ArtifactState::Uploading, OffsetDateTime::now_utc())
                .await,
            Err(ArtifactRepositoryError::NotFound { artifact_id })
                if artifact_id == unknown
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn update_rejects_progress_regression() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let artifact = uploading_artifact("firmware.bin", 100, [0xAB; 32], created_at)?;
        store.create_artifact(&artifact).await?;
        let artifact_id = artifact.id();
        let first_at = created_at + Duration::SECOND;
        store
            .update_artifact(artifact_id, 80, ArtifactState::Uploading, first_at)
            .await?;

        // A stale writer replaying an older offset must be refused, not
        // silently accepted: a hole in the file would be impossible to
        // detect later.
        let stale_at = created_at + Duration::SECOND * 2;
        assert!(matches!(
            store
                .update_artifact(artifact_id, 50, ArtifactState::Uploading, stale_at)
                .await,
            Err(ArtifactRepositoryError::ProgressRegression {
                artifact_id: id,
                persisted: 80,
                requested: 50,
            }) if id == artifact_id
        ));
        let stored = store
            .find_artifact(artifact_id)
            .await?
            .ok_or("stored artifact is missing")?;
        assert_eq!(stored.uploaded_bytes(), 80);
        assert_eq!(stored.updated_at(), first_at);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn update_rejects_progress_beyond_the_declared_size() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let artifact = uploading_artifact("firmware.bin", 100, [0xAB; 32], created_at)?;
        store.create_artifact(&artifact).await?;
        let artifact_id = artifact.id();

        assert!(matches!(
            store
                .update_artifact(
                    artifact_id,
                    101,
                    ArtifactState::Uploading,
                    created_at + Duration::SECOND,
                )
                .await,
            Err(ArtifactRepositoryError::ProgressExceedsSize {
                artifact_id: id,
                uploaded: 101,
                size: 100,
            }) if id == artifact_id
        ));
        let stored = store
            .find_artifact(artifact_id)
            .await?
            .ok_or("stored artifact is missing")?;
        assert_eq!(stored.uploaded_bytes(), 0);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn update_rejects_ready_before_the_upload_is_complete() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let artifact = uploading_artifact("firmware.bin", 100, [0xAB; 32], created_at)?;
        store.create_artifact(&artifact).await?;
        let artifact_id = artifact.id();
        store
            .update_artifact(
                artifact_id,
                50,
                ArtifactState::Uploading,
                created_at + Duration::SECOND,
            )
            .await?;

        // A caller that bypasses the domain lifecycle (the only path that
        // enforces `Ready` ⇒ complete) is refused against the persisted
        // row; the database itself has no cross-column constraint, so this
        // repository guard is the backstop.
        assert!(matches!(
            store
                .update_artifact(
                    artifact_id,
                    50,
                    ArtifactState::Ready,
                    created_at + Duration::SECOND * 2,
                )
                .await,
            Err(ArtifactRepositoryError::IncompleteUpload {
                artifact_id: id,
                uploaded: 50,
                size: 100,
            }) if id == artifact_id
        ));
        let stored = store
            .find_artifact(artifact_id)
            .await?
            .ok_or("stored artifact is missing")?;
        assert_eq!(stored.state(), ArtifactState::Uploading);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn terminal_artifacts_are_immutable() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let ready_source = uploading_artifact("ready.bin", 100, [0x01; 32], created_at)?;
        store.create_artifact(&ready_source).await?;
        let ready_id = ready_source.id();
        store
            .update_artifact(
                ready_id,
                100,
                ArtifactState::Ready,
                created_at + Duration::SECOND,
            )
            .await?;
        let failed_source = uploading_artifact("failed.bin", 100, [0x02; 32], created_at)?;
        store.create_artifact(&failed_source).await?;
        let failed_id = failed_source.id();
        store
            .update_artifact(
                failed_id,
                10,
                ArtifactState::Failed,
                created_at + Duration::SECOND,
            )
            .await?;

        // A terminal verdict is never reopened: not by more progress, not by
        // another phase — the §0.4.0 "明确失败" guarantee.
        for (artifact_id, terminal) in [
            (ready_id, ArtifactState::Ready),
            (failed_id, ArtifactState::Failed),
        ] {
            for (uploaded_bytes, state) in [
                (100, ArtifactState::Uploading),
                (100, ArtifactState::Ready),
                (10, ArtifactState::Failed),
            ] {
                assert!(matches!(
                    store
                        .update_artifact(
                            artifact_id,
                            uploaded_bytes,
                            state,
                            created_at + Duration::SECOND * 2,
                        )
                        .await,
                    Err(ArtifactRepositoryError::TerminalConflict {
                        artifact_id: id,
                        state: persisted,
                    }) if id == artifact_id && persisted == terminal
                ));
            }
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn reports_corrupt_stored_rows() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        let sha256 = String::from("ab").repeat(32);

        // Every corrupt row is written directly, bypassing the repository's
        // domain validation — exactly what a row written by a bug or a
        // future build would look like. The migration only CHECKs the state
        // code set, so all of these are insertable; rehydration must refuse
        // each one as a corrupt aggregate.
        let invalid_sha256 = insert_row(
            &store,
            "corrupt.bin",
            100,
            "not-a-digest",
            "uploading",
            0,
            now,
            now,
        )
        .await?;
        assert!(matches!(
            store.find_artifact(invalid_sha256).await,
            Err(ArtifactRepositoryError::Corrupt {
                artifact_id,
                source: StoredArtifactError::InvalidSha256(_),
            }) if artifact_id == invalid_sha256
        ));

        let invalid_name = insert_row(&store, "", 100, &sha256, "uploading", 0, now, now).await?;
        assert!(matches!(
            store.find_artifact(invalid_name).await,
            Err(ArtifactRepositoryError::Corrupt {
                artifact_id,
                source: StoredArtifactError::InvalidName(_),
            }) if artifact_id == invalid_name
        ));

        let negative_progress = insert_row(
            &store,
            "corrupt.bin",
            100,
            &sha256,
            "uploading",
            -1,
            now,
            now,
        )
        .await?;
        assert!(matches!(
            store.find_artifact(negative_progress).await,
            Err(ArtifactRepositoryError::Corrupt {
                artifact_id,
                source: StoredArtifactError::InvalidUploadedBytes { actual: -1 },
            }) if artifact_id == negative_progress
        ));

        let inverted_timeline = insert_row(
            &store,
            "corrupt.bin",
            100,
            &sha256,
            "uploading",
            0,
            now,
            now - Duration::SECOND,
        )
        .await?;
        assert!(matches!(
            store.find_artifact(inverted_timeline).await,
            Err(ArtifactRepositoryError::Corrupt {
                artifact_id,
                source: StoredArtifactError::InvalidRestore(ArtifactRestoreError::InvalidTimeline),
            }) if artifact_id == inverted_timeline
        ));

        let oversized_progress = insert_row(
            &store,
            "corrupt.bin",
            100,
            &sha256,
            "uploading",
            200,
            now,
            now,
        )
        .await?;
        assert!(matches!(
            store.find_artifact(oversized_progress).await,
            Err(ArtifactRepositoryError::Corrupt {
                artifact_id,
                source: StoredArtifactError::InvalidRestore(
                    ArtifactRestoreError::ProgressExceedsSize { uploaded: 200, size: 100 }
                ),
            }) if artifact_id == oversized_progress
        ));

        let ready_without_bytes =
            insert_row(&store, "corrupt.bin", 100, &sha256, "ready", 50, now, now).await?;
        assert!(matches!(
            store.find_artifact(ready_without_bytes).await,
            Err(ArtifactRepositoryError::Corrupt {
                artifact_id,
                source: StoredArtifactError::InvalidRestore(
                    ArtifactRestoreError::ReadyBeforeCompleteUpload { uploaded: 50, size: 100 }
                ),
            }) if artifact_id == ready_without_bytes
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn artifact_file_paths_are_deterministic_and_scoped_to_the_data_directory()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        let artifact_id = ArtifactId::generate();

        let first = store.artifact_file_path(artifact_id);
        let second = store.artifact_file_path(artifact_id);
        assert_eq!(
            first, second,
            "the same identity must always map to the same path"
        );
        assert!(
            first.starts_with(directory.path()),
            "artifact files must live under the product data directory"
        );
        let expected_parent = directory.path().join("artifacts");
        assert_eq!(first.parent(), Some(expected_parent.as_path()));
        assert_eq!(
            first.file_name(),
            Some(OsStr::new(&format!("{artifact_id}.bin")))
        );
        assert_ne!(
            store.artifact_file_path(ArtifactId::generate()),
            first,
            "two identities must never collide"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    fn uploading_artifact(
        name: &str,
        size_bytes: u64,
        sha256: [u8; 32],
        created_at: OffsetDateTime,
    ) -> Result<Artifact, ArtifactNameError> {
        Ok(Artifact::new(
            ArtifactId::generate(),
            ArtifactName::parse(name)?,
            size_bytes,
            Sha256Hex::from_bytes(sha256),
            created_at,
        ))
    }

    /// Inserts one raw row directly, bypassing repository validation.
    ///
    /// The eight parameters mirror the eight table columns exactly; a
    /// grouped structure would obscure which column each corrupt case is
    /// targeting, so the argument count is the accepted trade-off.
    #[allow(clippy::too_many_arguments)]
    async fn insert_row(
        store: &SqliteStore,
        name: &str,
        size_bytes: i64,
        sha256: &str,
        state: &str,
        uploaded_bytes: i64,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<ArtifactId, Box<dyn Error>> {
        let artifact_id = ArtifactId::generate();
        artifact::ActiveModel {
            id: Set(artifact_id.into_uuid()),
            name: Set(name.to_owned()),
            size_bytes: Set(size_bytes),
            sha256: Set(sha256.to_owned()),
            state: Set(state.to_owned()),
            uploaded_bytes: Set(uploaded_bytes),
            created_at: Set(created_at),
            updated_at: Set(updated_at),
        }
        .insert(&store.database)
        .await?;
        Ok(artifact_id)
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
