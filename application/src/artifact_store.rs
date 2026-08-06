//! The §14.3 firmware artifact upload store.
//!
//! Design section 14.3 turns a firmware update into: upload the artifact
//! bytes, compute the SHA-256 digest, and save the [`Artifact`] before any
//! BMC is contacted. This use case is the upload half of that rule: it
//! declares the artifact manifest, appends base64-encoded byte ranges to the
//! on-disk file strictly in order, and verifies the stored file's digest at
//! `finalize` before the artifact may become `Ready`.
//!
//! # Why the file I/O lives here and not in persistence
//!
//! The persistence boundary derives the deterministic on-disk location
//! ([`ArtifactRepository::artifact_file_path`]) but performs no file I/O:
//! per §7.2 the domain carries no OS API, and the persistence crate owns the
//! database, not the artifact bytes. The decoded chunk write and the finalize
//! hash are therefore this use case's job, executed under `spawn_blocking`
//! (§7.8: hashing and large file operations must never block a Tokio
//! worker).
//!
//! # Why no injected clock
//!
//! Every mutation takes `now` as an argument instead of an injected
//! [`Clock`]: the Web handler owns the clock and supplies one instant for the
//! whole request, exactly like the operation submission and Task monitor
//! precedents (`# Why no clock` in `task_monitor.rs`). A clock field would be
//! a second time authority shadowed by the argument.
//!
//! # The upload protocol
//!
//! 1. `create` declares the manifest (name, declared size, expected digest)
//!    and persists an `Uploading` artifact with zero bytes received.
//! 2. `append_chunk` receives one base64-encoded range and writes the decoded
//!    bytes at exactly the current `uploaded_bytes` offset — the resume point
//!    — so holes can never be opened and an interrupted upload resumes by
//!    re-running the remaining chunks (§0.4.0 大文件断点和进度).
//! 3. `finalize` hashes the complete file and compares it with the declared
//!    digest; a match makes the artifact `Ready`, any mismatch or incomplete
//!    upload makes it terminally `Failed` with an explicit reason (§0.4.0
//!    acceptance: 固件上传中断可恢复或明确失败).

use std::{
    error::Error,
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

use base64::{Engine, engine::general_purpose::STANDARD};
use rutilus_domain::{Artifact, ArtifactError, ArtifactId, ArtifactName, ArtifactState, Sha256Hex};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::task::spawn_blocking;

use crate::BoundaryFuture;

/// One chunk's maximum wire size in base64 characters (4 MiB).
///
/// The limit applies to the base64 text, not the decoded bytes, so a client
/// can compute it from the request it is about to send; 4 MiB of base64
/// decode to about 3 MiB of artifact bytes. The bound keeps one request
/// bounded in memory and gives the Web boundary a cheap check before any
/// decoding work.
pub const ARTIFACT_CHUNK_BASE64_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// The persistence boundary of the artifact lifecycle (§9.3, §14.3).
///
/// The five methods mirror the concrete `SqliteStore` surface exactly, so the
/// embedding runtime implements this trait by delegating to its store — the
/// same composition as every other application boundary. The contract:
///
/// - `create_artifact` persists a new manifest and is at-least-once safe
///   (a re-declared identity keeps the stored row, §15.4).
/// - `find_artifact` reads one artifact; `None` for an unknown identity.
/// - `list_artifacts_by_state` lists one lifecycle phase in declaration
///   order; the use case merges the three phases for the inventory.
/// - `update_artifact` advances the persisted progress and state together
///   and refuses regressions, oversized progress, `Ready` before complete,
///   and terminal rows — the persisted-row backstop of the §0.4.0
///   "明确失败" guarantee.
/// - `artifact_file_path` is a pure function of the identity and the store
///   location (no I/O); the use case performs the file I/O under
///   `spawn_blocking` (§7.8).
pub trait ArtifactRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn create_artifact<'a>(
        &'a self,
        artifact: &'a Artifact,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>>;

    fn list_artifacts_by_state(
        &self,
        state: ArtifactState,
    ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>>;

    fn update_artifact(
        &self,
        artifact_id: ArtifactId,
        uploaded_bytes: u64,
        state: ArtifactState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>>;

    fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf;
}

impl<Repository> ArtifactRepository for &Repository
where
    Repository: ArtifactRepository + ?Sized,
{
    type Error = Repository::Error;

    fn create_artifact<'a>(
        &'a self,
        artifact: &'a Artifact,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::create_artifact(*self, artifact)
    }

    fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
        Repository::find_artifact(*self, artifact_id)
    }

    fn list_artifacts_by_state(
        &self,
        state: ArtifactState,
    ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
        Repository::list_artifacts_by_state(*self, state)
    }

    fn update_artifact(
        &self,
        artifact_id: ArtifactId,
        uploaded_bytes: u64,
        state: ArtifactState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Repository::update_artifact(*self, artifact_id, uploaded_bytes, state, occurred_at)
    }

    fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
        Repository::artifact_file_path(*self, artifact_id)
    }
}

/// The upload progress of one artifact: the resume offset for the next chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactProgress {
    artifact_id: ArtifactId,
    uploaded_bytes: u64,
    size_bytes: u64,
}

impl ArtifactProgress {
    #[must_use]
    pub const fn new(artifact_id: ArtifactId, uploaded_bytes: u64, size_bytes: u64) -> Self {
        Self {
            artifact_id,
            uploaded_bytes,
            size_bytes,
        }
    }

    #[must_use]
    pub const fn artifact_id(&self) -> ArtifactId {
        self.artifact_id
    }

    /// Returns the bytes received so far; the offset the next chunk must
    /// carry to continue an interrupted upload.
    #[must_use]
    pub const fn uploaded_bytes(&self) -> u64 {
        self.uploaded_bytes
    }

    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
}

/// Drives one artifact from declaration to `Ready` (§14.3).
pub struct ArtifactStore<Repository> {
    repository: Repository,
}

impl<Repository> ArtifactStore<Repository>
where
    Repository: ArtifactRepository,
{
    #[must_use]
    pub const fn new(repository: Repository) -> Self {
        Self { repository }
    }

    /// Declares a new artifact manifest before any byte is transferred.
    ///
    /// `name` and `sha256` are validated and normalized by their domain
    /// types; `size_bytes` must be positive — a zero-byte firmware file is a
    /// client error, never a valid §14.3 update (the domain still models
    /// zero-size artifacts so persistence can restore any stored row). The
    /// artifact starts `Uploading` with zero bytes received, and `now` is the
    /// manifest's creation and update time.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::InvalidName`] for an unusable label,
    /// [`ArtifactStoreError::InvalidSha256`] for an unusable digest,
    /// [`ArtifactStoreError::ZeroSize`] for a zero-byte declaration, or
    /// [`ArtifactStoreError::Repository`] when the manifest cannot be
    /// persisted.
    pub async fn create(
        &self,
        name: &str,
        size_bytes: u64,
        sha256: &str,
        now: OffsetDateTime,
    ) -> Result<Artifact, ArtifactStoreError<Repository::Error>> {
        if size_bytes == 0 {
            return Err(ArtifactStoreError::ZeroSize);
        }
        let name = ArtifactName::parse(name).map_err(ArtifactStoreError::InvalidName)?;
        let sha256 = Sha256Hex::parse(sha256).map_err(ArtifactStoreError::InvalidSha256)?;
        let artifact = Artifact::new(ArtifactId::generate(), name, size_bytes, sha256, now);
        self.repository
            .create_artifact(&artifact)
            .await
            .map_err(ArtifactStoreError::Repository)?;
        Ok(artifact)
    }

    /// Receives one base64-encoded byte range of the artifact file.
    ///
    /// # The offset discipline (why strict ordering)
    ///
    /// The chunk's `offset` is compared with the persisted `uploaded_bytes`,
    /// the single resume point:
    ///
    /// - `offset < uploaded_bytes`: the range is already received. The
    ///   payload is ignored and the current progress returned unchanged — the
    ///   §15.4 at-least-once retransmission discipline, so a chunk whose
    ///   acknowledgement was lost can be sent again without corrupting the
    ///   file. The retransmitted payload is only checked for well-formedness
    ///   (wire size and base64), never compared byte-for-byte with the stored
    ///   content: comparison would re-read the file on every retry, and the
    ///   finalize SHA-256 check is the single end-to-end integrity gate.
    /// - `offset == uploaded_bytes`: the exact continuation; the decoded
    ///   bytes are written to the file and the progress advances.
    /// - A non-empty payload with `offset > uploaded_bytes` is refused as
    ///   out of order. Accepting it would open a hole that no later step
    ///   could distinguish from a gap, so the protocol never creates one.
    ///
    /// An empty payload is a no-op at any offset: it is acknowledged with the
    /// current progress before the offset discipline applies, because
    /// nothing can be written and no hole can be opened by it.
    ///
    /// The file is written before the row advances: if the row update fails
    /// after a successful write, the retry simply re-writes the same range
    /// (the client always resends the same source bytes for an offset), and
    /// a torn file can only surface as a clean `FinalizeFailed` verdict.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::NotFound`] for an unknown id,
    /// [`ArtifactStoreError::NotUploading`] when the artifact already
    /// finished, [`ArtifactStoreError::ChunkTooLarge`] when the base64 text
    /// exceeds [`ARTIFACT_CHUNK_BASE64_MAX_BYTES`],
    /// [`ArtifactStoreError::InvalidBase64`] for malformed base64,
    /// [`ArtifactStoreError::OutOfOrder`] for a non-empty payload whose
    /// offset lies beyond the current progress,
    /// [`ArtifactStoreError::ChunkExceedsSize`] when the range
    /// would push the file past the declared size,
    /// [`ArtifactStoreError::File`] when the file cannot be written, or
    /// [`ArtifactStoreError::Repository`] when the progress cannot be
    /// persisted.
    pub async fn append_chunk(
        &self,
        artifact_id: ArtifactId,
        offset: u64,
        data_base64: &str,
        now: OffsetDateTime,
    ) -> Result<ArtifactProgress, ArtifactStoreError<Repository::Error>> {
        let artifact = self
            .repository
            .find_artifact(artifact_id)
            .await
            .map_err(ArtifactStoreError::Repository)?
            .ok_or(ArtifactStoreError::NotFound { artifact_id })?;
        if artifact.state().is_terminal() {
            return Err(ArtifactStoreError::NotUploading {
                artifact_id,
                state: artifact.state(),
            });
        }
        let requested = u64::try_from(data_base64.len()).unwrap_or(u64::MAX);
        if requested > ARTIFACT_CHUNK_BASE64_MAX_BYTES {
            return Err(ArtifactStoreError::ChunkTooLarge {
                requested,
                maximum: ARTIFACT_CHUNK_BASE64_MAX_BYTES,
            });
        }
        let decoded = STANDARD
            .decode(data_base64)
            .map_err(ArtifactStoreError::InvalidBase64)?;
        if decoded.is_empty() {
            // An empty range changes nothing; acknowledge the current resume
            // point so the client stays in lock-step with the server.
            return Ok(progress_of(&artifact));
        }
        if offset < artifact.uploaded_bytes() {
            // At-least-once retransmission of an already-received range
            // (§15.4): ignore the payload, acknowledge the current progress.
            return Ok(progress_of(&artifact));
        }
        if offset > artifact.uploaded_bytes() {
            return Err(ArtifactStoreError::OutOfOrder {
                offset,
                uploaded_bytes: artifact.uploaded_bytes(),
            });
        }
        let chunk_bytes = decoded.len() as u64;
        let Some(end) = offset.checked_add(chunk_bytes) else {
            return Err(ArtifactStoreError::ChunkExceedsSize {
                offset,
                chunk: chunk_bytes,
                size: artifact.size_bytes(),
            });
        };
        if end > artifact.size_bytes() {
            return Err(ArtifactStoreError::ChunkExceedsSize {
                offset,
                chunk: chunk_bytes,
                size: artifact.size_bytes(),
            });
        }
        let path = self.repository.artifact_file_path(artifact_id);
        write_chunk(path, offset, decoded)
            .await
            .map_err(ArtifactStoreError::File)?;
        let mut artifact = artifact;
        artifact
            .record_bytes_received(chunk_bytes)
            .map_err(ArtifactStoreError::Domain)?;
        self.repository
            .update_artifact(
                artifact_id,
                artifact.uploaded_bytes(),
                ArtifactState::Uploading,
                now,
            )
            .await
            .map_err(ArtifactStoreError::Repository)?;
        Ok(progress_of(&artifact))
    }

    /// Verifies the stored file against the declared digest (§14.3).
    ///
    /// A complete, digest-matching file makes the artifact `Ready`. Anything
    /// else makes it terminally `Failed` with the exact reason, so an
    /// interrupted or corrupted upload ends in an explicit verdict (§0.4.0
    /// acceptance: 固件上传中断可恢复或明确失败) instead of reaching a BMC.
    ///
    /// - An already `Ready` artifact finalizes again as an idempotent success
    ///   (the §15.4 duplicate-acceptance discipline).
    /// - An already `Failed` artifact is refused with
    ///   [`ArtifactStoreError::AlreadyFailed`]: the client must declare a new
    ///   artifact rather than retry a terminal verdict.
    /// - An incomplete upload (fewer bytes received than declared) is an
    ///   explicit give-up signal and fails the artifact.
    /// - A complete upload whose file digest differs from the declaration
    ///   fails the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::NotFound`] for an unknown id,
    /// [`ArtifactStoreError::AlreadyFailed`] for a previously failed
    /// artifact, [`ArtifactStoreError::FinalizeFailed`] (carrying the
    /// terminal `Failed` projection and the reason) when verification cannot
    /// pass, [`ArtifactStoreError::File`] when the stored file cannot be read
    /// (an environmental failure: the artifact is left unchanged so the
    /// client can retry), or [`ArtifactStoreError::Repository`] when the
    /// verdict cannot be persisted.
    pub async fn finalize(
        &self,
        artifact_id: ArtifactId,
        now: OffsetDateTime,
    ) -> Result<Artifact, ArtifactStoreError<Repository::Error>> {
        let artifact = self
            .repository
            .find_artifact(artifact_id)
            .await
            .map_err(ArtifactStoreError::Repository)?
            .ok_or(ArtifactStoreError::NotFound { artifact_id })?;
        match artifact.state() {
            ArtifactState::Ready => return Ok(artifact),
            ArtifactState::Failed => {
                return Err(ArtifactStoreError::AlreadyFailed { artifact_id });
            }
            ArtifactState::Uploading => {}
        }
        if artifact.uploaded_bytes() < artifact.size_bytes() {
            let reason = format!(
                "upload is incomplete: {} of {} bytes received",
                artifact.uploaded_bytes(),
                artifact.size_bytes()
            );
            return self.fail(artifact, now, reason).await;
        }
        let path = self.repository.artifact_file_path(artifact_id);
        let computed = hash_file(path).await.map_err(ArtifactStoreError::File)?;
        if computed != artifact.sha256() {
            let reason = format!(
                "SHA-256 verification failed: expected {}, computed {}",
                artifact.sha256(),
                computed
            );
            return self.fail(artifact, now, reason).await;
        }
        let mut artifact = artifact;
        artifact.mark_ready().map_err(ArtifactStoreError::Domain)?;
        self.repository
            .update_artifact(
                artifact_id,
                artifact.uploaded_bytes(),
                ArtifactState::Ready,
                now,
            )
            .await
            .map_err(ArtifactStoreError::Repository)?;
        // Rehydrate the verdict with the persisted update time: the domain
        // entity's `updated_at` only changes at the persistence boundary, so
        // the returned projection must carry `now`, exactly like the stored
        // row. The reconstruction refuses a caller clock that predates the
        // artifact creation — the hazard that would otherwise persist an
        // inverted timeline the next read cannot restore.
        Artifact::try_from_parts(
            artifact.id(),
            artifact.name().clone(),
            artifact.size_bytes(),
            artifact.sha256(),
            ArtifactState::Ready,
            artifact.uploaded_bytes(),
            artifact.created_at(),
            now,
        )
        .map_err(ArtifactStoreError::Restore)
    }

    /// Lists every artifact in declaration order across all three phases.
    ///
    /// The persistence boundary lists per state (§0.4.0 recovery scan), so
    /// the inventory use case merges the three state listings; each listing
    /// is already ordered by creation time and identity, and an artifact can
    /// only ever be in one phase, so the merged result is deterministic
    /// (§9.3 artifact inventory projection).
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::Repository`] when any phase listing
    /// fails.
    pub async fn list(&self) -> Result<Vec<Artifact>, ArtifactStoreError<Repository::Error>> {
        let mut artifacts = Vec::new();
        for state in [
            ArtifactState::Uploading,
            ArtifactState::Ready,
            ArtifactState::Failed,
        ] {
            artifacts.extend(
                self.repository
                    .list_artifacts_by_state(state)
                    .await
                    .map_err(ArtifactStoreError::Repository)?,
            );
        }
        artifacts.sort_by_key(|artifact| (artifact.created_at(), artifact.id()));
        Ok(artifacts)
    }

    /// Reads one artifact by id; `None` when the id is unknown.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::Repository`] when the read fails.
    pub async fn find(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<Option<Artifact>, ArtifactStoreError<Repository::Error>> {
        self.repository
            .find_artifact(artifact_id)
            .await
            .map_err(ArtifactStoreError::Repository)
    }

    /// Reports one artifact's upload progress; the resume point for the next
    /// chunk of an interrupted upload.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactStoreError::NotFound`] for an unknown id, or
    /// [`ArtifactStoreError::Repository`] when the read fails.
    pub async fn progress(
        &self,
        artifact_id: ArtifactId,
    ) -> Result<ArtifactProgress, ArtifactStoreError<Repository::Error>> {
        let artifact = self
            .repository
            .find_artifact(artifact_id)
            .await
            .map_err(ArtifactStoreError::Repository)?
            .ok_or(ArtifactStoreError::NotFound { artifact_id })?;
        Ok(progress_of(&artifact))
    }

    /// Marks the artifact terminally failed and returns the failure verdict.
    ///
    /// The caller has already established that the artifact is `Uploading`
    /// and must fail; the reason string is the verdict's human-readable
    /// explanation carried to the client with the terminal projection. The
    /// carried projection rehydrates with `now` as the update time, exactly
    /// like the persisted row.
    async fn fail(
        &self,
        artifact: Artifact,
        now: OffsetDateTime,
        reason: String,
    ) -> Result<Artifact, ArtifactStoreError<Repository::Error>> {
        let mut failed = artifact;
        failed.mark_failed().map_err(ArtifactStoreError::Domain)?;
        let artifact_id = failed.id();
        self.repository
            .update_artifact(
                artifact_id,
                failed.uploaded_bytes(),
                ArtifactState::Failed,
                now,
            )
            .await
            .map_err(ArtifactStoreError::Repository)?;
        let failed = Artifact::try_from_parts(
            failed.id(),
            failed.name().clone(),
            failed.size_bytes(),
            failed.sha256(),
            ArtifactState::Failed,
            failed.uploaded_bytes(),
            failed.created_at(),
            now,
        )
        .map_err(ArtifactStoreError::Restore)?;
        Err(ArtifactStoreError::FinalizeFailed {
            artifact_id,
            artifact: failed,
            reason,
        })
    }
}

fn progress_of(artifact: &Artifact) -> ArtifactProgress {
    ArtifactProgress::new(
        artifact.id(),
        artifact.uploaded_bytes(),
        artifact.size_bytes(),
    )
}

/// Writes one decoded chunk at its exact offset under `spawn_blocking`
/// (§7.8).
///
/// The artifact directory is created on demand — the manifest may outlive
/// any file, and the first chunk is the moment the bytes exist. The write
/// seeks to the offset and overwrites exactly that range, so a retried range
/// (the at-least-once retransmission of the protocol) lands on the same
/// bytes instead of duplicating them.
async fn write_chunk(path: PathBuf, offset: u64, data: Vec<u8>) -> Result<(), io::Error> {
    spawn_blocking(move || {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(&data)
    })
    .await
    .map_err(io::Error::other)?
}

/// Hashes one artifact file under `spawn_blocking` (§7.8) and returns the
/// digest in the domain's canonical form for comparison with the declared
/// value.
async fn hash_file(path: PathBuf) -> Result<Sha256Hex, io::Error> {
    spawn_blocking(move || {
        let mut file = fs::File::open(&path)?;
        let mut hasher = Sha256::new();
        // Heap-buffered reads: the buffer must stay off the Tokio worker
        // stack (§7.8), and a heap buffer keeps the worker's stack usage
        // independent of the chosen read size.
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(Sha256Hex::from_bytes(hasher.finalize().into()))
    })
    .await
    .map_err(io::Error::other)?
}

/// A controlled failure while declaring, uploading, or finalizing one
/// artifact (§14.3).
///
/// The generic parameter is the repository boundary's error type, so every
/// persistence failure stays reachable as the source of the chain.
#[derive(Debug, Error)]
pub enum ArtifactStoreError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    /// The artifact identity is unknown.
    #[error("artifact {artifact_id} was not found")]
    NotFound { artifact_id: ArtifactId },
    /// The declared label cannot be used.
    #[error("artifact name is invalid: {0}")]
    InvalidName(#[source] rutilus_domain::ArtifactNameError),
    /// The declared digest cannot be used.
    #[error("artifact SHA-256 digest is invalid: {0}")]
    InvalidSha256(#[source] rutilus_domain::Sha256HexParseError),
    /// A firmware artifact must declare at least one byte.
    #[error("artifact size must be at least one byte")]
    ZeroSize,
    /// The chunk text is not valid RFC 4648 §4 base64.
    #[error("artifact chunk is not valid base64: {0}")]
    InvalidBase64(#[source] base64::DecodeError),
    /// The chunk text exceeds the per-chunk wire limit.
    #[error(
        "artifact chunk of {requested} base64 characters exceeds the limit of {maximum} characters"
    )]
    ChunkTooLarge { requested: u64, maximum: u64 },
    /// The chunk would push the file past the declared size.
    #[error(
        "artifact chunk at offset {offset} of {chunk} bytes exceeds the declared size of {size} bytes"
    )]
    ChunkExceedsSize { offset: u64, chunk: u64, size: u64 },
    /// The chunk starts beyond the current progress; accepting it would open
    /// a hole in the file.
    #[error(
        "artifact chunk at offset {offset} is out of order; the next offset must be {uploaded_bytes}"
    )]
    OutOfOrder { offset: u64, uploaded_bytes: u64 },
    /// The artifact already finished and no longer accepts chunks.
    #[error("artifact {artifact_id} is in state {state} and no longer accepts chunks")]
    NotUploading {
        artifact_id: ArtifactId,
        state: ArtifactState,
    },
    /// Finalize was attempted on an artifact that already failed; the
    /// client must declare a new artifact.
    #[error("artifact {artifact_id} already failed; declare a new artifact")]
    AlreadyFailed { artifact_id: ArtifactId },
    /// Finalize could not validate the received bytes; the artifact is now
    /// terminally `Failed` and carries the exact reason.
    #[error("artifact {artifact_id} finalize failed: {reason}")]
    FinalizeFailed {
        artifact_id: ArtifactId,
        artifact: Artifact,
        reason: String,
    },
    /// The domain lifecycle refused a step the use case pre-checked.
    #[error("artifact lifecycle refused the step: {0}")]
    Domain(#[source] ArtifactError),
    /// The verdict could not be rehydrated with the caller's update time.
    #[error("artifact verdict could not be rehydrated: {0}")]
    Restore(#[source] rutilus_domain::ArtifactRestoreError),
    /// The artifact file could not be read or written.
    #[error("artifact file operation failed: {0}")]
    File(#[source] io::Error),
    /// The repository boundary failed.
    #[error("artifact persistence failed: {0}")]
    Repository(#[source] RepositoryError),
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, sync::Mutex};

    use rutilus_domain::{ArtifactNameError, Sha256HexParseError};
    use sha2::{Digest as _, Sha256};
    use thiserror::Error as ThisError;
    use time::Duration;

    use super::*;
    use crate::BoundaryFuture;

    /// One valid 64-character digest used when the test cares about the
    /// lifecycle rather than the hash content.
    fn declared_digest() -> Sha256Hex {
        Sha256Hex::from_bytes([0xAB; 32])
    }

    /// The digest of `content`, exactly what a finalize must verify.
    fn digest_of(content: &[u8]) -> Sha256Hex {
        Sha256Hex::from_bytes(Sha256::digest(content).into())
    }

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
    enum MockError {
        #[error("mock artifact state is unavailable")]
        Lock,
        #[error("simulated artifact persistence failure")]
        Repository,
        #[error("mock artifact was not found")]
        NotFound,
        #[error("mock artifact is already terminal")]
        TerminalConflict,
        #[error("mock artifact progress regressed")]
        Regression,
        #[error("mock artifact progress exceeds its declared size")]
        ExceedsSize,
        #[error("mock artifact cannot become ready before its upload is complete")]
        IncompleteUpload,
        #[error("mock artifact row is corrupt")]
        Corrupt,
    }

    /// In-memory manifest fake behind the [`ArtifactRepository`] boundary
    /// with real file I/O under a temporary directory, mirroring the
    /// `SqliteStore` contract: at-least-once creation, per-phase listing in
    /// declaration order, and an update that refuses terminal rows, progress
    /// regression, oversized progress, and `Ready` before completeness.
    struct MockRepository {
        rows: Mutex<HashMap<ArtifactId, Artifact>>,
        _directory: tempfile::TempDir,
        artifact_directory: PathBuf,
        fail: bool,
    }

    impl MockRepository {
        fn new() -> Result<Self, io::Error> {
            let directory = tempfile::tempdir()?;
            let artifact_directory = directory.path().join("artifacts");
            Ok(Self {
                rows: Mutex::new(HashMap::new()),
                _directory: directory,
                artifact_directory,
                fail: false,
            })
        }

        /// A fake whose artifact directory chain is blocked by a regular
        /// file, so every write fails like a full or unwritable disk.
        fn blocked() -> Result<Self, io::Error> {
            let directory = tempfile::tempdir()?;
            let blocker = directory.path().join("blocker");
            std::fs::write(&blocker, b"not a directory")?;
            Ok(Self {
                rows: Mutex::new(HashMap::new()),
                _directory: directory,
                artifact_directory: blocker.join("artifacts"),
                fail: false,
            })
        }

        fn failing() -> Result<Self, io::Error> {
            Ok(Self {
                fail: true,
                ..Self::new()?
            })
        }

        fn stored(&self, artifact_id: ArtifactId) -> Option<Artifact> {
            self.rows.lock().ok()?.get(&artifact_id).cloned()
        }

        fn file_path(&self, artifact_id: ArtifactId) -> PathBuf {
            self.artifact_directory.join(format!("{artifact_id}.bin"))
        }
    }

    impl ArtifactRepository for MockRepository {
        type Error = MockError;

        fn create_artifact<'a>(
            &'a self,
            artifact: &'a Artifact,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                if self.fail {
                    return Err(MockError::Repository);
                }
                let mut rows = self.rows.lock().map_err(|_| MockError::Lock)?;
                rows.entry(artifact.id())
                    .or_insert_with(|| artifact.clone());
                Ok(())
            })
        }

        fn find_artifact(
            &self,
            artifact_id: ArtifactId,
        ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
            Box::pin(async move {
                if self.fail {
                    return Err(MockError::Repository);
                }
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .get(&artifact_id)
                    .cloned())
            })
        }

        fn list_artifacts_by_state(
            &self,
            state: ArtifactState,
        ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
            Box::pin(async move {
                if self.fail {
                    return Err(MockError::Repository);
                }
                let rows = self.rows.lock().map_err(|_| MockError::Lock)?;
                let mut artifacts: Vec<_> = rows
                    .values()
                    .filter(|artifact| artifact.state() == state)
                    .cloned()
                    .collect();
                artifacts.sort_by_key(|artifact| (artifact.created_at(), artifact.id()));
                Ok(artifacts)
            })
        }

        fn update_artifact(
            &self,
            artifact_id: ArtifactId,
            uploaded_bytes: u64,
            state: ArtifactState,
            occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                if self.fail {
                    return Err(MockError::Repository);
                }
                let mut rows = self.rows.lock().map_err(|_| MockError::Lock)?;
                let current = rows.get(&artifact_id).ok_or(MockError::NotFound)?.clone();
                if current.state().is_terminal() {
                    return Err(MockError::TerminalConflict);
                }
                if uploaded_bytes < current.uploaded_bytes() {
                    return Err(MockError::Regression);
                }
                if uploaded_bytes > current.size_bytes() {
                    return Err(MockError::ExceedsSize);
                }
                if state == ArtifactState::Ready && uploaded_bytes != current.size_bytes() {
                    return Err(MockError::IncompleteUpload);
                }
                let updated = Artifact::try_from_parts(
                    current.id(),
                    current.name().clone(),
                    current.size_bytes(),
                    current.sha256(),
                    state,
                    uploaded_bytes,
                    current.created_at(),
                    occurred_at,
                )
                .map_err(|_| MockError::Corrupt)?;
                rows.insert(artifact_id, updated);
                Ok(())
            })
        }

        fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
            self.file_path(artifact_id)
        }
    }

    /// One fresh fake repository; every test composes its own store so the
    /// borrow of the repository outlives the store's use.
    fn created_repository() -> Result<MockRepository, io::Error> {
        MockRepository::new()
    }

    /// Uploads `content` in 3-byte chunks and returns the repository and the
    /// artifact identity, so tests can compose a store and finalize or query
    /// against the exact upload.
    async fn uploaded_artifact(
        content: &[u8],
    ) -> Result<(MockRepository, ArtifactId), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create(
                "firmware.bin",
                content.len() as u64,
                &digest_of(content).to_string(),
                now(),
            )
            .await?;
        let artifact_id = artifact.id();
        for (offset, chunk) in content.chunks(3).enumerate() {
            store
                .append_chunk(
                    artifact_id,
                    (offset * 3) as u64,
                    &STANDARD.encode(chunk),
                    now() + Duration::SECOND,
                )
                .await?;
        }
        Ok((repository, artifact_id))
    }

    #[tokio::test]
    async fn create_declares_an_uploading_artifact_with_zero_bytes() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let created_at = now();

        let artifact = store
            .create(
                "  BMC firmware 2024  ",
                6,
                &declared_digest().to_string(),
                created_at,
            )
            .await?;

        assert_eq!(artifact.state(), ArtifactState::Uploading);
        assert_eq!(artifact.uploaded_bytes(), 0);
        assert_eq!(artifact.size_bytes(), 6);
        assert_eq!(artifact.name().as_str(), "BMC firmware 2024");
        assert_eq!(artifact.sha256(), declared_digest());
        assert_eq!(artifact.created_at(), created_at);
        assert_eq!(artifact.updated_at(), created_at);
        assert_eq!(
            repository
                .stored(artifact.id())
                .as_ref()
                .map(Artifact::state),
            Some(ArtifactState::Uploading)
        );
        Ok(())
    }

    #[tokio::test]
    async fn create_rejects_invalid_declarations_without_persisting() -> Result<(), Box<dyn Error>>
    {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let digest = declared_digest().to_string();

        assert!(matches!(
            store.create("  ", 6, &digest, now()).await,
            Err(ArtifactStoreError::InvalidName(ArtifactNameError::Empty))
        ));
        assert!(matches!(
            store.create("firmware.bin", 6, "not-a-digest", now()).await,
            Err(ArtifactStoreError::InvalidSha256(
                Sha256HexParseError::InvalidLength { .. }
            ))
        ));
        assert!(matches!(
            store.create("firmware.bin", 0, &digest, now()).await,
            Err(ArtifactStoreError::ZeroSize)
        ));
        assert!(
            repository
                .rows
                .lock()
                .map_err(|_| MockError::Lock)?
                .is_empty(),
            "a refused declaration must not persist a manifest"
        );
        Ok(())
    }

    #[tokio::test]
    async fn append_chunk_decodes_writes_and_advances_progress() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();
        let written_at = now() + Duration::SECOND;

        let progress = store
            .append_chunk(artifact_id, 0, "aGVsbG8h", written_at)
            .await?;

        assert_eq!(progress, ArtifactProgress::new(artifact_id, 6, 6));
        assert_eq!(std::fs::read(repository.file_path(artifact_id))?, b"hello!");
        let stored = repository
            .stored(artifact_id)
            .ok_or_else(|| std::io::Error::other("stored artifact is missing"))?;
        assert_eq!(stored.uploaded_bytes(), 6);
        assert_eq!(stored.updated_at(), written_at);
        Ok(())
    }

    #[tokio::test]
    async fn chunk_writes_land_exactly_at_their_offset() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();

        store
            .append_chunk(artifact_id, 0, "aGVs", now() + Duration::SECOND)
            .await?;
        let progress = store
            .append_chunk(artifact_id, 3, "bG8h", now() + Duration::SECOND)
            .await?;

        assert_eq!(progress, ArtifactProgress::new(artifact_id, 6, 6));
        assert_eq!(std::fs::read(repository.file_path(artifact_id))?, b"hello!");
        Ok(())
    }

    #[tokio::test]
    async fn retransmitted_ranges_are_ignored_with_the_current_progress()
    -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();
        store
            .append_chunk(artifact_id, 0, "aGVs", now() + Duration::SECOND)
            .await?;

        // The acknowledgement was lost, so the client sends the same range
        // again — with different payload bytes on purpose to prove the
        // retransmission is ignored, not compared or rewritten.
        let progress = store
            .append_chunk(artifact_id, 0, "SEVMRkla", now() + Duration::SECOND)
            .await?;

        assert_eq!(progress, ArtifactProgress::new(artifact_id, 3, 6));
        assert_eq!(
            std::fs::read(repository.file_path(artifact_id))?,
            b"hel",
            "a retransmitted range must never overwrite the stored bytes"
        );
        Ok(())
    }

    #[tokio::test]
    async fn out_of_order_chunks_are_rejected_without_touching_the_file()
    -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();

        assert!(matches!(
            store.append_chunk(artifact_id, 4, "bG8h", now()).await,
            Err(ArtifactStoreError::OutOfOrder {
                offset: 4,
                uploaded_bytes: 0,
            })
        ));
        assert!(
            !repository.file_path(artifact_id).exists(),
            "a rejected chunk must not create the file"
        );

        store.append_chunk(artifact_id, 0, "aGVs", now()).await?;
        assert!(matches!(
            store.append_chunk(artifact_id, 5, "IQ==", now()).await,
            Err(ArtifactStoreError::OutOfOrder {
                offset: 5,
                uploaded_bytes: 3,
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn chunks_cannot_exceed_the_declared_size() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();

        assert!(matches!(
            store
                .append_chunk(artifact_id, 0, &STANDARD.encode(b"hello!!"), now())
                .await,
            Err(ArtifactStoreError::ChunkExceedsSize {
                offset: 0,
                chunk: 7,
                size: 6,
            })
        ));
        // A range starting at the exact continuation but crossing the end of
        // the declared size.
        store.append_chunk(artifact_id, 0, "aGVs", now()).await?;
        assert!(matches!(
            store
                .append_chunk(artifact_id, 3, &STANDARD.encode(b"world"), now())
                .await,
            Err(ArtifactStoreError::ChunkExceedsSize {
                offset: 3,
                chunk: 5,
                size: 6,
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn chunks_cannot_exceed_the_wire_limit() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();
        let oversized = "A".repeat(usize::try_from(ARTIFACT_CHUNK_BASE64_MAX_BYTES)? + 1);

        assert!(matches!(
            store.append_chunk(artifact_id, 0, &oversized, now()).await,
            Err(ArtifactStoreError::ChunkTooLarge { requested, maximum })
                if requested == ARTIFACT_CHUNK_BASE64_MAX_BYTES + 1
                    && maximum == ARTIFACT_CHUNK_BASE64_MAX_BYTES
        ));
        Ok(())
    }

    #[tokio::test]
    async fn malformed_base64_and_empty_chunks_are_handled() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();

        assert!(matches!(
            store
                .append_chunk(artifact_id, 0, "!!!not-base64!!!", now())
                .await,
            Err(ArtifactStoreError::InvalidBase64(_))
        ));
        let progress = store.append_chunk(artifact_id, 0, "", now()).await?;
        assert_eq!(
            progress,
            ArtifactProgress::new(artifact_id, 0, 6),
            "an empty range is a no-op that acknowledges the resume point"
        );
        assert!(!repository.file_path(artifact_id).exists());
        Ok(())
    }

    #[tokio::test]
    async fn finalize_marks_ready_when_the_digest_matches() -> Result<(), Box<dyn Error>> {
        let (repository, artifact_id) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);
        let finalized_at = now() + Duration::SECOND * 3;

        let artifact = store.finalize(artifact_id, finalized_at).await?;

        assert_eq!(artifact.state(), ArtifactState::Ready);
        assert_eq!(artifact.uploaded_bytes(), 6);
        assert_eq!(artifact.updated_at(), finalized_at);
        assert_eq!(
            repository.stored(artifact_id).map(|stored| stored.state()),
            Some(ArtifactState::Ready)
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_fails_an_artifact_whose_digest_differs() -> Result<(), Box<dyn Error>> {
        let (repository, _) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("wrong.bin", 6, &declared_digest().to_string(), now())
            .await?;
        let wrong_id = artifact.id();
        store
            .append_chunk(
                wrong_id,
                0,
                &STANDARD.encode(b"hello!"),
                now() + Duration::SECOND,
            )
            .await?;

        let error = store
            .finalize(wrong_id, now() + Duration::SECOND * 2)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("mismatched finalize must fail"))?;

        let ArtifactStoreError::FinalizeFailed {
            artifact_id: failed_id,
            artifact: failed,
            reason,
        } = error
        else {
            return Err(std::io::Error::other("unexpected finalize verdict").into());
        };
        assert_eq!(failed_id, wrong_id);
        assert_eq!(failed.state(), ArtifactState::Failed);
        assert!(reason.contains("SHA-256 verification failed"));
        assert_eq!(
            repository.stored(wrong_id).map(|stored| stored.state()),
            Some(ArtifactState::Failed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_fails_incomplete_uploads_explicitly() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();
        store
            .append_chunk(artifact_id, 0, "aGVs", now() + Duration::SECOND)
            .await?;

        let error = store
            .finalize(artifact_id, now() + Duration::SECOND * 2)
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("incomplete finalize must fail"))?;

        let ArtifactStoreError::FinalizeFailed {
            reason, artifact, ..
        } = error
        else {
            return Err(std::io::Error::other("unexpected finalize verdict").into());
        };
        assert_eq!(artifact.state(), ArtifactState::Failed);
        assert!(reason.contains("3 of 6 bytes received"));
        assert_eq!(
            repository.stored(artifact_id).map(|stored| stored.state()),
            Some(ArtifactState::Failed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn finalize_is_idempotent_when_ready_and_refuses_when_failed()
    -> Result<(), Box<dyn Error>> {
        let (repository, artifact_id) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);
        let finalized_at = now() + Duration::SECOND * 3;

        let first = store.finalize(artifact_id, finalized_at).await?;
        let second = store
            .finalize(artifact_id, finalized_at + Duration::SECOND)
            .await?;
        assert_eq!(first, second);
        assert_eq!(second.state(), ArtifactState::Ready);

        let (repository, _) = uploaded_artifact(b"wrong!").await?;
        let store = ArtifactStore::new(&repository);
        let failed = store
            .create("failed.bin", 6, &declared_digest().to_string(), now())
            .await?;
        let failed_id = failed.id();
        store
            .append_chunk(
                failed_id,
                0,
                &STANDARD.encode(b"wrong!"),
                now() + Duration::SECOND,
            )
            .await?;
        assert!(
            store
                .finalize(failed_id, now() + Duration::SECOND * 2)
                .await
                .is_err()
        );
        assert!(matches!(
            store.finalize(failed_id, now() + Duration::SECOND * 3).await,
            Err(ArtifactStoreError::AlreadyFailed { artifact_id })
                if artifact_id == failed_id
        ));
        Ok(())
    }

    #[tokio::test]
    async fn terminal_artifacts_reject_chunks() -> Result<(), Box<dyn Error>> {
        let (repository, ready_id) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);
        store
            .finalize(ready_id, now() + Duration::SECOND * 3)
            .await?;
        assert!(matches!(
            store.append_chunk(ready_id, 6, "", now() + Duration::SECOND * 4).await,
            Err(ArtifactStoreError::NotUploading {
                artifact_id: id,
                state: ArtifactState::Ready,
            }) if id == ready_id
        ));

        let (repository, _) = uploaded_artifact(b"wrong!").await?;
        let store = ArtifactStore::new(&repository);
        let failed = store
            .create("failed.bin", 6, &declared_digest().to_string(), now())
            .await?;
        let failed_id = failed.id();
        store
            .append_chunk(
                failed_id,
                0,
                &STANDARD.encode(b"wrong!"),
                now() + Duration::SECOND,
            )
            .await?;
        assert!(
            store
                .finalize(failed_id, now() + Duration::SECOND * 2)
                .await
                .is_err()
        );
        assert!(matches!(
            store.append_chunk(failed_id, 6, "", now() + Duration::SECOND * 3).await,
            Err(ArtifactStoreError::NotUploading {
                artifact_id: id,
                state: ArtifactState::Failed,
            }) if id == failed_id
        ));
        Ok(())
    }

    #[tokio::test]
    async fn progress_reports_the_resume_offset() -> Result<(), Box<dyn Error>> {
        let (repository, artifact_id) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);

        let progress = store.progress(artifact_id).await?;

        assert_eq!(progress, ArtifactProgress::new(artifact_id, 6, 6));
        assert!(matches!(
            store.progress(ArtifactId::generate()).await,
            Err(ArtifactStoreError::NotFound { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn list_merges_all_phases_in_declaration_order() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let ready = store
            .create("ready.bin", 1, &digest_of(b"x").to_string(), now())
            .await?;
        store
            .append_chunk(
                ready.id(),
                0,
                &STANDARD.encode(b"x"),
                now() + Duration::SECOND,
            )
            .await?;
        store
            .finalize(ready.id(), now() + Duration::SECOND * 2)
            .await?;
        let failed = store
            .create(
                "failed.bin",
                1,
                &digest_of(b"y").to_string(),
                now() + Duration::SECOND,
            )
            .await?;
        store
            .append_chunk(
                failed.id(),
                0,
                &STANDARD.encode(b"y"),
                now() + Duration::SECOND * 2,
            )
            .await?;
        store
            .finalize(failed.id(), now() + Duration::SECOND * 3)
            .await
            .ok();
        let uploading = store
            .create(
                "uploading.bin",
                1,
                &digest_of(b"z").to_string(),
                now() + Duration::SECOND * 2,
            )
            .await?;

        let listed = store.list().await?;
        let ids: Vec<ArtifactId> = listed.iter().map(Artifact::id).collect();
        assert_eq!(
            ids,
            vec![ready.id(), failed.id(), uploading.id()],
            "list must merge the three phases in declaration order"
        );
        Ok(())
    }

    #[tokio::test]
    async fn find_reads_one_artifact() -> Result<(), Box<dyn Error>> {
        let (repository, artifact_id) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);

        let found = store
            .find(artifact_id)
            .await?
            .ok_or_else(|| std::io::Error::other("uploaded artifact must be findable"))?;
        assert_eq!(found.id(), artifact_id);
        assert_eq!(found.uploaded_bytes(), 6);
        assert_eq!(store.find(ArtifactId::generate()).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn unknown_artifacts_are_not_found_everywhere() -> Result<(), Box<dyn Error>> {
        let repository = created_repository()?;
        let store = ArtifactStore::new(&repository);
        let unknown = ArtifactId::generate();

        assert!(matches!(
            store.append_chunk(unknown, 0, "", now()).await,
            Err(ArtifactStoreError::NotFound { artifact_id })
                if artifact_id == unknown
        ));
        assert!(matches!(
            store.finalize(unknown, now()).await,
            Err(ArtifactStoreError::NotFound { artifact_id })
                if artifact_id == unknown
        ));
        assert!(matches!(
            store.progress(unknown).await,
            Err(ArtifactStoreError::NotFound { artifact_id })
                if artifact_id == unknown
        ));
        assert_eq!(store.find(unknown).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn file_write_failures_are_typed_and_leave_the_row_unchanged()
    -> Result<(), Box<dyn Error>> {
        let store = ArtifactStore::new(MockRepository::blocked()?);
        let artifact = store
            .create("firmware.bin", 6, &digest_of(b"hello!").to_string(), now())
            .await?;
        let artifact_id = artifact.id();

        // A regular file blocks the artifact directory, so create_dir_all must
        // fail: no byte is written and no progress is recorded, and the client
        // can retry the same range once the disk is usable again.
        assert!(matches!(
            store
                .append_chunk(artifact_id, 0, "aGVs", now() + Duration::SECOND)
                .await,
            Err(ArtifactStoreError::File(_))
        ));
        assert_eq!(
            store.progress(artifact_id).await?,
            ArtifactProgress::new(artifact_id, 0, 6)
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_files_fail_finalize_without_changing_state() -> Result<(), Box<dyn Error>> {
        let (repository, artifact_id) = uploaded_artifact(b"hello!").await?;
        let store = ArtifactStore::new(&repository);
        std::fs::remove_file(repository.file_path(artifact_id))?;

        assert!(matches!(
            store.finalize(artifact_id, now() + Duration::SECOND).await,
            Err(ArtifactStoreError::File(_))
        ));
        assert_eq!(
            repository.stored(artifact_id).map(|stored| stored.state()),
            Some(ArtifactState::Uploading),
            "an environmental read failure must not burn the artifact"
        );
        Ok(())
    }

    #[tokio::test]
    async fn repository_failures_propagate_as_sources() -> Result<(), Box<dyn Error>> {
        let store = ArtifactStore::new(MockRepository::failing()?);

        let error = store
            .create("firmware.bin", 6, &declared_digest().to_string(), now())
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("create must fail"))?;
        assert!(matches!(
            error,
            ArtifactStoreError::Repository(MockError::Repository)
        ));
        assert!(error.to_string().contains("artifact persistence failed"));
        Ok(())
    }
}
