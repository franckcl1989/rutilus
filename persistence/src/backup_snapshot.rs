//! Consistent `SQLite` snapshots and offline restore (design §20.1/§20.2).
//!
//! §20.1's "pause new write transactions → wait for the current write to
//! finish → close or safely freeze `SQLite` → copy the consistent database →
//! reopen writes" is realized with the store's exclusive write gate: every
//! write repository and `close` already serialize on the one-permit
//! `write_gate` semaphore, so holding the gate pauses new writes and waits
//! for the in-flight transaction to finish. While the gate is held no writer
//! can commit, which is the "safe freeze" alternative the design allows —
//! the pool stays open and readers keep working.
//!
//! The snapshot is the main database file plus the durable WAL sidecar, read
//! into memory while the gate is held. `SQLite` in WAL mode guarantees that a
//! database file plus its full WAL is always a consistent state, and the
//! gate prevents writers from growing the WAL mid-copy. A concurrent
//! automatic checkpoint (triggered by a reader on a large WAL) can still
//! move frames from the WAL into the main file and truncate the WAL; the
//! copy therefore reads the WAL before and after the main file and retries
//! when the two reads differ, so a truncated WAL can never be paired with a
//! main file that missed the checkpointed frames. A bounded retry budget
//! keeps the wait finite.
//!
//! Restore is offline (design §20.2): the caller holds the runtime lock, and
//! [`restore_database_files`] replaces the database and its sidecars through
//! sibling temporary files plus rename, removing any stale WAL and
//! shared-memory index so the restored state cannot replay old frames.
//!
//! Each file is replaced atomically, but the database and its WAL are not a
//! pair-replaceable unit (R6-D-5): a crash between the renames leaves a
//! mixed pair — the new main file beside the old WAL or vice versa — and
//! `SQLite` resolves that silently by discarding the WAL whose salts no
//! longer match the database header, so the restore's WAL-only commits would
//! be lost without a trace. The restore therefore writes a durable
//! "restore in progress" marker (the `<database>-restore-pending` sidecar,
//! holding SHA-256 fingerprints of the snapshot pair and of the live pair)
//! before the first overwrite and removes it only after every file is fully
//! in place. The next [`SqliteStore::open`] finds a surviving marker and
//! verifies the live pair against the recorded fingerprints: a pair that
//! matches the snapshot (the restore completed) or the recorded pre-restore
//! state (the restore never touched the files) is accepted and the marker
//! cleared; anything else is refused as an interrupted restore instead of
//! being opened in a silently mixed state.

use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use rutilus_migration::Migrator;
use sea_orm::{DbErr, EntityTrait};
use sea_orm_migration::MigratorTrait;
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::sync::{AcquireError, OwnedSemaphorePermit};

use crate::{OpenStoreError, SqliteStore};

/// The fixed WAL sidecar suffix `SQLite` uses in WAL journal mode.
const WAL_SIDECAR_SUFFIX: &str = "-wal";
/// The transient shared-memory index sidecar, rebuilt on every open.
const SHM_SIDECAR_SUFFIX: &str = "-shm";
/// The sidecar suffix of the persistent "restore in progress" marker: it
/// exists from the first restore overwrite to the completed pair, and the
/// next open verifies the live files against the fingerprints it records.
const RESTORE_PENDING_SUFFIX: &str = "-restore-pending";
/// The marker's textual state tokens.
const MARKER_ABSENT: &str = "absent";
const MARKER_NONE: &str = "none";
/// Bounded retry budget for a checkpoint racing the snapshot copy.
const SNAPSHOT_RETRY_BUDGET: usize = 4;
/// The migration table name recorded by the default `MigratorTrait`.
const MIGRATION_TABLE_NAME: &str = "seaql_migrations";

/// A byte-exact consistent copy of the `SQLite` database and its WAL.
///
/// The main file alone is not a complete state: recent commits may live only
/// in the WAL. Restore replays the pair exactly as `SQLite` would after a
/// crash, so the snapshot is what the instance will see on its next open.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseSnapshot {
    database: Vec<u8>,
    wal: Option<Vec<u8>>,
}

impl DatabaseSnapshot {
    /// Rebuilds a snapshot from verified entry bytes (restore path).
    ///
    /// The caller is responsible for the bytes' provenance — a restore
    /// supplies the decrypted and digest-verified database entry of an
    /// authenticated backup package.
    #[must_use]
    pub fn from_parts(database: Vec<u8>, wal: Option<Vec<u8>>) -> Self {
        Self {
            database,
            wal: wal.filter(|wal| !wal.is_empty()),
        }
    }

    /// The consistent main database file bytes.
    #[must_use]
    pub fn database(&self) -> &[u8] {
        &self.database
    }

    /// The durable WAL sidecar bytes, when the database had one.
    #[must_use]
    pub fn wal(&self) -> Option<&[u8]> {
        self.wal.as_deref()
    }
}

impl SqliteStore {
    /// Copies a consistent `SQLite` snapshot under the write gate.
    ///
    /// Acquiring the store's exclusive write gate pauses new write
    /// transactions and waits for the in-flight one to commit; with the gate
    /// held the main file and its WAL are read into memory (the "safe
    /// freeze" of §20.1), and releasing the permit reopens writes. A
    /// concurrent WAL checkpoint can race the copy, so the WAL is read
    /// before and after the main file and the copy retries (bounded) until
    /// both reads agree.
    ///
    /// The race window is narrow: while the gate is held no writer can
    /// commit, so the WAL cannot grow and no automatic checkpoint can be
    /// scheduled — only a passive checkpoint already in flight can still
    /// move frames mid-copy. `SQLite` moves whole 4 `KiB`-aligned pages, so
    /// the before/after comparison always pairs the main file with a
    /// complete pre- or post-checkpoint WAL, never a torn mixture, and the
    /// bounded retry absorbs the window.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError`] when write coordination is unavailable, a
    /// source file is missing or not a regular file, reading fails, or the
    /// retry budget is exhausted by a checkpoint that never settles.
    pub async fn consistent_snapshot(&self) -> Result<DatabaseSnapshot, SnapshotError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(SnapshotError::Coordinate)?;
        let wal_path = sidecar_path(&self.database_path, WAL_SIDECAR_SUFFIX);
        for _attempt in 0..SNAPSHOT_RETRY_BUDGET {
            let wal_before = read_optional_snapshot_file(&wal_path)?;
            let database = read_snapshot_file(&self.database_path)?;
            let wal_after = read_optional_snapshot_file(&wal_path)?;
            if wal_before == wal_after {
                return Ok(DatabaseSnapshot {
                    database,
                    wal: wal_after.filter(|wal| !wal.is_empty()),
                });
            }
        }
        Err(SnapshotError::CheckpointRacing)
    }

    /// Holds the store's exclusive write gate for the caller's duration —
    /// the §20.1 "pause new write transactions" primitive
    /// [`Self::consistent_snapshot`] uses internally.
    ///
    /// Holding the returned permit pauses new write transactions and waits
    /// for the in-flight one to commit; dropping it reopens writes. The
    /// runtime exposes the permit for coordination seams that must freeze
    /// writes beyond a snapshot — the shutdown-drain test holds it to keep
    /// one audit append deterministically in flight while the stop signal
    /// fires.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::Coordinate`] when write coordination is
    /// unavailable.
    pub async fn acquire_write_gate(&self) -> Result<OwnedSemaphorePermit, SnapshotError> {
        self.write_gate
            .clone()
            .acquire_owned()
            .await
            .map_err(SnapshotError::Coordinate)
    }

    /// The number of migrations applied when the store was last opened.
    ///
    /// Recorded in the backup manifest as the schema version, so a restore
    /// can reject a backup whose schema is newer than this binary supports.
    ///
    /// # Errors
    ///
    /// Returns [`AppliedMigrationsError`] when the applied-migration query
    /// fails or the count exceeds the `u32` schema-version range.
    pub async fn applied_migration_count(&self) -> Result<u32, AppliedMigrationsError> {
        let applied = Migrator::get_applied_migrations_read_only(&self.database)
            .await
            .map_err(AppliedMigrationsError::Inspect)?;
        u32::try_from(applied.len()).map_err(|_| AppliedMigrationsError::Overflow {
            count: applied.len(),
        })
    }
}

/// A controlled failure while reading the applied migration count.
#[derive(Debug, Error)]
pub enum AppliedMigrationsError {
    #[error("failed to read the applied migrations: {0}")]
    Inspect(#[source] DbErr),
    #[error("applied migration count {count} exceeds the u32 schema-version range")]
    Overflow { count: usize },
}

/// Replaces the live database files with one snapshot's bytes.
///
/// The database and WAL are written through sibling temporary files and
/// atomically renamed into place; a snapshot without a WAL removes any stale
/// WAL, and the transient shared-memory index is always removed so the
/// restored pair cannot replay frames from a previous database generation.
///
/// The two files are not replaceable as one atomic unit (R6-D-5): before the
/// first overwrite, a durable restore-pending marker records SHA-256
/// fingerprints of the snapshot pair and of the live pair; it is removed
/// only after every replacement succeeded. A crash between the renames
/// leaves the marker behind, and the next store open verifies the live pair
/// against the recorded fingerprints, refusing a mixed pair instead of
/// letting `SQLite` silently discard the mismatched WAL.
///
/// A surviving marker also refuses a re-run of the restore (W7-F-2): a
/// fresh marker would record the current live pair — possibly the mixed
/// pair an interrupted first generation left behind — as the pre-restore
/// state, and the next open would then legitimize that mixed pair as
/// "untouched". The re-run is refused instead, so the interrupted state can
/// only be resolved through a store open, which accepts exactly the
/// recorded snapshot pair (complete) or the recorded pre-restore pair
/// (untouched) and refuses a mixed pair.
///
/// # Errors
///
/// Returns [`RestoreError`] for any failed temporary write, synchronization,
/// rename, marker, or stale-sidecar removal stage, and
/// [`RestoreError::RestoreInterrupted`] when a restore-pending marker
/// already survives. A failure after the marker was written leaves the
/// marker in place, so the interrupted state is detected at the next open.
pub fn restore_database_files(
    database_path: &Path,
    snapshot: &DatabaseSnapshot,
) -> Result<(), RestoreError> {
    let marker_path = sidecar_path(database_path, RESTORE_PENDING_SUFFIX);
    match fs::symlink_metadata(&marker_path) {
        Ok(_) => {
            return Err(RestoreError::RestoreInterrupted {
                path: marker_path,
                source: io::Error::other(
                    "the restore-pending marker of an earlier interrupted restore already exists",
                ),
            });
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        // Fail closed when the marker's state cannot even be inspected: an
        // unwritable or unreadable marker path must not be overwritten blind.
        Err(source) => {
            return Err(RestoreError::RestoreInterrupted {
                path: marker_path,
                source,
            });
        }
    }
    write_restore_marker(database_path, &marker_path, snapshot)?;
    let result = (|| {
        replace_file(database_path, &snapshot.database)?;
        let wal_path = sidecar_path(database_path, WAL_SIDECAR_SUFFIX);
        match &snapshot.wal {
            Some(wal) => replace_file(&wal_path, wal)?,
            None => remove_stale_sidecar(&wal_path)?,
        }
        remove_stale_sidecar(&sidecar_path(database_path, SHM_SIDECAR_SUFFIX))
    })();
    if result.is_ok() {
        // The pair is fully in place; the marker's job is done. A failure to
        // clear it reports an unresolved restore state — the next open would
        // verify the complete pair and clear the marker, but the error is
        // the honest signal for this call.
        remove_restore_marker(&marker_path)?;
    }
    result
}

/// Removes the restore-pending marker, mapping the sidecar-removal failure
/// onto the marker's own error variant.
fn remove_restore_marker(marker_path: &Path) -> Result<(), RestoreError> {
    match remove_stale_sidecar(marker_path) {
        Ok(()) => Ok(()),
        Err(RestoreError::RemoveSidecar { path, source }) => {
            Err(RestoreError::RemoveMarker { path, source })
        }
        Err(other) => Err(RestoreError::RemoveMarker {
            path: marker_path.to_path_buf(),
            source: io::Error::other(other.to_string()),
        }),
    }
}

/// The lowercase hex SHA-256 fingerprint of one byte slice.
fn fingerprint_bytes(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push(char::from(HEX_DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(HEX_DIGITS[usize::from(byte & 0x0F)]));
    }
    hex
}

/// The fingerprint of one file's bytes, or the fallback token when the file
/// is missing or unreadable — a sidecar that cannot be read at marker time
/// is recorded as absent, because a rollback restores the database state,
/// not an unreadable leftover.
fn fingerprint_of_file_or(path: &Path, fallback: &str) -> String {
    match fs::read(path) {
        Ok(bytes) => fingerprint_bytes(&bytes),
        Err(_) => fallback.to_owned(),
    }
}

/// Writes the restore-pending marker for a data directory: four
/// space-separated tokens — the snapshot database fingerprint, the snapshot
/// WAL fingerprint (or `none`), the live database fingerprint (or `absent`),
/// and the live WAL fingerprint (or `none`).
fn write_restore_marker(
    database_path: &Path,
    marker_path: &Path,
    snapshot: &DatabaseSnapshot,
) -> Result<(), RestoreError> {
    let parent = database_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        fs::create_dir_all(parent).map_err(|source| RestoreError::CreateParent {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let snapshot_wal = snapshot
        .wal()
        .map_or_else(|| MARKER_NONE.to_owned(), fingerprint_bytes);
    let pre_database = fingerprint_of_file_or(database_path, MARKER_ABSENT);
    let pre_wal = fingerprint_of_file_or(
        &sidecar_path(database_path, WAL_SIDECAR_SUFFIX),
        MARKER_NONE,
    );
    let content = format!(
        "{} {snapshot_wal} {pre_database} {pre_wal}\n",
        fingerprint_bytes(&snapshot.database),
    );
    write_and_sync_file(marker_path, content.as_bytes()).map_err(|source| {
        RestoreError::WriteMarker {
            path: marker_path.to_path_buf(),
            source,
        }
    })
}

/// Verifies the restore-pending marker of a data directory, if one survives.
///
/// Called by the store open before anything else touches the files. A live
/// pair matching the recorded snapshot fingerprints means the restore
/// completed (the marker's removal did not land); a pair matching the
/// recorded pre-restore fingerprints means the restore never overwrote
/// anything. Both are accepted and the marker is cleared. Any other pair is
/// a mixed state left by an interrupted restore and is refused, so `SQLite`
/// never opens a pair whose WAL it would silently discard.
///
/// # Errors
///
/// Returns [`OpenStoreError::RestoreInterrupted`] when the live pair
/// matches neither recorded state, the marker is unreadable or malformed,
/// or the marker cannot be cleared after a successful verification.
pub(crate) fn verify_restore_marker(database_path: &Path) -> Result<(), OpenStoreError> {
    let marker_path = sidecar_path(database_path, RESTORE_PENDING_SUFFIX);
    let content = match fs::read_to_string(&marker_path) {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(OpenStoreError::RestoreInterrupted {
                marker: marker_path,
                reason: format!("the restore marker could not be read: {source}"),
            });
        }
    };
    let tokens: Vec<&str> = content.split_whitespace().collect();
    let [snapshot_database, snapshot_wal, pre_database, pre_wal] = tokens.as_slice() else {
        return Err(OpenStoreError::RestoreInterrupted {
            marker: marker_path,
            reason: String::from("the restore marker is malformed"),
        });
    };
    let live_database = fingerprint_of_file_or(database_path, MARKER_ABSENT);
    let live_wal = fingerprint_of_file_or(
        &sidecar_path(database_path, WAL_SIDECAR_SUFFIX),
        MARKER_NONE,
    );
    let complete = live_database == *snapshot_database && live_wal == *snapshot_wal;
    let untouched = live_database == *pre_database && live_wal == *pre_wal;
    if !(complete || untouched) {
        return Err(OpenStoreError::RestoreInterrupted {
            marker: marker_path,
            reason: String::from(
                "the live database pair matches neither the recorded snapshot nor the \
                 recorded pre-restore state — a restore was interrupted mid-overwrite",
            ),
        });
    }
    remove_restore_marker(&marker_path).map_err(|source| OpenStoreError::RestoreInterrupted {
        marker: marker_path,
        reason: format!("the verified restore marker could not be cleared: {source}"),
    })
}

/// Whether a backup database can be restored by this product binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RestoreCompatibility {
    /// Every applied migration is known; the binary will apply the pending
    /// ones on the next open.
    Compatible { pending_migrations: usize },
    /// The backup applied migrations this binary does not know; restoring it
    /// would downgrade the schema.
    NewerSchema {
        backup_applied: usize,
        supported: usize,
    },
}

/// Checks a backup database's applied migrations against this binary's
/// migration stack (design §20.2 "check Product and Schema version").
///
/// The backup bytes — the main database file and, when the snapshot carried
/// one, its durable WAL sidecar — are staged in a fresh temporary directory
/// and opened there, so the check never touches the live data directory.
/// The pair is opened with the store's own connect options (read-write, WAL
/// mode): a WAL-mode snapshot's recent commits may live only in the WAL, and
/// `SQLite` replays the WAL on the first read — a read-only open could not
/// build the WAL index for a fresh staging directory, so the applied count
/// is read after the replay, exactly as the live store would see it. The
/// `NewerSchema` gate and the pending count therefore reflect the snapshot's
/// true state, never a stale main file.
///
/// # Errors
///
/// Returns [`RestoreCheckError`] when the backup cannot be staged or the
/// inspection fails.
pub async fn restore_compatibility(
    database: &[u8],
    wal: Option<&[u8]>,
) -> Result<RestoreCompatibility, RestoreCheckError> {
    let staging = tempfile::tempdir().map_err(RestoreCheckError::Stage)?;
    let database_path = staging.path().join("rutilus.db");
    write_and_sync_file(&database_path, database).map_err(RestoreCheckError::Stage)?;
    if let Some(wal) = wal {
        write_and_sync_file(&sidecar_path(&database_path, WAL_SIDECAR_SUFFIX), wal)
            .map_err(RestoreCheckError::Stage)?;
    }

    let mut options =
        crate::sqlite_connect_options(&database_path, crate::SqliteSettings::default());
    options.sqlx_logging(false);
    let database = sea_orm::Database::connect(options)
        .await
        .map_err(RestoreCheckError::Connect)?;

    let applied = if sea_orm_migration::SchemaManager::new(&database)
        .has_table(MIGRATION_TABLE_NAME)
        .await
        .map_err(RestoreCheckError::Inspect)?
    {
        sea_orm_migration::seaql_migrations::Entity::find()
            .all(&database)
            .await
            .map_err(RestoreCheckError::Inspect)?
            .into_iter()
            .map(|model| model.version)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    database.close().await.map_err(RestoreCheckError::Close)?;

    let supported = Migrator::migrations();
    let supported_names = supported
        .iter()
        .map(|migration| migration.name().to_owned())
        .collect::<Vec<_>>();
    if applied.iter().any(|name| !supported_names.contains(name)) {
        return Ok(RestoreCompatibility::NewerSchema {
            backup_applied: applied.len(),
            supported: supported_names.len(),
        });
    }
    Ok(RestoreCompatibility::Compatible {
        pending_migrations: supported_names.len() - applied.len(),
    })
}

/// The `SQLite` sidecar path for one suffix (WAL or shared-memory index).
fn sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut path = std::ffi::OsString::from(database_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

fn read_snapshot_file(path: &Path) -> Result<Vec<u8>, SnapshotError> {
    inspect_regular(path)?;
    fs::read(path).map_err(|source| SnapshotError::Read {
        path: path.to_path_buf(),
        source,
    })
}

fn read_optional_snapshot_file(path: &Path) -> Result<Option<Vec<u8>>, SnapshotError> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_snapshot_file(path).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(SnapshotError::Inspect {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn inspect_regular(path: &Path) -> Result<(), SnapshotError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| SnapshotError::Inspect {
        path: path.to_path_buf(),
        source,
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(SnapshotError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Replaces one file with `bytes` through a sibling temporary and rename.
fn replace_file(path: &Path, bytes: &[u8]) -> Result<(), RestoreError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| RestoreError::InvalidPath {
            path: path.to_path_buf(),
        })?;
    fs::create_dir_all(parent).map_err(|source| RestoreError::CreateParent {
        path: parent.to_path_buf(),
        source,
    })?;
    let temporary =
        NamedTempFile::new_in(parent).map_err(|source| RestoreError::CreateTemporary {
            directory: parent.to_path_buf(),
            source,
        })?;
    write_and_sync(temporary.as_file(), bytes).map_err(|source| RestoreError::WriteTemporary {
        path: path.to_path_buf(),
        source,
    })?;
    let persisted = temporary
        .persist(path)
        .map_err(|error| RestoreError::Persist {
            path: path.to_path_buf(),
            source: error.error,
        })?;
    persisted
        .sync_all()
        .map_err(|source| RestoreError::SynchronizePersisted {
            path: path.to_path_buf(),
            source,
        })
}

fn write_and_sync(mut file: &File, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Writes `bytes` to `path` and synchronizes the file.
fn write_and_sync_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file = fs::File::create(path)?;
    write_and_sync(&file, bytes)
}

/// Removes a stale `SQLite` sidecar, treating absence as success.
fn remove_stale_sidecar(path: &Path) -> Result<(), RestoreError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(RestoreError::RemoveSidecar {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// A controlled failure while copying a consistent `SQLite` snapshot.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("failed to coordinate the SQLite snapshot with the write gate: {0}")]
    Coordinate(#[source] AcquireError),
    #[error("failed to inspect SQLite snapshot source {path}: {source}")]
    Inspect {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("SQLite snapshot source is not a regular non-symlink file: {path}")]
    NotRegular { path: PathBuf },
    #[error("failed to read SQLite snapshot source {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("a WAL checkpoint kept racing the snapshot copy beyond the retry budget")]
    CheckpointRacing,
}

/// A controlled failure while replacing live database files from a snapshot.
#[derive(Debug, Error)]
pub enum RestoreError {
    #[error("restore target has no usable parent directory: {path}")]
    InvalidPath { path: PathBuf },
    #[error("failed to create restore target directory {path}: {source}")]
    CreateParent {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create a temporary restore file in {directory}: {source}")]
    CreateTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write the temporary restore file for {path}: {source}")]
    WriteTemporary {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to move the temporary restore file over {path}: {source}")]
    Persist {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to synchronize the restored file {path}: {source}")]
    SynchronizePersisted {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to remove a stale SQLite sidecar at {path}: {source}")]
    RemoveSidecar {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "an interrupted restore is pending at {path}; refusing to overwrite its marker — \
         open the instance to verify the live pair, or resolve the marker manually: {source}"
    )]
    RestoreInterrupted {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write the restore-pending marker at {path}: {source}")]
    WriteMarker {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to remove the restore-pending marker at {path}: {source}")]
    RemoveMarker {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// A controlled failure while checking a backup database against the
/// current migration stack.
#[derive(Debug, Error)]
pub enum RestoreCheckError {
    #[error("failed to stage the backup database for inspection: {0}")]
    Stage(#[source] io::Error),
    #[error("failed to open the staged backup database: {0}")]
    Connect(#[source] DbErr),
    #[error("failed to inspect the staged backup database: {0}")]
    Inspect(#[source] DbErr),
    #[error("failed to close the staged backup database: {0}")]
    Close(#[source] DbErr),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use rutilus_entity::credential;
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use sea_orm_migration::MigratorTrait as _;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    async fn insert_credential(
        database: &impl sea_orm::ConnectionTrait,
        name: &str,
    ) -> Result<(), DbErr> {
        let now = OffsetDateTime::now_utc();
        credential::ActiveModel {
            id: Set(Uuid::now_v7()),
            name: Set(String::from(name)),
            username: Set(String::from("administrator")),
            active_version_id: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(database)
        .await
        .map(|_| ())
    }

    async fn credential_names(store: &SqliteStore) -> Result<Vec<String>, DbErr> {
        Ok(credential::Entity::find()
            .all(&store.database)
            .await?
            .into_iter()
            .map(|model| model.name)
            .collect())
    }

    /// One repository-ready credential whose write acquires the write gate.
    fn queued_credential()
    -> Result<crate::NewCredential, rutilus_security::CredentialProtectionError> {
        let master_key = rutilus_security::MasterKey::from_boxed_bytes(Box::new([0x61; 32]));
        let protected = rutilus_security::encrypt_credential(
            &master_key,
            rutilus_domain::CredentialId::generate(),
            rutilus_domain::CredentialVersionId::generate(),
            &secrecy::SecretString::from(String::from("queued password")),
        )?;
        Ok(crate::NewCredential::new(
            rutilus_domain::CredentialName::parse("queued").map_err(|_| {
                rutilus_security::CredentialProtectionError::InvalidPlaintextEncoding
            })?,
            rutilus_domain::CredentialUsername::parse("administrator").map_err(|_| {
                rutilus_security::CredentialProtectionError::InvalidPlaintextEncoding
            })?,
            protected,
        ))
    }

    #[tokio::test]
    async fn snapshot_restore_round_trip_reverts_later_changes() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("nested").join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;
        insert_credential(&store.database, "before-backup").await?;
        let snapshot = store.consistent_snapshot().await?;
        insert_credential(&store.database, "after-backup").await?;
        store.close().await?;

        restore_database_files(&database_path, &snapshot)?;
        let wal_path = sidecar_path(&database_path, WAL_SIDECAR_SUFFIX);
        match snapshot.wal() {
            Some(wal) => assert_eq!(std::fs::read(&wal_path)?, wal),
            None => assert!(!wal_path.exists()),
        }
        assert!(!sidecar_path(&database_path, SHM_SIDECAR_SUFFIX).exists());

        let restored = SqliteStore::open(&database_path).await?;
        let mut names = credential_names(&restored).await?;
        names.sort();
        assert_eq!(names, vec!["before-backup"]);
        restored.close().await?;
        Ok(())
    }

    /// The R6-D-5 refusal path: a restore interrupted mid-overwrite (the
    /// main database replaced, the WAL replacement failed) leaves a mixed
    /// pair that the next open must refuse instead of letting `SQLite`
    /// silently discard the mismatched WAL.
    #[tokio::test]
    async fn an_interrupted_restore_is_refused_at_the_next_open() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;
        insert_credential(&store.database, "before-backup").await?;
        let snapshot = store.consistent_snapshot().await?;
        insert_credential(&store.database, "after-backup").await?;
        store.close().await?;

        // Sabotage the restore mid-overwrite: a directory squatting on the
        // WAL sidecar makes the second replacement fail after the main
        // database was already replaced — exactly the mixed-pair state the
        // restore-pending marker must catch at the next open.
        let wal_path = sidecar_path(&database_path, WAL_SIDECAR_SUFFIX);
        std::fs::remove_file(&wal_path).ok();
        std::fs::create_dir(&wal_path)?;
        let Err(error) = restore_database_files(&database_path, &snapshot) else {
            unreachable!("the sabotaged restore must fail")
        };
        assert!(
            matches!(error, RestoreError::Persist { .. }),
            "the restore must fail replacing the WAL, got: {error}"
        );
        std::fs::remove_dir(&wal_path)?;
        assert!(
            sidecar_path(&database_path, RESTORE_PENDING_SUFFIX).exists(),
            "the interrupted restore must leave the restore-pending marker"
        );

        let reopened = SqliteStore::open(&database_path).await;
        assert!(
            matches!(reopened, Err(OpenStoreError::RestoreInterrupted { .. })),
            "a mixed pair after an interrupted restore must be refused, got: {reopened:?}"
        );
        Ok(())
    }

    /// The R6-D-5 acceptance path after completion: a restore that finished
    /// but whose marker removal did not land (a crash after the last
    /// replacement) leaves a complete pair under the marker; the next open
    /// verifies it against the recorded snapshot fingerprints and clears the
    /// marker instead of refusing.
    #[tokio::test]
    async fn a_complete_pair_under_the_restore_marker_is_accepted_at_open()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;
        insert_credential(&store.database, "before-backup").await?;
        let snapshot = store.consistent_snapshot().await?;
        store.close().await?;

        restore_database_files(&database_path, &snapshot)?;
        let marker_path = sidecar_path(&database_path, RESTORE_PENDING_SUFFIX);
        write_restore_marker(&database_path, &marker_path, &snapshot)?;

        let reopened = SqliteStore::open(&database_path).await?;
        assert!(
            !marker_path.exists(),
            "the open must clear a marker whose recorded pair matches the live files"
        );
        let mut names = credential_names(&reopened).await?;
        names.sort();
        assert_eq!(names, vec!["before-backup"]);
        reopened.close().await?;
        Ok(())
    }

    /// The R6-D-5 acceptance path before any overwrite: a restore that
    /// crashed after writing the marker but before the first replacement
    /// leaves the live pair untouched; the next open recognizes the recorded
    /// pre-restore fingerprints, clears the marker, and opens normally.
    #[tokio::test]
    async fn an_untouched_pair_under_the_restore_marker_is_accepted_at_open()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;
        insert_credential(&store.database, "before-backup").await?;
        let snapshot = store.consistent_snapshot().await?;
        store.close().await?;

        let marker_path = sidecar_path(&database_path, RESTORE_PENDING_SUFFIX);
        write_restore_marker(&database_path, &marker_path, &snapshot)?;

        let reopened = SqliteStore::open(&database_path).await?;
        assert!(
            !marker_path.exists(),
            "the open must clear a marker whose recorded pre-restore pair \
             matches the untouched live files"
        );
        let mut names = credential_names(&reopened).await?;
        names.sort();
        assert_eq!(names, vec!["before-backup"]);
        reopened.close().await?;
        Ok(())
    }

    /// W7-F-2: the two-generation restore scenario. The first restore crashes
    /// after replacing the main database, leaving the snapshot's database
    /// beside the pre-restore WAL — a mixed pair — under the restore-pending
    /// marker. A re-run of the restore must refuse to write a fresh marker
    /// (which would record the mixed pair as the pre-restore state and
    /// legitimize it as "untouched" at the next open), and the mixed pair
    /// must stay refused at the open.
    #[tokio::test]
    async fn a_rerun_restore_refuses_to_legitimize_a_mixed_pair_from_the_first_generation()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;
        insert_credential(&store.database, "before-backup").await?;
        let snapshot = store.consistent_snapshot().await?;
        insert_credential(&store.database, "after-backup").await?;
        // `SQLite` deletes the WAL sidecar on a clean close, so the
        // pre-restore WAL bytes are captured while the store is still open
        // and recreated beside the database afterwards — the first
        // generation's crash left that old WAL in place.
        let pre_restore_wal = sidecar_path(&database_path, WAL_SIDECAR_SUFFIX);
        let pre_restore_wal_bytes = std::fs::read(&pre_restore_wal)?;
        assert_ne!(
            pre_restore_wal_bytes,
            snapshot.wal().ok_or("the snapshot must carry a WAL")?,
            "the pre-restore WAL must differ from the snapshot WAL for the pair to be mixed"
        );
        store.close().await?;
        std::fs::write(&pre_restore_wal, &pre_restore_wal_bytes)?;

        // Generation 1: the marker is written and the main database is
        // replaced, then the restore "crashes" before the WAL replacement —
        // the live pair is now the snapshot's database beside the
        // pre-restore WAL.
        let marker_path = sidecar_path(&database_path, RESTORE_PENDING_SUFFIX);
        write_restore_marker(&database_path, &marker_path, &snapshot)?;
        std::fs::write(&database_path, snapshot.database())?;

        // Generation 2: the operator re-runs the restore. It must refuse to
        // overwrite the marker, so the interrupted state stays detectable
        // instead of being re-recorded with the mixed pair as the
        // pre-restore state.
        let Err(error) = restore_database_files(&database_path, &snapshot) else {
            unreachable!("the re-run restore must refuse to overwrite the pending marker")
        };
        assert!(
            matches!(error, RestoreError::RestoreInterrupted { .. }),
            "the re-run restore must refuse with the interrupted-restore error, got: {error}"
        );

        // The open still verifies against the marker's original fingerprints:
        // the live pair matches neither the snapshot pair nor the recorded
        // pre-restore pair, so the mixed state is refused.
        let reopened = SqliteStore::open(&database_path).await;
        assert!(
            matches!(reopened, Err(OpenStoreError::RestoreInterrupted { .. })),
            "the mixed pair must stay refused at the next open, got: {reopened:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_contents_match_the_open_database_bytes() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;
        insert_credential(&store.database, "sealed").await?;
        // The snapshot reflects the byte state while the store is open: the
        // main file plus the WAL frames, before a close-time checkpoint
        // moves the frames into the main file.
        let live_database = std::fs::read(&database_path)?;
        let live_wal = std::fs::read(sidecar_path(&database_path, WAL_SIDECAR_SUFFIX))?;
        let snapshot = store.consistent_snapshot().await?;

        assert_eq!(snapshot.database(), live_database);
        if live_wal.is_empty() {
            assert_eq!(snapshot.wal(), None);
        } else {
            assert_eq!(snapshot.wal(), Some(live_wal.as_slice()));
        }
        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn snapshot_waits_for_the_in_flight_write_and_pauses_new_ones()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let store = Arc::new(SqliteStore::open(&database_path).await?);

        // A writer holds the gate; both the snapshot and a new write must
        // wait for it, and both complete once it releases.
        let held_permit = store.write_gate.acquire().await?;
        let snapshot_task = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.consistent_snapshot().await })
        };
        // The queued write goes through a repository write, which acquires
        // the gate for its whole transaction — exactly the writer a backup
        // must pause.
        let queued_credential = queued_credential()?;
        let queued_write = {
            let store = Arc::clone(&store);
            tokio::spawn(async move { store.create_credential(queued_credential).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            !snapshot_task.is_finished(),
            "snapshot must wait for the current write"
        );
        assert!(
            !queued_write.is_finished(),
            "new writes must pause during the snapshot"
        );

        drop(held_permit);
        let snapshot = snapshot_task.await??;
        queued_write.await??;
        let names = credential_names(&store).await?;
        assert_eq!(names, vec!["queued"]);
        assert!(!snapshot.database().is_empty());
        let store = Arc::try_unwrap(store)
            .map_err(|_| std::io::Error::other("test retained unexpected store references"))?;
        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn compatibility_accepts_known_schemas_and_rejects_newer_ones()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let partial_path = directory.path().join("partial.db");
        let mut options =
            crate::sqlite_connect_options(&partial_path, crate::SqliteSettings::default());
        options.sqlx_logging(false);
        let partial = sea_orm::Database::connect(options).await?;
        Migrator::up(&partial, Some(1)).await?;
        partial.close().await?;
        let partial_bytes = std::fs::read(&partial_path)?;

        let compatibility = restore_compatibility(&partial_bytes, None).await?;
        assert_eq!(
            compatibility,
            RestoreCompatibility::Compatible {
                pending_migrations: Migrator::migrations().len() - 1
            }
        );

        // A backup from a newer product carries an applied migration this
        // binary does not know; the staged inspection must report it.
        let newer_path = directory.path().join("newer.db");
        let mut options =
            crate::sqlite_connect_options(&newer_path, crate::SqliteSettings::default());
        options.sqlx_logging(false);
        let newer = sea_orm::Database::connect(options).await?;
        Migrator::up(&newer, None).await?;
        sea_orm_migration::seaql_migrations::Entity::insert(
            sea_orm_migration::seaql_migrations::ActiveModel {
                version: Set(String::from("m20990101_000001_from_the_future")),
                applied_at: Set(1_000_000_000_i64),
            },
        )
        .exec(&newer)
        .await?;
        newer.close().await?;
        let newer_bytes = std::fs::read(&newer_path)?;

        let compatibility = restore_compatibility(&newer_bytes, None).await?;
        assert_eq!(
            compatibility,
            RestoreCompatibility::NewerSchema {
                // The future row sits on a database that applied every
                // registered migration, so the counts are derived from the
                // live stack — never hardcoded, so a migration added later
                // cannot stale the test (R6-D-2).
                backup_applied: Migrator::migrations().len() + 1,
                supported: Migrator::migrations().len(),
            }
        );
        Ok(())
    }

    #[tokio::test]
    async fn compatibility_replays_the_wal_before_reading_the_applied_migrations()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("live.db");
        let store = SqliteStore::open(&database_path).await?;
        // A migration row lives only in the WAL while the store is open: the
        // close-time checkpoint that would move the frames into the main
        // file has not run, so the main file alone is stale.
        sea_orm_migration::seaql_migrations::Entity::insert(
            sea_orm_migration::seaql_migrations::ActiveModel {
                version: Set(String::from("m20990101_000001_from_the_future")),
                applied_at: Set(1_000_000_000_i64),
            },
        )
        .exec(&store.database)
        .await?;
        let snapshot = store.consistent_snapshot().await?;
        assert!(snapshot.wal().is_some(), "the open store must have a WAL");
        let wal = snapshot.wal().ok_or("snapshot without a WAL")?;

        // The main file alone cannot see the WAL-only migration: the check
        // would report a compatible schema and miss the future row entirely
        // (the defect this test pins).
        let stale = restore_compatibility(snapshot.database(), None).await?;
        assert!(matches!(stale, RestoreCompatibility::Compatible { .. }));

        // With the WAL staged beside the main file, the check replays it and
        // reads the true applied state: every real migration plus the future
        // row, which the `NewerSchema` gate must refuse.
        let replayed = restore_compatibility(snapshot.database(), Some(wal)).await?;
        assert_eq!(
            replayed,
            RestoreCompatibility::NewerSchema {
                backup_applied: Migrator::migrations().len() + 1,
                supported: Migrator::migrations().len(),
            }
        );
        store.close().await?;
        Ok(())
    }
}
