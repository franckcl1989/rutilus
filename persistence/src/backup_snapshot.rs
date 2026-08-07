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
//! [`restore_database_files`] replaces the database and its sidecars
//! atomically (sibling temporary file plus rename), removing any stale WAL
//! and shared-memory index so the restored state cannot replay old frames.

use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

use rutilus_migration::Migrator;
use sea_orm::{DbErr, EntityTrait};
use sea_orm_migration::MigratorTrait;
use tempfile::NamedTempFile;
use thiserror::Error;
use tokio::sync::AcquireError;

use crate::SqliteStore;

/// The fixed WAL sidecar suffix `SQLite` uses in WAL journal mode.
const WAL_SIDECAR_SUFFIX: &str = "-wal";
/// The transient shared-memory index sidecar, rebuilt on every open.
const SHM_SIDECAR_SUFFIX: &str = "-shm";
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
/// # Errors
///
/// Returns [`RestoreError`] for any failed temporary write, synchronization,
/// rename, or stale-sidecar removal stage.
pub fn restore_database_files(
    database_path: &Path,
    snapshot: &DatabaseSnapshot,
) -> Result<(), RestoreError> {
    replace_file(database_path, &snapshot.database)?;
    let wal_path = sidecar_path(database_path, WAL_SIDECAR_SUFFIX);
    match &snapshot.wal {
        Some(wal) => replace_file(&wal_path, wal)?,
        None => remove_stale_sidecar(&wal_path)?,
    }
    remove_stale_sidecar(&sidecar_path(database_path, SHM_SIDECAR_SUFFIX))
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
/// The backup bytes are staged in a temporary file and opened read-only, so
/// the check never touches the live data directory.
///
/// # Errors
///
/// Returns [`RestoreCheckError`] when the backup cannot be staged or the
/// read-only inspection fails.
pub async fn restore_compatibility(
    database: &[u8],
) -> Result<RestoreCompatibility, RestoreCheckError> {
    let staging = NamedTempFile::new().map_err(RestoreCheckError::Stage)?;
    write_and_sync(staging.as_file(), database).map_err(RestoreCheckError::Stage)?;

    let mut options = crate::sqlite_read_only_connect_options(staging.path());
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
}

/// A controlled failure while checking a backup database against the
/// current migration stack.
#[derive(Debug, Error)]
pub enum RestoreCheckError {
    #[error("failed to stage the backup database for inspection: {0}")]
    Stage(#[source] io::Error),
    #[error("failed to open the staged backup database read-only: {0}")]
    Connect(#[source] DbErr),
    #[error("failed to inspect the staged backup database: {0}")]
    Inspect(#[source] DbErr),
    #[error("failed to close the read-only backup inspection: {0}")]
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

        let compatibility = restore_compatibility(&partial_bytes).await?;
        assert_eq!(
            compatibility,
            RestoreCompatibility::Compatible {
                pending_migrations: Migrator::migrations().len() - 1
            }
        );

        // A backup from a newer product carries an applied migration this
        // binary does not know; the read-only inspection must report it.
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

        let compatibility = restore_compatibility(&newer_bytes).await?;
        assert!(matches!(
            compatibility,
            RestoreCompatibility::NewerSchema {
                backup_applied: 20,
                supported: 19
            }
        ));
        Ok(())
    }
}
