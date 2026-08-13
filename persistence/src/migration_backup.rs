use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use thiserror::Error;
use uuid::Uuid;

const BACKUP_DIRECTORY_NAME: &str = "backups";
const MIGRATION_DIRECTORY_NAME: &str = "migrations";
const COMPLETE_MARKER_NAME: &str = "complete.rut";
const COMPLETE_MARKER: &[u8] = b"RUTILUS-SQLITE-BACKUP-1";
/// The directory-name prefix of every pre-migration recovery backup; the
/// retention pruner only ever touches directories with this prefix.
const MIGRATION_BACKUP_PREFIX: &str = "pre-migration-";
/// How many of the most recent complete pre-migration recovery backups are
/// kept; each new committed backup prunes the complete backups beyond this
/// bound and every incomplete directory (see [`prune_retention`]).
const PRE_MIGRATION_BACKUP_RETENTION: usize = 3;

/// One immutable recovery directory committed before a pending migration runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationBackup {
    path: PathBuf,
}

impl MigrationBackup {
    /// Copies the closed `SQLite` database and any durable `WAL` into a unique
    /// recovery directory, synchronizing every file before a completion marker,
    /// then prunes the older recovery directories to the retention bound.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationBackupError`] for invalid source files or any failed
    /// directory, copy, verification, or synchronization stage. Incomplete
    /// directories deliberately remain without a completion marker.
    pub fn create(database_path: &Path) -> Result<Self, MigrationBackupError> {
        let data_directory = database_path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let backup_root = data_directory
            .join(BACKUP_DIRECTORY_NAME)
            .join(MIGRATION_DIRECTORY_NAME);
        fs::create_dir_all(&backup_root).map_err(|source| MigrationBackupError::CreateRoot {
            path: backup_root.clone(),
            source,
        })?;
        let path = backup_root.join(format!("{MIGRATION_BACKUP_PREFIX}{}", Uuid::now_v7()));
        fs::create_dir(&path).map_err(|source| MigrationBackupError::CreateDirectory {
            path: path.clone(),
            source,
        })?;

        copy_required_file(database_path, &path)?;
        let wal_path = sqlite_sidecar_path(database_path, "-wal");
        if source_exists(&wal_path)? {
            copy_required_file(&wal_path, &path)?;
        }
        commit_backup(&path)?;
        // The new backup is committed and durable before any older one is
        // removed: at every instant at least one complete backup exists.
        prune_retention(&backup_root, PRE_MIGRATION_BACKUP_RETENTION);
        Ok(Self { path })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn source_exists(path: &Path) -> Result<bool, MigrationBackupError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(MigrationBackupError::SourceNotRegular {
                path: path.to_path_buf(),
            })
        }
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(MigrationBackupError::ReadSourceMetadata {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn copy_required_file(source: &Path, backup_directory: &Path) -> Result<(), MigrationBackupError> {
    if !source_exists(source)? {
        return Err(MigrationBackupError::SourceMissing {
            path: source.to_path_buf(),
        });
    }
    let file_name = source
        .file_name()
        .ok_or_else(|| MigrationBackupError::SourceMissing {
            path: source.to_path_buf(),
        })?;
    let destination = backup_directory.join(file_name);
    let expected = fs::metadata(source)
        .map_err(|source_error| MigrationBackupError::ReadSourceMetadata {
            path: source.to_path_buf(),
            source: source_error,
        })?
        .len();
    let copied =
        fs::copy(source, &destination).map_err(|source_error| MigrationBackupError::Copy {
            source_path: source.to_path_buf(),
            destination: destination.clone(),
            source: source_error,
        })?;
    if copied != expected {
        return Err(MigrationBackupError::CopyLengthMismatch {
            source_path: source.to_path_buf(),
            destination,
            expected,
            copied,
        });
    }
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(&destination)
        .and_then(|file| file.sync_all())
        .map_err(|source| MigrationBackupError::SynchronizeCopy {
            path: destination,
            source,
        })?;
    Ok(())
}

fn commit_backup(backup_directory: &Path) -> Result<(), MigrationBackupError> {
    let marker_path = backup_directory.join(COMPLETE_MARKER_NAME);
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker_path)
        .map_err(|source| MigrationBackupError::CreateMarker {
            path: marker_path.clone(),
            source,
        })?;
    marker
        .write_all(COMPLETE_MARKER)
        .map_err(|source| MigrationBackupError::WriteMarker {
            path: marker_path.clone(),
            source,
        })?;
    marker
        .sync_all()
        .map_err(|source| MigrationBackupError::SynchronizeMarker {
            path: marker_path,
            source,
        })
}

/// Keeps the `retained` most recent complete recovery directories and
/// removes everything older, plus every incomplete directory.
///
/// The pruner runs after a new backup committed (never before), so the new
/// backup is one of the retained complete directories and the recovery
/// contract — the most recent pre-migration state — is always intact. The
/// directories are ordered by name: the `pre-migration-<uuid v7>` names
/// sort lexicographically in creation order, exactly like the migration
/// files' `mYYYYMMDD_HHMMSS` naming. Incomplete directories (no completion
/// marker) are always removed: a failed `create` aborts the open before any
/// migration runs, so the copied state is still the live database and the
/// new complete backup supersedes every partial copy.
///
/// The pruning is best-effort and never fails the open: the committed
/// backup is the value the caller needs, and a stale directory that cannot
/// be removed only means more recovery copies than the bound — the safe
/// failure direction.
fn prune_retention(backup_root: &Path, retained: usize) {
    let Ok(entries) = fs::read_dir(backup_root) else {
        return;
    };
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with(MIGRATION_BACKUP_PREFIX) {
            candidates.push((name, path));
        }
    }
    // Newest first: the uuid v7 in the name sorts chronologically.
    candidates.sort_by(|a, b| b.0.cmp(&a.0));
    let mut complete_seen = 0_usize;
    for (_name, path) in candidates {
        let complete = path.join(COMPLETE_MARKER_NAME).is_file();
        if !complete || complete_seen >= retained {
            // Best-effort by contract; a removal failure is ignored.
            let _ = fs::remove_dir_all(&path);
            continue;
        }
        complete_seen += 1;
    }
}

fn sqlite_sidecar_path(database_path: &Path, suffix: &str) -> PathBuf {
    let mut path = OsString::from(database_path.as_os_str());
    path.push(suffix);
    PathBuf::from(path)
}

/// A controlled failure while creating a recoverable pre-migration file set.
#[derive(Debug, Error)]
pub enum MigrationBackupError {
    #[error("failed to create migration-backup root {path}: {source}")]
    CreateRoot {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create unique migration-backup directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to inspect SQLite backup source {path}: {source}")]
    ReadSourceMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("SQLite backup source is missing: {path}")]
    SourceMissing { path: PathBuf },
    #[error("SQLite backup source is not a regular non-symlink file: {path}")]
    SourceNotRegular { path: PathBuf },
    #[error("failed to copy SQLite backup source {source_path} to {destination}: {source}")]
    Copy {
        source_path: PathBuf,
        destination: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "SQLite backup copy length mismatch for {source_path} to {destination}: expected {expected}, copied {copied}"
    )]
    CopyLengthMismatch {
        source_path: PathBuf,
        destination: PathBuf,
        expected: u64,
        copied: u64,
    },
    #[error("failed to synchronize SQLite backup copy {path}: {source}")]
    SynchronizeCopy {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create SQLite backup completion marker {path}: {source}")]
    CreateMarker {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write SQLite backup completion marker {path}: {source}")]
    WriteMarker {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to synchronize SQLite backup completion marker {path}: {source}")]
    SynchronizeMarker {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn copies_main_and_wal_into_unique_committed_backups() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("rutilus.db");
        let wal = sqlite_sidecar_path(&database, "-wal");
        fs::write(&database, b"sqlite-main")?;
        fs::write(&wal, b"sqlite-wal")?;

        let first = MigrationBackup::create(&database)?;
        let second = MigrationBackup::create(&database)?;

        assert_ne!(first, second);
        for backup in [first, second] {
            assert_eq!(
                backup.path().parent().and_then(Path::file_name),
                Some(std::ffi::OsStr::new(MIGRATION_DIRECTORY_NAME))
            );
            assert_eq!(fs::read(backup.path().join("rutilus.db"))?, b"sqlite-main");
            assert_eq!(
                fs::read(backup.path().join("rutilus.db-wal"))?,
                b"sqlite-wal"
            );
            assert_eq!(
                fs::read(backup.path().join(COMPLETE_MARKER_NAME))?,
                COMPLETE_MARKER
            );
        }
        Ok(())
    }

    #[test]
    fn rejects_missing_and_non_regular_database_sources() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let missing = directory.path().join("missing.db");
        let non_file = directory.path().join("database-directory");
        fs::create_dir(&non_file)?;

        assert!(matches!(
            MigrationBackup::create(&missing),
            Err(MigrationBackupError::SourceMissing { .. })
        ));
        assert!(matches!(
            MigrationBackup::create(&non_file),
            Err(MigrationBackupError::SourceNotRegular { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_non_regular_wal_without_committing_the_backup() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("rutilus.db");
        let wal = sqlite_sidecar_path(&database, "-wal");
        fs::write(&database, b"sqlite-main")?;
        fs::create_dir(&wal)?;

        let result = MigrationBackup::create(&database);

        assert!(matches!(
            result,
            Err(MigrationBackupError::SourceNotRegular { .. })
        ));
        let migration_root = directory
            .path()
            .join(BACKUP_DIRECTORY_NAME)
            .join(MIGRATION_DIRECTORY_NAME);
        let incomplete_directories =
            fs::read_dir(migration_root)?.collect::<Result<Vec<_>, _>>()?;
        assert_eq!(incomplete_directories.len(), 1);
        assert!(
            !incomplete_directories[0]
                .path()
                .join(COMPLETE_MARKER_NAME)
                .exists()
        );
        Ok(())
    }

    #[test]
    fn prunes_complete_backups_beyond_the_retention_bound() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("rutilus.db");
        fs::write(&database, b"sqlite-main")?;

        // The first four backups all survive while the bound is not
        // exceeded; the fifth pushes the two oldest out, newest first.
        let created = (0..5)
            .map(|_| MigrationBackup::create(&database).map(|backup| backup.path.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        let survivors = migration_backup_directories(directory.path())?;
        assert_eq!(
            survivors.len(),
            PRE_MIGRATION_BACKUP_RETENTION,
            "only the newest complete backups may survive"
        );
        let mut newest_first = created[2..].to_vec();
        newest_first.reverse();
        assert_eq!(
            newest_first, survivors,
            "the newest backups must be the survivors"
        );
        assert!(
            !created[0].exists() && !created[1].exists(),
            "the two oldest backups must be pruned"
        );
        for survivor in &survivors {
            assert!(survivor.join(COMPLETE_MARKER_NAME).is_file());
        }
        Ok(())
    }

    #[test]
    fn a_successful_backup_removes_incomplete_directories() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("rutilus.db");
        fs::write(&database, b"sqlite-main")?;
        // An interrupted create leaves a directory without the completion
        // marker; the next successful backup supersedes it (the failed
        // create aborted the open, so no migration ran and the copied state
        // is still the live database).
        let root = directory
            .path()
            .join(BACKUP_DIRECTORY_NAME)
            .join(MIGRATION_DIRECTORY_NAME);
        fs::create_dir_all(&root)?;
        let incomplete = root.join(format!("{MIGRATION_BACKUP_PREFIX}{}", Uuid::now_v7()));
        fs::create_dir(&incomplete)?;
        fs::write(incomplete.join("rutilus.db"), b"partial copy")?;

        MigrationBackup::create(&database)?;

        let survivors = migration_backup_directories(directory.path())?;
        assert_eq!(survivors.len(), 1);
        assert!(survivors[0].join(COMPLETE_MARKER_NAME).is_file());
        assert!(
            !incomplete.exists(),
            "the incomplete directory must be pruned by the successful backup"
        );
        Ok(())
    }

    #[test]
    fn a_failed_backup_never_prunes() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("rutilus.db");
        // One committed backup occupies the root before the failing create.
        fs::write(&database, b"sqlite-main")?;
        let existing = MigrationBackup::create(&database)?;

        // The create fails before any new backup commits (the source is a
        // directory), so the retention pruner must not run: no directory
        // can disappear behind a failed open.
        let database_directory = directory.path().join("database-directory");
        fs::create_dir(&database_directory)?;
        assert!(matches!(
            MigrationBackup::create(&database_directory),
            Err(MigrationBackupError::SourceNotRegular { .. })
        ));
        assert!(
            existing.path().is_dir(),
            "a failed create must never prune committed backups"
        );
        Ok(())
    }

    /// The committed pre-migration backup directories, newest first.
    fn migration_backup_directories(
        data_directory: &std::path::Path,
    ) -> Result<Vec<std::path::PathBuf>, Box<dyn Error>> {
        let root = data_directory
            .join(BACKUP_DIRECTORY_NAME)
            .join(MIGRATION_DIRECTORY_NAME);
        let mut names = fs::read_dir(&root)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort_by(|a, b| b.cmp(a));
        Ok(names.into_iter().map(|name| root.join(name)).collect())
    }

    #[test]
    fn reports_root_copy_and_marker_collisions_without_overwriting() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("rutilus.db");
        fs::write(&database, b"sqlite-main")?;
        fs::write(
            directory.path().join(BACKUP_DIRECTORY_NAME),
            b"root collision",
        )?;
        assert!(matches!(
            MigrationBackup::create(&database),
            Err(MigrationBackupError::CreateRoot { .. })
        ));

        let copy_directory = directory.path().join("copy");
        fs::create_dir(&copy_directory)?;
        fs::create_dir(copy_directory.join("rutilus.db"))?;
        assert!(matches!(
            copy_required_file(&database, &copy_directory),
            Err(MigrationBackupError::Copy { .. })
        ));

        let marker_directory = directory.path().join("marker");
        fs::create_dir(&marker_directory)?;
        commit_backup(&marker_directory)?;
        assert!(matches!(
            commit_backup(&marker_directory),
            Err(MigrationBackupError::CreateMarker { .. })
        ));
        assert_eq!(
            fs::read(marker_directory.join(COMPLETE_MARKER_NAME))?,
            COMPLETE_MARKER
        );
        Ok(())
    }
}
