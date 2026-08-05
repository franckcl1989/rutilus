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

/// One immutable recovery directory committed before a pending migration runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MigrationBackup {
    path: PathBuf,
}

impl MigrationBackup {
    /// Copies the closed `SQLite` database and any durable `WAL` into a unique
    /// recovery directory, synchronizing every file before a completion marker.
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
        let path = backup_root.join(format!("pre-migration-{}", Uuid::now_v7()));
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
