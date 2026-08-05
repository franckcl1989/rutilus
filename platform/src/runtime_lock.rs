use std::{
    fmt,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

use fs4::TryLockError;
use thiserror::Error;

/// An advisory exclusive lease held for the complete lifetime of one runtime.
pub struct RuntimeLock {
    file: File,
    path: PathBuf,
}

impl RuntimeLock {
    /// Acquires an exclusive, non-blocking lock without deleting a previous
    /// process's lock file. The operating system releases the lease when this
    /// value and its file handle are dropped.
    ///
    /// # Errors
    ///
    /// Returns [`RuntimeLockError::AlreadyHeld`] when another process owns the
    /// instance, with separate variants for directory, file, and lock failures.
    pub fn acquire(path: impl Into<PathBuf>) -> Result<Self, RuntimeLockError> {
        let path = path.into();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .ok_or_else(|| RuntimeLockError::InvalidPath { path: path.clone() })?;
        fs::create_dir_all(parent).map_err(|source| RuntimeLockError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| RuntimeLockError::Open {
                path: path.clone(),
                source,
            })?;
        match fs4::FileExt::try_lock(&file) {
            Ok(()) => Ok(Self { file, path }),
            Err(TryLockError::WouldBlock) => Err(RuntimeLockError::AlreadyHeld { path }),
            Err(TryLockError::Error(source)) => Err(RuntimeLockError::Acquire { path, source }),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for RuntimeLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeLock")
            .field("path", &self.path)
            .field("held", &true)
            .finish_non_exhaustive()
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        let _result = fs4::FileExt::unlock(&self.file);
    }
}

/// A controlled failure while enforcing one process per data directory.
#[derive(Debug, Error)]
pub enum RuntimeLockError {
    #[error("runtime lock path has no usable parent directory: {path}")]
    InvalidPath { path: PathBuf },
    #[error("failed to create runtime data directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open runtime lock file at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("another Rutilus process already owns runtime data at {path}")]
    AlreadyHeld { path: PathBuf },
    #[error("failed to acquire runtime lock at {path}: {source}")]
    Acquire {
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
    fn admits_exactly_one_owner_and_releases_on_drop() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("nested").join(".rutilus.lock");

        let first = RuntimeLock::acquire(&path)?;
        let second = RuntimeLock::acquire(&path);

        assert_eq!(first.path(), path);
        assert!(format!("{first:?}").contains("held: true"));
        assert!(matches!(second, Err(RuntimeLockError::AlreadyHeld { .. })));
        drop(first);

        let reacquired = RuntimeLock::acquire(&path)?;
        assert_eq!(reacquired.path(), path);
        Ok(())
    }

    #[test]
    fn rejects_a_relative_file_without_a_parent() {
        assert!(matches!(
            RuntimeLock::acquire(".rutilus.lock"),
            Err(RuntimeLockError::InvalidPath { .. })
        ));
    }
}
