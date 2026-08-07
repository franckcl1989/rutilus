use std::{
    env, io,
    path::{Path, PathBuf},
};

use thiserror::Error;

const PRODUCT_DIRECTORY_NAME: &str = "rutilus";
const PORTABLE_DIRECTORY_NAME: &str = "rutilus-data";
const DATABASE_FILE_NAME: &str = "rutilus.db";
const MASTER_KEY_FILE_NAME: &str = "master-key.rut";
const SYSTEM_MASTER_KEY_FILE_NAME: &str = "system-master-key.rut";
const INSTANCE_MARKER_FILE_NAME: &str = "instance.rut";
const RUNTIME_LOCK_FILE_NAME: &str = ".rutilus.lock";
const TLS_DIRECTORY_NAME: &str = "tls";

/// User-scoped installed storage or storage carried beside the product binary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DataLocation {
    Installed,
    Portable,
}

impl DataLocation {
    /// Resolves this location using the current platform and executable.
    ///
    /// # Errors
    ///
    /// Returns [`DataPathError`] when the platform has no valid local data
    /// directory or the current executable path cannot be resolved safely.
    pub fn resolve(self) -> Result<RuntimePaths, DataPathError> {
        match self {
            Self::Installed => RuntimePaths::installed(),
            Self::Portable => RuntimePaths::portable(),
        }
    }
}

/// Absolute, deterministic paths owned by one Rutilus runtime instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimePaths {
    data_directory: PathBuf,
    database_path: PathBuf,
    master_key_path: PathBuf,
    system_master_key_path: PathBuf,
    instance_marker_path: PathBuf,
    runtime_lock_path: PathBuf,
    tls_directory: PathBuf,
}

impl RuntimePaths {
    /// Resolves user-local installed data with the native platform convention.
    ///
    /// Windows uses `LocalAppData`, macOS uses `Application Support`, and Linux
    /// uses `XDG` data home or its standard fallback.
    ///
    /// # Errors
    ///
    /// Returns [`DataPathError::PlatformDirectoryUnavailable`] if the operating
    /// system cannot provide a local user data directory.
    pub fn installed() -> Result<Self, DataPathError> {
        let base = installed_data_root().ok_or(DataPathError::PlatformDirectoryUnavailable)?;
        Self::from_root(base.join(PRODUCT_DIRECTORY_NAME))
    }

    /// Resolves portable data beside the currently executing binary.
    ///
    /// # Errors
    ///
    /// Returns [`DataPathError`] if the operating system cannot report an
    /// absolute executable path or that path has no usable parent directory.
    pub fn portable() -> Result<Self, DataPathError> {
        let executable = env::current_exe().map_err(DataPathError::CurrentExecutable)?;
        Self::portable_from_executable(executable)
    }

    /// Resolves portable data beside an explicit absolute executable path.
    ///
    /// # Errors
    ///
    /// Returns [`DataPathError`] when the path is relative, lacks a file name,
    /// or has no usable parent directory.
    pub fn portable_from_executable(executable: impl AsRef<Path>) -> Result<Self, DataPathError> {
        let executable = executable.as_ref();
        if !executable.is_absolute() {
            return Err(DataPathError::ExecutableNotAbsolute {
                path: executable.to_path_buf(),
            });
        }
        if executable.file_name().is_none() {
            return Err(DataPathError::InvalidExecutablePath {
                path: executable.to_path_buf(),
            });
        }
        let parent = executable
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| DataPathError::InvalidExecutablePath {
                path: executable.to_path_buf(),
            })?;
        Self::from_root(parent.join(PORTABLE_DIRECTORY_NAME))
    }

    /// Constructs the standard layout below one explicit absolute data root.
    ///
    /// # Errors
    ///
    /// Returns [`DataPathError::DataDirectoryNotAbsolute`] for a relative root.
    pub fn from_root(data_directory: impl Into<PathBuf>) -> Result<Self, DataPathError> {
        let data_directory = data_directory.into();
        if !data_directory.is_absolute() {
            return Err(DataPathError::DataDirectoryNotAbsolute {
                path: data_directory,
            });
        }
        Ok(Self {
            database_path: data_directory.join(DATABASE_FILE_NAME),
            master_key_path: data_directory.join(MASTER_KEY_FILE_NAME),
            system_master_key_path: data_directory.join(SYSTEM_MASTER_KEY_FILE_NAME),
            instance_marker_path: data_directory.join(INSTANCE_MARKER_FILE_NAME),
            runtime_lock_path: data_directory.join(RUNTIME_LOCK_FILE_NAME),
            tls_directory: data_directory.join(TLS_DIRECTORY_NAME),
            data_directory,
        })
    }

    #[must_use]
    pub fn data_directory(&self) -> &Path {
        &self.data_directory
    }

    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    #[must_use]
    pub fn master_key_path(&self) -> &Path {
        &self.master_key_path
    }

    /// The OS-protected master-key envelope path (unattended Site unlocks).
    #[must_use]
    pub fn system_master_key_path(&self) -> &Path {
        &self.system_master_key_path
    }

    #[must_use]
    pub fn instance_marker_path(&self) -> &Path {
        &self.instance_marker_path
    }

    #[must_use]
    pub fn runtime_lock_path(&self) -> &Path {
        &self.runtime_lock_path
    }

    /// The directory holding the Site's TLS certificate and private key.
    #[must_use]
    pub fn tls_directory(&self) -> &Path {
        &self.tls_directory
    }
}

/// A controlled failure while selecting a cross-platform runtime location.
#[derive(Debug, Error)]
pub enum DataPathError {
    #[error("the operating system did not provide an absolute local user data directory")]
    PlatformDirectoryUnavailable,
    #[error("failed to resolve the current executable path: {0}")]
    CurrentExecutable(#[source] io::Error),
    #[error("portable executable path must be absolute: {path}")]
    ExecutableNotAbsolute { path: PathBuf },
    #[error("portable executable path has no usable file or parent directory: {path}")]
    InvalidExecutablePath { path: PathBuf },
    #[error("runtime data directory must be absolute: {path}")]
    DataDirectoryNotAbsolute { path: PathBuf },
}

fn absolute_environment_path(name: &str) -> Option<PathBuf> {
    env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

#[cfg(target_os = "windows")]
fn installed_data_root() -> Option<PathBuf> {
    absolute_environment_path("LOCALAPPDATA")
}

#[cfg(target_os = "macos")]
fn installed_data_root() -> Option<PathBuf> {
    absolute_environment_path("HOME").map(|home| home.join("Library/Application Support"))
}

#[cfg(target_os = "linux")]
fn installed_data_root() -> Option<PathBuf> {
    absolute_environment_path("XDG_DATA_HOME")
        .or_else(|| absolute_environment_path("HOME").map(|home| home.join(".local").join("share")))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn installed_data_root() -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn derives_the_complete_portable_layout_beside_the_binary() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("bin").join("rutilus-test");

        let paths = RuntimePaths::portable_from_executable(&executable)?;

        assert_eq!(
            paths.data_directory(),
            directory.path().join("bin").join(PORTABLE_DIRECTORY_NAME)
        );
        assert_eq!(
            paths.database_path(),
            paths.data_directory().join(DATABASE_FILE_NAME)
        );
        assert_eq!(
            paths.master_key_path(),
            paths.data_directory().join(MASTER_KEY_FILE_NAME)
        );
        assert_eq!(
            paths.system_master_key_path(),
            paths.data_directory().join(SYSTEM_MASTER_KEY_FILE_NAME)
        );
        assert_eq!(
            paths.instance_marker_path(),
            paths.data_directory().join(INSTANCE_MARKER_FILE_NAME)
        );
        assert_eq!(
            paths.runtime_lock_path(),
            paths.data_directory().join(RUNTIME_LOCK_FILE_NAME)
        );
        assert_eq!(
            paths.tls_directory(),
            paths.data_directory().join(TLS_DIRECTORY_NAME)
        );
        Ok(())
    }

    #[test]
    fn rejects_relative_roots_and_executable_paths() {
        assert!(matches!(
            RuntimePaths::from_root("relative-data"),
            Err(DataPathError::DataDirectoryNotAbsolute { .. })
        ));
        assert!(matches!(
            RuntimePaths::portable_from_executable("rutilus"),
            Err(DataPathError::ExecutableNotAbsolute { .. })
        ));
    }

    #[test]
    fn installed_location_is_absolute_and_uses_the_product_directory() -> Result<(), Box<dyn Error>>
    {
        let paths = DataLocation::Installed.resolve()?;

        assert!(paths.data_directory().is_absolute());
        assert_eq!(
            paths.data_directory().file_name(),
            Some(std::ffi::OsStr::new(PRODUCT_DIRECTORY_NAME))
        );
        Ok(())
    }
}
