use std::{
    fs::{self, File},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use rutilus_security::{
    MAX_SYSTEM_KEY_PAYLOAD_LENGTH, SYSTEM_KEY_ENVELOPE_MAGIC, SystemMasterKeyEnvelopeError,
    SystemProtectedMasterKey,
};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Defensive upper bound for one persisted system envelope: the `RUTOSK001`
/// marker plus the security layer's payload bound. No envelope is read
/// unbounded.
const MAX_SYSTEM_ENVELOPE_LENGTH: usize =
    SYSTEM_KEY_ENVELOPE_MAGIC.len() + MAX_SYSTEM_KEY_PAYLOAD_LENGTH;

/// Exclusive, bounded persistence for one OS-protected master-key envelope.
///
/// Unlike the passphrase [`MasterKeyFile`](crate::MasterKeyFile), this file
/// may be replaced: re-wrapping the master key to the operating-system
/// unlock source updates the same envelope. On Unix the envelope is created
/// with mode 0600 and loads reject a file that carries group or other
/// permissions — on Linux, where the operating system provides no secret
/// store, this restrictive file is the master key's protection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SystemMasterKeyFile {
    path: PathBuf,
}

impl SystemMasterKeyFile {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persists (or replaces) one OS-protected envelope.
    ///
    /// The envelope is written to a securely created sibling temporary file,
    /// synchronized, renamed over any previous envelope, and synchronized
    /// again before returning. On Unix the temporary file is restricted to
    /// mode 0600 before any secret bytes are written.
    ///
    /// # Errors
    ///
    /// Returns [`SystemMasterKeyFileError`] retaining the exact I/O stage
    /// without including key or envelope bytes.
    pub fn create(
        &self,
        protected: &SystemProtectedMasterKey,
    ) -> Result<(), SystemMasterKeyFileError> {
        let parent = self.parent_directory()?;
        fs::create_dir_all(parent).map_err(|source| SystemMasterKeyFileError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| {
            SystemMasterKeyFileError::CreateTemporary {
                directory: parent.to_path_buf(),
                source,
            }
        })?;
        restrict_temporary_permissions(temporary.path())?;
        temporary
            .write_all(protected.as_bytes())
            .map_err(|source| SystemMasterKeyFileError::WriteTemporary {
                directory: parent.to_path_buf(),
                source,
            })?;
        temporary.as_file().sync_all().map_err(|source| {
            SystemMasterKeyFileError::SynchronizeTemporary {
                directory: parent.to_path_buf(),
                source,
            }
        })?;

        let persisted =
            temporary
                .persist(&self.path)
                .map_err(|error| SystemMasterKeyFileError::Persist {
                    path: self.path.clone(),
                    source: error.error,
                })?;
        persisted
            .sync_all()
            .map_err(|source| SystemMasterKeyFileError::SynchronizePersisted {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    /// Loads one exact, regular, non-symlink envelope without unbounded reads.
    ///
    /// On Unix the file must not carry group or other permissions; a
    /// world-accessible envelope is refused rather than read.
    ///
    /// # Errors
    ///
    /// Returns [`SystemMasterKeyFileError`] when metadata or I/O fails, the
    /// path is not a private regular file, or the security layer rejects its
    /// envelope format.
    pub fn load(&self) -> Result<SystemProtectedMasterKey, SystemMasterKeyFileError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|source| {
            SystemMasterKeyFileError::ReadMetadata {
                path: self.path.clone(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(SystemMasterKeyFileError::NotRegularFile {
                path: self.path.clone(),
            });
        }
        if metadata.len() > MAX_SYSTEM_ENVELOPE_LENGTH as u64 {
            return Err(SystemMasterKeyFileError::Envelope {
                path: self.path.clone(),
                source: SystemMasterKeyEnvelopeError::EnvelopeTooLong,
            });
        }
        require_private_permissions(&self.path, &metadata.permissions())?;
        let mut file = File::open(&self.path).map_err(|source| SystemMasterKeyFileError::Open {
            path: self.path.clone(),
            source,
        })?;
        let opened_metadata =
            file.metadata()
                .map_err(|source| SystemMasterKeyFileError::ReadMetadata {
                    path: self.path.clone(),
                    source,
                })?;
        if !opened_metadata.is_file() {
            return Err(SystemMasterKeyFileError::NotRegularFile {
                path: self.path.clone(),
            });
        }
        require_private_permissions(&self.path, &opened_metadata.permissions())?;
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| {
            SystemMasterKeyFileError::Envelope {
                path: self.path.clone(),
                source: SystemMasterKeyEnvelopeError::EnvelopeTooLong,
            }
        })?);
        file.read_to_end(&mut bytes)
            .map_err(|source| SystemMasterKeyFileError::Read {
                path: self.path.clone(),
                source,
            })?;
        SystemProtectedMasterKey::from_bytes(bytes).map_err(|source| {
            SystemMasterKeyFileError::Envelope {
                path: self.path.clone(),
                source,
            }
        })
    }

    fn parent_directory(&self) -> Result<&Path, SystemMasterKeyFileError> {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| SystemMasterKeyFileError::InvalidPath {
                path: self.path.clone(),
            })
    }
}

/// Restricts a freshly created temporary envelope to mode 0600 before any
/// secret bytes are written (Unix only; Windows has no POSIX modes).
#[cfg(unix)]
fn restrict_temporary_permissions(path: &Path) -> Result<(), SystemMasterKeyFileError> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        SystemMasterKeyFileError::RestrictPermissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

// The non-Unix twins mirror the Unix signatures so the call sites stay
// cfg-free; they cannot fail on Windows.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn restrict_temporary_permissions(_path: &Path) -> Result<(), SystemMasterKeyFileError> {
    Ok(())
}

/// Refuses to load an envelope that any other account could read or write.
#[cfg(unix)]
fn require_private_permissions(
    path: &Path,
    permissions: &fs::Permissions,
) -> Result<(), SystemMasterKeyFileError> {
    use std::os::unix::fs::PermissionsExt;

    if permissions.mode() & 0o077 != 0 {
        return Err(SystemMasterKeyFileError::NotPrivateFile {
            path: path.to_path_buf(),
            mode: permissions.mode() & 0o777,
        });
    }
    Ok(())
}

// The non-Unix twin mirrors the Unix signature so the call sites stay
// cfg-free; Windows has no POSIX modes to enforce.
#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn require_private_permissions(
    _path: &Path,
    _permissions: &fs::Permissions,
) -> Result<(), SystemMasterKeyFileError> {
    Ok(())
}

/// A secret-safe failure while persisting the system-protected master-key
/// envelope.
#[derive(Debug, Error)]
pub enum SystemMasterKeyFileError {
    #[error("system master-key path has no usable parent directory: {path}")]
    InvalidPath { path: PathBuf },
    #[error("failed to create the system master-key directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create a temporary system master-key file in {directory}: {source}")]
    CreateTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to restrict the temporary system master-key file at {path}: {source}")]
    RestrictPermissions {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write a temporary system master-key file in {directory}: {source}")]
    WriteTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to synchronize a temporary system master-key file in {directory}: {source}")]
    SynchronizeTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to persist system master-key file at {path}: {source}")]
    Persist {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "system master-key file was persisted but could not be synchronized at {path}: {source}"
    )]
    SynchronizePersisted {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read system master-key metadata at {path}: {source}")]
    ReadMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("system master-key path is not a regular non-symlink file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("system master-key file is accessible by other accounts (mode {mode:o}): {path}")]
    NotPrivateFile { path: PathBuf, mode: u32 },
    #[error("failed to open system master-key file at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read system master-key file at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid system master-key envelope at {path}: {source}")]
    Envelope {
        path: PathBuf,
        #[source]
        source: SystemMasterKeyEnvelopeError,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_security::{MASTER_KEY_ENVELOPE_LENGTH, SystemProtectedMasterKey};

    use super::*;

    fn envelope(key_byte: u8) -> Result<SystemProtectedMasterKey, SystemMasterKeyEnvelopeError> {
        let mut payload = [0_u8; 32];
        payload.fill(key_byte);
        let mut bytes = SYSTEM_KEY_ENVELOPE_MAGIC.to_vec();
        bytes.extend_from_slice(&payload);
        SystemProtectedMasterKey::from_bytes(bytes)
    }

    #[test]
    fn creates_replaces_and_loads_an_envelope() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key_file =
            SystemMasterKeyFile::new(directory.path().join("nested").join("system-key.rut"));
        let first = envelope(0x31)?;
        let second = envelope(0x32)?;

        key_file.create(&first)?;
        key_file.create(&second)?;
        let loaded = key_file.load()?;

        assert_eq!(loaded, second);
        assert_eq!(loaded.as_bytes(), second.as_bytes());
        assert_eq!(
            key_file.path(),
            directory.path().join("nested").join("system-key.rut")
        );
        Ok(())
    }

    #[test]
    fn rejects_unbounded_or_unknown_envelope_files_without_echoing_bytes()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key_file = SystemMasterKeyFile::new(directory.path().join("system-key.rut"));
        fs::write(key_file.path(), b"secret-looking truncated input")?;

        let error = key_file
            .load()
            .err()
            .ok_or("truncated key file unexpectedly loaded")?;

        assert!(matches!(
            error,
            SystemMasterKeyFileError::Envelope {
                source: SystemMasterKeyEnvelopeError::UnsupportedEnvelope,
                ..
            }
        ));
        assert!(!error.to_string().contains("secret-looking"));

        fs::write(key_file.path(), [0_u8; MASTER_KEY_ENVELOPE_LENGTH])?;
        assert!(matches!(
            key_file.load(),
            Err(SystemMasterKeyFileError::Envelope {
                source: SystemMasterKeyEnvelopeError::UnsupportedEnvelope,
                ..
            })
        ));

        let oversized = vec![0_u8; MAX_SYSTEM_ENVELOPE_LENGTH + 1];
        fs::write(key_file.path(), oversized)?;
        assert!(matches!(
            key_file.load(),
            Err(SystemMasterKeyFileError::Envelope {
                source: SystemMasterKeyEnvelopeError::EnvelopeTooLong,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_paths_without_a_parent_directory() {
        let key_file = SystemMasterKeyFile::new("system-key.rut");

        assert!(matches!(
            key_file.parent_directory(),
            Err(SystemMasterKeyFileError::InvalidPath { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn created_envelopes_are_private_and_public_ones_are_refused() -> Result<(), Box<dyn Error>> {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir()?;
        let key_file = SystemMasterKeyFile::new(directory.path().join("system-key.rut"));
        key_file.create(&envelope(0x33)?)?;

        let mode = fs::metadata(key_file.path())?.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        fs::set_permissions(key_file.path(), fs::Permissions::from_mode(0o644))?;
        assert!(matches!(
            key_file.load(),
            Err(SystemMasterKeyFileError::NotPrivateFile { mode: 0o644, .. })
        ));
        Ok(())
    }
}
