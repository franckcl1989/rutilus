use std::{
    fs::{self, File},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use rutilus_security::{MASTER_KEY_ENVELOPE_LENGTH, MasterKeyProtectionError, ProtectedMasterKey};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Exclusive, bounded persistence for one passphrase-protected master key.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MasterKeyFile {
    path: PathBuf,
}

impl MasterKeyFile {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Creates a new key file without ever replacing an existing instance key.
    ///
    /// The envelope is written to a securely created sibling temporary file,
    /// synchronized, and persisted with no-clobber semantics. A successful
    /// persist is synchronized again before returning.
    ///
    /// # Errors
    ///
    /// Returns [`MasterKeyFileError::AlreadyExists`] if initialization already
    /// produced a key file. Other variants retain the exact I/O stage without
    /// including passphrases, plaintext keys, or envelope bytes.
    pub fn create(&self, protected: &ProtectedMasterKey) -> Result<(), MasterKeyFileError> {
        let parent = self.parent_directory()?;
        fs::create_dir_all(parent).map_err(|source| MasterKeyFileError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| {
            MasterKeyFileError::CreateTemporary {
                directory: parent.to_path_buf(),
                source,
            }
        })?;
        temporary
            .write_all(protected.as_bytes())
            .map_err(|source| MasterKeyFileError::WriteTemporary {
                directory: parent.to_path_buf(),
                source,
            })?;
        temporary.as_file().sync_all().map_err(|source| {
            MasterKeyFileError::SynchronizeTemporary {
                directory: parent.to_path_buf(),
                source,
            }
        })?;

        let persisted = temporary.persist_noclobber(&self.path).map_err(|error| {
            if error.error.kind() == io::ErrorKind::AlreadyExists {
                MasterKeyFileError::AlreadyExists {
                    path: self.path.clone(),
                }
            } else {
                MasterKeyFileError::Persist {
                    path: self.path.clone(),
                    source: error.error,
                }
            }
        })?;
        persisted
            .sync_all()
            .map_err(|source| MasterKeyFileError::SynchronizePersisted {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    /// Replaces the key file with a re-protected envelope — the legacy
    /// (`RUTMK001` → `RUTMK002`) format migration: the migrated envelope is
    /// written to a securely created sibling temporary file, synchronized,
    /// and renamed over the existing file. Unlike [`Self::create`] this
    /// overwrites on purpose; it is meant to run under the runtime lock the
    /// unlock path already holds, so the load → re-protect → replace
    /// sequence cannot interleave with a concurrent writer.
    ///
    /// # Errors
    ///
    /// Returns [`MasterKeyFileError`] when the path has no parent directory
    /// or any write, synchronize, or rename stage fails.
    pub fn replace(&self, protected: &ProtectedMasterKey) -> Result<(), MasterKeyFileError> {
        let parent = self.parent_directory()?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|source| {
            MasterKeyFileError::CreateTemporary {
                directory: parent.to_path_buf(),
                source,
            }
        })?;
        temporary
            .write_all(protected.as_bytes())
            .map_err(|source| MasterKeyFileError::WriteTemporary {
                directory: parent.to_path_buf(),
                source,
            })?;
        temporary.as_file().sync_all().map_err(|source| {
            MasterKeyFileError::SynchronizeTemporary {
                directory: parent.to_path_buf(),
                source,
            }
        })?;

        let persisted =
            temporary
                .persist(&self.path)
                .map_err(|error| MasterKeyFileError::Persist {
                    path: self.path.clone(),
                    source: error.error,
                })?;
        persisted
            .sync_all()
            .map_err(|source| MasterKeyFileError::SynchronizePersisted {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    /// Loads one exact, regular, non-symlink envelope without unbounded reads.
    ///
    /// # Errors
    ///
    /// Returns [`MasterKeyFileError`] when metadata or I/O fails, the path is not
    /// a regular file, or the security layer rejects its envelope format.
    pub fn load(&self) -> Result<ProtectedMasterKey, MasterKeyFileError> {
        let metadata = fs::symlink_metadata(&self.path).map_err(|source| {
            MasterKeyFileError::ReadMetadata {
                path: self.path.clone(),
                source,
            }
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(MasterKeyFileError::NotRegularFile {
                path: self.path.clone(),
            });
        }
        let mut file = File::open(&self.path).map_err(|source| MasterKeyFileError::Open {
            path: self.path.clone(),
            source,
        })?;
        let opened_metadata =
            file.metadata()
                .map_err(|source| MasterKeyFileError::ReadMetadata {
                    path: self.path.clone(),
                    source,
                })?;
        if !opened_metadata.is_file() || opened_metadata.len() != MASTER_KEY_ENVELOPE_LENGTH as u64
        {
            return Err(MasterKeyFileError::Envelope {
                path: self.path.clone(),
                source: MasterKeyProtectionError::InvalidEnvelopeLength,
            });
        }
        let mut bytes = [0_u8; MASTER_KEY_ENVELOPE_LENGTH];
        file.read_exact(&mut bytes)
            .map_err(|source| MasterKeyFileError::Read {
                path: self.path.clone(),
                source,
            })?;
        ProtectedMasterKey::from_bytes(&bytes).map_err(|source| MasterKeyFileError::Envelope {
            path: self.path.clone(),
            source,
        })
    }

    fn parent_directory(&self) -> Result<&Path, MasterKeyFileError> {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| MasterKeyFileError::InvalidPath {
                path: self.path.clone(),
            })
    }
}

/// A secret-safe failure while persisting the encrypted master-key envelope.
#[derive(Debug, Error)]
pub enum MasterKeyFileError {
    #[error("protected master-key path has no usable parent directory: {path}")]
    InvalidPath { path: PathBuf },
    #[error("failed to create master-key directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to create a temporary master-key file in {directory}: {source}")]
    CreateTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write a temporary master-key file in {directory}: {source}")]
    WriteTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to synchronize a temporary master-key file in {directory}: {source}")]
    SynchronizeTemporary {
        directory: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("protected master-key file already exists at {path}")]
    AlreadyExists { path: PathBuf },
    #[error("failed to persist protected master-key file at {path}: {source}")]
    Persist {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "protected master-key file was persisted but could not be synchronized at {path}: {source}"
    )]
    SynchronizePersisted {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read protected master-key metadata at {path}: {source}")]
    ReadMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("protected master-key path is not a regular non-symlink file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("failed to open protected master-key file at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read protected master-key file at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid protected master-key envelope at {path}: {source}")]
    Envelope {
        path: PathBuf,
        #[source]
        source: MasterKeyProtectionError,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_security::{MasterKey, protect_master_key, recover_master_key};
    use secrecy::SecretString;

    use super::*;

    fn protected_key(
        key_byte: u8,
        passphrase: &SecretString,
    ) -> Result<ProtectedMasterKey, MasterKeyProtectionError> {
        protect_master_key(
            &MasterKey::from_boxed_bytes(Box::new([key_byte; 32])),
            passphrase,
        )
    }

    #[test]
    fn creates_loads_and_never_overwrites_an_instance_key() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key_file = MasterKeyFile::new(directory.path().join("nested").join("master-key.rut"));
        let passphrase: SecretString = String::from("local unlock phrase").into();
        let first = protected_key(0x41, &passphrase)?;
        let second = protected_key(0x42, &passphrase)?;

        key_file.create(&first)?;
        let duplicate = key_file.create(&second);
        let loaded = key_file.load()?;
        let _recovered = recover_master_key(&loaded, &passphrase)?;

        assert!(matches!(
            duplicate,
            Err(MasterKeyFileError::AlreadyExists { .. })
        ));
        assert_eq!(loaded, first);
        assert_ne!(loaded, second);
        assert_eq!(
            fs::metadata(key_file.path())?.len(),
            MASTER_KEY_ENVELOPE_LENGTH as u64
        );
        assert!(
            !fs::read(key_file.path())?
                .windows("local unlock phrase".len())
                .any(|window| window == b"local unlock phrase")
        );
        Ok(())
    }

    #[test]
    fn replace_rewrites_the_existing_key_file_with_the_migrated_envelope()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key_file = MasterKeyFile::new(directory.path().join("master-key.rut"));
        let passphrase: SecretString = String::from("local unlock phrase").into();
        let first = protected_key(0x45, &passphrase)?;
        let migrated = protected_key(0x46, &passphrase)?;

        key_file.create(&first)?;
        key_file.replace(&migrated)?;

        let loaded = key_file.load()?;
        assert_eq!(loaded, migrated);
        let _recovered = recover_master_key(&loaded, &passphrase)?;
        assert_eq!(
            fs::metadata(key_file.path())?.len(),
            MASTER_KEY_ENVELOPE_LENGTH as u64
        );
        Ok(())
    }

    #[test]
    fn rejects_unbounded_or_unknown_envelope_files_without_echoing_bytes()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let key_file = MasterKeyFile::new(directory.path().join("master-key.rut"));
        fs::write(key_file.path(), b"secret-looking truncated input")?;

        let error = key_file
            .load()
            .err()
            .ok_or("truncated key file unexpectedly loaded")?;

        assert!(matches!(
            error,
            MasterKeyFileError::Envelope {
                source: MasterKeyProtectionError::InvalidEnvelopeLength,
                ..
            }
        ));
        assert!(!error.to_string().contains("secret-looking"));

        fs::write(key_file.path(), [0_u8; MASTER_KEY_ENVELOPE_LENGTH])?;
        assert!(matches!(
            key_file.load(),
            Err(MasterKeyFileError::Envelope {
                source: MasterKeyProtectionError::UnsupportedEnvelope,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_paths_without_a_parent_directory() {
        let key_file = MasterKeyFile::new("master-key.rut");

        assert!(matches!(
            key_file.parent_directory(),
            Err(MasterKeyFileError::InvalidPath { .. })
        ));
    }
}
