use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read as _, Write as _},
    path::{Path, PathBuf},
};

use thiserror::Error;

const INSTANCE_MARKER: [u8; 8] = *b"RUTINS01";

/// Validated durable initialization state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstanceMarkerState {
    Missing,
    Complete,
}

/// The last-written commit marker for a fully initialized runtime instance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstanceMarkerFile {
    path: PathBuf,
}

impl InstanceMarkerFile {
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reports only a missing or a fully validated marker. Truncated, extended,
    /// unknown, symlinked, or non-file values are explicit errors.
    ///
    /// # Errors
    ///
    /// Returns [`InstanceMarkerError`] for every state other than missing or
    /// the exact supported marker version.
    pub fn state(&self) -> Result<InstanceMarkerState, InstanceMarkerError> {
        let metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(InstanceMarkerState::Missing);
            }
            Err(source) => {
                return Err(InstanceMarkerError::ReadMetadata {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(InstanceMarkerError::NotRegularFile {
                path: self.path.clone(),
            });
        }
        if metadata.len() != INSTANCE_MARKER.len() as u64 {
            return Err(InstanceMarkerError::Unsupported {
                path: self.path.clone(),
            });
        }

        let mut file = File::open(&self.path).map_err(|source| InstanceMarkerError::Open {
            path: self.path.clone(),
            source,
        })?;
        let mut marker = [0_u8; INSTANCE_MARKER.len()];
        file.read_exact(&mut marker)
            .map_err(|source| InstanceMarkerError::Read {
                path: self.path.clone(),
                source,
            })?;
        if marker != INSTANCE_MARKER {
            return Err(InstanceMarkerError::Unsupported {
                path: self.path.clone(),
            });
        }
        Ok(InstanceMarkerState::Complete)
    }

    /// Writes the completion marker exactly once after all required instance
    /// state has been synchronized.
    ///
    /// # Errors
    ///
    /// Returns [`InstanceMarkerError::AlreadyExists`] instead of replacing any
    /// existing marker, including an invalid marker left by interrupted I/O.
    pub fn create(&self) -> Result<(), InstanceMarkerError> {
        let parent = self.parent_directory()?;
        fs::create_dir_all(parent).map_err(|source| InstanceMarkerError::CreateDirectory {
            path: parent.to_path_buf(),
            source,
        })?;
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(InstanceMarkerError::AlreadyExists {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                return Err(InstanceMarkerError::Create {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        file.write_all(&INSTANCE_MARKER)
            .map_err(|source| InstanceMarkerError::Write {
                path: self.path.clone(),
                source,
            })?;
        file.sync_all()
            .map_err(|source| InstanceMarkerError::Synchronize {
                path: self.path.clone(),
                source,
            })?;
        Ok(())
    }

    fn parent_directory(&self) -> Result<&Path, InstanceMarkerError> {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .ok_or_else(|| InstanceMarkerError::InvalidPath {
                path: self.path.clone(),
            })
    }
}

/// A controlled failure while reading or committing initialization state.
#[derive(Debug, Error)]
pub enum InstanceMarkerError {
    #[error("instance marker path has no usable parent directory: {path}")]
    InvalidPath { path: PathBuf },
    #[error("failed to create instance-marker directory {path}: {source}")]
    CreateDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("instance marker already exists at {path}")]
    AlreadyExists { path: PathBuf },
    #[error("failed to create instance marker at {path}: {source}")]
    Create {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write instance marker at {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to synchronize instance marker at {path}: {source}")]
    Synchronize {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read instance-marker metadata at {path}: {source}")]
    ReadMetadata {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("instance marker is not a regular non-symlink file: {path}")]
    NotRegularFile { path: PathBuf },
    #[error("failed to open instance marker at {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read instance marker at {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("instance marker at {path} is truncated, extended, or unsupported")]
    Unsupported { path: PathBuf },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn distinguishes_missing_and_complete_without_overwriting() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let marker = InstanceMarkerFile::new(directory.path().join("nested").join("instance.rut"));

        assert_eq!(marker.state()?, InstanceMarkerState::Missing);
        marker.create()?;
        assert_eq!(marker.state()?, InstanceMarkerState::Complete);
        assert!(matches!(
            marker.create(),
            Err(InstanceMarkerError::AlreadyExists { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_unknown_truncated_and_non_file_markers() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let marker = InstanceMarkerFile::new(directory.path().join("instance.rut"));
        fs::write(marker.path(), b"unknown!")?;
        assert!(matches!(
            marker.state(),
            Err(InstanceMarkerError::Unsupported { .. })
        ));

        fs::write(marker.path(), b"short")?;
        assert!(matches!(
            marker.state(),
            Err(InstanceMarkerError::Unsupported { .. })
        ));

        fs::remove_file(marker.path())?;
        fs::create_dir(marker.path())?;
        assert!(matches!(
            marker.state(),
            Err(InstanceMarkerError::NotRegularFile { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_a_relative_file_without_a_parent() {
        let marker = InstanceMarkerFile::new("instance.rut");
        assert!(matches!(
            marker.create(),
            Err(InstanceMarkerError::InvalidPath { .. })
        ));
    }
}
