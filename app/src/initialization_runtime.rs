use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use rutilus_persistence::{CloseStoreError, OpenStoreError, SqliteStore};
use rutilus_platform::{
    InstanceMarkerError, InstanceMarkerFile, InstanceMarkerState, MasterKeyFile,
    MasterKeyFileError, RuntimeLock, RuntimeLockError, RuntimePaths,
};
use rutilus_security::{
    CredentialProtectionError, MasterKey, MasterKeyProtectionError, protect_master_key,
    recover_master_key,
};
use secrecy::{ExposeSecret as _, SecretString};
use thiserror::Error;

const MINIMUM_PASSPHRASE_CHARACTERS: usize = 12;
const MAXIMUM_PASSPHRASE_BYTES: usize = 1024;

/// A locally confirmed unlock passphrase whose debug view is always redacted.
pub struct StandaloneUnlock(SecretString);

impl StandaloneUnlock {
    /// Validates one passphrase entered to unlock an existing instance.
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneUnlockError`] when the value falls outside the
    /// bounded local-unlock policy.
    pub fn existing(passphrase: SecretString) -> Result<Self, StandaloneUnlockError> {
        validate_passphrase(&passphrase)?;
        Ok(Self(passphrase))
    }

    /// Validates two independently entered passphrases before any instance state
    /// is created or changed.
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneUnlockError`] when values differ or fall outside the
    /// bounded local-unlock policy. Error values never retain either input.
    pub fn confirm(
        passphrase: SecretString,
        confirmation: &SecretString,
    ) -> Result<Self, StandaloneUnlockError> {
        let exposed = passphrase.expose_secret();
        validate_passphrase(&passphrase)?;
        if exposed != confirmation.expose_secret() {
            return Err(StandaloneUnlockError::ConfirmationMismatch);
        }
        Ok(Self(passphrase))
    }

    pub(crate) fn passphrase(&self) -> &SecretString {
        &self.0
    }
}

fn validate_passphrase(passphrase: &SecretString) -> Result<(), StandaloneUnlockError> {
    let exposed = passphrase.expose_secret();
    if exposed.len() > MAXIMUM_PASSPHRASE_BYTES {
        return Err(StandaloneUnlockError::TooLong);
    }
    if exposed.chars().count() < MINIMUM_PASSPHRASE_CHARACTERS {
        return Err(StandaloneUnlockError::TooShort);
    }
    Ok(())
}

impl fmt::Debug for StandaloneUnlock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StandaloneUnlock([REDACTED])")
    }
}

/// Whether initialization started fresh or safely resumed a committed key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InitializationOutcome {
    Created,
    Resumed,
}

/// Initializes a complete Standalone instance under one exclusive data lock.
///
/// The protected master key is committed before `SQLite`. If a process stops
/// between those steps, a later invocation with the same passphrase authenticates
/// the existing key and resumes. The versioned instance marker is written last
/// and is the only durable indication of completed initialization.
///
/// # Errors
///
/// Returns [`InitializationError`] for an existing complete instance, ambiguous
/// unpaired database, lock contention, key authentication, storage, migration,
/// close, or completion-marker failure. No variant retains secret input.
pub async fn initialize_standalone(
    paths: &RuntimePaths,
    unlock: &StandaloneUnlock,
) -> Result<InitializationOutcome, InitializationError> {
    let _runtime_lock = RuntimeLock::acquire(paths.runtime_lock_path())
        .map_err(InitializationError::RuntimeLock)?;
    let marker = InstanceMarkerFile::new(paths.instance_marker_path());
    let key_exists = path_exists(paths.master_key_path())?;
    let database_exists = path_exists(paths.database_path())?;
    match marker.state().map_err(InitializationError::ReadMarker)? {
        InstanceMarkerState::Complete if key_exists && database_exists => {
            return Err(InitializationError::AlreadyInitialized);
        }
        InstanceMarkerState::Complete => {
            return Err(InitializationError::IncompleteInitializedInstance {
                master_key_missing: !key_exists,
                database_missing: !database_exists,
            });
        }
        InstanceMarkerState::Missing => {}
    }

    let key_file = MasterKeyFile::new(paths.master_key_path());
    let outcome = if key_exists {
        let protected = key_file
            .load()
            .map_err(InitializationError::MasterKeyFile)?;
        let _master_key = recover_master_key(&protected, unlock.passphrase())
            .map_err(InitializationError::MasterKeyProtection)?;
        InitializationOutcome::Resumed
    } else {
        if database_exists {
            return Err(InitializationError::UnpairedDatabase {
                path: paths.database_path().to_path_buf(),
            });
        }
        let master_key = MasterKey::generate().map_err(InitializationError::GenerateMasterKey)?;
        let protected = protect_master_key(&master_key, unlock.passphrase())
            .map_err(InitializationError::MasterKeyProtection)?;
        key_file
            .create(&protected)
            .map_err(InitializationError::MasterKeyFile)?;
        InitializationOutcome::Created
    };

    let store = SqliteStore::open(paths.database_path())
        .await
        .map_err(InitializationError::OpenStore)?;
    store
        .close()
        .await
        .map_err(InitializationError::CloseStore)?;
    marker.create().map_err(InitializationError::CommitMarker)?;
    Ok(outcome)
}

fn path_exists(path: &Path) -> Result<bool, InitializationError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(InitializationError::InspectPath {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// A secret-free validation failure before Standalone initialization begins.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum StandaloneUnlockError {
    #[error("local unlock passphrase must contain at least 12 characters")]
    TooShort,
    #[error("local unlock passphrase must not exceed 1024 UTF-8 bytes")]
    TooLong,
    #[error("local unlock passphrase confirmation does not match")]
    ConfirmationMismatch,
}

/// A secret-safe failure while creating or resuming a Standalone instance.
#[derive(Debug, Error)]
pub enum InitializationError {
    #[error("failed to acquire exclusive runtime ownership: {0}")]
    RuntimeLock(#[source] RuntimeLockError),
    #[error("failed to inspect initialization marker: {0}")]
    ReadMarker(#[source] InstanceMarkerError),
    #[error("this Rutilus data directory is already initialized")]
    AlreadyInitialized,
    #[error(
        "initialized instance is incomplete (master key missing: {master_key_missing}, database missing: {database_missing})"
    )]
    IncompleteInitializedInstance {
        master_key_missing: bool,
        database_missing: bool,
    },
    #[error("failed to inspect runtime path {path}: {source}")]
    InspectPath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("refusing to generate a new master key for unpaired database {path}")]
    UnpairedDatabase { path: PathBuf },
    #[error("failed to generate the instance master key: {0}")]
    GenerateMasterKey(#[source] CredentialProtectionError),
    #[error("failed to protect or authenticate the instance master key: {0}")]
    MasterKeyProtection(#[source] MasterKeyProtectionError),
    #[error("failed to persist or load the protected instance master key: {0}")]
    MasterKeyFile(#[source] MasterKeyFileError),
    #[error("failed to open and migrate the instance database: {0}")]
    OpenStore(#[source] OpenStoreError),
    #[error("failed to close the initialized instance database: {0}")]
    CloseStore(#[source] CloseStoreError),
    #[error("database and master key are durable but initialization could not be committed: {0}")]
    CommitMarker(#[source] InstanceMarkerError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    fn unlock(value: &str) -> Result<StandaloneUnlock, StandaloneUnlockError> {
        StandaloneUnlock::confirm(value.to_owned().into(), &value.to_owned().into())
    }

    #[tokio::test]
    async fn creates_a_complete_instance_and_refuses_reinitialization() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;

        let outcome = initialize_standalone(&paths, &unlock).await?;

        assert_eq!(outcome, InitializationOutcome::Created);
        assert!(paths.database_path().is_file());
        assert!(paths.master_key_path().is_file());
        assert_eq!(
            InstanceMarkerFile::new(paths.instance_marker_path()).state()?,
            InstanceMarkerState::Complete
        );
        assert!(matches!(
            initialize_standalone(&paths, &unlock).await,
            Err(InitializationError::AlreadyInitialized)
        ));
        fs::remove_file(paths.database_path())?;
        assert!(matches!(
            initialize_standalone(&paths, &unlock).await,
            Err(InitializationError::IncompleteInitializedInstance {
                master_key_missing: false,
                database_missing: true,
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn resumes_a_key_only_interruption_after_authentication() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("resume local unlock phrase")?;
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x51; 32]));
        let protected = protect_master_key(&master_key, unlock.passphrase())?;
        MasterKeyFile::new(paths.master_key_path()).create(&protected)?;

        let outcome = initialize_standalone(&paths, &unlock).await?;

        assert_eq!(outcome, InitializationOutcome::Resumed);
        assert!(paths.database_path().is_file());
        assert_eq!(
            InstanceMarkerFile::new(paths.instance_marker_path()).state()?,
            InstanceMarkerState::Complete
        );
        Ok(())
    }

    #[tokio::test]
    async fn wrong_unlock_cannot_resume_or_create_database_state() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let correct = unlock("correct resume unlock phrase")?;
        let wrong = unlock("incorrect resume phrase")?;
        let master_key = MasterKey::from_boxed_bytes(Box::new([0x52; 32]));
        let protected = protect_master_key(&master_key, correct.passphrase())?;
        MasterKeyFile::new(paths.master_key_path()).create(&protected)?;

        let result = initialize_standalone(&paths, &wrong).await;

        assert!(matches!(
            result,
            Err(InitializationError::MasterKeyProtection(
                MasterKeyProtectionError::AuthenticationFailed
            ))
        ));
        assert!(!paths.database_path().exists());
        assert_eq!(
            InstanceMarkerFile::new(paths.instance_marker_path()).state()?,
            InstanceMarkerState::Missing
        );
        Ok(())
    }

    #[tokio::test]
    async fn refuses_an_unpaired_database_and_a_concurrent_owner() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        fs::create_dir_all(paths.data_directory())?;
        fs::write(paths.database_path(), b"unpaired database")?;
        let unlock = unlock("correct local unlock phrase")?;

        assert!(matches!(
            initialize_standalone(&paths, &unlock).await,
            Err(InitializationError::UnpairedDatabase { .. })
        ));
        fs::remove_file(paths.database_path())?;
        let _owner = RuntimeLock::acquire(paths.runtime_lock_path())?;
        assert!(matches!(
            initialize_standalone(&paths, &unlock).await,
            Err(InitializationError::RuntimeLock(
                RuntimeLockError::AlreadyHeld { .. }
            ))
        ));
        Ok(())
    }

    #[test]
    fn validates_confirmation_bounds_without_exposing_inputs() {
        let too_short =
            StandaloneUnlock::confirm("short".to_owned().into(), &"short".to_owned().into());
        let mismatch = StandaloneUnlock::confirm(
            "first local unlock phrase".to_owned().into(),
            &"second local unlock phrase".to_owned().into(),
        );
        let long_value = "x".repeat(MAXIMUM_PASSPHRASE_BYTES + 1);
        let too_long = StandaloneUnlock::confirm(long_value.clone().into(), &long_value.into());
        let accepted = unlock("accepted local unlock phrase");
        let existing = StandaloneUnlock::existing("existing local unlock phrase".to_owned().into());

        assert!(matches!(&too_short, Err(StandaloneUnlockError::TooShort)));
        assert!(matches!(
            &mismatch,
            Err(StandaloneUnlockError::ConfirmationMismatch)
        ));
        assert!(matches!(&too_long, Err(StandaloneUnlockError::TooLong)));
        assert_eq!(
            format!("{:?}", accepted.as_ref().ok()),
            "Some(StandaloneUnlock([REDACTED]))"
        );
        assert!(existing.is_ok());
        for message in [
            too_short.err().map(|error| error.to_string()),
            mismatch.err().map(|error| error.to_string()),
            too_long.err().map(|error| error.to_string()),
        ] {
            assert!(
                !message
                    .as_deref()
                    .unwrap_or_default()
                    .contains("local unlock phrase")
            );
        }
    }
}
