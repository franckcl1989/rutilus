//! The `rutilus backup create` / `rutilus backup restore` orchestration
//! (design §20.1/§20.2, 0.6.0 debt S0).
//!
//! # Backup contents (§20.1)
//!
//! One encrypted package carries: the consistent `SQLite` snapshot (which
//! holds the credential ciphertext, the center binding state, and the
//! artifact metadata rows), the protected master-key envelope(s) — never the
//! plaintext key (§10.3) —, the instance completion marker, the Site TLS
//! pair when present, and the artifact files. The package is authenticated
//! and encrypted with the instance master key, so its confidentiality is
//! exactly the master key's and a package can only be opened by its own
//! instance — the §20.2 instance-identity binding.
//!
//! # Process model
//!
//! The write gate of a running instance is process-local, so the CLI cannot
//! pause another process's writers: `backup create` therefore requires the
//! instance to be stopped, enforced with the runtime lock, and then runs the
//! §20.1 pause → wait → freeze → copy → release sequence through
//! `SqliteStore::consistent_snapshot` on its own store. `backup restore` is
//! offline by construction (§20.2): stop the instance, verify and decrypt
//! the package, check the product and schema versions, restore the data,
//! and let the operator start the instance.
//!
//! # Cross-machine restore (§20.2)
//!
//! The package is encrypted with the instance master key, so only the
//! instance holding that key can open it — the §20.2 instance-identity
//! binding. Restoring a backup on a *different* machine therefore requires
//! carrying the key itself, not just the package:
//!
//! 1. Initialize the target machine and leave it stopped.
//! 2. Copy the source machine's passphrase envelope (`master-key.rut` below
//!    the source data directory) over the target machine's `master-key.rut`.
//! 3. Run `backup restore` with the same passphrase the source envelope was
//!    created with — the carried envelope must match the backup.
//!
//! The passphrase envelope is a portable file, so this supported flow works
//! across machines and platforms. The operating-system envelope
//! (`system-master-key.rut`, DPAPI/Keychain) is bound to the machine that
//! created it and cannot be carried; §10.3 Site/Center instances always use
//! the system envelope, so they are not restorable across machines. A naive
//! restore without the carried envelope fails with a key-mismatch error
//! whose message names both possible causes (wrong passphrase, or another
//! instance's backup).

use std::{
    collections::HashSet,
    fs,
    io::{self, Write as _},
    path::{Path, PathBuf},
};

use rutilus_domain::{ArtifactId, ArtifactState};
use rutilus_persistence::{
    AppliedMigrationsError, ArtifactRepositoryError, CloseStoreError, DatabaseSnapshot,
    OpenStoreError, RestoreCheckError, RestoreCompatibility, RestoreError, SnapshotError,
    SqliteStore, artifact_file_path, restore_compatibility, restore_database_files,
};
use rutilus_platform::{
    InstanceMarkerError, InstanceMarkerFile, InstanceMarkerState, MasterKeyFile,
    MasterKeyFileError, RuntimeLock, RuntimeLockError, RuntimePaths, SystemMasterKeyFile,
    SystemMasterKeyFileError, SystemSecretStore, SystemSecretStoreError,
};
use rutilus_security::{
    BackupEntry, BackupEntryKind, BackupPackageError, DecryptedBackup, MasterKey,
    MasterKeyProtectionError, SystemMasterKeyError, create_backup_package, open_backup_package,
    recover_master_key, recover_master_key_system,
};
use secrecy::SecretString;
use tempfile::NamedTempFile;
use thiserror::Error;
use uuid::Uuid;

/// The product version recorded in every backup package.
const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The backup package entry names, part of the package format contract.
const ENTRY_DATABASE: &str = "database";
const ENTRY_DATABASE_WAL: &str = "database-wal";
const ENTRY_MASTER_KEY: &str = "master-key";
const ENTRY_SYSTEM_MASTER_KEY: &str = "system-master-key";
const ENTRY_INSTANCE_MARKER: &str = "instance";
const ENTRY_TLS_CERTIFICATE: &str = "tls-certificate";
const ENTRY_TLS_PRIVATE_KEY: &str = "tls-private-key";
const ARTIFACT_ENTRY_PREFIX: &str = "artifact-";

/// How the instance master key is unlocked for one backup command.
#[derive(Clone, Debug)]
pub enum BackupKeyUnlock {
    /// The passphrase envelope below the data directory.
    Passphrase(SecretString),
    /// The operating-system-protected envelope.
    System,
}

/// What one `backup create` produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BackupOutcome {
    path: PathBuf,
    entry_count: usize,
    schema_version: u32,
}

impl BackupOutcome {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn entry_count(&self) -> usize {
        self.entry_count
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }
}

/// What one `backup restore` produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreOutcome {
    restored_entries: usize,
    pending_migrations: usize,
}

impl RestoreOutcome {
    #[must_use]
    pub const fn restored_entries(&self) -> usize {
        self.restored_entries
    }

    #[must_use]
    pub const fn pending_migrations(&self) -> usize {
        self.pending_migrations
    }
}

/// Runs the §20.1 backup flow against a stopped instance.
///
/// The runtime lock is held for the whole operation (the instance must not
/// be running: its write gate is process-local and cannot be paused from
/// here), the store is snapshotted under its write gate, and the encrypted
/// package is written to `output` or to the default `backups/` directory
/// below the data directory. The written package is reopened and verified
/// before the outcome is reported.
///
/// # Errors
///
/// Returns [`BackupError`] when the instance is running or not initialized,
/// any state cannot be read, the master key cannot be recovered, the
/// package cannot be created or verified, or the output cannot be written.
pub async fn create_backup(
    paths: &RuntimePaths,
    unlock: &BackupKeyUnlock,
    output: Option<&Path>,
) -> Result<BackupOutcome, BackupError> {
    let _runtime_lock = acquire_stopped_instance(paths)?;
    let store = SqliteStore::open(paths.database_path())
        .await
        .map_err(BackupError::OpenStore)?;
    let snapshot = store
        .consistent_snapshot()
        .await
        .map_err(BackupError::Snapshot)?;
    let schema_version = store
        .applied_migration_count()
        .await
        .map_err(BackupError::SchemaVersion)?;
    let master_key = recover_instance_master_key(paths, unlock).await?;
    let entries = collect_backup_entries(paths, &store, &snapshot).await?;
    store.close().await.map_err(BackupError::CloseStore)?;

    let package = create_backup_package(&master_key, PRODUCT_VERSION, schema_version, &entries)
        .map_err(BackupError::Package)?;
    let output_path = output.map_or_else(|| default_backup_path(paths), Path::to_path_buf);
    write_package(&output_path, &package)?;

    // §20.1 "校验备份": the written package must open again with the same
    // key and carry every entry.
    let verified = open_backup_package(&master_key, &package).map_err(BackupError::Package)?;
    if verified.entries().len() != entries.len() {
        return Err(BackupError::VerificationFailed {
            written: entries.len(),
            verified: verified.entries().len(),
        });
    }

    Ok(BackupOutcome {
        path: output_path,
        entry_count: entries.len(),
        schema_version,
    })
}

/// Runs the §20.2 offline restore flow.
///
/// The instance must be stopped (runtime lock) and must still carry its
/// master key: the package is encrypted with that key, so recovering it both
/// unlocks the package and proves the package belongs to this instance. The
/// package is verified and decrypted, the product and schema versions are
/// checked, and the database, key envelopes, instance marker, TLS pair, and
/// artifact files are restored into the data directory. The restored
/// database is then opened read-only and verified against the package
/// snapshot before the outcome is reported.
///
/// Cross-machine restores are supported only with a carried passphrase
/// envelope (see the module documentation): a key mismatch here — the
/// envelope cannot be unlocked, or the package refuses the recovered key —
/// is reported with an error naming both the wrong-passphrase cause and the
/// other-instance cause, since the two are indistinguishable.
///
/// # Errors
///
/// Returns [`BackupError`] when the instance is running, the master key is
/// unrecoverable or does not match the package, the package is invalid, the
/// versions are incompatible, or any file cannot be written or verified.
pub async fn restore_backup(
    paths: &RuntimePaths,
    unlock: &BackupKeyUnlock,
    package_path: &Path,
) -> Result<RestoreOutcome, BackupError> {
    let _runtime_lock = acquire_stopped_instance(paths)?;
    let master_key = match recover_instance_master_key(paths, unlock).await {
        Ok(master_key) => master_key,
        Err(error)
            if matches!(
                error,
                BackupError::MasterKeyProtection(_) | BackupError::SystemMasterKeyProtection(_)
            ) =>
        {
            // A failed unlock cannot be attributed to a wrong passphrase
            // alone: the envelope present may belong to another machine.
            return Err(BackupError::RestoreUnlockAuthentication(Box::new(error)));
        }
        Err(error) => return Err(error),
    };
    let package = fs::read(package_path).map_err(|source| BackupError::ReadPackage {
        path: package_path.to_path_buf(),
        source,
    })?;
    let backup = open_backup_package(&master_key, &package).map_err(|error| match error {
        BackupPackageError::AuthenticationFailed => BackupError::RestorePackageAuthentication,
        other => BackupError::Package(other),
    })?;
    check_product_version(&backup)?;

    let database_entry = backup
        .entry(ENTRY_DATABASE)
        .ok_or_else(|| BackupError::MissingDatabaseEntry)?;
    let wal_entry = backup.entry(ENTRY_DATABASE_WAL);
    let snapshot = DatabaseSnapshot::from_parts(
        database_entry.content().to_vec(),
        wal_entry.map(|entry| entry.content().to_vec()),
    );
    let compatibility = restore_compatibility(snapshot.database())
        .await
        .map_err(BackupError::RestoreCheck)?;
    let pending_migrations = match compatibility {
        RestoreCompatibility::Compatible { pending_migrations } => pending_migrations,
        RestoreCompatibility::NewerSchema {
            backup_applied,
            supported,
        } => {
            return Err(BackupError::NewerSchema {
                backup_applied,
                supported,
            });
        }
    };

    restore_database_files(paths.database_path(), &snapshot).map_err(BackupError::RestoreFiles)?;
    let restored = restore_data_directory_files(paths, &backup)?;

    // §20.2 verification: the restored database must be byte-identical to
    // the verified package snapshot and must open read-only with a known
    // schema before the restore is reported complete. The staged read-only
    // inspection applies no migrations; pending migrations still apply at
    // the next real open.
    let restored_database =
        fs::read(paths.database_path()).map_err(|source| BackupError::ReadRestored {
            path: paths.database_path().to_path_buf(),
            source,
        })?;
    if restored_database != snapshot.database() {
        return Err(BackupError::RestoredDatabaseDiffers);
    }
    restore_compatibility(&restored_database)
        .await
        .map_err(BackupError::RestoreCheck)?;

    Ok(RestoreOutcome {
        restored_entries: restored,
        pending_migrations,
    })
}

/// Acquires the runtime lock and requires a completed instance.
///
/// # Errors
///
/// Returns [`BackupError`] when the instance is running or not initialized.
fn acquire_stopped_instance(paths: &RuntimePaths) -> Result<RuntimeLock, BackupError> {
    let runtime_lock =
        RuntimeLock::acquire(paths.runtime_lock_path()).map_err(BackupError::RuntimeLock)?;
    match InstanceMarkerFile::new(paths.instance_marker_path())
        .state()
        .map_err(BackupError::Marker)?
    {
        InstanceMarkerState::Missing => return Err(BackupError::NotInitialized),
        InstanceMarkerState::Complete => {}
    }
    Ok(runtime_lock)
}

/// Recovers the instance master key from its protected envelope(s).
///
/// # Errors
///
/// Returns [`BackupError`] when no envelope exists or the envelope cannot be
/// loaded or authenticated.
async fn recover_instance_master_key(
    paths: &RuntimePaths,
    unlock: &BackupKeyUnlock,
) -> Result<MasterKey, BackupError> {
    match unlock {
        BackupKeyUnlock::Passphrase(passphrase) => {
            let protected = MasterKeyFile::new(paths.master_key_path())
                .load()
                .map_err(BackupError::MasterKeyFile)?;
            recover_master_key(&protected, passphrase).map_err(BackupError::MasterKeyProtection)
        }
        BackupKeyUnlock::System => {
            let protected = SystemMasterKeyFile::new(paths.system_master_key_path())
                .load()
                .map_err(BackupError::SystemMasterKeyFile)?;
            let store = SystemSecretStore::new();
            recover_master_key_system(&protected, &store)
                .await
                .map_err(BackupError::SystemMasterKeyProtection)
        }
    }
}

/// Collects every §20.1 entry of the running instance's data directory.
async fn collect_backup_entries(
    paths: &RuntimePaths,
    store: &SqliteStore,
    snapshot: &DatabaseSnapshot,
) -> Result<Vec<BackupEntry>, BackupError> {
    let mut entries = Vec::new();
    entries.push(BackupEntry::new(
        ENTRY_DATABASE,
        BackupEntryKind::Database,
        snapshot.database().to_vec(),
    )?);
    if let Some(wal) = snapshot.wal() {
        entries.push(BackupEntry::new(
            ENTRY_DATABASE_WAL,
            BackupEntryKind::DatabaseWal,
            wal.to_vec(),
        )?);
    }
    if let Ok(protected) = MasterKeyFile::new(paths.master_key_path()).load() {
        entries.push(BackupEntry::new(
            ENTRY_MASTER_KEY,
            BackupEntryKind::MasterKey,
            protected.as_bytes().to_vec(),
        )?);
    }
    if let Ok(protected) = SystemMasterKeyFile::new(paths.system_master_key_path()).load() {
        entries.push(BackupEntry::new(
            ENTRY_SYSTEM_MASTER_KEY,
            BackupEntryKind::SystemMasterKey,
            protected.into_bytes(),
        )?);
    }
    let marker =
        fs::read(paths.instance_marker_path()).map_err(|source| BackupError::ReadState {
            path: paths.instance_marker_path().to_path_buf(),
            source,
        })?;
    entries.push(BackupEntry::new(
        ENTRY_INSTANCE_MARKER,
        BackupEntryKind::InstanceMarker,
        marker,
    )?);
    collect_tls_entries(paths, &mut entries)?;
    collect_artifact_entries(store, &mut entries).await?;
    Ok(entries)
}

/// Adds the Site TLS pair when it was persisted below `tls/`.
fn collect_tls_entries(
    paths: &RuntimePaths,
    entries: &mut Vec<BackupEntry>,
) -> Result<(), BackupError> {
    let cert_path = paths.tls_directory().join("cert.pem");
    let key_path = paths.tls_directory().join("key.pem");
    match (fs::read(&cert_path), fs::read(&key_path)) {
        (Ok(cert), Ok(key)) => {
            entries.push(BackupEntry::new(
                ENTRY_TLS_CERTIFICATE,
                BackupEntryKind::TlsCertificate,
                cert,
            )?);
            entries.push(BackupEntry::new(
                ENTRY_TLS_PRIVATE_KEY,
                BackupEntryKind::TlsPrivateKey,
                key,
            )?);
            Ok(())
        }
        (Err(cert_error), Err(key_error))
            if cert_error.kind() == io::ErrorKind::NotFound
                && key_error.kind() == io::ErrorKind::NotFound =>
        {
            Ok(())
        }
        (Err(source), _) => Err(BackupError::ReadState {
            path: cert_path,
            source,
        }),
        (_, Err(source)) => Err(BackupError::ReadState {
            path: key_path,
            source,
        }),
    }
}

/// Adds one artifact-file entry per stored artifact whose bytes exist.
async fn collect_artifact_entries(
    store: &SqliteStore,
    entries: &mut Vec<BackupEntry>,
) -> Result<(), BackupError> {
    let mut seen = HashSet::new();
    for state in [
        ArtifactState::Uploading,
        ArtifactState::Ready,
        ArtifactState::Failed,
    ] {
        for artifact in store
            .list_artifacts_by_state(state)
            .await
            .map_err(BackupError::ListArtifacts)?
        {
            let artifact_id = artifact.id();
            if !seen.insert(artifact_id) {
                continue;
            }
            let path = artifact_file_path(store.database_path(), artifact_id);
            match fs::read(&path) {
                Ok(bytes) => {
                    entries.push(BackupEntry::new(
                        format!("{ARTIFACT_ENTRY_PREFIX}{artifact_id}"),
                        BackupEntryKind::ArtifactFile,
                        bytes,
                    )?);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    // A declared artifact may legitimately have no bytes yet
                    // (an interrupted upload); its metadata row is restored
                    // through the database entry.
                }
                Err(source) => {
                    return Err(BackupError::ReadArtifact {
                        artifact_id,
                        path,
                        source,
                    });
                }
            }
        }
    }
    Ok(())
}

/// Writes the restored non-database files below the data directory.
fn restore_data_directory_files(
    paths: &RuntimePaths,
    backup: &DecryptedBackup,
) -> Result<usize, BackupError> {
    let mut restored = 0_usize;
    if let Some(entry) = backup.entry(ENTRY_MASTER_KEY) {
        write_restored_file(paths.master_key_path(), entry.content())?;
        restored += 1;
    }
    if let Some(entry) = backup.entry(ENTRY_SYSTEM_MASTER_KEY) {
        write_restored_file(paths.system_master_key_path(), entry.content())?;
        restored += 1;
    }
    if let Some(entry) = backup.entry(ENTRY_INSTANCE_MARKER) {
        write_restored_file(paths.instance_marker_path(), entry.content())?;
        restored += 1;
    }
    if let Some(entry) = backup.entry(ENTRY_TLS_CERTIFICATE) {
        write_restored_file(&paths.tls_directory().join("cert.pem"), entry.content())?;
        restored += 1;
    }
    if let Some(entry) = backup.entry(ENTRY_TLS_PRIVATE_KEY) {
        write_restored_file(&paths.tls_directory().join("key.pem"), entry.content())?;
        restored += 1;
    }
    for entry in backup.entries() {
        if entry.kind() != BackupEntryKind::ArtifactFile {
            continue;
        }
        let artifact_id = entry
            .name()
            .strip_prefix(ARTIFACT_ENTRY_PREFIX)
            .and_then(|value| Uuid::parse_str(value).ok())
            .ok_or_else(|| BackupError::InvalidArtifactEntryName {
                name: entry.name().to_owned(),
            })?;
        let path = artifact_file_path(paths.database_path(), ArtifactId::from_uuid(artifact_id));
        write_restored_file(&path, entry.content())?;
        restored += 1;
    }
    Ok(restored)
}

/// Rejects a backup created by a different product version.
fn check_product_version(backup: &DecryptedBackup) -> Result<(), BackupError> {
    if backup.product_version() == PRODUCT_VERSION {
        Ok(())
    } else {
        Err(BackupError::ProductVersionMismatch {
            backup: backup.product_version().to_owned(),
            current: PRODUCT_VERSION.to_owned(),
        })
    }
}

/// Writes one restored file through a sibling temporary and rename.
fn write_restored_file(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    write_file_atomic(path, bytes).map_err(|source| BackupError::WriteRestored {
        path: path.to_path_buf(),
        source,
    })
}

/// Writes the backup package itself.
fn write_package(path: &Path, bytes: &[u8]) -> Result<(), BackupError> {
    write_file_atomic(path, bytes).map_err(|source| BackupError::WritePackage {
        path: path.to_path_buf(),
        source,
    })
}

/// Atomically replaces `path` with `bytes` (sibling temporary plus rename).
fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    let persisted = temporary.persist(path).map_err(|error| error.error)?;
    persisted.sync_all()
}

/// The default backup location: `backups/backup-<uuid>.rut` below the data
/// directory, next to the pre-migration recovery backups.
fn default_backup_path(paths: &RuntimePaths) -> PathBuf {
    paths
        .data_directory()
        .join("backups")
        .join(format!("backup-{}.rut", Uuid::now_v7()))
}

impl From<BackupPackageError> for BackupError {
    fn from(source: BackupPackageError) -> Self {
        Self::Package(source)
    }
}

/// A controlled failure of one backup or restore command.
#[derive(Debug, Error)]
pub enum BackupError {
    #[error("failed to acquire exclusive runtime ownership (is the instance running?): {0}")]
    RuntimeLock(#[source] RuntimeLockError),
    #[error("this data directory is not initialized; run `rutilus init` first")]
    NotInitialized,
    #[error("failed to read the instance completion marker: {0}")]
    Marker(#[source] InstanceMarkerError),
    #[error("failed to open the product database: {0}")]
    OpenStore(#[source] OpenStoreError),
    #[error("failed to close the product database: {0}")]
    CloseStore(#[source] CloseStoreError),
    #[error("failed to copy the consistent database snapshot: {0}")]
    Snapshot(#[source] SnapshotError),
    #[error("failed to read the applied schema version: {0}")]
    SchemaVersion(#[source] AppliedMigrationsError),
    #[error("failed to load the protected master key: {0}")]
    MasterKeyFile(#[source] MasterKeyFileError),
    #[error("failed to authenticate the master key: {0}")]
    MasterKeyProtection(#[source] MasterKeyProtectionError),
    #[error("failed to load the system-protected master key: {0}")]
    SystemMasterKeyFile(#[source] SystemMasterKeyFileError),
    #[error("failed to recover the system-protected master key: {0}")]
    SystemMasterKeyProtection(#[source] SystemMasterKeyError<SystemSecretStoreError>),
    #[error("failed to read instance state at {path}: {source}")]
    ReadState {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to list artifacts for the backup: {0}")]
    ListArtifacts(#[source] ArtifactRepositoryError),
    #[error("failed to read artifact {artifact_id} at {path}: {source}")]
    ReadArtifact {
        artifact_id: ArtifactId,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to build the backup package: {0}")]
    Package(#[source] BackupPackageError),
    #[error("backup verification failed: wrote {written} entries but reopened {verified}")]
    VerificationFailed { written: usize, verified: usize },
    #[error("restore target has no usable parent directory: {path}")]
    InvalidWritePath { path: PathBuf },
    #[error("failed to write {path}: {source}")]
    WriteRestored {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to write the backup package at {path}: {source}")]
    WritePackage {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to read the backup package at {path}: {source}")]
    ReadPackage {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("backup package is missing its database entry")]
    MissingDatabaseEntry,
    #[error("backup package was created by rutilus {backup}, this binary is rutilus {current}")]
    ProductVersionMismatch { backup: String, current: String },
    #[error(
        "backup schema is newer than this binary supports ({backup_applied} applied, {supported} supported)"
    )]
    NewerSchema {
        backup_applied: usize,
        supported: usize,
    },
    #[error("failed to check the backup schema: {0}")]
    RestoreCheck(#[source] RestoreCheckError),
    #[error("failed to restore the database files: {0}")]
    RestoreFiles(#[source] RestoreError),
    #[error("failed to read the restored database at {path} for verification: {source}")]
    ReadRestored {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error(
        "restore verification failed: the restored database differs from the verified backup snapshot"
    )]
    RestoredDatabaseDiffers,
    #[error(
        "the backup package could not be authenticated with this instance's master key: the \
         passphrase is wrong, or the backup was created by another instance — a cross-machine \
         restore requires first copying the source instance's passphrase envelope over this \
         instance's envelope; instances protected by the operating-system envelope \
         (DPAPI/Keychain) cannot restore across machines"
    )]
    RestorePackageAuthentication,
    #[error(
        "this instance's master key could not be unlocked: the passphrase is wrong, or the key \
         envelope belongs to another instance — a cross-machine restore requires first copying \
         the source instance's passphrase envelope over this instance's envelope; instances \
         protected by the operating-system envelope (DPAPI/Keychain) cannot restore across \
         machines: {0}"
    )]
    RestoreUnlockAuthentication(#[source] Box<BackupError>),
    #[error("backup entry {name:?} has an unusable artifact identity")]
    InvalidArtifactEntryName { name: String },
}

#[cfg(test)]
mod tests {
    use std::{error::Error, path::Path};

    use rutilus_domain::{CredentialId, CredentialName, CredentialUsername, CredentialVersionId};
    use rutilus_persistence::SqliteStore;
    use secrecy::{ExposeSecret as _, SecretString};

    use super::*;

    fn passphrase_unlock(value: &str) -> BackupKeyUnlock {
        BackupKeyUnlock::Passphrase(SecretString::from(value.to_owned()))
    }

    /// Initializes an instance whose store carries one named credential.
    async fn initialized_instance(
        directory: &Path,
    ) -> Result<(RuntimePaths, BackupKeyUnlock), Box<dyn Error>> {
        let paths = RuntimePaths::from_root(directory.join("instance"))?;
        let passphrase = SecretString::from(String::from("correct local unlock phrase"));
        let confirmation = passphrase.clone();
        let unlock = crate::StandaloneUnlock::confirm(passphrase, &confirmation)?;
        crate::initialize_standalone(&paths, &unlock).await?;
        let store = SqliteStore::open(paths.database_path()).await?;
        store
            .create_credential(protected_credential("first-seed")?)
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        store.close().await?;
        Ok((paths, passphrase_unlock("correct local unlock phrase")))
    }

    fn protected_credential(
        name: &str,
    ) -> Result<rutilus_persistence::NewCredential, rutilus_security::CredentialProtectionError>
    {
        let master_key = rutilus_security::MasterKey::from_boxed_bytes(Box::new([0x42; 32]));
        let protected = rutilus_security::encrypt_credential(
            &master_key,
            CredentialId::generate(),
            CredentialVersionId::generate(),
            &SecretString::from(String::from("seed password")),
        )?;
        Ok(rutilus_persistence::NewCredential::new(
            CredentialName::parse(name).map_err(|_| {
                rutilus_security::CredentialProtectionError::InvalidPlaintextEncoding
            })?,
            CredentialUsername::parse("administrator").map_err(|_| {
                rutilus_security::CredentialProtectionError::InvalidPlaintextEncoding
            })?,
            protected,
        ))
    }

    async fn stored_credential_names(paths: &RuntimePaths) -> Result<Vec<String>, Box<dyn Error>> {
        let store = SqliteStore::open(paths.database_path()).await?;
        let names = store
            .list_credentials(100)
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?
            .into_iter()
            .map(|credential| credential.name().to_string())
            .collect();
        store.close().await?;
        Ok(names)
    }

    #[tokio::test]
    async fn create_and_restore_round_trip_preserves_the_data() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let (paths, unlock) = initialized_instance(directory.path()).await?;
        let output = directory.path().join("backups").join("test.rut");

        let outcome = create_backup(&paths, &unlock, Some(&output)).await?;
        assert_eq!(outcome.path(), output);
        assert!(
            outcome.entry_count() >= 3,
            "database, key, and marker entries"
        );
        assert_eq!(outcome.schema_version(), 19);
        let original_key_bytes = std::fs::read(paths.master_key_path())?;

        // Damage the live data after the backup.
        let store = SqliteStore::open(paths.database_path()).await?;
        store
            .create_credential(protected_credential("second-seed")?)
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        store.close().await?;

        let restored = restore_backup(&paths, &unlock, &output).await?;
        assert_eq!(restored.pending_migrations(), 0);

        let mut names = stored_credential_names(&paths).await?;
        names.sort();
        assert_eq!(names, vec!["first-seed"]);
        assert_eq!(std::fs::read(paths.master_key_path())?, original_key_bytes);
        assert!(paths.instance_marker_path().is_file());
        Ok(())
    }

    #[tokio::test]
    async fn restore_rejects_another_instances_package() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let (source_paths, source_unlock) = initialized_instance(directory.path()).await?;
        let output = directory.path().join("source.rut");
        create_backup(&source_paths, &source_unlock, Some(&output)).await?;

        let other_paths = RuntimePaths::from_root(directory.path().join("other"))?;
        let passphrase = SecretString::from(String::from("other local unlock phrase"));
        let confirmation = passphrase.clone();
        let other_unlock = crate::StandaloneUnlock::confirm(passphrase, &confirmation)?;
        crate::initialize_standalone(&other_paths, &other_unlock).await?;

        let result = restore_backup(
            &other_paths,
            &passphrase_unlock("other local unlock phrase"),
            &output,
        )
        .await;
        assert!(matches!(
            result,
            Err(BackupError::RestorePackageAuthentication)
        ));
        Ok(())
    }

    #[tokio::test]
    async fn cross_machine_restore_requires_carrying_the_source_envelope()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let (source_paths, source_unlock) = initialized_instance(directory.path()).await?;
        // Seed one credential under the source instance's own master key, so
        // the final decryption proves the carried envelope's key unlocks the
        // restored data (the `initialized_instance` helper's credential uses
        // a fixed test key and cannot prove that).
        let source_key = recover_instance_master_key(&source_paths, &source_unlock).await?;
        let source_store = SqliteStore::open(source_paths.database_path()).await?;
        let protected = rutilus_security::encrypt_credential(
            &source_key,
            CredentialId::generate(),
            CredentialVersionId::generate(),
            &SecretString::from(String::from("seed password")),
        )?;
        source_store
            .create_credential(rutilus_persistence::NewCredential::new(
                CredentialName::parse("carried-seed")?,
                CredentialUsername::parse("administrator")?,
                protected,
            ))
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        source_store.close().await?;
        let output = directory.path().join("source.rut");
        create_backup(&source_paths, &source_unlock, Some(&output)).await?;
        let source_envelope = std::fs::read(source_paths.master_key_path())?;

        // The target machine is a fresh instance initialized with the same
        // passphrase. The naive restore (package alone, no carried envelope)
        // must fail with the key-mismatch error whose message names the
        // cross-machine remedy.
        let target_paths = RuntimePaths::from_root(directory.path().join("target"))?;
        let passphrase = SecretString::from(String::from("correct local unlock phrase"));
        let confirmation = passphrase.clone();
        let target_unlock = crate::StandaloneUnlock::confirm(passphrase, &confirmation)?;
        crate::initialize_standalone(&target_paths, &target_unlock).await?;
        let target_unlock = passphrase_unlock("correct local unlock phrase");
        assert!(matches!(
            restore_backup(&target_paths, &target_unlock, &output).await,
            Err(BackupError::RestorePackageAuthentication)
        ));

        // The supported flow: carry the source passphrase envelope over the
        // target's, then restore with the source passphrase.
        std::fs::write(target_paths.master_key_path(), &source_envelope)?;
        let restored = restore_backup(&target_paths, &target_unlock, &output).await?;
        assert_eq!(restored.pending_migrations(), 0);

        // The restored data is the source's, and the carried envelope still
        // unlocks it: the master key recovered from the restored envelope
        // decrypts the restored credential ciphertext, and the restored
        // store serves the source's rows.
        let mut names = stored_credential_names(&target_paths).await?;
        names.sort();
        assert_eq!(names, vec!["carried-seed", "first-seed"]);
        let master_key = recover_instance_master_key(&target_paths, &target_unlock).await?;
        let store = SqliteStore::open(target_paths.database_path()).await?;
        let credentials = store
            .list_credentials(10)
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        let carried = credentials
            .iter()
            .find(|credential| credential.name().as_str() == "carried-seed")
            .ok_or_else(|| io::Error::other("carried-seed is missing after the restore"))?;
        let stored = store
            .find_active_credential(carried.id())
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        store.close().await?;
        let stored = stored.ok_or_else(|| io::Error::other("restored credential is missing"))?;
        let password = rutilus_security::decrypt_credential(&master_key, stored.protected_secret())
            .map_err(|error| -> Box<dyn Error> { error.into() })?;
        assert_eq!(password.expose_secret(), "seed password");

        // The restore wrote the package's envelope over the carried one: the
        // target now holds the source machine's exact envelope bytes.
        assert_eq!(
            std::fs::read(target_paths.master_key_path())?,
            source_envelope
        );
        Ok(())
    }

    #[tokio::test]
    async fn restore_with_a_source_passphrase_against_a_fresh_envelope_names_the_remedy()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let (source_paths, source_unlock) = initialized_instance(directory.path()).await?;
        let output = directory.path().join("source.rut");
        create_backup(&source_paths, &source_unlock, Some(&output)).await?;

        // The target machine uses a different passphrase and the operator
        // supplies the source one: the local envelope itself refuses the
        // passphrase, which is indistinguishable from a wrong passphrase, so
        // the error must carry the cross-machine remedy.
        let target_paths = RuntimePaths::from_root(directory.path().join("target"))?;
        let passphrase = SecretString::from(String::from("target machine passphrase"));
        let confirmation = passphrase.clone();
        let target_unlock = crate::StandaloneUnlock::confirm(passphrase, &confirmation)?;
        crate::initialize_standalone(&target_paths, &target_unlock).await?;

        let result = restore_backup(
            &target_paths,
            &passphrase_unlock("correct local unlock phrase"),
            &output,
        )
        .await;
        assert!(matches!(
            result,
            Err(BackupError::RestoreUnlockAuthentication(inner))
                if matches!(inner.as_ref(), BackupError::MasterKeyProtection(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn create_and_restore_require_a_stopped_instance() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let (paths, unlock) = initialized_instance(directory.path()).await?;

        // A running instance owns the runtime lock.
        let passphrase = SecretString::from(String::from("correct local unlock phrase"));
        let instance_unlock = crate::StandaloneUnlock::existing(passphrase)?;
        let instance = crate::StandaloneInstance::open(&paths, &instance_unlock).await?;
        let output = directory.path().join("while-running.rut");
        assert!(matches!(
            create_backup(&paths, &unlock, Some(&output)).await,
            Err(BackupError::RuntimeLock(
                RuntimeLockError::AlreadyHeld { .. }
            ))
        ));
        assert!(matches!(
            restore_backup(&paths, &unlock, &output).await,
            Err(BackupError::RuntimeLock(
                RuntimeLockError::AlreadyHeld { .. }
            ))
        ));
        instance.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn create_refuses_an_uninitialized_directory() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("fresh"))?;

        let result = create_backup(&paths, &passphrase_unlock("unused passphrase"), None).await;

        assert!(matches!(result, Err(BackupError::NotInitialized)));
        Ok(())
    }

    #[tokio::test]
    async fn restore_rejects_a_different_product_version() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let (paths, unlock) = initialized_instance(directory.path()).await?;
        let output = directory.path().join("source.rut");
        create_backup(&paths, &unlock, Some(&output)).await?;
        let package = std::fs::read(&output)?;
        let master_key = recover_instance_master_key(&paths, &unlock).await?;
        let opened = open_backup_package(&master_key, &package)?;
        // Rebuild the package under a different product identity; the
        // schema check itself is covered by the persistence suite.
        let entries = opened
            .entries()
            .iter()
            .map(|entry| BackupEntry::new(entry.name(), entry.kind(), entry.content().to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(BackupError::Package)?;
        let tampered =
            create_backup_package(&master_key, "0.9.9", opened.schema_version(), &entries)
                .map_err(BackupError::Package)?;
        std::fs::write(&output, tampered)?;

        let result = restore_backup(&paths, &unlock, &output).await;
        assert!(matches!(
            result,
            Err(BackupError::ProductVersionMismatch { .. })
        ));
        Ok(())
    }
}
