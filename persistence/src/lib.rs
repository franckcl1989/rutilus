#![forbid(unsafe_code)]

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rutilus_migration::Migrator;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, DbErr};
use sea_orm_migration::MigratorTrait;
use thiserror::Error;
use tokio::sync::Semaphore;

mod application_adapter;
mod artifact_repository;
mod audit_repository;
mod backup_snapshot;
mod bootstrap_repository;
mod center_binding_repository;
mod center_inbox_repository;
mod center_outbox_repository;
mod credential_repository;
mod endpoint_capability_repository;
mod endpoint_repository;
mod event_repository;
mod group_repository;
mod instance_repository;
mod migration_backup;
mod operation_repository;
mod password_repository;
mod principal_repository;
mod remote_task_repository;
mod resource_snapshot_repository;
mod session_repository;
mod sync_cursor_repository;
mod tag_repository;
mod telemetry_repository;
mod totp_repository;

pub use application_adapter::{EndpointInventoryPersistenceError, EndpointRefreshPersistenceError};
pub use artifact_repository::{ArtifactRepositoryError, StoredArtifactError, artifact_file_path};
pub use audit_repository::{AuditRepositoryError, StoredAuditEventError};
pub use backup_snapshot::{
    AppliedMigrationsError, DatabaseSnapshot, RestoreCheckError, RestoreCompatibility,
    RestoreError, SnapshotError, restore_compatibility, restore_database_files,
};
pub use bootstrap_repository::{BootstrapRepositoryError, StoredBootstrapCodeError};
pub use center_binding_repository::{
    CenterBindingRepositoryError, RevokeOutcome, StoredCenterBindingError,
};
pub use center_inbox_repository::{
    CenterInboxRepositoryError, CreateInboxOutcome, InboxAdvanceOutcome, StoredCenterInboxError,
};
pub use center_outbox_repository::{
    AckOutcome, CenterOutboxRepositoryError, StoredCenterOutboxError,
};
pub use credential_repository::{
    CredentialRepositoryError, NewCredential, StoredCredential, StoredCredentialError,
};
pub use endpoint_capability_repository::{
    EndpointCapabilityRepositoryError, StoredEndpointCapability, StoredEndpointCapabilityError,
};
pub use endpoint_repository::{EndpointRepositoryError, StoredEndpointError};
pub use event_repository::{EventRepositoryError, StoredEventError};
pub use group_repository::{GroupRepositoryError, StoredGroupError};
pub use instance_repository::{InstanceRepositoryError, StoredInstanceError};
pub use migration_backup::{MigrationBackup, MigrationBackupError};
pub use operation_repository::{OperationRepositoryError, StoredBatchError, StoredOperationError};
pub use password_repository::{PasswordRepositoryError, StoredPasswordError};
pub use principal_repository::{PrincipalRepositoryError, StoredPrincipalError};
pub use remote_task_repository::{RemoteTaskRepositoryError, StoredRemoteTaskError};
pub use resource_snapshot_repository::{
    NewResourceSnapshot, ResourceSnapshotRepositoryError, StoredResourceSnapshotError,
};
pub use session_repository::{SessionRepositoryError, StoredSessionError};
pub use sync_cursor_repository::{StoredSyncCursorError, SyncCursorRepositoryError};
pub use tag_repository::{StoredTagError, TagRepositoryError};
pub use telemetry_repository::{
    StoredTelemetryError, TelemetryPruneSummary, TelemetryRepositoryError,
};
pub use totp_repository::{StoredTotpError, TotpRepositoryError};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNECTIONS: u32 = 4;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct SqliteStore {
    database: DatabaseConnection,
    database_path: PathBuf,
    migration_backup: Option<MigrationBackup>,
    write_gate: Arc<Semaphore>,
}

impl SqliteStore {
    /// Opens a file-backed `SQLite` store and applies every pending migration.
    ///
    /// Existing corrupt or incompatible files are reported as errors and are
    /// never deleted or silently recreated.
    ///
    /// # Errors
    ///
    /// Returns [`OpenStoreError`] when the path is invalid, the data directory
    /// cannot be created, the database cannot be opened, or a migration fails.
    pub async fn open(database_path: impl AsRef<Path>) -> Result<Self, OpenStoreError> {
        Self::open_with_settings(database_path.as_ref(), SqliteSettings::default()).await
    }

    #[must_use]
    pub fn database_path(&self) -> &Path {
        &self.database_path
    }

    /// Returns the recovery directory created before migrations during this open.
    #[must_use]
    pub fn migration_backup_path(&self) -> Option<&Path> {
        self.migration_backup.as_ref().map(MigrationBackup::path)
    }

    /// Waits for the active write to finish, then closes the connection pool.
    ///
    /// # Errors
    ///
    /// Returns [`CloseStoreError`] when write coordination is unavailable or
    /// the underlying connection pool cannot close cleanly.
    pub async fn close(self) -> Result<(), CloseStoreError> {
        let Self {
            database,
            database_path,
            migration_backup: _,
            write_gate,
        } = self;
        let _write_permit =
            write_gate
                .acquire_owned()
                .await
                .map_err(|source| CloseStoreError::Coordinate {
                    path: database_path.clone(),
                    source,
                })?;
        database
            .close()
            .await
            .map_err(|source| CloseStoreError::Close {
                path: database_path,
                source,
            })
    }

    async fn open_with_settings(
        database_path: &Path,
        settings: SqliteSettings,
    ) -> Result<Self, OpenStoreError> {
        validate_database_path(database_path)?;
        let database_exists = existing_regular_database(database_path)?;
        let migration_backup = if database_exists && migrations_are_pending(database_path).await? {
            Some(
                MigrationBackup::create(database_path)
                    .map_err(OpenStoreError::CreateMigrationBackup)?,
            )
        } else {
            None
        };
        create_parent_directory(database_path)?;

        let mut options = sqlite_connect_options(database_path, settings);
        options.sqlx_logging(false);
        let database =
            Database::connect(options)
                .await
                .map_err(|source| OpenStoreError::Connect {
                    path: database_path.to_path_buf(),
                    source,
                })?;

        Migrator::up(&database, None)
            .await
            .map_err(|source| OpenStoreError::Migrate {
                path: database_path.to_path_buf(),
                recovery_backup: migration_backup
                    .as_ref()
                    .map(|backup| backup.path().to_path_buf()),
                source,
            })?;

        Ok(Self {
            database,
            database_path: database_path.to_path_buf(),
            migration_backup,
            write_gate: Arc::new(Semaphore::new(1)),
        })
    }
}

#[derive(Debug, Error)]
pub enum CloseStoreError {
    #[error("failed to coordinate shutdown of SQLite database {path}: {source}")]
    Coordinate {
        path: PathBuf,
        #[source]
        source: tokio::sync::AcquireError,
    },
    #[error("failed to close SQLite database {path}: {source}")]
    Close {
        path: PathBuf,
        #[source]
        source: DbErr,
    },
}

#[derive(Debug, Error)]
pub enum OpenStoreError {
    #[error("SQLite database path cannot be empty or name a directory root")]
    InvalidPath,
    #[error("failed to inspect SQLite database path {path}: {source}")]
    InspectDatabasePath {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("SQLite database path is not a regular non-symlink file: {path}")]
    DatabasePathNotRegular { path: PathBuf },
    #[error("failed to create SQLite data directory {path}: {source}")]
    CreateDataDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("failed to open SQLite database {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: DbErr,
    },
    #[error("failed to inspect pending SQLite migrations for {path}: {source}")]
    InspectMigrations {
        path: PathBuf,
        #[source]
        source: DbErr,
    },
    #[error("failed to close read-only SQLite migration inspection for {path}: {source}")]
    CloseMigrationInspection {
        path: PathBuf,
        #[source]
        source: DbErr,
    },
    #[error("failed to create a pre-migration recovery backup: {0}")]
    CreateMigrationBackup(#[source] MigrationBackupError),
    #[error(
        "failed to migrate SQLite database {path} (recovery backup: {recovery_backup:?}): {source}"
    )]
    Migrate {
        path: PathBuf,
        recovery_backup: Option<PathBuf>,
        #[source]
        source: DbErr,
    },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SqliteSettings {
    busy_timeout: Duration,
    max_connections: u32,
}

impl Default for SqliteSettings {
    fn default() -> Self {
        Self {
            busy_timeout: DEFAULT_BUSY_TIMEOUT,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

fn validate_database_path(database_path: &Path) -> Result<(), OpenStoreError> {
    if database_path.as_os_str().is_empty() || database_path.file_name().is_none() {
        return Err(OpenStoreError::InvalidPath);
    }
    Ok(())
}

fn create_parent_directory(database_path: &Path) -> Result<(), OpenStoreError> {
    let Some(parent) = database_path.parent() else {
        return Ok(());
    };
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(parent).map_err(|source| OpenStoreError::CreateDataDirectory {
        path: parent.to_path_buf(),
        source,
    })
}

fn existing_regular_database(database_path: &Path) -> Result<bool, OpenStoreError> {
    let metadata = match std::fs::symlink_metadata(database_path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(OpenStoreError::InspectDatabasePath {
                path: database_path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(OpenStoreError::DatabasePathNotRegular {
            path: database_path.to_path_buf(),
        });
    }
    Ok(true)
}

async fn migrations_are_pending(database_path: &Path) -> Result<bool, OpenStoreError> {
    Ok(migration_counts(database_path).await?.pending > 0)
}

/// The applied and pending migration counts of one closed database.
///
/// Read-only: the inspection never applies a migration, so a doctor check
/// can report the migration state without modifying the database.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationCounts {
    /// Migrations already recorded in the database.
    pub applied: usize,
    /// Migrations this binary would apply on the next open.
    pub pending: usize,
}

/// Inspects one closed database's migration state read-only.
///
/// # Errors
///
/// Returns [`OpenStoreError`] when the database cannot be opened read-only
/// or the migration state cannot be read.
pub async fn migration_counts(database_path: &Path) -> Result<MigrationCounts, OpenStoreError> {
    let mut options = sqlite_read_only_connect_options(database_path);
    options.sqlx_logging(false);
    let database =
        Database::connect(options)
            .await
            .map_err(|source| OpenStoreError::InspectMigrations {
                path: database_path.to_path_buf(),
                source,
            })?;
    let applied = Migrator::get_applied_migrations_read_only(&database)
        .await
        .map_err(|source| OpenStoreError::InspectMigrations {
            path: database_path.to_path_buf(),
            source,
        })?
        .len();
    let pending = Migrator::get_pending_migrations_read_only(&database)
        .await
        .map_err(|source| OpenStoreError::InspectMigrations {
            path: database_path.to_path_buf(),
            source,
        })?
        .len();
    database
        .close()
        .await
        .map_err(|source| OpenStoreError::CloseMigrationInspection {
            path: database_path.to_path_buf(),
            source,
        })?;
    Ok(MigrationCounts { applied, pending })
}

pub(crate) fn sqlite_connect_options(
    database_path: &Path,
    settings: SqliteSettings,
) -> ConnectOptions {
    let configured_path = database_path.to_path_buf();
    let mut options = ConnectOptions::new("sqlite://rutilus.db?mode=rwc");
    options
        .min_connections(1)
        .max_connections(settings.max_connections)
        .connect_timeout(CONNECTION_TIMEOUT)
        .acquire_timeout(CONNECTION_TIMEOUT)
        .map_sqlx_sqlite_opts(move |sqlite| {
            sqlite
                .filename(configured_path.clone())
                .create_if_missing(true)
                .shared_cache(false)
                .foreign_keys(true)
                .busy_timeout(settings.busy_timeout)
                .pragma("journal_mode", "WAL")
                .pragma("synchronous", "NORMAL")
        });
    options
}

pub(crate) fn sqlite_read_only_connect_options(database_path: &Path) -> ConnectOptions {
    let configured_path = database_path.to_path_buf();
    let mut options = ConnectOptions::new("sqlite://rutilus.db?mode=ro");
    options
        .min_connections(1)
        .max_connections(1)
        .connect_timeout(CONNECTION_TIMEOUT)
        .acquire_timeout(CONNECTION_TIMEOUT)
        .map_sqlx_sqlite_opts(move |sqlite| {
            sqlite
                .filename(configured_path.clone())
                .read_only(true)
                .create_if_missing(false)
                .shared_cache(false)
                .foreign_keys(true)
                .busy_timeout(DEFAULT_BUSY_TIMEOUT)
        });
    options
}

#[cfg(test)]
mod tests {
    use std::{error::Error, time::Instant};

    use rutilus_entity::{credential, endpoint_address};
    use sea_orm::{ActiveModelTrait, Set, TransactionTrait};
    use sea_orm_migration::SchemaManager;
    use time::OffsetDateTime;
    use uuid::Uuid;

    use super::*;

    #[tokio::test]
    async fn opens_migrates_and_configures_a_file_database() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("nested data").join("rutilus.db");
        let store = SqliteStore::open(&database_path).await?;

        assert_eq!(store.database_path(), database_path);
        assert!(store.migration_backup_path().is_none());
        assert_eq!(store.write_gate.available_permits(), 1);
        let schema = SchemaManager::new(&store.database);
        assert!(schema.has_table("credentials").await?);
        assert!(schema.has_table("endpoints").await?);

        let invalid_address = endpoint_address::ActiveModel {
            id: Set(Uuid::now_v7()),
            endpoint_id: Set(Uuid::now_v7()),
            address: Set(String::from("https://192.0.2.10")),
            is_active: Set(true),
            created_at: Set(OffsetDateTime::now_utc()),
            retired_at: Set(None),
        }
        .insert(&store.database)
        .await;
        assert!(invalid_address.is_err());

        let header = std::fs::read(&database_path)?;
        assert_eq!(header.get(18), Some(&2));
        assert_eq!(header.get(19), Some(&2));
        store.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn backs_up_a_closed_database_before_applying_pending_migrations()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let mut options = sqlite_connect_options(&database_path, SqliteSettings::default());
        options.sqlx_logging(false);
        let partial = Database::connect(options).await?;
        Migrator::up(&partial, Some(1)).await?;
        partial.close().await?;

        let store = SqliteStore::open(&database_path).await?;
        let backup_directory = store
            .migration_backup_path()
            .ok_or("pending migrations did not create a recovery backup")?
            .to_path_buf();
        let backup_database = backup_directory.join("rutilus.db");
        assert_eq!(
            std::fs::read(backup_directory.join("complete.rut"))?,
            b"RUTILUS-SQLITE-BACKUP-1"
        );

        let mut backup_options = sqlite_read_only_connect_options(&backup_database);
        backup_options.sqlx_logging(false);
        let backup = Database::connect(backup_options).await?;
        assert_eq!(
            Migrator::get_applied_migrations_read_only(&backup)
                .await?
                .len(),
            1
        );
        assert_eq!(
            Migrator::get_pending_migrations_read_only(&backup)
                .await?
                .len(),
            Migrator::migrations().len() - 1
        );
        backup.close().await?;
        assert_eq!(
            Migrator::get_applied_migrations_read_only(&store.database)
                .await?
                .len(),
            Migrator::migrations().len()
        );
        store.close().await?;

        let reopened = SqliteStore::open(&database_path).await?;
        assert!(reopened.migration_backup_path().is_none());
        reopened.close().await?;
        Ok(())
    }

    #[tokio::test]
    async fn rejects_a_directory_as_an_existing_database() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;

        let result = SqliteStore::open(directory.path()).await;

        assert!(matches!(
            result,
            Err(OpenStoreError::DatabasePathNotRegular { .. })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn bounds_locked_database_waits_with_the_busy_timeout() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("rutilus.db");
        let busy_timeout = Duration::from_millis(80);
        let store = SqliteStore::open_with_settings(
            &database_path,
            SqliteSettings {
                busy_timeout,
                max_connections: 2,
            },
        )
        .await?;

        let transaction = store.database.begin().await?;
        insert_credential(&transaction, "writer-one").await?;
        let started = Instant::now();
        let blocked_write = insert_credential(&store.database, "writer-two").await;
        let elapsed = started.elapsed();
        assert!(blocked_write.is_err());
        assert!(elapsed >= busy_timeout);
        assert!(elapsed < CONNECTION_TIMEOUT);
        transaction.rollback().await?;
        store.close().await?;
        Ok(())
    }

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
}
