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
mod credential_repository;
mod endpoint_capability_repository;
mod endpoint_repository;

pub use credential_repository::{
    CredentialRepositoryError, NewCredential, StoredCredential, StoredCredentialError,
};
pub use endpoint_capability_repository::{
    EndpointCapabilityRepositoryError, StoredEndpointCapability, StoredEndpointCapabilityError,
};
pub use endpoint_repository::{EndpointRepositoryError, StoredEndpointError};

const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNECTIONS: u32 = 4;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub struct SqliteStore {
    database: DatabaseConnection,
    database_path: PathBuf,
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
                source,
            })?;

        Ok(Self {
            database,
            database_path: database_path.to_path_buf(),
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
    #[error("failed to migrate SQLite database {path}: {source}")]
    Migrate {
        path: PathBuf,
        #[source]
        source: DbErr,
    },
}

#[derive(Clone, Copy, Debug)]
struct SqliteSettings {
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

fn sqlite_connect_options(database_path: &Path, settings: SqliteSettings) -> ConnectOptions {
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
