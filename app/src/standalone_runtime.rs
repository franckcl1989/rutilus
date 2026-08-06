use std::{
    future::Future,
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use rutilus_application::{BoundaryFuture, EndpointInventoryItem, EndpointInventoryRepository};
use rutilus_infra_redfish::NV_REDFISH_DEVELOPMENT_BASELINE;
use rutilus_persistence::{
    CloseStoreError, EndpointInventoryPersistenceError, OpenStoreError, SqliteStore,
};
use rutilus_platform::{
    InstanceMarkerError, InstanceMarkerFile, InstanceMarkerState, MasterKeyFile,
    MasterKeyFileError, RuntimeLock, RuntimeLockError, RuntimePaths,
};
use rutilus_security::{MasterKey, MasterKeyProtectionError, recover_master_key};
use rutilus_web::WebProductInfo;
use thiserror::Error;
use tokio::{net::TcpListener, sync::oneshot};

use crate::StandaloneUnlock;

const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-facing behavior for the foreground Standalone server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneRunOptions {
    open_browser: bool,
}

impl StandaloneRunOptions {
    #[must_use]
    pub const fn new(open_browser: bool) -> Self {
        Self { open_browser }
    }

    #[must_use]
    pub const fn open_browser(self) -> bool {
        self.open_browser
    }
}

impl Default for StandaloneRunOptions {
    fn default() -> Self {
        Self::new(true)
    }
}

/// A fully authenticated Standalone instance held exclusively for one process.
pub struct StandaloneInstance {
    state: Arc<StandaloneState>,
}

struct StandaloneState {
    store: SqliteStore,
    _master_key: MasterKey,
    _runtime_lock: RuntimeLock,
}

impl EndpointInventoryRepository for StandaloneState {
    type Error = EndpointInventoryPersistenceError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        EndpointInventoryRepository::list_endpoint_inventory(&self.store)
    }
}

impl StandaloneInstance {
    /// Authenticates and opens a completed instance without recreating missing
    /// database state.
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneInstanceError`] for lock contention, missing or invalid
    /// initialization state, master-key authentication, or database open/migration.
    pub async fn open(
        paths: &RuntimePaths,
        unlock: &StandaloneUnlock,
    ) -> Result<Self, StandaloneInstanceError> {
        let runtime_lock = RuntimeLock::acquire(paths.runtime_lock_path())
            .map_err(StandaloneInstanceError::RuntimeLock)?;
        let marker = InstanceMarkerFile::new(paths.instance_marker_path());
        match marker.state().map_err(StandaloneInstanceError::Marker)? {
            InstanceMarkerState::Missing => return Err(StandaloneInstanceError::NotInitialized),
            InstanceMarkerState::Complete => {}
        }
        require_existing_database(paths.database_path())?;
        let protected = MasterKeyFile::new(paths.master_key_path())
            .load()
            .map_err(StandaloneInstanceError::MasterKeyFile)?;
        let master_key = recover_master_key(&protected, unlock.passphrase())
            .map_err(StandaloneInstanceError::MasterKeyProtection)?;
        let store = SqliteStore::open(paths.database_path())
            .await
            .map_err(StandaloneInstanceError::OpenStore)?;
        Ok(Self {
            state: Arc::new(StandaloneState {
                store,
                _master_key: master_key,
                _runtime_lock: runtime_lock,
            }),
        })
    }

    #[must_use]
    pub fn database_path(&self) -> &std::path::Path {
        self.state.store.database_path()
    }

    /// Closes `SQLite` before releasing the master key and process lock.
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneInstanceCloseError`] if a Web request still owns
    /// authenticated state or coordinated `SQLite` shutdown fails.
    pub async fn close(self) -> Result<(), StandaloneInstanceCloseError> {
        let state = Arc::try_unwrap(self.state).map_err(|state| {
            StandaloneInstanceCloseError::OutstandingReferences {
                owners: Arc::strong_count(&state),
            }
        })?;
        let StandaloneState {
            store,
            _master_key,
            _runtime_lock,
        } = state;
        store
            .close()
            .await
            .map_err(StandaloneInstanceCloseError::Store)
    }
}

fn require_existing_database(path: &std::path::Path) -> Result<(), StandaloneInstanceError> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            return Err(StandaloneInstanceError::DatabaseMissing {
                path: path.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(StandaloneInstanceError::InspectDatabase {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(StandaloneInstanceError::DatabaseNotRegular {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// A socket already bound to an OS-assigned port on IPv4 loopback only.
#[derive(Debug)]
pub struct StandaloneBinding {
    listener: TcpListener,
    address: SocketAddr,
}

impl StandaloneBinding {
    /// Binds the Standalone listener without exposing a non-loopback option.
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneRunError::Bind`] when no loopback socket can be
    /// opened, or [`StandaloneRunError::LocalAddress`] when the OS cannot
    /// report the selected ephemeral port.
    pub async fn bind() -> Result<Self, StandaloneRunError> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(StandaloneRunError::Bind)?;
        let address = listener
            .local_addr()
            .map_err(StandaloneRunError::LocalAddress)?;
        Ok(Self { listener, address })
    }

    #[must_use]
    pub const fn address(&self) -> SocketAddr {
        self.address
    }

    #[must_use]
    pub fn url(&self) -> String {
        format!("http://{}/", self.address)
    }

    /// Serves the embedded Web application from an authenticated inventory
    /// provider until a tracked shutdown future resolves, then waits for
    /// Axum's graceful drain to complete.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bound listener fails while serving.
    pub async fn serve_until<Repository, Shutdown>(
        self,
        options: StandaloneRunOptions,
        inventory: Arc<Repository>,
        shutdown: Shutdown,
    ) -> io::Result<()>
    where
        Repository: EndpointInventoryRepository + 'static,
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let url = self.url();
        println!("Rutilus Standalone is listening at {url}");
        if options.open_browser() {
            launch_browser(url).await;
        }
        axum::serve(
            self.listener,
            rutilus_web::router(
                WebProductInfo::new(PRODUCT_VERSION, NV_REDFISH_DEVELOPMENT_BASELINE),
                inventory,
            ),
        )
        .with_graceful_shutdown(shutdown)
        .await
    }
}

/// Runs the foreground Standalone posture over an authenticated inventory
/// provider until Ctrl-C, with structured Axum shutdown and no non-loopback
/// plaintext mode.
///
/// # Errors
///
/// Returns [`StandaloneRunError`] when loopback binding, signal registration,
/// or HTTP serving fails.
pub async fn run_standalone<Repository>(
    options: StandaloneRunOptions,
    inventory: Arc<Repository>,
) -> Result<(), StandaloneRunError>
where
    Repository: EndpointInventoryRepository + 'static,
{
    let binding = StandaloneBinding::bind().await?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = binding.serve_until(options, inventory, async move {
        let _result = shutdown_receiver.await;
    });
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result.map_err(StandaloneRunError::Serve),
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(StandaloneRunError::Signal)?;
            let _result = shutdown_sender.send(());
            server.await.map_err(StandaloneRunError::Serve)
        }
    }
}

/// Opens an initialized instance, serves until Ctrl-C, closes `SQLite`, and only
/// then releases the process lock and master key.
///
/// # Errors
///
/// Returns [`StandaloneExecutionError`] while preserving both server and close
/// failures if they occur during the same shutdown.
pub async fn run_initialized_standalone(
    paths: &RuntimePaths,
    unlock: &StandaloneUnlock,
    options: StandaloneRunOptions,
) -> Result<(), StandaloneExecutionError> {
    let instance = StandaloneInstance::open(paths, unlock)
        .await
        .map_err(StandaloneExecutionError::Open)?;
    let inventory = Arc::clone(&instance.state);
    let run_result = run_standalone(options, inventory).await;
    let close_result = instance.close().await;
    match (run_result, close_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(StandaloneExecutionError::Run(source)),
        (Ok(()), Err(source)) => Err(StandaloneExecutionError::Close(source)),
        (Err(run), Err(close)) => Err(StandaloneExecutionError::RunAndClose { run, close }),
    }
}

async fn launch_browser(url: String) {
    let result = tokio::task::spawn_blocking(move || webbrowser::open(&url)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("Could not open the default browser: {error}"),
        Err(error) => eprintln!("Browser launch task failed: {error}"),
    }
}

/// A controlled failure before or during the local foreground server.
#[derive(Debug, Error)]
pub enum StandaloneRunError {
    #[error("failed to bind the Standalone loopback listener: {0}")]
    Bind(#[source] io::Error),
    #[error("failed to read the Standalone listener address: {0}")]
    LocalAddress(#[source] io::Error),
    #[error("failed to register the Standalone shutdown signal: {0}")]
    Signal(#[source] io::Error),
    #[error("Standalone HTTP server failed: {0}")]
    Serve(#[source] io::Error),
}

/// A controlled failure while authenticating and opening an initialized instance.
#[derive(Debug, Error)]
pub enum StandaloneInstanceError {
    #[error("failed to acquire exclusive runtime ownership: {0}")]
    RuntimeLock(#[source] RuntimeLockError),
    #[error("failed to read the instance completion marker: {0}")]
    Marker(#[source] InstanceMarkerError),
    #[error("Rutilus Standalone is not initialized in the selected data directory")]
    NotInitialized,
    #[error("initialized Standalone database is missing at {path}")]
    DatabaseMissing { path: PathBuf },
    #[error("failed to inspect initialized Standalone database at {path}: {source}")]
    InspectDatabase {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("initialized Standalone database is not a regular non-symlink file: {path}")]
    DatabaseNotRegular { path: PathBuf },
    #[error("failed to load the protected Standalone master key: {0}")]
    MasterKeyFile(#[source] MasterKeyFileError),
    #[error("failed to authenticate the Standalone master key: {0}")]
    MasterKeyProtection(#[source] MasterKeyProtectionError),
    #[error("failed to open the initialized Standalone database: {0}")]
    OpenStore(#[source] OpenStoreError),
}

/// A controlled failure while releasing authenticated Standalone state.
#[derive(Debug, Error)]
pub enum StandaloneInstanceCloseError {
    #[error("Standalone Web state still has {owners} live owners during shutdown")]
    OutstandingReferences { owners: usize },
    #[error("failed to close Standalone SQLite state: {0}")]
    Store(#[source] CloseStoreError),
}

/// A controlled failure across authenticated open, foreground serving, and close.
#[derive(Debug, Error)]
pub enum StandaloneExecutionError {
    #[error("failed to open initialized Standalone state: {0}")]
    Open(#[source] StandaloneInstanceError),
    #[error("Standalone server failed: {0}")]
    Run(#[source] StandaloneRunError),
    #[error("Standalone server stopped but SQLite shutdown failed: {0}")]
    Close(#[source] StandaloneInstanceCloseError),
    #[error("Standalone server and SQLite shutdown both failed (server: {run}; close: {close})")]
    RunAndClose {
        run: StandaloneRunError,
        close: StandaloneInstanceCloseError,
    },
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::*;
    use crate::{StandaloneUnlock, initialize_standalone};
    use secrecy::SecretString;

    #[tokio::test]
    async fn binds_only_loopback_and_serves_until_tracked_shutdown() -> Result<(), Box<dyn Error>> {
        let binding = StandaloneBinding::bind().await?;
        let address = binding.address();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        assert_eq!(binding.url(), format!("http://{address}/"));

        let directory = tempfile::tempdir()?;
        let store = Arc::new(SqliteStore::open(directory.path().join("rutilus.db")).await?);
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server = tokio::spawn(binding.serve_until(
            StandaloneRunOptions::new(false),
            Arc::clone(&store),
            async move {
                let _result = shutdown_receiver.await;
            },
        ));
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("{\"status\":\"ok\"}"));

        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(
                b"GET /api/v1/endpoints HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            )
            .await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(response.contains("{\"endpoints\":[]}"));

        shutdown_sender
            .send(())
            .map_err(|()| std::io::Error::other("server shutdown receiver was dropped"))?;
        server.await??;
        Arc::try_unwrap(store)
            .map_err(|_| std::io::Error::other("server retained the SQLite inventory"))?
            .close()
            .await?;
        drop(directory);
        Ok(())
    }

    #[test]
    fn standalone_options_default_to_browser_launch() {
        assert!(StandaloneRunOptions::default().open_browser());
        assert!(!StandaloneRunOptions::new(false).open_browser());
    }

    fn unlock(value: &str) -> Result<StandaloneUnlock, crate::StandaloneUnlockError> {
        StandaloneUnlock::existing(SecretString::from(value.to_owned()))
    }

    #[tokio::test]
    async fn opens_only_complete_authenticated_instance_state() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let correct = unlock("correct local unlock phrase")?;
        let wrong = unlock("incorrect local unlock phrase")?;

        assert!(matches!(
            StandaloneInstance::open(&paths, &correct).await,
            Err(StandaloneInstanceError::NotInitialized)
        ));
        assert!(matches!(
            run_initialized_standalone(&paths, &correct, StandaloneRunOptions::new(false)).await,
            Err(StandaloneExecutionError::Open(
                StandaloneInstanceError::NotInitialized
            ))
        ));
        initialize_standalone(&paths, &correct).await?;
        assert!(matches!(
            StandaloneInstance::open(&paths, &wrong).await,
            Err(StandaloneInstanceError::MasterKeyProtection(
                MasterKeyProtectionError::AuthenticationFailed
            ))
        ));

        let instance = StandaloneInstance::open(&paths, &correct).await?;
        assert_eq!(instance.database_path(), paths.database_path());
        assert!(matches!(
            StandaloneInstance::open(&paths, &correct).await,
            Err(StandaloneInstanceError::RuntimeLock(
                RuntimeLockError::AlreadyHeld { .. }
            ))
        ));
        let retained_state = Arc::clone(&instance.state);
        assert!(matches!(
            instance.close().await,
            Err(StandaloneInstanceCloseError::OutstandingReferences { owners: 2 })
        ));
        assert!(matches!(
            StandaloneInstance::open(&paths, &correct).await,
            Err(StandaloneInstanceError::RuntimeLock(
                RuntimeLockError::AlreadyHeld { .. }
            ))
        ));
        let state = Arc::try_unwrap(retained_state)
            .map_err(|_| std::io::Error::other("test retained unexpected Standalone state"))?;
        let StandaloneState {
            store,
            _master_key: master_key,
            _runtime_lock: runtime_lock,
        } = state;
        store.close().await?;
        drop((master_key, runtime_lock));
        StandaloneInstance::open(&paths, &correct)
            .await?
            .close()
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn never_recreates_a_missing_initialized_database() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        std::fs::remove_file(paths.database_path())?;

        assert!(matches!(
            StandaloneInstance::open(&paths, &unlock).await,
            Err(StandaloneInstanceError::DatabaseMissing { .. })
        ));
        assert!(!paths.database_path().exists());
        Ok(())
    }

    #[tokio::test]
    async fn rejects_corrupt_or_incomplete_initialized_state() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let marker_paths = RuntimePaths::from_root(directory.path().join("invalid-marker"))?;
        let key_paths = RuntimePaths::from_root(directory.path().join("missing-key"))?;
        let database_paths = RuntimePaths::from_root(directory.path().join("invalid-database"))?;
        let corrupt_database_paths =
            RuntimePaths::from_root(directory.path().join("corrupt-database"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&marker_paths, &unlock).await?;
        initialize_standalone(&key_paths, &unlock).await?;
        initialize_standalone(&database_paths, &unlock).await?;
        initialize_standalone(&corrupt_database_paths, &unlock).await?;

        std::fs::write(marker_paths.instance_marker_path(), b"invalid marker")?;
        std::fs::remove_file(key_paths.master_key_path())?;
        std::fs::remove_file(database_paths.database_path())?;
        std::fs::create_dir(database_paths.database_path())?;
        std::fs::write(
            corrupt_database_paths.database_path(),
            b"not a SQLite database",
        )?;

        assert!(matches!(
            StandaloneInstance::open(&marker_paths, &unlock).await,
            Err(StandaloneInstanceError::Marker(_))
        ));
        assert!(matches!(
            StandaloneInstance::open(&key_paths, &unlock).await,
            Err(StandaloneInstanceError::MasterKeyFile(_))
        ));
        assert!(matches!(
            StandaloneInstance::open(&database_paths, &unlock).await,
            Err(StandaloneInstanceError::DatabaseNotRegular { .. })
        ));
        assert!(matches!(
            StandaloneInstance::open(&corrupt_database_paths, &unlock).await,
            Err(StandaloneInstanceError::OpenStore(_))
        ));
        Ok(())
    }
}
