use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    future::Future,
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository,
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialCreationRepository,
    CredentialInventoryRepository, CredentialResolver, CredentialSecretProtector,
    DiscoveredEndpointRepository, EndpointInventoryItem, EndpointInventoryRepository,
    EndpointRefreshRepository, OperationExecutor, ProtectedCredentialCreation, RedfishDiscovery,
    ResolvedCredential, ResourceObservation, StoredCapability, TaskMonitor, TlsIdentityProbe,
};
use rutilus_domain::{
    Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, Credential, CredentialId,
    CredentialVersionId, DeploymentPosture, Endpoint, EndpointCapabilityObservation, EndpointId,
    Operation, OperationId, OperationState, ResourceSnapshot,
};
use rutilus_infra_redfish::{
    NV_REDFISH_DEVELOPMENT_BASELINE, RedfishCommandExecutor, RedfishGateway, TlsProbeInitError,
};
use rutilus_operation_engine::{
    BoundaryFuture as OperationBoundaryFuture, OperationEngine, OperationStore,
};
use rutilus_persistence::{
    ArtifactRepositoryError, AuditRepositoryError, CloseStoreError, CredentialRepositoryError,
    EndpointInventoryPersistenceError, EndpointRefreshPersistenceError, EndpointRepositoryError,
    NewCredential, OpenStoreError, OperationRepositoryError, SqliteStore,
};
use rutilus_platform::{
    InstanceMarkerError, InstanceMarkerFile, InstanceMarkerState, MasterKeyFile,
    MasterKeyFileError, RuntimeLock, RuntimeLockError, RuntimePaths,
};
use rutilus_security::{
    CredentialProtectionError, MasterKey, MasterKeyProtectionError, ProtectedCredentialVersion,
    decrypt_credential, encrypt_credential, recover_master_key,
};
use rutilus_web::{AuditEventQuery, ProductServices, WebProductInfo, router};
use secrecy::SecretString;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{net::TcpListener, sync::oneshot};

use crate::{ActiveCredentialResolverError, StandaloneUnlock, SystemClock, scheduler};

/// Defensive upper bound for the in-memory recent-audit tail served by the
/// Standalone console until persistence exposes a bounded listing query.
const AUDIT_TAIL_EVENTS: usize = 1024;

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
    master_key: MasterKey,
    _runtime_lock: RuntimeLock,
    audit_tail: Arc<Mutex<VecDeque<AuditEvent>>>,
}

impl EndpointInventoryRepository for StandaloneState {
    type Error = EndpointInventoryPersistenceError;

    fn list_endpoint_inventory(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<EndpointInventoryItem>, Self::Error>> {
        EndpointInventoryRepository::list_endpoint_inventory(&self.store)
    }
}

impl CredentialInventoryRepository for StandaloneState {
    type Error = CredentialRepositoryError;

    fn list_credentials(&self) -> BoundaryFuture<'_, Result<Vec<Credential>, Self::Error>> {
        <SqliteStore as CredentialInventoryRepository>::list_credentials(&self.store)
    }
}

impl CredentialSecretProtector for StandaloneState {
    type Protected = ProtectedCredentialVersion;
    type Error = CredentialProtectionError;

    fn protect(
        &self,
        credential_id: CredentialId,
        version_id: CredentialVersionId,
        password: SecretString,
    ) -> Result<Self::Protected, Self::Error> {
        encrypt_credential(&self.master_key, credential_id, version_id, &password)
    }
}

impl CredentialCreationRepository<ProtectedCredentialVersion> for StandaloneState {
    type Error = CredentialRepositoryError;

    /// Persists one identity-bound encrypted version, then returns the domain
    /// projection requested by the application use case.
    ///
    /// The store assigns its own wall-clock timestamps to the persisted rows,
    /// while `CredentialCreation` verifies that the returned credential
    /// matches the protected creation's clock-derived timeline exactly. The
    /// adapter therefore rebuilds the domain value from the preallocated
    /// identities and the creation timestamp after the durable write, keeping
    /// the closed loop consistent for this release.
    fn create_credential(
        &self,
        creation: ProtectedCredentialCreation<ProtectedCredentialVersion>,
    ) -> BoundaryFuture<'_, Result<Credential, Self::Error>> {
        Box::pin(async move {
            let (credential_id, version_id, name, username, protected, created_at) =
                creation.into_parts();
            let _persisted = self
                .store
                .create_credential(NewCredential::new(
                    name.clone(),
                    username.clone(),
                    protected,
                ))
                .await?;
            Credential::try_new(
                credential_id,
                name,
                username,
                version_id,
                created_at,
                created_at,
            )
            .map_err(CredentialRepositoryError::InvalidTimeline)
        })
    }
}

impl CredentialResolver for StandaloneState {
    type Error = ActiveCredentialResolverError;

    fn resolve(
        &self,
        credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        // The 'static resolver boundary cannot borrow the instance's store
        // and master key, so the durable resolution logic is inlined here.
        Box::pin(async move {
            let Some(stored) = self
                .store
                .find_active_credential(credential_id)
                .await
                .map_err(ActiveCredentialResolverError::Repository)?
            else {
                return Ok(None);
            };
            let username = stored.metadata().username().clone();
            let password = decrypt_credential(&self.master_key, stored.protected_secret())
                .map_err(ActiveCredentialResolverError::Protection)?;
            Ok(Some(ResolvedCredential::new(username, password)))
        })
    }
}

impl DiscoveredEndpointRepository for StandaloneState {
    type Error = EndpointRepositoryError;

    fn create_discovered_endpoint<'a>(
        &'a self,
        endpoint: Endpoint,
        observations: &'a [EndpointCapabilityObservation],
    ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
        <SqliteStore as DiscoveredEndpointRepository>::create_discovered_endpoint(
            &self.store,
            endpoint,
            observations,
        )
    }
}

impl EndpointRefreshRepository for StandaloneState {
    type Error = EndpointRefreshPersistenceError;

    fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        <SqliteStore as EndpointRefreshRepository>::find_endpoint(&self.store, endpoint_id)
    }

    fn commit_resource_generation<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [ResourceObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        <SqliteStore as EndpointRefreshRepository>::commit_resource_generation(
            &self.store,
            endpoint_id,
            observations,
            observed_at,
        )
    }
}

impl AuditEventWriter for StandaloneState {
    type Error = StandaloneAuditWriteError;

    /// Persists the immutable fact first, then mirrors it into the bounded
    /// in-memory tail served by the console audit query.
    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            <SqliteStore as AuditEventWriter>::append_audit_event(&self.store, event)
                .await
                .map_err(StandaloneAuditWriteError::Store)?;
            let mut tail = self
                .audit_tail
                .lock()
                .map_err(|_| StandaloneAuditWriteError::Tail(StandaloneAuditTailError))?;
            if tail.len() == AUDIT_TAIL_EVENTS {
                tail.pop_front();
            }
            tail.push_back(event.clone());
            Ok(())
        })
    }
}

impl AuditEventQuery for StandaloneState {
    type Error = StandaloneAuditTailError;

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<AuditEvent>, Self::Error>> {
        Box::pin(async move {
            let tail = self
                .audit_tail
                .lock()
                .map_err(|_| StandaloneAuditTailError)?;
            let take = usize::try_from(limit.get()).map_err(|_| StandaloneAuditTailError)?;
            Ok(tail.iter().rev().take(take).cloned().collect())
        })
    }
}

impl CapabilityQueryRepository for StandaloneState {
    type Error = <SqliteStore as CapabilityQueryRepository>::Error;

    fn find_endpoint_capabilities(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Vec<StoredCapability>>, Self::Error>> {
        <SqliteStore as CapabilityQueryRepository>::find_endpoint_capabilities(
            &self.store,
            endpoint_id,
        )
    }
}

impl OperationStore for StandaloneState {
    type Error = OperationRepositoryError;

    /// Delegates the operation lifecycle to the same `SqliteStore` that owns
    /// every other aggregate, so the Web layer's operation submission and
    /// listing paths (which compose the `OperationStore` boundary of the
    /// product-services bundle) and the local scheduling loop always observe
    /// one authoritative record.
    fn create_operation<'a>(
        &'a self,
        operation: &'a Operation,
    ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
        <SqliteStore as OperationStore>::create_operation(&self.store, operation)
    }

    fn find_operation(
        &self,
        operation_id: OperationId,
    ) -> OperationBoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
        <SqliteStore as OperationStore>::find_operation(&self.store, operation_id)
    }

    fn apply_transition(
        &self,
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
        <SqliteStore as OperationStore>::apply_transition(
            &self.store,
            operation_id,
            new_state,
            occurred_at,
        )
    }

    fn list_operations(
        &self,
        state: Option<OperationState>,
    ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        <SqliteStore as OperationStore>::list_operations(&self.store, state)
    }
}

impl ArtifactRepository for StandaloneState {
    type Error = ArtifactRepositoryError;

    /// Delegates the artifact lifecycle to the same `SqliteStore` that owns
    /// every other aggregate, so the Web layer's §14.3 artifact upload paths
    /// (which compose the `ArtifactRepository` boundary of the
    /// product-services bundle) always observe one authoritative manifest and
    /// progress row — the same row any future recovery scan reads. The store
    /// persists the manifest and progress only; the application upload use
    /// case performs the file bytes under `spawn_blocking` (§7.8) at the
    /// deterministic `artifact_file_path`.
    fn create_artifact<'a>(
        &'a self,
        artifact: &'a Artifact,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { self.store.create_artifact(artifact).await })
    }

    fn find_artifact(
        &self,
        artifact_id: ArtifactId,
    ) -> BoundaryFuture<'_, Result<Option<Artifact>, Self::Error>> {
        Box::pin(async move { self.store.find_artifact(artifact_id).await })
    }

    fn list_artifacts_by_state(
        &self,
        state: ArtifactState,
    ) -> BoundaryFuture<'_, Result<Vec<Artifact>, Self::Error>> {
        Box::pin(async move { self.store.list_artifacts_by_state(state).await })
    }

    fn update_artifact(
        &self,
        artifact_id: ArtifactId,
        uploaded_bytes: u64,
        state: ArtifactState,
        occurred_at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .update_artifact(artifact_id, uploaded_bytes, state, occurred_at)
                .await
        })
    }

    fn artifact_file_path(&self, artifact_id: ArtifactId) -> PathBuf {
        self.store.artifact_file_path(artifact_id)
    }
}

impl CapabilitySnapshotRepository for StandaloneState {
    type Error = <SqliteStore as CapabilitySnapshotRepository>::Error;

    /// The refresh writes the capability snapshot through the same store that
    /// owns the endpoint aggregate, so both rows move atomically and the
    /// whole-snapshot rejection rules cannot diverge between use cases.
    fn replace_endpoint_capabilities<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [EndpointCapabilityObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        <SqliteStore as CapabilitySnapshotRepository>::replace_endpoint_capabilities(
            &self.store,
            endpoint_id,
            observations,
            observed_at,
        )
    }
}

/// A controlled failure while durably appending one audit fact.
#[derive(Debug, Error)]
pub enum StandaloneAuditWriteError {
    #[error("failed to append the audit event: {0}")]
    Store(#[source] AuditRepositoryError),
    #[error("failed to record the in-memory audit tail: {0}")]
    Tail(#[source] StandaloneAuditTailError),
}

/// The in-memory recent-audit tail cannot be read or bounded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneAuditTailError;

impl fmt::Display for StandaloneAuditTailError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the in-memory audit tail is unavailable")
    }
}

impl Error for StandaloneAuditTailError {}

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
                master_key,
                _runtime_lock: runtime_lock,
                audit_tail: Arc::new(Mutex::new(VecDeque::new())),
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
            master_key: _,
            _runtime_lock,
            audit_tail: _,
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

    /// Serves the embedded Web application over the injected product services
    /// until a tracked shutdown future resolves, then waits for Axum's
    /// graceful drain to complete.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bound listener fails while serving.
    pub async fn serve_until<Services, Gateway, Time, Shutdown>(
        self,
        options: StandaloneRunOptions,
        services: Arc<Services>,
        gateway: Arc<Gateway>,
        clock: Time,
        shutdown: Shutdown,
    ) -> io::Result<()>
    where
        Services: ProductServices + 'static,
        Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
        Time: Clock + Clone + 'static,
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let url = self.url();
        println!("Rutilus Standalone is listening at {url}");
        if options.open_browser() {
            launch_browser(url).await;
        }
        axum::serve(
            self.listener,
            router(
                WebProductInfo::new(PRODUCT_VERSION, NV_REDFISH_DEVELOPMENT_BASELINE),
                AuditActor::LocalOperator,
                DeploymentPosture::Standalone,
                services,
                gateway,
                clock,
            ),
        )
        .with_graceful_shutdown(shutdown)
        .await
    }
}

/// Runs the foreground Standalone posture over the injected product services
/// until Ctrl-C, with structured Axum shutdown and no non-loopback plaintext
/// mode.
///
/// # Errors
///
/// Returns [`StandaloneRunError`] when loopback binding, signal registration,
/// or HTTP serving fails.
pub async fn run_standalone<Services, Gateway, Time>(
    options: StandaloneRunOptions,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
) -> Result<(), StandaloneRunError>
where
    Services: ProductServices + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    let binding = StandaloneBinding::bind().await?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    let server = binding.serve_until(options, services, gateway, clock, async move {
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
/// Besides the console, the foreground Standalone run starts the operation
/// scheduling loop (design sections 13.3 and 13.6): one background task
/// sweeps the persisted operations every [`scheduler::TICK_INTERVAL`] while
/// the HTTP server serves. Both stop through one stop signal, drained in the
/// design §7.8 order — scheduling first (the in-flight tick finishes), then
/// the server — before `SQLite` closes, so no task ever touches the store
/// after shutdown begins.
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
    let gateway = RedfishGateway::from_system_roots()
        .await
        .map_err(StandaloneExecutionError::Gateway)?;
    let instance = StandaloneInstance::open(paths, unlock)
        .await
        .map_err(StandaloneExecutionError::Open)?;
    let gateway = Arc::new(gateway);
    let run_result = async {
        let binding = StandaloneBinding::bind().await?;
        // One stop signal stops the scheduler and drains the server in
        // order; the loop task owns its own Arc clones of the authenticated
        // state and the gateway, so it is `'static` and spawnable.
        let (stop_signal, stop_watch) = scheduler::StopSignal::new();
        let scheduler = tokio::spawn(run_operation_scheduler(
            stop_watch.clone(),
            Arc::clone(&instance.state),
            gateway.clone(),
        ));
        run_standalone_with_scheduler(
            binding,
            options,
            Arc::clone(&instance.state),
            gateway,
            stop_watch,
            stop_signal,
            scheduler,
        )
        .await
    }
    .await;
    let close_result = instance.close().await;
    match (run_result, close_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(StandaloneExecutionError::Run(source)),
        (Ok(()), Err(source)) => Err(StandaloneExecutionError::Close(source)),
        (Err(run), Err(close)) => Err(StandaloneExecutionError::RunAndClose { run, close }),
    }
}

/// Assembles the operation scheduling loop over the authenticated Standalone
/// state and runs it until the stop watch fires.
///
/// # Why the composition lives here
///
/// The loop's executor and monitor compose the concrete `StandaloneState`
/// (store, credential resolver, audit writer) and the `RedfishGateway`, and
/// the state type is private to this module, so the composition cannot live
/// in `scheduler`. The task owns its Arc clones, so the composition is
/// `'static` and spawnable.
async fn run_operation_scheduler(
    stop: scheduler::StopWatch,
    state: Arc<StandaloneState>,
    gateway: Arc<RedfishGateway>,
) {
    // One gateway clone serves both the executor (dispatch + verification)
    // and the monitor (Task reads + verification); every boundary resolves
    // the endpoint and credential rows itself, so the loop never sees
    // secrets or transport details (design section 7.2).
    // Every boundary composes over `&StandaloneState` (the Arc itself
    // implements no boundary): the state implements the credential resolver
    // and audit writer roles next to the store's persistence roles.
    let command_executor =
        RedfishCommandExecutor::new(gateway.as_ref().clone(), &state.store, state.as_ref());
    let executor = OperationExecutor::new(
        &state.store,
        &command_executor,
        state.as_ref(),
        SystemClock,
        AuditActor::LocalOperator,
        DeploymentPosture::Standalone,
    );
    let monitor = TaskMonitor::new(
        &state.store,
        &command_executor,
        state.as_ref(),
        AuditActor::LocalOperator,
        DeploymentPosture::Standalone,
    );
    let engine = OperationEngine::new(&state.store);
    scheduler::run(
        stop,
        engine,
        executor,
        monitor,
        scheduler::TICK_INTERVAL,
        SystemClock,
    )
    .await;
}

/// Serves the Standalone console with the operation scheduling loop until
/// Ctrl-C, then drains in the design §7.8 order: stop scheduling first (the
/// loop finishes its in-flight tick), drain the HTTP server, and only then
/// return so `SQLite` can close.
///
/// # Errors
///
/// Returns [`StandaloneRunError`] when loopback binding, signal registration,
/// or HTTP serving fails; the scheduler's own shutdown is always awaited
/// before the store close.
async fn run_standalone_with_scheduler(
    binding: StandaloneBinding,
    options: StandaloneRunOptions,
    services: Arc<StandaloneState>,
    gateway: Arc<RedfishGateway>,
    stop_watch: scheduler::StopWatch,
    stop_signal: scheduler::StopSignal,
    mut scheduler: tokio::task::JoinHandle<()>,
) -> Result<(), StandaloneRunError> {
    // The server's graceful drain waits for the scheduler to have fully
    // stopped first (design §7.8: stop scheduling, then serve): the channel
    // is fired only after the loop task is joined.
    let (scheduler_done_sender, scheduler_done_receiver) = oneshot::channel();
    let server = binding.serve_until(options, services, gateway, SystemClock, async move {
        let mut stop = stop_watch;
        stop.stopped().await;
        let _ = scheduler_done_receiver.await;
    });
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            // The server stopped on its own (a serving failure): stop the
            // scheduler too, and wait for its drain before closing the store.
            stop_signal.signal();
            drain_scheduler(&mut scheduler).await;
            let _ = scheduler_done_sender.send(());
            result.map_err(StandaloneRunError::Serve)
        }
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(StandaloneRunError::Signal)?;
            // §7.8: stop the scheduler first; its in-flight tick finishes.
            stop_signal.signal();
            drain_scheduler(&mut scheduler).await;
            let _ = scheduler_done_sender.send(());
            // The server's shutdown future resolves now; await its drain.
            server.await.map_err(StandaloneRunError::Serve)
        }
    }
}

/// Waits for the scheduling-loop task and reports an unexpected failure.
///
/// The loop never returns an error — it exits only on the stop signal — so a
/// `JoinError` means the task panicked or was cancelled, a programming
/// defect worth surfacing but not a blocker for the `SQLite` close that
/// follows.
async fn drain_scheduler(scheduler: &mut tokio::task::JoinHandle<()>) {
    if let Err(join_error) = scheduler.await {
        eprintln!("The operation scheduling loop failed: {join_error}");
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
    #[error("failed to load platform TLS trust for the Standalone server: {0}")]
    Gateway(#[source] TlsProbeInitError),
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
    use std::{error::Error, fmt};

    use rutilus_application::{
        BoundaryFuture, CoreResourceReader, EndpointDiscovery, RedfishDiscovery,
        ResourceObservation, TlsIdentityObservation, TlsIdentityProbe,
    };
    use rutilus_domain::{CredentialUsername, EndpointAddress, TlsTrust};
    use secrecy::SecretString;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::*;

    /// Every Redfish gateway boundary reports a controlled failure so the
    /// loopback serving test never opens a socket or loads platform trust.
    #[derive(Clone, Copy)]
    struct UnavailableGateway;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct UnavailableGatewayError;

    impl fmt::Display for UnavailableGatewayError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test gateway is unavailable")
        }
    }

    impl Error for UnavailableGatewayError {}

    impl TlsIdentityProbe for UnavailableGateway {
        type Error = UnavailableGatewayError;

        fn observe<'a>(
            &'a self,
            _address: &'a EndpointAddress,
        ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
            Box::pin(async { Err(UnavailableGatewayError) })
        }
    }

    impl RedfishDiscovery for UnavailableGateway {
        type Error = UnavailableGatewayError;

        fn probe_core_capabilities<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
            Box::pin(async { Err(UnavailableGatewayError) })
        }
    }

    impl CoreResourceReader for UnavailableGateway {
        type Error = UnavailableGatewayError;

        fn read_core_resources<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
            Box::pin(async { Err(UnavailableGatewayError) })
        }
    }
    use crate::{StandaloneUnlock, initialize_standalone};

    #[tokio::test]
    async fn binds_only_loopback_and_serves_until_tracked_shutdown() -> Result<(), Box<dyn Error>> {
        let binding = StandaloneBinding::bind().await?;
        let address = binding.address();
        assert!(address.ip().is_loopback());
        assert_ne!(address.port(), 0);
        assert_eq!(binding.url(), format!("http://{address}/"));

        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server = tokio::spawn(binding.serve_until(
            StandaloneRunOptions::new(false),
            Arc::clone(&instance.state),
            Arc::new(UnavailableGateway),
            SystemClock,
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
        instance.close().await?;
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
            master_key,
            _runtime_lock: runtime_lock,
            audit_tail: _,
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
