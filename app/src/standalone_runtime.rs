use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    future::Future,
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroU64,
    path::PathBuf,
    sync::atomic::{AtomicBool, Ordering},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use tracing::instrument;

use axum::http::StatusCode;
use rutilus_application::{
    ArtifactRepository, AuditEventWriter, BoundaryFuture, CapabilityQueryRepository,
    CapabilitySnapshotRepository, CenterSessionRegistry, ClassifiedOperationListing, Clock,
    CoreResourceReader, CredentialCreationRepository, CredentialInventoryRepository,
    CredentialResolver, CredentialSecretProtector, DiscoveredEndpointRepository,
    EndpointInventoryItem, EndpointInventoryRepository, EndpointRefreshRepository, EventIngestion,
    EventRepository, EventStream, EventStreamPull, GroupRepository, MetricReportSnapshotReader,
    OperationExecutor, ProtectedCredentialCreation, RedfishDiscovery, ResolvedCredential,
    ResourceDecodeFailure, ResourceObservation, StoredCapability, TagRepository, TaskMonitor,
    TelemetryRepository, TelemetrySampler, TlsIdentityProbe,
};
use rutilus_domain::{
    Argon2IdHash, Artifact, ArtifactId, ArtifactState, AuditActor, AuditEvent, BootstrapCode,
    BootstrapCodeId, Credential, CredentialId, CredentialVersionId, DeploymentPosture, Endpoint,
    EndpointCapabilityObservation, EndpointId, Event, Group, GroupId, Operation, OperationId,
    OperationState, PasswordCredential, Principal, PrincipalId, PrincipalName, PrincipalState,
    ResourceSnapshot, RoleAssignment, SeriesKey, Session, SessionId, Tag, TagName, TelemetrySample,
    TelemetrySeries, TelemetrySeriesId, TotpAuthenticator, TotpAuthenticatorError,
};
use rutilus_infra_redfish::{
    EventStream as GatewayEventStream, EventStreamError, EventStreamOpenError,
    NV_REDFISH_DEVELOPMENT_BASELINE, RedfishCommandExecutor, RedfishGateway, TlsProbeInitError,
};
use rutilus_operation_engine::{
    BoundaryFuture as OperationBoundaryFuture, ClassifiedBatchChild, OperationEngine,
    OperationStore, RemoteTask, RemoteTaskState, RemoteTaskStore,
};
use rutilus_persistence::{
    ArtifactRepositoryError, AuditRepositoryError, BootstrapRepositoryError, CloseStoreError,
    CredentialRepositoryError, EndpointInventoryPersistenceError, EndpointRefreshPersistenceError,
    EndpointRepositoryError, EventRepositoryError, GroupRepositoryError, NewCredential,
    OpenStoreError, OperationRepositoryError, PasswordRepositoryError, PrincipalRepositoryError,
    RemoteTaskRepositoryError, SessionRepositoryError, SqliteStore, TagRepositoryError,
    TelemetryRepositoryError, TotpRepositoryError,
};
use rutilus_platform::{
    InstanceMarkerError, InstanceMarkerFile, InstanceMarkerState, MasterKeyFile,
    MasterKeyFileError, RuntimeLock, RuntimeLockError, RuntimePaths, SystemMasterKeyFile,
    SystemMasterKeyFileError, SystemSecretStore, SystemSecretStoreError,
};
use rutilus_security::{
    CredentialProtectionError, CsrfToken, MasterKey, MasterKeyProtectionError, PasswordHashError,
    ProtectedCredentialVersion, SessionToken, SessionTokenError, SystemMasterKeyError,
    decrypt_credential, encrypt_credential, hash_bootstrap_code, hash_password, recover_master_key,
    recover_master_key_system, verify_code, verify_password,
};
use rutilus_web::{
    AuditEventQuery, AuthGate, AuthPolicy, AuthServices, CenterServices, IssuedSessionTokens,
    ProductServices, WebProductInfo, router_with_auth,
};
use secrecy::{ExposeSecret, SecretBox, SecretString};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::{
    net::TcpListener,
    sync::{Semaphore, SemaphorePermit, oneshot},
    task::spawn_blocking,
};
use tokio_util::sync::CancellationToken;
use tower_http::timeout::TimeoutLayer;

use crate::{
    ActiveCredentialResolverError, StandaloneUnlock, SystemClock, event_listener, scheduler,
    telemetry_sampler::{self, TelemetryRetention},
};

/// Defensive upper bound for the in-memory recent-audit tail served by the
/// Standalone console; the tail is warmed from the store's bounded listing
/// at startup (audit follow-up V5A-2).
const AUDIT_TAIL_EVENTS: usize = 1024;

/// The bounded audit compensation queue (V5A-4): every event whose durable
/// append failed is queued here and retried by the background compensation
/// drain, so a transient store failure can never leave an operation's audit
/// trail permanently dangling after its terminal state was persisted. The
/// queue is purely in-memory: events still queued at process exit (crash or
/// shutdown) are lost, so the guarantee holds only for the process lifetime.
/// A durable outbox for the compensation queue is deferred to a later
/// iteration.
const AUDIT_COMPENSATION_EVENTS: usize = 256;

/// How often the compensation drain retries the queued audit appends.
const AUDIT_COMPENSATION_DRAIN_INTERVAL: Duration = Duration::from_secs(30);

/// The process-wide bounded audit compensation queue.
///
/// The queue is a process-global like the endpoint write gates
/// ([`crate::scheduler::ENDPOINT_WRITE_GATES`]): one process owns one store
/// and one audit trail, so the compensation state has no per-instance home —
/// the `StandaloneState` struct is assembled by three postures whose
/// literals would each need a new field.
static AUDIT_COMPENSATION: OnceLock<Mutex<VecDeque<AuditEvent>>> = OnceLock::new();

/// Whether the startup tail warm-up found corrupt persisted history (V5A-2).
///
/// A corrupt row is presented truthfully: the console audit query reports
/// the failure instead of silently serving a partial view, and the warm-up
/// error is logged with the corrupt operation's identity. The flag is a
/// process-global for the same reason as the compensation queue; it survives
/// a poisoned tail lock (it is a plain atomic, not a mutex), so a broken
/// tail cache never hides the warm-up verdict.
static AUDIT_TAIL_WARM_FAILED: AtomicBool = AtomicBool::new(false);

/// The application-side cap on concurrent Argon2id derivations (P4-12).
///
/// Every derivation the request surface runs — the sign-in verification, the
/// dummy verification of the unknown-user branches (`web/src/auth.rs`), the
/// password-change verification and derivation, the bootstrap-claim
/// derivation, and the administrator set-password derivation
/// (`web/src/auth.rs`) — allocates [`rutilus_domain::ARGON2ID_MEMORY_KIB`]
/// (64 MiB) of memory while it runs. The blocking pool alone would run any
/// number of
/// them concurrently, so a sign-in burst across many usernames could
/// allocate unbounded Argon2id memory at once. This cap bounds the
/// *derivation* concurrency instead: at most [`MAX_CONCURRENT_PASSWORD_DERIVATIONS`]
/// derivations are in flight, so the peak concurrent derivation memory is
/// 4 × 64 MiB = 256 MiB no matter how many attempts queue, and every excess
/// attempt waits for a slot rather than allocating. The gate sits outside
/// `spawn_blocking` on purpose (§7.8): it limits the derivations, never the
/// blocking pool's other work.
const MAX_CONCURRENT_PASSWORD_DERIVATIONS: usize = 4;

/// The cap on requests waiting behind the derivation gate (W3S-1).
///
/// The slot semaphore alone bounds the *running* derivations; the waiters
/// were unbounded — every concurrent request whose derivation had to queue
/// kept its full request state in the gate with no limit on how many could
/// pile up. This cap bounds the *queue*: at most
/// [`MAX_QUEUED_PASSWORD_DERIVATIONS`] requests wait for a slot, and a
/// request arriving past the cap is refused honestly (a fail-closed
/// verification verdict or a [`StandaloneAuthError::HashGateBusy`]
/// boundary error) instead of joining an unbounded queue. The two bounds
/// together mean at most `MAX_CONCURRENT_PASSWORD_DERIVATIONS + MAX_QUEUED_PASSWORD_DERIVATIONS`
/// requests are ever inside the gate.
const MAX_QUEUED_PASSWORD_DERIVATIONS: usize = 8;

/// The process-wide derivation gate of [`MAX_CONCURRENT_PASSWORD_DERIVATIONS`].
///
/// One gate serves every posture (Standalone, Site, Center) and every
/// authenticated instance in the process — the runtime lock guarantees a
/// single instance anyway, and a process-wide gate is exactly what the
/// memory bound means. The permit is acquired before the `spawn_blocking`
/// dispatch and moves into the blocking task itself, so at most the
/// constant's worth of blocking-pool threads are ever busy with Argon2id
/// work; excess callers wait in the gate, occupying no blocking-pool
/// thread.
static PASSWORD_DERIVATION_SLOTS: Semaphore =
    Semaphore::const_new(MAX_CONCURRENT_PASSWORD_DERIVATIONS);

/// The bounded wait queue in front of the derivation gate (W3S-1).
///
/// [`acquire_derivation_slot`] takes one permit before waiting for a slot,
/// so the number of requests waiting behind [`PASSWORD_DERIVATION_SLOTS`]
/// is capped at [`MAX_QUEUED_PASSWORD_DERIVATIONS`] and every further
/// request is refused immediately instead of queueing without bound.
static PASSWORD_DERIVATION_QUEUE: Semaphore = Semaphore::const_new(MAX_QUEUED_PASSWORD_DERIVATIONS);

/// Acquires one derivation slot behind the bounded queue (W3S-1).
///
/// The queue permit is taken with `try_acquire`, so a request arriving when
/// [`MAX_QUEUED_PASSWORD_DERIVATIONS`] others are already waiting is
/// refused right away — `None` — rather than joining an unbounded queue.
/// The queue permit is held only for the wait: it bounds the waiters, while
/// the returned slot permit bounds the running derivations.
async fn acquire_derivation_slot() -> Option<SemaphorePermit<'static>> {
    let Ok(queue_permit) = PASSWORD_DERIVATION_QUEUE.try_acquire() else {
        return None;
    };
    // At most MAX_QUEUED_PASSWORD_DERIVATIONS requests can be waiting
    // here, so the wait for a slot is bounded; the semaphore is never
    // closed, and the fail-closed arm is a totality courtesy.
    let Ok(permit) = PASSWORD_DERIVATION_SLOTS.acquire().await else {
        return None;
    };
    // The queue permit bounds the waiters, never the running derivations:
    // it is released as soon as the slot is acquired, so a freed slot can
    // admit the next waiter.
    drop(queue_permit);
    Some(permit)
}

/// The bounded grace period for in-flight HTTP requests once a shutdown
/// signal resolves (N2-2): the server stops accepting and gives the
/// remaining connections this long to finish, then force-closes them and
/// completes the stop, so a slow client can never stall the shutdown
/// forever.
///
/// The same value bounds every console request handler (the
/// [`tower_http::timeout::TimeoutLayer`] in `serve_until`): a handler that
/// outlives the bound is aborted with a 408. That layer is what actually
/// terminates a slow in-flight request (axum 0.8 runs each connection in
/// its own task, so dropping the serve future alone would leave the
/// handler running against the closing store); the drain race in
/// [`serve_with_bounded_drain`] then bounds the connections whose request
/// never reached a handler (a client that stalls mid-head).
///
/// The 10-second bound is generous for the console's request surface (no
/// handler is expected to run for minutes) and keeps the server's drain
/// comfortably inside the 30-second Windows SCM wait hint
/// (`platform/src/service/windows.rs`) even after the background tasks'
/// own §7.8 drain, so a service stop always lands inside the SCM's hint
/// window.
pub(crate) const GRACEFUL_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

const PRODUCT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-facing behavior for the foreground Standalone server.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandaloneRunOptions {
    open_browser: bool,
    telemetry_retention: TelemetryRetention,
}

impl StandaloneRunOptions {
    #[must_use]
    pub const fn new(open_browser: bool, telemetry_retention: TelemetryRetention) -> Self {
        Self {
            open_browser,
            telemetry_retention,
        }
    }

    #[must_use]
    pub const fn open_browser(self) -> bool {
        self.open_browser
    }

    /// The configured telemetry history retention window (default seven
    /// days); the background sampling loop prunes older history with it.
    #[must_use]
    pub const fn telemetry_retention(self) -> TelemetryRetention {
        self.telemetry_retention
    }
}

impl Default for StandaloneRunOptions {
    fn default() -> Self {
        Self::new(true, TelemetryRetention::default())
    }
}

/// A fully authenticated Standalone instance held exclusively for one process.
pub struct StandaloneInstance {
    state: Arc<StandaloneState>,
}

/// The authenticated runtime state shared with the Site posture's server
/// and background tasks (crate-internal: only the instance hands it out).
///
/// The `registry` tracks the online §15.1 connections of the center
/// posture; the Edge postures never touch it, and the center runtime shares
/// one registry between its accept loop and its web console services.
pub(crate) struct StandaloneState {
    pub(crate) store: SqliteStore,
    /// The instance master key, shared with the store (which holds its `Arc`
    /// clone for the at-rest command protection), so the secret bytes exist
    /// in one allocation.
    pub(crate) master_key: Arc<MasterKey>,
    pub(crate) _runtime_lock: RuntimeLock,
    pub(crate) audit_tail: Arc<Mutex<VecDeque<AuditEvent>>>,
    pub(crate) registry: Arc<CenterSessionRegistry>,
    /// The center certificate-issuer adapter of the center posture; the
    /// Edge postures keep the empty slot, and the center runtime arms it at
    /// startup (the center binding surface is refused without it).
    pub(crate) center_issuer: Mutex<Option<super::center_runtime::CenterCaIssuer>>,
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
        decode_failures: &'a [ResourceDecodeFailure],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        <SqliteStore as EndpointRefreshRepository>::commit_resource_generation(
            &self.store,
            endpoint_id,
            observations,
            decode_failures,
            observed_at,
        )
    }
}

impl AuditEventWriter for StandaloneState {
    type Error = StandaloneAuditWriteError;

    /// Persists the immutable fact first, then mirrors it into the bounded
    /// in-memory tail served by the console audit query.
    ///
    /// A failed durable append is not left silently dangling (V5A-4): the
    /// event is queued for the background compensation drain before the
    /// error escapes, so a transient store failure is retried instead of
    /// permanently losing the terminal fact of an already-terminal
    /// operation. A failed tail mirror is the persistence fork of V5A-6: the
    /// event is durably stored and the query falls back to the store when
    /// the tail cache is broken, so the mirror failure is warned about
    /// rather than reported as a lost append.
    fn append_audit_event<'a>(
        &'a self,
        event: &'a AuditEvent,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            if let Err(source) =
                <SqliteStore as AuditEventWriter>::append_audit_event(&self.store, event).await
            {
                enqueue_audit_compensation(event, &source);
                return Err(StandaloneAuditWriteError::Store(source));
            }
            self.mirror_audit_event_to_tail(event);
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
            if AUDIT_TAIL_WARM_FAILED.load(Ordering::Relaxed) {
                // The warm-up found corrupt persisted history: the console
                // must see the failure, never a partial view that hides it
                // (V5A-2 — the same fail-closed contract as the store's own
                // corrupt-trail read).
                return Err(StandaloneAuditTailError);
            }
            // The tail-lock guard must not live across the fallback await
            // below, so the tail read is completed and the guard dropped
            // before any await.
            if let Ok(tail) = self.audit_tail.lock() {
                let take = usize::try_from(limit.get()).map_err(|_| StandaloneAuditTailError)?;
                return Ok(tail.iter().rev().take(take).cloned().collect());
            }
            // V5A-6: the in-memory tail cache is broken (a poisoned lock —
            // `std::sync::Mutex` poisoning is permanent, so a mirror retry
            // could never succeed). The persisted store remains the truth,
            // and the query falls back to it so the console never silently
            // loses events to the fork.
            tracing::warn!(
                "the in-memory audit tail is unavailable; serving the audit query from the \
                 persisted store"
            );
            self.store
                .list_recent_audit_events(limit.get())
                .await
                .map_err(|_| StandaloneAuditTailError)
        })
    }
}

impl StandaloneState {
    /// Warms the bounded in-memory audit tail from the store's newest
    /// persisted events (V5A-2), so the console's audit query sees the
    /// pre-restart history instead of an empty page.
    ///
    /// The warm-up revalidates every stored row through the same typed
    /// read-back as the per-operation trail read: a corrupt persisted row
    /// marks the tail failed — the console query reports the failure
    /// ([`AuditEventQuery`]) and the corruption is logged with its operation
    /// identity — instead of silently serving a partial view.
    async fn warm_audit_tail(&self) {
        match self
            .store
            .list_recent_audit_events(AUDIT_TAIL_EVENTS as u64)
            .await
        {
            Ok(events) => {
                let Ok(mut tail) = self.audit_tail.lock() else {
                    // A poisoned tail at startup is the V5A-6 broken-cache
                    // case; the query falls back to the store.
                    tracing::warn!(
                        "the in-memory audit tail is unavailable at startup; the audit query \
                         will serve from the persisted store"
                    );
                    return;
                };
                // The listing is newest-first; the tail keeps oldest→newest
                // so the query's reverse iteration serves the newest first.
                for event in events.into_iter().rev() {
                    tail.push_back(event);
                }
            }
            Err(error) => {
                AUDIT_TAIL_WARM_FAILED.store(true, Ordering::Relaxed);
                tracing::error!(
                    "the audit tail could not be warmed from persisted history; the console \
                     audit query will report the failure: {error}"
                );
            }
        }
    }

    /// Mirrors one durably appended event into the bounded in-memory tail.
    ///
    /// A mirror failure is warned about, never fatal: the event is already
    /// persisted, and the console query falls back to the store while the
    /// tail cache is broken (V5A-6).
    fn mirror_audit_event_to_tail(&self, event: &AuditEvent) {
        match self.audit_tail.lock() {
            Ok(mut tail) => {
                if tail.len() == AUDIT_TAIL_EVENTS {
                    tail.pop_front();
                }
                tail.push_back(event.clone());
            }
            Err(_) => {
                tracing::warn!(
                    "an audit event is persisted but could not be mirrored into the in-memory \
                     tail; the console audit query will serve from the persisted store"
                );
            }
        }
    }

    /// Persists one event and mirrors it into the tail — the shared write
    /// path of the append boundary and the compensation drain.
    async fn persist_and_mirror_audit_event(
        &self,
        event: &AuditEvent,
    ) -> Result<(), StandaloneAuditWriteError> {
        <SqliteStore as AuditEventWriter>::append_audit_event(&self.store, event)
            .await
            .map_err(StandaloneAuditWriteError::Store)?;
        self.mirror_audit_event_to_tail(event);
        Ok(())
    }

    /// Retries one queued audit append (V5A-4): a successful retry persists
    /// and mirrors the event; a failed one is requeued — bounded by
    /// [`AUDIT_COMPENSATION_EVENTS`] — and warned about, so the compensation
    /// keeps trying while the store is unavailable and never grows without
    /// bound.
    async fn drain_audit_compensation(&self) {
        let event = {
            let Ok(mut queue) = AUDIT_COMPENSATION
                .get_or_init(|| Mutex::new(VecDeque::new()))
                .lock()
            else {
                tracing::error!("the audit compensation queue is unavailable");
                return;
            };
            queue.pop_front()
        };
        let Some(event) = event else {
            return;
        };
        match self.persist_and_mirror_audit_event(&event).await {
            Ok(()) => {}
            Err(source) => {
                tracing::warn!(
                    "the audit compensation retry failed; the event stays queued: {source}"
                );
                if let Ok(mut queue) = AUDIT_COMPENSATION
                    .get_or_init(|| Mutex::new(VecDeque::new()))
                    .lock()
                {
                    if queue.len() == AUDIT_COMPENSATION_EVENTS {
                        queue.pop_front();
                    }
                    queue.push_back(event);
                }
            }
        }
    }
}

/// Queues one failed audit append for the compensation drain (V5A-4),
/// bounded by [`AUDIT_COMPENSATION_EVENTS`] with the oldest entry dropped.
fn enqueue_audit_compensation(event: &AuditEvent, source: &AuditRepositoryError) {
    let Ok(mut queue) = AUDIT_COMPENSATION
        .get_or_init(|| Mutex::new(VecDeque::new()))
        .lock()
    else {
        tracing::error!(
            "the audit compensation queue is unavailable; the event will not be retried"
        );
        return;
    };
    if queue.len() == AUDIT_COMPENSATION_EVENTS {
        queue.pop_front();
    }
    queue.push_back(event.clone());
    tracing::warn!(
        "the audit append failed ({source}); the event is queued for the compensation drain"
    );
}

/// Runs the audit compensation drain until the stop watch fires: every
/// [`AUDIT_COMPENSATION_DRAIN_INTERVAL`] one queued event whose durable
/// append failed is retried (V5A-4).
async fn run_audit_compensation_drain(mut stop: scheduler::StopWatch, state: Arc<StandaloneState>) {
    let mut interval = tokio::time::interval(AUDIT_COMPENSATION_DRAIN_INTERVAL);
    loop {
        tokio::select! {
            () = stop.stopped() => return,
            _ = interval.tick() => state.drain_audit_compensation().await,
        }
    }
}

/// The §16.2 authentication boundaries of the Standalone runtime: every
/// store method forwards to `SqliteStore` (the TOTP secret flows through the
/// instance master key on the way in and out), and every crypto operation
/// delegates to the security crate, so the Web crate never touches
/// persistence or security internals.
impl AuthServices for StandaloneState {
    type Error = StandaloneAuthError;

    fn find_session_by_token_hash<'a>(
        &'a self,
        token_hash: &'a [u8; 32],
    ) -> BoundaryFuture<'a, Result<Option<Session>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_session_by_token_hash(token_hash)
                .await
                .map_err(StandaloneAuthError::Session)
        })
    }
    fn create_session<'a>(
        &'a self,
        session: &'a Session,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .create_session(session)
                .await
                .map_err(StandaloneAuthError::Session)
        })
    }
    fn touch_session(
        &self,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .touch_session(session_id, at)
                .await
                .map_err(StandaloneAuthError::Session)
        })
    }
    fn revoke_session(
        &self,
        session_id: SessionId,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .revoke_session(session_id, at)
                .await
                .map_err(StandaloneAuthError::Session)
        })
    }
    fn revoke_sessions_for_principal(
        &self,
        principal_id: PrincipalId,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<u64, Self::Error>> {
        Box::pin(async move {
            self.store
                .revoke_sessions_for_principal(principal_id, at)
                .await
                .map_err(StandaloneAuthError::Session)
        })
    }
    fn list_sessions(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Vec<Session>, Self::Error>> {
        Box::pin(async move {
            self.store
                .list_sessions(principal_id)
                .await
                .map_err(StandaloneAuthError::Session)
        })
    }
    fn find_principal(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<Principal>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_principal(principal_id)
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn find_principal_by_name<'a>(
        &'a self,
        name: &'a PrincipalName,
    ) -> BoundaryFuture<'a, Result<Option<Principal>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_principal_by_name(name)
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn list_principals(&self) -> BoundaryFuture<'_, Result<Vec<Principal>, Self::Error>> {
        Box::pin(async move {
            self.store
                .list_principals()
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn create_principal<'a>(
        &'a self,
        principal: &'a Principal,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .create_principal(principal)
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn set_principal_state(
        &self,
        principal_id: PrincipalId,
        state: PrincipalState,
        at: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .set_principal_state(principal_id, state, at)
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn assign_role<'a>(
        &'a self,
        assignment: &'a RoleAssignment,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .assign_role(assignment)
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn find_role_assignment(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<RoleAssignment>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_role_assignment(principal_id)
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn list_role_assignments(
        &self,
    ) -> BoundaryFuture<'_, Result<Vec<RoleAssignment>, Self::Error>> {
        Box::pin(async move {
            self.store
                .list_role_assignments()
                .await
                .map_err(StandaloneAuthError::Principal)
        })
    }
    fn find_password_credential(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Option<PasswordCredential>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_password_credential(principal_id)
                .await
                .map_err(StandaloneAuthError::Password)
        })
    }
    fn save_password_credential<'a>(
        &'a self,
        credential: &'a PasswordCredential,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .save_password_credential(credential)
                .await
                .map_err(StandaloneAuthError::Password)
        })
    }
    fn list_totp_authenticators(
        &self,
        principal_id: PrincipalId,
    ) -> BoundaryFuture<'_, Result<Vec<TotpAuthenticator>, Self::Error>> {
        Box::pin(async move {
            self.store
                .list_totp_authenticators(&self.master_key, principal_id)
                .await
                .map_err(StandaloneAuthError::Totp)
        })
    }
    fn record_totp_step(
        &self,
        authenticator_id: rutilus_domain::TotpAuthenticatorId,
        step: u64,
    ) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
        Box::pin(async move {
            self.store
                .record_totp_step(authenticator_id, step)
                .await
                .map_err(StandaloneAuthError::Totp)
        })
    }
    fn find_bootstrap_code_by_hash<'a>(
        &'a self,
        code_hash: &'a [u8; 32],
    ) -> BoundaryFuture<'a, Result<Option<BootstrapCode>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_bootstrap_code_by_hash(code_hash)
                .await
                .map_err(StandaloneAuthError::Bootstrap)
        })
    }
    fn has_unconsumed_bootstrap_code(&self) -> BoundaryFuture<'_, Result<bool, Self::Error>> {
        Box::pin(async move {
            self.store
                .has_unconsumed_bootstrap_code()
                .await
                .map_err(StandaloneAuthError::Bootstrap)
        })
    }
    fn consume_bootstrap_code<'a>(
        &'a self,
        code_id: BootstrapCodeId,
        used_by: PrincipalId,
        password: &'a PasswordCredential,
        authenticator: Option<&'a TotpAuthenticator>,
        session: &'a Session,
        consumed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .consume_bootstrap_code(
                    &self.master_key,
                    code_id,
                    used_by,
                    password,
                    authenticator,
                    session,
                    consumed_at,
                )
                .await
                .map_err(StandaloneAuthError::Bootstrap)
        })
    }
    fn verify_password(&self, hash: &Argon2IdHash, password: &SecretString) -> bool {
        verify_password(hash, password)
    }
    fn verify_password_async<'a>(
        &'a self,
        hash: &'a Argon2IdHash,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, bool> {
        // §7.8: the Argon2id derivation (64 MiB, 3 passes, 1 lane — the
        // domain constants the value object pins) runs on the blocking pool,
        // never on a worker thread. The `JoinError` arm fails closed: a
        // panicked worker is a wrong-password verdict, which is also the
        // fail-closed choice for the login rate limiter.
        //
        // P4-12: the derivation gate is acquired *before* the blocking-pool
        // dispatch, so a sign-in burst queues here instead of running more
        // than `MAX_CONCURRENT_PASSWORD_DERIVATIONS` derivations at once.
        // W3S-1: the wait queue is bounded — a request past the cap fails
        // closed exactly like a panicked worker, the established
        // fail-closed verdict of this boundary.
        //
        // W3N-1: the permit moves into the blocking task and comes back in
        // its payload, so a cancelled request cannot release it while the
        // derivation still runs — the slot stays occupied until the
        // derivation completes, as the gate's contract states.
        let hash = hash.clone();
        let password = SecretString::from(password.expose_secret().to_owned());
        Box::pin(async move {
            let Some(permit) = acquire_derivation_slot().await else {
                return false;
            };
            spawn_blocking(move || {
                let verdict = verify_password(&hash, &password);
                (permit, verdict)
            })
            .await
            .is_ok_and(|(_permit, verdict)| verdict)
        })
    }
    fn verify_totp(
        &self,
        secret: &SecretBox<[u8; rutilus_domain::TOTP_SECRET_LENGTH]>,
        code: &str,
        now: OffsetDateTime,
        last_used_step: Option<u64>,
    ) -> Result<u64, TotpAuthenticatorError> {
        verify_code(secret, code, now, last_used_step)
    }
    fn hash_password(&self, password: &SecretString) -> Result<Argon2IdHash, Self::Error> {
        hash_password(password).map_err(StandaloneAuthError::Hash)
    }
    fn hash_password_async<'a>(
        &'a self,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<Argon2IdHash, Self::Error>> {
        // §7.8: the Argon2id derivation runs on the blocking pool, never on
        // a worker thread. A panicked worker surfaces as a boundary error —
        // the handlers treat it as the 500 the derivation failure already
        // is.
        //
        // P4-12: the derivation gate is acquired *before* the blocking-pool
        // dispatch, exactly like [`Self::verify_password_async`], so the
        // bootstrap-claim and password-change derivations queue behind the
        // same cap. W3S-1: the wait queue is bounded — a request past the
        // cap is refused with [`StandaloneAuthError::HashGateBusy`], which
        // the web handlers surface as the 503 the exhausted capacity is.
        //
        // W3N-1: the permit moves into the blocking task and comes back in
        // its payload, so a cancelled request cannot release it while the
        // derivation still runs — the slot stays occupied until the
        // derivation completes, as the gate's contract states.
        let password = SecretString::from(password.expose_secret().to_owned());
        Box::pin(async move {
            let Some(permit) = acquire_derivation_slot().await else {
                return Err(StandaloneAuthError::HashGateBusy);
            };
            spawn_blocking(move || {
                let derived = hash_password(&password);
                (permit, derived)
            })
            .await
            .map(|(_permit, derived)| derived)
            .map_err(StandaloneAuthError::HashWorker)?
            .map_err(StandaloneAuthError::Hash)
        })
    }
    fn hash_bootstrap_code(&self, code: &str) -> [u8; 32] {
        hash_bootstrap_code(code)
    }
    fn issue_tokens(&self) -> Result<IssuedSessionTokens, Self::Error> {
        let session_token = SessionToken::generate().map_err(StandaloneAuthError::Tokens)?;
        let csrf_token = CsrfToken::generate().map_err(StandaloneAuthError::Tokens)?;
        Ok(IssuedSessionTokens::new(
            session_token.as_base64url(),
            session_token.hash(),
            csrf_token.as_base64url(),
            csrf_token.hash(),
        ))
    }
    fn token_hash(&self, wire: &str) -> [u8; 32] {
        // An unparseable presentation hashes to a value no stored session
        // row carries, so the lookup refuses it without a dedicated error.
        SessionToken::from_base64url(wire).map_or([0_u8; 32], |token| token.hash())
    }

    /// The bounded derivation queue is the only boundary failure the web
    /// layer must distinguish: [`Self::Error`] would otherwise be opaque to
    /// the generic handlers, and the exhausted-capacity refusal deserves
    /// the 503 it is, not the 500 a failed derivation is (W3S-1).
    fn is_derivation_gate_busy(&self, error: &Self::Error) -> bool {
        matches!(error, StandaloneAuthError::HashGateBusy)
    }
}

/// A controlled failure of the §16.2 authentication boundaries.
#[derive(Debug, Error)]
pub enum StandaloneAuthError {
    #[error("session store operation failed: {0}")]
    Session(#[source] SessionRepositoryError),
    #[error("principal store operation failed: {0}")]
    Principal(#[source] PrincipalRepositoryError),
    #[error("password store operation failed: {0}")]
    Password(#[source] PasswordRepositoryError),
    #[error("TOTP store operation failed: {0}")]
    Totp(#[source] TotpRepositoryError),
    #[error("bootstrap store operation failed: {0}")]
    Bootstrap(#[source] BootstrapRepositoryError),
    #[error("password derivation failed: {0}")]
    Hash(#[source] PasswordHashError),
    #[error("the password derivation worker task failed: {0}")]
    HashWorker(#[source] tokio::task::JoinError),
    #[error("the password derivation gate is at capacity; try again later")]
    HashGateBusy,
    #[error("session token issuance failed: {0}")]
    Tokens(#[source] SessionTokenError),
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

    fn apply_transition_if_current(
        &self,
        operation_id: OperationId,
        expected_state: OperationState,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
        <SqliteStore as OperationStore>::apply_transition_if_current(
            &self.store,
            operation_id,
            expected_state,
            new_state,
            occurred_at,
        )
    }

    fn record_failure_kind(
        &self,
        operation_id: OperationId,
        kind: rutilus_domain::FailureKind,
    ) -> OperationBoundaryFuture<'_, Result<(), Self::Error>> {
        <SqliteStore as OperationStore>::record_failure_kind(&self.store, operation_id, kind)
    }

    fn list_operations(
        &self,
        state: Option<OperationState>,
    ) -> OperationBoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
        <SqliteStore as OperationStore>::list_operations(&self.store, state)
    }

    fn create_batch<'a>(
        &'a self,
        batch: &'a rutilus_domain::BatchOperation,
        children: &'a [Operation],
    ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
        <SqliteStore as OperationStore>::create_batch(&self.store, batch, children)
    }

    fn find_batch(
        &self,
        batch_id: rutilus_domain::BatchOperationId,
    ) -> OperationBoundaryFuture<'_, Result<Option<rutilus_domain::BatchOperation>, Self::Error>>
    {
        <SqliteStore as OperationStore>::find_batch(&self.store, batch_id)
    }

    fn list_batches(
        &self,
    ) -> OperationBoundaryFuture<'_, Result<Vec<rutilus_domain::BatchOperation>, Self::Error>> {
        <SqliteStore as OperationStore>::list_batches(&self.store)
    }

    fn list_batch_children(
        &self,
        batch_id: rutilus_domain::BatchOperationId,
    ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
        <SqliteStore as OperationStore>::list_batch_children(&self.store, batch_id)
    }
}

impl ClassifiedOperationListing for StandaloneState {
    /// Delegates the batch-classified §13.7 operation listing to the same
    /// `SqliteStore` that owns every other aggregate, so the Web layer's
    /// operation-history path (which composes the `ClassifiedOperationListing`
    /// boundary of the product-services bundle) reads the store's one-query
    /// classified listing (V4P-1) instead of resolving through the reference
    /// blanket and paying one classification lookup per listed row.
    fn list_classified(
        &self,
        state: Option<OperationState>,
    ) -> OperationBoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
        <SqliteStore as ClassifiedOperationListing>::list_classified(&self.store, state)
    }
}

impl RemoteTaskStore for StandaloneState {
    type Error = RemoteTaskRepositoryError;

    /// Delegates the §13.6 remote-task observation rows to the same
    /// `SqliteStore` that owns every other aggregate, so the local scheduling
    /// loop's Task monitor and the executor's recovery path always observe
    /// the same persisted row.
    fn save_remote_task<'a>(
        &'a self,
        task: &'a RemoteTask,
    ) -> OperationBoundaryFuture<'a, Result<(), Self::Error>> {
        <SqliteStore as RemoteTaskStore>::save_remote_task(&self.store, task)
    }

    fn find_remote_task(
        &self,
        operation_id: OperationId,
    ) -> OperationBoundaryFuture<'_, Result<Option<RemoteTask>, Self::Error>> {
        <SqliteStore as RemoteTaskStore>::find_remote_task(&self.store, operation_id)
    }

    fn list_remote_tasks_by_state(
        &self,
        state: RemoteTaskState,
    ) -> OperationBoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>> {
        <SqliteStore as RemoteTaskStore>::list_remote_tasks_by_state(&self.store, state)
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

impl EventRepository for StandaloneState {
    type Error = EventRepositoryError;

    /// Delegates the §14.4 event lifecycle to the same `SqliteStore`
    /// that owns every other aggregate, so the `EventService` listeners (which
    /// append through the application ingestion use case) and the console's
    /// event query (which composes the `EventRepository` boundary of the
    /// product-services bundle) always observe one authoritative record —
    /// the same row whose §14.4 dedup unique index absorbs redelivered SSE
    /// frames.
    fn append_event<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { self.store.append_event(event).await })
    }

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        Box::pin(async move {
            // The store's bounded listing takes a plain `usize` (its own
            // contract: `0` lists nothing); the Web layer already caps every
            // query limit at EVENT_QUERY_MAX_LIMIT, so a limit this large
            // cannot be unrepresentable on any supported pointer width — the
            // saturation fallback is the audit projection's precedent.
            let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
            self.store.list_recent_events(limit).await
        })
    }
}

impl TelemetryRepository for StandaloneState {
    type Error = SharedTelemetryRepositoryError;

    /// Delegates the §14.4 telemetry lifecycle to the same `SqliteStore`
    /// that owns every other aggregate, so the sampling task (which appends
    /// through the application use case) and the console's telemetry queries
    /// (which compose the `TelemetryRepository` boundary of the
    /// product-services bundle) always observe one authoritative record —
    /// the same rows the retention prune rewrites.
    fn upsert_series<'a>(
        &'a self,
        endpoint_id: EndpointId,
        series_key: &'a SeriesKey,
    ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>> {
        Box::pin(async move {
            self.store
                .upsert_series(endpoint_id, series_key.clone())
                .await
                .map_err(SharedTelemetryRepositoryError::Telemetry)
        })
    }

    fn append_sample<'a>(
        &'a self,
        sample: &'a TelemetrySample,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .append_sample(sample)
                .await
                .map_err(SharedTelemetryRepositoryError::Telemetry)
        })
    }

    fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
        Box::pin(async move { list_all_telemetry_series(self).await })
    }

    fn list_samples(
        &self,
        series_id: TelemetrySeriesId,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
        Box::pin(async move {
            // The store's bounded listing takes a plain `usize` (its own
            // contract: `0` lists nothing); the Web layer already caps every
            // query limit at TELEMETRY_QUERY_MAX_LIMIT, so a limit this
            // large cannot be unrepresentable on any supported pointer
            // width — the audit projection's saturation fallback precedent.
            let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
            self.store
                .list_samples(series_id, limit)
                .await
                .map_err(SharedTelemetryRepositoryError::Telemetry)
        })
    }

    fn prune_before(&self, cutoff: OffsetDateTime) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .prune_before(cutoff)
                .await
                .map(|_summary| ())
                .map_err(SharedTelemetryRepositoryError::Telemetry)
        })
    }
}

impl GroupRepository for StandaloneState {
    type Error = SharedGroupRepositoryError;

    /// Delegates the §12.1 static-group lifecycle to the same `SqliteStore`
    /// that owns every other aggregate, so the console's grouping paths
    /// (which compose the `GroupRepository` boundary of the product-services
    /// bundle) and the `groups`/`group_members` tables always observe one
    /// authoritative membership.
    fn create<'a>(&'a self, group: &'a Group) -> BoundaryFuture<'a, Result<Group, Self::Error>> {
        Box::pin(async move {
            // The store's create acknowledges the write without returning the
            // row (§15.4 at-least-once: a stored identity is a no-op and the
            // stored row is authoritative); the boundary contract hands the
            // stored row back, so the read-back is the rehydration.
            self.store.create_group(group).await?;
            self.store.find_group(group.id()).await?.ok_or(
                SharedGroupRepositoryError::MissingAfterCreate {
                    group_id: group.id(),
                },
            )
        })
    }

    fn find(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<Option<Group>, Self::Error>> {
        Box::pin(async move {
            self.store
                .find_group(group_id)
                .await
                .map_err(SharedGroupRepositoryError::from)
        })
    }

    fn list(&self) -> BoundaryFuture<'_, Result<Vec<Group>, Self::Error>> {
        Box::pin(async move {
            self.store
                .list_groups()
                .await
                .map_err(SharedGroupRepositoryError::from)
        })
    }

    fn add_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .add_member(group_id, endpoint_id)
                .await
                .map_err(SharedGroupRepositoryError::Group)
        })
    }

    fn remove_member(
        &self,
        group_id: GroupId,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .remove_member(group_id, endpoint_id)
                .await
                .map_err(SharedGroupRepositoryError::Group)
        })
    }

    fn delete(&self, group_id: GroupId) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            self.store
                .delete_group(group_id)
                .await
                .map_err(SharedGroupRepositoryError::Group)
        })
    }
}

/// A controlled failure of the shared group store role.
///
/// The wrapper composes the store's create (which acknowledges the write
/// without returning the row) with the read-back the boundary contract
/// requires; the crate-local error keeps the boundary's failure type single
/// while preserving the source chain, like `SharedTelemetryRepositoryError`.
#[derive(Debug, Error)]
pub(crate) enum SharedGroupRepositoryError {
    #[error("group persistence failed: {0}")]
    Group(#[from] GroupRepositoryError),
    #[error("created group {group_id} cannot be read back")]
    MissingAfterCreate { group_id: GroupId },
}

impl TagRepository for StandaloneState {
    type Error = TagRepositoryError;

    /// Delegates the §14.2 tag lifecycle to the same `SqliteStore` that owns
    /// every other aggregate, so the console's tag paths (which compose the
    /// `TagRepository` boundary of the product-services bundle) and the
    /// `tags`/`endpoint_tags` tables always observe one authoritative
    /// binding — the same rows the §14.2 homepage tag filter reads.
    fn assign<'a>(&'a self, tag: &'a Tag) -> BoundaryFuture<'a, Result<Tag, Self::Error>> {
        Box::pin(async move { self.store.assign_tag(tag.endpoint_id(), tag.name()).await })
    }

    fn remove<'a>(
        &'a self,
        endpoint_id: EndpointId,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { self.store.remove_tag(endpoint_id, tag_name).await })
    }

    fn list_for_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Vec<Tag>, Self::Error>> {
        Box::pin(async move { self.store.list_tags_for_endpoint(endpoint_id).await })
    }

    fn list_by_tag<'a>(
        &'a self,
        tag_name: &'a TagName,
    ) -> BoundaryFuture<'a, Result<Vec<Tag>, Self::Error>> {
        Box::pin(async move {
            // The store's per-name listing returns endpoint identities only
            // (its own contract); the boundary hands full bindings back, so
            // each endpoint's tags are re-read and the exact name selects the
            // binding — one per endpoint by the natural key.
            let mut tags = Vec::new();
            for endpoint_id in self.store.list_endpoints_by_tag(tag_name).await? {
                for tag in self.store.list_tags_for_endpoint(endpoint_id).await? {
                    if tag.name() == tag_name {
                        tags.push(tag);
                    }
                }
            }
            Ok(tags)
        })
    }
}

/// Lists every telemetry series across every enrolled endpoint.
///
/// The store's listing is per-endpoint, and the product's current-value
/// surface is one series inventory across endpoints: the wrapper merges the
/// per-endpoint listings through the store's light endpoint-only listing.
async fn list_all_telemetry_series(
    state: &StandaloneState,
) -> Result<Vec<TelemetrySeries>, SharedTelemetryRepositoryError> {
    let endpoints = state
        .store
        .list_endpoints()
        .await
        .map_err(SharedTelemetryRepositoryError::Endpoints)?;
    let mut series = Vec::new();
    for endpoint in &endpoints {
        series.extend(
            state
                .store
                .list_series(endpoint.id())
                .await
                .map_err(SharedTelemetryRepositoryError::Telemetry)?,
        );
    }
    Ok(series)
}

/// The `'static` event-repository role shared by the listener tasks.
///
/// # Why the wrapper exists
///
/// The `EventService` listener tasks are spawned with `'static` bounds
/// (design §7.8: every task is tracked), so the ingestion use case they
/// share cannot hold a borrow of the instance — it owns its repository
/// through an `Arc`. An `Arc<StandaloneState>` cannot implement the
/// application boundary directly (the orphan rule: neither the trait nor the
/// outer type is local), so this crate-local wrapper is the owned role,
/// exactly like the listener supervisor owns its stream boundary and sink.
struct SharedEventRepository(Arc<StandaloneState>);

impl EventRepository for SharedEventRepository {
    type Error = EventRepositoryError;

    fn append_event<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Box::pin(async move { self.0.store.append_event(event).await })
    }

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        Box::pin(async move {
            let limit = usize::try_from(limit.get()).unwrap_or(usize::MAX);
            self.0.store.list_recent_events(limit).await
        })
    }
}

/// The `'static` telemetry-repository role shared by the sampling task.
///
/// # Why the wrapper exists
///
/// Exactly like [`SharedEventRepository`]: the sampling loop task is spawned
/// with `'static` bounds (design §7.8), so the telemetry store role it holds
/// cannot borrow the instance — it owns its repository through an `Arc`. An
/// `Arc<StandaloneState>` cannot implement the application boundary directly
/// (the orphan rule), so this crate-local wrapper is the owned role. The
/// retention-prune summary the store returns is deliberately dropped at the
/// boundary: the loop's failures are already recorded through
/// `tracing::error!`.
struct SharedTelemetryRepository(Arc<StandaloneState>);

impl TelemetryRepository for SharedTelemetryRepository {
    type Error = SharedTelemetryRepositoryError;

    fn upsert_series<'a>(
        &'a self,
        endpoint_id: EndpointId,
        series_key: &'a SeriesKey,
    ) -> BoundaryFuture<'a, Result<TelemetrySeries, Self::Error>> {
        TelemetryRepository::upsert_series(self.0.as_ref(), endpoint_id, series_key)
    }

    fn append_sample<'a>(
        &'a self,
        sample: &'a TelemetrySample,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        TelemetryRepository::append_sample(self.0.as_ref(), sample)
    }

    fn list_series(&self) -> BoundaryFuture<'_, Result<Vec<TelemetrySeries>, Self::Error>> {
        TelemetryRepository::list_series(self.0.as_ref())
    }

    fn list_samples(
        &self,
        series_id: TelemetrySeriesId,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<TelemetrySample>, Self::Error>> {
        TelemetryRepository::list_samples(self.0.as_ref(), series_id, limit)
    }

    fn prune_before(&self, cutoff: OffsetDateTime) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        TelemetryRepository::prune_before(self.0.as_ref(), cutoff)
    }
}

/// A controlled failure of the shared telemetry store role.
///
/// The wrapper composes the store's telemetry operations with the light
/// endpoint-only listing, whose error vocabulary differs; the crate-local
/// error keeps the boundary's failure type single while preserving the
/// source chain for the loop's `Display` recording.
#[derive(Debug, Error)]
pub(crate) enum SharedTelemetryRepositoryError {
    #[error("telemetry persistence failed: {0}")]
    Telemetry(#[source] TelemetryRepositoryError),
    #[error("enrolled endpoint listing failed: {0}")]
    Endpoints(#[source] EndpointRepositoryError),
}

/// The §14.4 enrolled-endpoint listing shared by the sampling loop and the
/// event-listener supervisor over the concrete Standalone composition.
///
/// Lists through the store's endpoint-only listing — one light query per
/// tick or sweep.
struct StandaloneEndpointLister(Arc<StandaloneState>);

impl telemetry_sampler::EndpointLister for StandaloneEndpointLister {
    type Error = EndpointRepositoryError;

    fn list_enrolled_endpoints(&self) -> BoundaryFuture<'_, Result<Vec<EndpointId>, Self::Error>> {
        Box::pin(async move {
            let endpoints = self.0.store.list_endpoints().await?;
            Ok(endpoints.iter().map(Endpoint::id).collect())
        })
    }
}

impl event_listener::EndpointLister for StandaloneEndpointLister {
    type Error = EndpointRepositoryError;

    fn list_enrolled_endpoints(&self) -> BoundaryFuture<'_, Result<Vec<EndpointId>, Self::Error>> {
        Box::pin(async move {
            let endpoints = self.0.store.list_endpoints().await?;
            Ok(endpoints.iter().map(Endpoint::id).collect())
        })
    }
}

/// A controlled failure while durably appending one audit fact.
///
/// The tail mirror is deliberately not part of the vocabulary: a failed
/// mirror is warned about and the event stays durably stored (V5A-6), so
/// the append boundary's error is exactly "the persisted append failed".
#[derive(Debug, Error)]
pub enum StandaloneAuditWriteError {
    #[error("failed to append the audit event: {0}")]
    Store(#[source] AuditRepositoryError),
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
        let runtime_lock = Self::acquire_runtime(paths)?;
        let protected = MasterKeyFile::new(paths.master_key_path())
            .load()
            .map_err(StandaloneInstanceError::MasterKeyFile)?;
        let master_key = recover_master_key(&protected, unlock.passphrase())
            .map_err(StandaloneInstanceError::MasterKeyProtection)?;
        Self::assemble(paths, runtime_lock, master_key).await
    }

    /// Authenticates and opens a completed instance through the operating
    /// system's secret store (0.6.0 S3: unattended Site service boots).
    ///
    /// The OS-protected envelope is loaded and recovered without any
    /// passphrase; every other check matches [`Self::open`].
    ///
    /// # Errors
    ///
    /// Returns [`StandaloneInstanceError`] for lock contention, missing or
    /// invalid initialization state, a missing or invalid OS-protected
    /// envelope, OS-store rejection, or database open/migration.
    pub async fn open_system(
        paths: &RuntimePaths,
        store: &SystemSecretStore,
    ) -> Result<Self, StandaloneInstanceError> {
        let runtime_lock = Self::acquire_runtime(paths)?;
        let protected = SystemMasterKeyFile::new(paths.system_master_key_path())
            .load()
            .map_err(StandaloneInstanceError::SystemMasterKeyFile)?;
        let master_key = recover_master_key_system(&protected, store)
            .await
            .map_err(StandaloneInstanceError::SystemMasterKeyProtection)?;
        Self::assemble(paths, runtime_lock, master_key).await
    }

    /// Acquires the runtime lock and verifies the completed-instance state
    /// before any key material is touched.
    fn acquire_runtime(paths: &RuntimePaths) -> Result<RuntimeLock, StandaloneInstanceError> {
        let runtime_lock = RuntimeLock::acquire(paths.runtime_lock_path())
            .map_err(StandaloneInstanceError::RuntimeLock)?;
        let marker = InstanceMarkerFile::new(paths.instance_marker_path());
        match marker.state().map_err(StandaloneInstanceError::Marker)? {
            InstanceMarkerState::Missing => return Err(StandaloneInstanceError::NotInitialized),
            InstanceMarkerState::Complete => {}
        }
        require_existing_database(paths.database_path())?;
        Ok(runtime_lock)
    }

    /// Assembles the authenticated instance around a recovered master key.
    async fn assemble(
        paths: &RuntimePaths,
        runtime_lock: RuntimeLock,
        master_key: MasterKey,
    ) -> Result<Self, StandaloneInstanceError> {
        let master_key = Arc::new(master_key);
        // The store protects the operation command columns at rest with the
        // same master key the credential and TOTP paths use.
        let store =
            SqliteStore::open_with_command_key(paths.database_path(), Arc::clone(&master_key))
                .await
                .map_err(StandaloneInstanceError::OpenStore)?;
        let state = Arc::new(StandaloneState {
            store,
            master_key,
            _runtime_lock: runtime_lock,
            audit_tail: Arc::new(Mutex::new(VecDeque::new())),
            registry: Arc::new(CenterSessionRegistry::new()),
            center_issuer: Mutex::new(None),
        });
        // V5A-2: the console's audit query reads the bounded in-memory tail,
        // so the tail is warmed from the store's newest persisted events at
        // startup — a restart never hides the persisted history. A corrupt
        // persisted row marks the tail failed instead of being silently
        // skipped.
        state.warm_audit_tail().await;
        Ok(Self { state })
    }

    #[must_use]
    pub fn database_path(&self) -> &std::path::Path {
        self.state.store.database_path()
    }

    /// The authenticated state shared with the Site runtime's server and
    /// background tasks.
    pub(crate) fn state(&self) -> Arc<StandaloneState> {
        Arc::clone(&self.state)
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
            registry: _,
            center_issuer: _,
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
    /// graceful drain to complete — bounded by `drain_timeout` (N2-2). Every
    /// handler is capped at the same bound (a slower request is aborted with
    /// a 408); once the shutdown future resolves, the in-flight requests get
    /// the remaining grace to finish, and the server then force-closes the
    /// connections it is still waiting on and completes the stop, so a slow
    /// client can never stall the shutdown forever.
    ///
    /// The §16.2 session policy is the caller's decision — the Standalone
    /// runtime arms it from the bootstrap state of its store, while the
    /// generic run paths pass [`AuthPolicy::Open`]. Serving through
    /// `into_make_service_with_connect_info` exposes the client address to
    /// the sign-in rate limiter.
    ///
    /// # Errors
    ///
    /// Returns an I/O error if the bound listener fails while serving.
    #[allow(clippy::too_many_arguments)]
    pub async fn serve_until<Services, Gateway, Time, Shutdown>(
        self,
        options: StandaloneRunOptions,
        posture: DeploymentPosture,
        policy: AuthPolicy,
        services: Arc<Services>,
        gateway: Arc<Gateway>,
        clock: Time,
        shutdown: Shutdown,
        drain_timeout: Duration,
    ) -> io::Result<()>
    where
        Services: ProductServices + AuthServices + CenterServices + 'static,
        Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
        Time: Clock + Clone + 'static,
        Shutdown: Future<Output = ()> + Send + 'static,
    {
        let url = self.url();
        println!("Rutilus Standalone is listening at {url}");
        if options.open_browser() {
            launch_browser(url).await;
        }
        // N2-2: every handler is capped at the same bound as the shutdown
        // drain, so a slow request is aborted with a 408 instead of
        // outliving the drain against the closing store.
        let router = router_with_auth(
            WebProductInfo::new(PRODUCT_VERSION, NV_REDFISH_DEVELOPMENT_BASELINE),
            AuditActor::LocalOperator,
            posture,
            policy,
            services,
            gateway,
            clock,
        )
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            drain_timeout,
        ))
        .into_make_service_with_connect_info::<SocketAddr>();
        // The drain signal fires exactly when the graceful shutdown future
        // resolves — the moment hyper stops accepting and begins draining
        // the in-flight connections — so the bounded-drain race below
        // measures the drain itself, never the serving lifetime.
        let (drain_signal_sender, drain_signal_receiver) = oneshot::channel();
        let serve = axum::serve(self.listener, router).with_graceful_shutdown(async move {
            shutdown.await;
            let _ = drain_signal_sender.send(());
        });
        // `with_graceful_shutdown` returns an `IntoFuture`, not a `Future`;
        // the bounded-drain runner takes the real serve future.
        serve_with_bounded_drain(serve.into_future(), drain_signal_receiver, drain_timeout).await
    }
}

/// Runs one axum serve future under a bounded graceful drain (N2-2).
///
/// The value is the `with_graceful_shutdown` serve future of the caller
/// (axum's serve futures implement `IntoFuture`, not `Future` directly),
/// and `drain_signal` fires exactly when its graceful shutdown future
/// resolves — the moment hyper stops accepting and begins draining the
/// in-flight connections. Until then this races the serve future itself:
/// the server runs for its natural lifetime. Once the signal fires, the
/// drain gets `drain_timeout` to finish; when that bound is exceeded, the
/// timed-out serve future is dropped, so the stop is no longer waiting on
/// the connections, and the shutdown completes as a success (the stop did
/// happen — just forcibly).
///
/// # Why the race is not the whole fix
///
/// axum 0.8 runs each connection in its own spawned task, so dropping the
/// serve future stops the drain's *wait* but cannot kill a connection
/// task. The handler timeout layer (see [`GRACEFUL_DRAIN_TIMEOUT`]) is
/// what actually terminates slow in-flight requests — their handlers are
/// aborted and the connections complete and exit — while this race bounds
/// the connections that never dispatched a request (a client that stalls
/// mid-head), whose tasks then live only until the process exits without
/// ever touching the store.
///
/// Shared by the Standalone and Site `serve_until` paths (the Center
/// console serves through the Site path), so all three postures bound the
/// drain identically.
pub(crate) async fn serve_with_bounded_drain<Server>(
    serve: Server,
    drain_signal: oneshot::Receiver<()>,
    drain_timeout: Duration,
) -> io::Result<()>
where
    Server: IntoFuture<Output = io::Result<()>>,
    Server::IntoFuture: Future<Output = io::Result<()>> + Send,
{
    let serve = serve.into_future();
    tokio::pin!(serve);
    tokio::select! {
        result = &mut serve => result,
        _ = drain_signal => {
            match tokio::time::timeout(drain_timeout, &mut serve).await {
                Ok(result) => result,
                Err(_elapsed) => {
                    tracing::warn!(
                        "graceful drain exceeded its {drain_timeout:?} bound; aborting the drain wait; the process will close the remaining connections on exit"
                    );
                    Ok(())
                }
            }
        }
    }
}

/// The console's stop signal: Ctrl-C on every platform, plus SIGTERM and
/// SIGHUP on Unix (0.6.0 S3 graceful shutdown — service managers deliver
/// SIGTERM on stop).
///
/// Public so the binary's `service run` path can arm the same stop future
/// the Site runtime waits on.
///
/// # Errors
///
/// Returns an I/O error when the operating system cannot arm a signal
/// handler.
pub async fn console_stop_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let mut hangup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
        tokio::select! {
            signal = tokio::signal::ctrl_c() => signal,
            _ = terminate.recv() => Ok(()),
            _ = hangup.recv() => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await
    }
}

/// Runs the foreground Standalone posture over the injected product services
/// until the console stop signal, with structured Axum shutdown and no
/// non-loopback plaintext mode.
///
/// # Errors
///
/// Returns [`StandaloneRunError`] when loopback binding, signal registration,
/// or HTTP serving fails.
#[instrument(skip_all)]
pub async fn run_standalone<Services, Gateway, Time>(
    options: StandaloneRunOptions,
    services: Arc<Services>,
    gateway: Arc<Gateway>,
    clock: Time,
) -> Result<(), StandaloneRunError>
where
    Services: ProductServices + AuthServices + CenterServices + 'static,
    Gateway: TlsIdentityProbe + RedfishDiscovery + CoreResourceReader + 'static,
    Time: Clock + Clone + 'static,
{
    let binding = StandaloneBinding::bind().await?;
    let (shutdown_sender, shutdown_receiver) = oneshot::channel();
    // The generic run path serves the pre-0.6 open console; the initialized
    // path arms the policy from its bootstrap state.
    let server = binding.serve_until(
        options,
        DeploymentPosture::Standalone,
        AuthPolicy::Open,
        services,
        gateway,
        clock,
        async move {
            let _result = shutdown_receiver.await;
        },
        GRACEFUL_DRAIN_TIMEOUT,
    );
    tokio::pin!(server);

    tokio::select! {
        result = &mut server => result.map_err(StandaloneRunError::Serve),
        signal = console_stop_signal() => {
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
/// the HTTP server serves — and, from §14.4, the per-endpoint `EventService`
/// listeners: one background task per enrolled endpoint consumes the
/// endpoint's SSE stream and records every event through the ingestion use
/// case. All of them stop through one stop signal, drained in the design
/// §7.8 order — scheduling first (the in-flight tick finishes), then the
/// event listeners (each in-flight event finishes), then the telemetry
/// sampler (its in-flight sweep finishes), then the server — before
/// `SQLite` closes, so no task ever touches the store after shutdown begins.
///
/// # Errors
///
/// Returns [`StandaloneExecutionError`] while preserving both server and close
/// failures if they occur during the same shutdown.
#[instrument(skip_all, fields(data_directory = %paths.data_directory().display()))]
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
        let services_for_server = Arc::clone(&instance.state);
        let gateway_for_server = Arc::clone(&gateway);
        run_background_services(
            Arc::clone(&instance.state),
            gateway,
            options.telemetry_retention(),
            DeploymentPosture::Standalone,
            AuditActor::LocalOperator,
            move |policy, stop_watch, scheduler_done_receiver| {
                binding.serve_until(
                    options,
                    DeploymentPosture::Standalone,
                    policy,
                    services_for_server,
                    gateway_for_server,
                    SystemClock,
                    async move {
                        let mut stop = stop_watch;
                        stop.stopped().await;
                        let _ = scheduler_done_receiver.await;
                    },
                    GRACEFUL_DRAIN_TIMEOUT,
                )
            },
            console_stop_signal(),
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

/// Serves one initialized console with the operation scheduling loop, the
/// §14.4 event listeners, and the §14.4 telemetry sampling loop until the
/// external `stop` future resolves (or the server fails), then drains in the
/// design §7.8 order: stop scheduling first (the loop finishes its in-flight
/// tick), then the event listeners (each in-flight event finishes), then the
/// telemetry sampler (its in-flight sweep finishes), then the HTTP server.
///
/// Both the Standalone and Site postures serve through this one drain
/// structure: each arms its own server future (loopback plaintext or the
/// Site's HTTPS listener) and its own stop future (the console stop signal,
/// plus the SCM stop watch for Windows services), and the same one-stop
/// signal path stops every background task before the store closes.
///
/// `retention` is the telemetry history window the sampling loop prunes
/// with — the runtime's configured policy from the run options, so both
/// postures honor the operator's `--telemetry-retention-days` value.
///
/// `posture` and `actor` are the §16.3 base attribution of the posture's
/// operation executions (audit follow-up V5A-3): the Standalone runtime
/// passes the local operator from the Standalone origin, and the Site
/// runtime passes the local operator from the Site origin. The executor and
/// monitor refine the base attribution per operation from the operation's
/// persisted source — a center-dispatched offer executed at the site names
/// the center's automation with the site origin.
///
/// # Errors
///
/// Returns [`StandaloneRunError`] when signal registration or HTTP serving
/// fails; the background tasks' own shutdowns are always awaited before the
/// store close.
#[instrument(skip_all)]
pub(crate) async fn run_background_services<Server, Stop>(
    services: Arc<StandaloneState>,
    gateway: Arc<RedfishGateway>,
    retention: TelemetryRetention,
    posture: DeploymentPosture,
    actor: AuditActor,
    make_server: impl FnOnce(AuthPolicy, scheduler::StopWatch, oneshot::Receiver<()>) -> Server,
    stop: Stop,
) -> Result<(), StandaloneRunError>
where
    Server: Future<Output = io::Result<()>> + Send,
    Stop: Future<Output = io::Result<()>> + Send,
{
    // One stop signal stops the scheduler, the event listeners, the
    // telemetry sampler, the audit compensation drain, and the server in
    // order; each task owns its own Arc clones of the authenticated state
    // and the gateway, so it is `'static` and spawnable.
    let (stop_signal, stop_watch) = scheduler::StopSignal::new();
    let mut scheduler = tokio::spawn(run_operation_scheduler(
        stop_watch.clone(),
        Arc::clone(&services),
        Arc::clone(&gateway),
        posture,
        actor,
    ));
    // §14.4: one EventService listener per enrolled endpoint, reconciled
    // against the enrolled set every LISTENER_RECONCILE_INTERVAL — the
    // first sweep arms every endpoint enrolled before startup, a later
    // sweep arms an endpoint enrolled mid-run and stops one that left the
    // set, and a failed listing only skips the sweep.
    let mut listeners = tokio::spawn(run_event_listeners(
        stop_watch.clone(),
        Arc::clone(&services),
        Arc::clone(&gateway),
    ));
    // §14.4: the telemetry sampling loop ticks on its own cadence over
    // the stored MetricReport snapshots, re-listing the enrolled
    // endpoints every tick.
    let mut sampler = tokio::spawn(run_telemetry_sampler(
        stop_watch.clone(),
        Arc::clone(&services),
        retention,
    ));
    // V5A-4: the audit compensation drain retries the queued failed audit
    // appends on its own cadence, so a transient store failure never leaves
    // a terminal audit fact permanently missing.
    let mut compensation = tokio::spawn(run_audit_compensation_drain(
        stop_watch.clone(),
        Arc::clone(&services),
    ));
    // The §16.2 first-run lifecycle: while an unconsumed bootstrap code
    // exists the console serves only the claim surface (the bootstrap
    // endpoint, `me`, and the static console are Public; the product
    // surface stays closed — S3-2), and the claim itself arms the gate; a
    // store that already consumed its code starts guarded. The Site
    // posture arms the same policy from the same bootstrap state.
    let policy = match services.store.has_unconsumed_bootstrap_code().await {
        Ok(true) => AuthPolicy::PendingBootstrap(AuthGate::open()),
        Ok(false) => AuthPolicy::Guarded,
        Err(error) => {
            // Fail closed (Guarded) like a consumed code, but record the
            // query failure: a store that cannot answer the first-run gate
            // must not look indistinguishable from an already-claimed
            // instance, or the operator diagnoses a login problem that is
            // actually a storage problem.
            tracing::error!(
                "could not read the bootstrap-code state for the first-run gate, starting guarded: {error}"
            );
            AuthPolicy::Guarded
        }
    };
    // The server's graceful drain waits for the background tasks to have
    // fully stopped first (design §7.8: stop scheduling and listening, then
    // serve): the channel is fired only after both tasks are joined.
    let (scheduler_done_sender, scheduler_done_receiver) = oneshot::channel();
    let server = make_server(policy, stop_watch, scheduler_done_receiver);
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            // The server stopped on its own (a serving failure): stop the
            // background tasks too, and wait for their drains before closing
            // the store.
            stop_signal.signal();
            drain_scheduler(&mut scheduler).await;
            drain_listeners(&mut listeners).await;
            drain_sampler(&mut sampler).await;
            drain_compensation(&mut compensation).await;
            let _ = scheduler_done_sender.send(());
            result.map_err(StandaloneRunError::Serve)
        }
        signal = stop => {
            signal.map_err(StandaloneRunError::Signal)?;
            // §7.8: stop the scheduler first; its in-flight tick finishes.
            stop_signal.signal();
            drain_scheduler(&mut scheduler).await;
            // The listeners drain next; each in-flight event finishes.
            drain_listeners(&mut listeners).await;
            // The telemetry sampler drains next; its in-flight sweep
            // finishes.
            drain_sampler(&mut sampler).await;
            // The audit compensation drain stops last; its in-flight retry
            // finishes.
            drain_compensation(&mut compensation).await;
            let _ = scheduler_done_sender.send(());
            // The server's shutdown future resolves now; await its drain.
            server.await.map_err(StandaloneRunError::Serve)
        }
    }
}

/// Assembles the §14.4 `EventService` listeners over the authenticated
/// Standalone state and runs the reconciling supervisor until the stop
/// watch fires.
///
/// # Why the composition lives here
///
/// Like [`run_operation_scheduler`]: the listeners compose the concrete
/// `StandaloneState` (through the `EventIngestion` use case over its
/// `EventRepository` role), the `RedfishGateway` (through the
/// [`StandaloneEventStream`] adapter), and the enrolled-endpoint listing
/// ([`StandaloneEndpointLister`]), and the state type is private to this
/// module. The task owns its Arc clones, so the composition is `'static` and
/// spawnable. The task returns when the stop signal fires, after every
/// per-endpoint listener has drained (§7.8), and the runtime joins it before
/// closing `SQLite` — no listener ever touches the store after shutdown
/// begins.
async fn run_event_listeners(
    stop: scheduler::StopWatch,
    state: Arc<StandaloneState>,
    gateway: Arc<RedfishGateway>,
) {
    let stream = Arc::new(StandaloneEventStream {
        state: Arc::clone(&state),
        gateway: Arc::clone(&gateway),
    });
    let sink = Arc::new(EventIngestion::new(SharedEventRepository(Arc::clone(
        &state,
    ))));
    let lister = StandaloneEndpointLister(Arc::clone(&state));
    event_listener::run(
        stop,
        &lister,
        &stream,
        &sink,
        event_listener::ReconnectPolicy::default(),
        event_listener::LISTENER_RECONCILE_INTERVAL,
    )
    .await;
}

/// The §14.4 `EventStream` boundary over the concrete Standalone
/// composition.
///
/// The adapter owns the pieces the gateway boundary cannot see: it resolves
/// the endpoint's address, trust decision, and active credential through the
/// state's application roles, then opens the endpoint's `EventService` SSE
/// stream through the gateway's credentialed open — the same resolution the
/// scheduler's command executor performs for writes.
struct StandaloneEventStream {
    state: Arc<StandaloneState>,
    gateway: Arc<RedfishGateway>,
}

impl EventStream for StandaloneEventStream {
    type Error = StandaloneEventStreamError;
    type Stream = GatewayEventPull;

    fn open_stream(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Self::Stream, Self::Error>> {
        Box::pin(async move {
            let endpoint =
                EndpointRefreshRepository::find_endpoint(self.state.as_ref(), endpoint_id)
                    .await
                    .map_err(StandaloneEventStreamError::Endpoint)?
                    .ok_or(StandaloneEventStreamError::UnknownEndpoint { endpoint_id })?;
            let Some(resolved) =
                CredentialResolver::resolve(self.state.as_ref(), endpoint.credential_id())
                    .await
                    .map_err(StandaloneEventStreamError::Credential)?
            else {
                return Err(StandaloneEventStreamError::MissingCredential { endpoint_id });
            };
            // The gateway stream owns its cancellation token (§7.8: every
            // long-lived connection has a shutdown signal); the listener
            // fires it through the pull handle's graceful close.
            let cancel = CancellationToken::new();
            let stream = self
                .gateway
                .open_event_stream(
                    endpoint.address(),
                    endpoint.trust(),
                    resolved.username(),
                    resolved.password(),
                    endpoint_id,
                    cancel,
                )
                .await
                .map_err(StandaloneEventStreamError::Open)?;
            Ok(GatewayEventPull { stream })
        })
    }
}

/// The pull handle of one opened gateway stream.
///
/// `pull` forwards to the gateway stream's `next`, which delivers each
/// endpoint-bound event, then the terminal error item once, and finally
/// `None`; `close` runs the gateway's graceful `shutdown` — cancel, close
/// the connection, delete the transient Session — which is the boundary's
/// §7.8 drain contract.
struct GatewayEventPull {
    stream: GatewayEventStream,
}

impl EventStreamPull for GatewayEventPull {
    type Error = StandaloneEventStreamError;

    fn pull(&mut self) -> BoundaryFuture<'_, Result<Option<Event>, Self::Error>> {
        Box::pin(async move {
            match self.stream.next().await {
                Some(Ok(endpoint_event)) => Ok(Some(endpoint_event.event().clone())),
                Some(Err(error)) => Err(StandaloneEventStreamError::Stream(error)),
                None => Ok(None),
            }
        })
    }

    fn close(&mut self) -> BoundaryFuture<'_, ()> {
        Box::pin(async move { self.stream.shutdown().await })
    }
}

/// A controlled failure while opening one endpoint's event stream.
#[derive(Debug, Error)]
enum StandaloneEventStreamError {
    #[error("the endpoint could not be resolved for its event stream: {0}")]
    Endpoint(#[source] EndpointRefreshPersistenceError),
    #[error("endpoint {endpoint_id} is not a managed endpoint")]
    UnknownEndpoint { endpoint_id: EndpointId },
    #[error("the endpoint's credential could not be resolved: {0}")]
    Credential(#[source] ActiveCredentialResolverError),
    #[error("endpoint {endpoint_id} has no active credential to open its event stream")]
    MissingCredential { endpoint_id: EndpointId },
    #[error("the endpoint's event stream could not be opened: {0}")]
    Open(#[source] EventStreamOpenError),
    #[error("the endpoint's event stream failed: {0}")]
    Stream(#[source] EventStreamError),
}

/// Assembles the §14.4 telemetry sampling loop over the authenticated
/// Standalone state and runs it until the stop watch fires.
///
/// `retention` is the configured history window (default seven days) the
/// prune uses; it comes from the run options, so the operator's
/// `--telemetry-retention-days` value reaches the prune verbatim.
///
/// # Why the composition lives here
///
/// Like [`run_operation_scheduler`]: the loop's sampler composes the
/// concrete `StandaloneState` — the stored-snapshot reader over the state's
/// inventory role, the shared telemetry store role, and the endpoint lister
/// — and the state type is private to this module, so the composition cannot
/// live in `telemetry_sampler`. The task owns its Arc clones, so the
/// composition is `'static` and spawnable; it exits on the stop signal after
/// its in-flight sweep finishes, and the runtime joins it before closing
/// `SQLite`.
async fn run_telemetry_sampler(
    stop: scheduler::StopWatch,
    state: Arc<StandaloneState>,
    retention: TelemetryRetention,
) {
    // The reader borrows the state for the task's lifetime, and the store
    // role owns it through the Arc wrapper; the sampler's clock is the
    // product's `SystemClock`, so the sweep instant and the retention cutoff
    // both come from one clock.
    let reader = MetricReportSnapshotReader::new(state.as_ref());
    let store = SharedTelemetryRepository(Arc::clone(&state));
    let sampler = TelemetrySampler::new(reader, store, SystemClock);
    let lister = StandaloneEndpointLister(Arc::clone(&state));
    telemetry_sampler::run(
        stop,
        &sampler,
        &lister,
        telemetry_sampler::TELEMETRY_SAMPLE_INTERVAL,
        retention.as_duration(),
        SystemClock,
    )
    .await;
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
    posture: DeploymentPosture,
    actor: AuditActor,
) {
    // One gateway clone serves both the executor (dispatch + verification)
    // and the monitor (Task reads + verification); every boundary resolves
    // the endpoint and credential rows itself, so the loop never sees
    // secrets or transport details (design section 7.2).
    // Every boundary composes over `&StandaloneState` (the Arc itself
    // implements no boundary): the state implements the credential resolver
    // and audit writer roles next to the store's persistence roles. The
    // executor's store role is the state itself — it carries the
    // `ArtifactRepository` role the §13.3 step-4 artifact pre-flight of an
    // Update command needs, beside the operation, capability, and remote-task
    // roles it delegates to `SqliteStore` — while the command executor keeps
    // the raw `SqliteStore` for its endpoint lookups.
    //
    // `posture` and `actor` are the §16.3 base attribution (V5A-3): the
    // executor and monitor refine it per operation from the operation's
    // persisted source, so a center-dispatched operation executed at the
    // site audits under the center's automation with the site origin.
    let command_executor =
        RedfishCommandExecutor::new(gateway.as_ref().clone(), &state.store, state.as_ref());
    let executor = OperationExecutor::new(
        state.as_ref(),
        &command_executor,
        state.as_ref(),
        SystemClock,
        actor,
        posture,
    );
    let monitor = TaskMonitor::new(
        &state.store,
        &command_executor,
        state.as_ref(),
        actor,
        posture,
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

/// Waits for the audit compensation drain task and reports an unexpected
/// failure.
///
/// The drain never returns an error — it exits only on the stop signal — so
/// a `JoinError` means the task panicked or was cancelled, a programming
/// defect worth surfacing but not a blocker for the `SQLite` close that
/// follows.
#[instrument(skip_all)]
async fn drain_compensation(compensation: &mut tokio::task::JoinHandle<()>) {
    if let Err(join_error) = compensation.await {
        tracing::error!("The audit compensation drain failed: {join_error}");
    }
}

/// Waits for the scheduling-loop task and reports an unexpected failure.
///
/// The loop never returns an error — it exits only on the stop signal — so a
/// `JoinError` means the task panicked or was cancelled, a programming
/// defect worth surfacing but not a blocker for the `SQLite` close that
/// follows.
#[instrument(skip_all)]
async fn drain_scheduler(scheduler: &mut tokio::task::JoinHandle<()>) {
    if let Err(join_error) = scheduler.await {
        tracing::error!("The operation scheduling loop failed: {join_error}");
    }
}

/// Waits for the event-listener task and reports an unexpected failure.
///
/// The listener supervisor never returns an error — it exits on the stop
/// signal, after every per-endpoint listener has drained — so a `JoinError`
/// means the wrapper panicked or was cancelled, a programming defect worth
/// surfacing but not a blocker for the `SQLite` close that follows.
#[instrument(skip_all)]
async fn drain_listeners(listeners: &mut tokio::task::JoinHandle<()>) {
    if let Err(join_error) = listeners.await {
        tracing::error!("The event listener task failed: {join_error}");
    }
}

/// Waits for the telemetry-sampler task and reports an unexpected failure.
///
/// The sampler never returns an error — it exits only on the stop signal,
/// after its in-flight sweep finishes — so a `JoinError` means the wrapper
/// panicked or was cancelled, a programming defect worth surfacing but not a
/// blocker for the `SQLite` close that follows.
#[instrument(skip_all)]
async fn drain_sampler(sampler: &mut tokio::task::JoinHandle<()>) {
    if let Err(join_error) = sampler.await {
        tracing::error!("The telemetry sampling task failed: {join_error}");
    }
}

async fn launch_browser(url: String) {
    let result = tokio::task::spawn_blocking(move || webbrowser::open(&url)).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::error!("Could not open the default browser: {error}"),
        Err(error) => tracing::error!("Browser launch task failed: {error}"),
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
    #[error("failed to load the system-protected Standalone master key: {0}")]
    SystemMasterKeyFile(#[source] SystemMasterKeyFileError),
    #[error("failed to recover the system-protected Standalone master key: {0}")]
    SystemMasterKeyProtection(#[source] SystemMasterKeyError<SystemSecretStoreError>),
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
        BoundaryFuture, CoreResourceReadOutcome, CoreResourceReader, EndpointDiscovery,
        RedfishDiscovery, TlsIdentityObservation, TlsIdentityProbe,
    };
    use rutilus_domain::{
        ARGON2ID_HASH_LENGTH, ARGON2ID_SALT_LENGTH, AuditAction, AuditOperationContext,
        AuditOperationId, AuditParameterSummary, AuditRedfishOperation, AuditSequence, AuditTarget,
        CredentialUsername, EndpointAddress, ProductPermission, TlsTrust,
    };
    use secrecy::SecretString;
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::TcpStream,
    };

    use super::*;

    /// The audit tests share the process-wide compensation queue and the
    /// warm-up flag exactly like the production runtime does, so they
    /// serialize through this lock (the same discipline as the derivation
    /// gate's `GATE_TEST_LOCK`).
    static AUDIT_GLOBALS_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// The tests share the process-wide audit compensation queue and the
    /// warm-up flag exactly like the production runtime does, so each test
    /// resets them before it runs.
    fn reset_audit_globals() {
        if let Ok(mut queue) = AUDIT_COMPENSATION
            .get_or_init(|| Mutex::new(VecDeque::new()))
            .lock()
        {
            queue.clear();
        }
        AUDIT_TAIL_WARM_FAILED.store(false, Ordering::Relaxed);
    }

    /// One legal audit context for the tests: a CSV import by the local
    /// operator, the vocabulary shape every runtime audit helper can append.
    fn import_context() -> Result<AuditOperationContext, Box<dyn Error>> {
        Ok(AuditOperationContext::try_new(
            AuditOperationId::generate(),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            AuditTarget::Product,
            AuditParameterSummary::csv_endpoint_import(1)?,
            ProductPermission::ManageEndpoints,
            AuditAction::ImportEndpoints,
            AuditRedfishOperation::None,
        )?)
    }

    /// The audit query limit of the audit tests: larger than the event
    /// counts the tests assert, so the bounded query never truncates them.
    fn audit_query_limit() -> Result<NonZeroU64, Box<dyn Error>> {
        NonZeroU64::new(10)
            .ok_or_else(|| std::io::Error::other("ten is a valid audit query limit").into())
    }

    /// The derivation-gate tests share the process-wide
    /// [`PASSWORD_DERIVATION_SLOTS`] and [`PASSWORD_DERIVATION_QUEUE`]
    /// semaphores, so they serialize through this lock instead of racing
    /// each other's permits (a test holding the queue would refuse another
    /// test's queued derivation).
    static GATE_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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
        ) -> BoundaryFuture<'a, Result<CoreResourceReadOutcome, Self::Error>> {
            Box::pin(async { Err(UnavailableGatewayError) })
        }
    }

    /// A Redfish gateway whose TLS identity observation is deliberately
    /// slow: one trust-establishment request stays in flight in its handler
    /// for `delay`. `entered` signals the moment an observation begins, so
    /// tests can wait deterministically for the request to be in flight
    /// before stopping the server.
    #[derive(Clone)]
    struct SlowGateway {
        entered: Arc<tokio::sync::Notify>,
        delay: Duration,
    }

    impl TlsIdentityProbe for SlowGateway {
        type Error = UnavailableGatewayError;

        fn observe<'a>(
            &'a self,
            _address: &'a EndpointAddress,
        ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
            self.entered.notify_one();
            let delay = self.delay;
            Box::pin(async move {
                tokio::time::sleep(delay).await;
                Err(UnavailableGatewayError)
            })
        }
    }

    impl RedfishDiscovery for SlowGateway {
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

    impl CoreResourceReader for SlowGateway {
        type Error = UnavailableGatewayError;

        fn read_core_resources<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<CoreResourceReadOutcome, Self::Error>> {
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
            StandaloneRunOptions::new(false, TelemetryRetention::default()),
            DeploymentPosture::Standalone,
            AuthPolicy::Open,
            Arc::clone(&instance.state),
            Arc::new(UnavailableGateway),
            SystemClock,
            async move {
                let _result = shutdown_receiver.await;
            },
            GRACEFUL_DRAIN_TIMEOUT,
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

    /// A trust-establishment request whose gateway observation outlives the
    /// drain grace is still served when it completes inside the bound: the
    /// graceful drain waits for it and its response is delivered.
    #[tokio::test]
    async fn an_in_flight_request_completing_in_time_is_served_during_the_drain()
    -> Result<(), Box<dyn Error>> {
        let binding = StandaloneBinding::bind().await?;
        let address = binding.address();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        // The gateway observation takes 200ms; the drain grace is 2s, so
        // the in-flight request finishes inside the bound.
        let entered = Arc::new(tokio::sync::Notify::new());
        let server = tokio::spawn(binding.serve_until(
            StandaloneRunOptions::new(false, TelemetryRetention::default()),
            DeploymentPosture::Standalone,
            AuthPolicy::Open,
            Arc::clone(&instance.state),
            Arc::new(SlowGateway {
                entered: Arc::clone(&entered),
                delay: Duration::from_millis(200),
            }),
            SystemClock,
            async move {
                let _result = shutdown_receiver.await;
            },
            Duration::from_secs(2),
        ));
        let mut stream = TcpStream::connect(address).await?;
        let body = r#"{"address":"https://192.0.2.1"}"#;
        stream
            .write_all(
                format!(
                    "POST /api/v1/endpoints/trust HTTP/1.1\r\nHost: localhost\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await?;
        // The handler is now in flight: the gateway observation started.
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .map_err(|_| io::Error::other("the slow handler never started"))?;
        shutdown_sender
            .send(())
            .map_err(|()| io::Error::other("server shutdown receiver was dropped"))?;
        // The graceful drain waits for the in-flight request; its failure
        // response is still delivered.
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(response.starts_with("HTTP/1.1 502"));
        server.await??;
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    /// A slow request still in flight when the drain grace expires must not
    /// stall the shutdown: the server force-closes it and the whole stop
    /// completes inside the drain bound (N2-2).
    #[tokio::test]
    async fn shutdown_completes_in_bounded_time_with_a_slow_request_in_flight()
    -> Result<(), Box<dyn Error>> {
        let binding = StandaloneBinding::bind().await?;
        let address = binding.address();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        // The gateway observation takes 5s — far beyond the 300ms drain
        // grace — so the shutdown must force-close the in-flight request.
        let entered = Arc::new(tokio::sync::Notify::new());
        let server = tokio::spawn(binding.serve_until(
            StandaloneRunOptions::new(false, TelemetryRetention::default()),
            DeploymentPosture::Standalone,
            AuthPolicy::Open,
            Arc::clone(&instance.state),
            Arc::new(SlowGateway {
                entered: Arc::clone(&entered),
                delay: Duration::from_secs(5),
            }),
            SystemClock,
            async move {
                let _result = shutdown_receiver.await;
            },
            Duration::from_millis(300),
        ));
        let mut stream = TcpStream::connect(address).await?;
        let body = r#"{"address":"https://192.0.2.1"}"#;
        stream
            .write_all(
                format!(
                    "POST /api/v1/endpoints/trust HTTP/1.1\r\nHost: localhost\r\n\
                     Content-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await?;
        // The handler is now in flight: the gateway observation started.
        tokio::time::timeout(Duration::from_secs(2), entered.notified())
            .await
            .map_err(|_| io::Error::other("the slow handler never started"))?;
        shutdown_sender
            .send(())
            .map_err(|()| io::Error::other("server shutdown receiver was dropped"))?;
        // The whole shutdown stays inside the drain bound: the server stops
        // about 300ms after the signal, never after the handler's 5s
        // observation.
        let joined = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .map_err(|_| io::Error::other("the shutdown exceeded the drain bound"))?;
        joined??;
        // The slow handler was aborted at the drain bound: the client
        // receives the handler-timeout 408, never the handler's 502.
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let response = String::from_utf8(response)?;
        assert!(
            response.starts_with("HTTP/1.1 408"),
            "the bounded drain must abort the slow handler with a 408, got: {response}"
        );
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    /// A client that stalls before completing a request head never dispatches
    /// a request, so no handler bound can end its connection wait: only the
    /// drain race can force-complete the shutdown at the bound (N2-2).
    #[tokio::test]
    async fn shutdown_is_bounded_even_for_a_connection_that_never_completes_a_request()
    -> Result<(), Box<dyn Error>> {
        let binding = StandaloneBinding::bind().await?;
        let address = binding.address();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;
        let (shutdown_sender, shutdown_receiver) = oneshot::channel();
        let server = tokio::spawn(binding.serve_until(
            StandaloneRunOptions::new(false, TelemetryRetention::default()),
            DeploymentPosture::Standalone,
            AuthPolicy::Open,
            Arc::clone(&instance.state),
            Arc::new(UnavailableGateway),
            SystemClock,
            async move {
                let _result = shutdown_receiver.await;
            },
            Duration::from_millis(300),
        ));
        // The client stalls mid-head: the request never reaches a handler,
        // so the connection wait can only end through the drain race.
        let mut stream = TcpStream::connect(address).await?;
        stream
            .write_all(b"GET /api/v1/health HTTP/1.1\r\nHost: localhost\r\n")
            .await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        shutdown_sender
            .send(())
            .map_err(|()| io::Error::other("server shutdown receiver was dropped"))?;
        // The drain race force-completes the stop at the 300ms bound.
        let joined = tokio::time::timeout(Duration::from_secs(2), server)
            .await
            .map_err(|_| io::Error::other("the shutdown exceeded the drain bound"))?;
        joined??;
        // The stalled client's disconnect lets its connection task exit and
        // release the instance state; the store close then succeeds.
        drop(stream);
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while Arc::strong_count(&instance.state) > 1 && std::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            Arc::strong_count(&instance.state),
            1,
            "the stalled connection task never released the instance state"
        );
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    #[test]
    fn standalone_options_default_to_browser_launch_and_seven_day_retention()
    -> Result<(), Box<dyn Error>> {
        assert!(StandaloneRunOptions::default().open_browser());
        assert!(!StandaloneRunOptions::new(false, TelemetryRetention::default()).open_browser());
        // The configured retention rides in the options, so a configured
        // `--telemetry-retention-days` reaches the background sampler.
        assert_eq!(
            StandaloneRunOptions::default().telemetry_retention().days(),
            TelemetryRetention::DEFAULT_DAYS
        );
        assert_eq!(
            StandaloneRunOptions::new(false, TelemetryRetention::try_new(3)?).telemetry_retention(),
            TelemetryRetention::try_new(3)?
        );
        Ok(())
    }

    /// P4-12: the derivation gate queues excess Argon2id work — at most
    /// [`MAX_CONCURRENT_PASSWORD_DERIVATIONS`] derivations are ever in
    /// flight, and a freed slot advances exactly one queued caller, so a
    /// sign-in burst cannot multiply the 64 MiB per-derivation memory
    /// without bound.
    #[tokio::test]
    async fn password_derivations_queue_beyond_the_concurrency_cap() -> Result<(), Box<dyn Error>> {
        let _gate = GATE_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;

        // A fixed hash lets the verification run the full Argon2id
        // computation (the wrong-password cost of the real branch) without
        // a derivation of its own.
        let Ok(hash) =
            Argon2IdHash::from_parts(&[0x11; ARGON2ID_SALT_LENGTH], &[0x22; ARGON2ID_HASH_LENGTH])
        else {
            return Err("the fixed derivation-hash parts are invalid".into());
        };
        let password: SecretString = "correct horse battery staple".to_owned().into();

        // Hold every slot: four derivations are already in flight.
        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_PASSWORD_DERIVATIONS {
            let Ok(permit) = PASSWORD_DERIVATION_SLOTS.acquire().await else {
                return Err("the derivation gate is closed".into());
            };
            held.push(permit);
        }

        // Two excess derivations — one verification, one derivation, the two
        // async boundary forms — queue behind the cap and record their
        // completion on the shared counter.
        let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut queued = Vec::new();
        for derive in [false, true] {
            let state = Arc::clone(&instance.state);
            let hash = hash.clone();
            let password = SecretString::from(password.expose_secret().to_owned());
            let completed = Arc::clone(&completed);
            queued.push(tokio::spawn(async move {
                if derive {
                    let _ = state.hash_password_async(&password).await;
                } else {
                    let _ = state.verify_password_async(&hash, &password).await;
                }
                completed.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }));
        }

        // Neither can start while every slot is held: with the cap fully
        // occupied, the excess derivations stay queued and no completion can
        // arrive inside the probe window.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an excess derivation ran despite every slot of the cap being held"
        );

        // Releasing one slot advances exactly one queued derivation; the
        // other still waits.
        held.pop();
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        while completed.load(std::sync::atomic::Ordering::SeqCst) == 0
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a freed slot must serve exactly one queued derivation"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a freed slot served more than one queued derivation"
        );

        // The remaining slots release the rest of the queue.
        held.clear();
        for handle in queued {
            handle.await?;
        }
        assert_eq!(
            completed.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "every queued derivation must complete once slots free"
        );

        instance.close().await?;
        drop(directory);
        Ok(())
    }

    /// W3S-1: the derivation queue is bounded — a request arriving when
    /// [`MAX_QUEUED_PASSWORD_DERIVATIONS`] others already wait is refused
    /// honestly (a fail-closed verification verdict, a
    /// [`StandaloneAuthError::HashGateBusy`] derivation error) instead of
    /// joining an unbounded queue, and a freed queue slot admits exactly
    /// one next request.
    #[tokio::test]
    async fn derivation_gate_refuses_when_the_bounded_queue_is_full() -> Result<(), Box<dyn Error>>
    {
        let _gate = GATE_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;

        let password: SecretString = "correct horse battery staple".to_owned().into();
        let Ok(hash) =
            Argon2IdHash::from_parts(&[0x11; ARGON2ID_SALT_LENGTH], &[0x22; ARGON2ID_HASH_LENGTH])
        else {
            return Err("the fixed derivation-hash parts are invalid".into());
        };

        // Fill the queue: hold every queue permit so no derivation can
        // enqueue behind the slots.
        let mut queue_holds = Vec::new();
        for _ in 0..MAX_QUEUED_PASSWORD_DERIVATIONS {
            let Ok(permit) = PASSWORD_DERIVATION_QUEUE.try_acquire() else {
                return Err("the derivation queue is closed".into());
            };
            queue_holds.push(permit);
        }

        // Both boundary forms refuse honestly: the verification fails
        // closed, the derivation surfaces the gate refusal the web layer
        // can recognize.
        let verified = instance.state.verify_password_async(&hash, &password).await;
        assert!(
            !verified,
            "a full derivation queue must fail the verification closed"
        );
        let derived = instance.state.hash_password_async(&password).await;
        let Err(error) = derived else {
            return Err("a full derivation queue must refuse the derivation".into());
        };
        assert!(
            matches!(error, StandaloneAuthError::HashGateBusy),
            "the derivation refusal must carry the gate-busy classification"
        );
        assert!(
            instance.state.is_derivation_gate_busy(&error),
            "the runtime must report the gate refusal to the web layer"
        );
        assert!(
            !instance
                .state
                .is_derivation_gate_busy(&StandaloneAuthError::Hash(
                    PasswordHashError::InvalidHashParts
                )),
            "a real derivation failure must not be reported as a gate refusal"
        );

        // Freeing one queue slot admits exactly one next request, which
        // runs the full derivation once the slot is free — the boundary
        // completing with a derived hash is the assertion.
        queue_holds.pop();
        let _derived = tokio::time::timeout(
            Duration::from_secs(30),
            instance.state.hash_password_async(&password),
        )
        .await
        .map_err(|_| io::Error::other("the derivation never ran after the queue freed"))??;

        instance.close().await?;
        drop(directory);
        Ok(())
    }

    /// W3N-1: the gate permit rides inside the `spawn_blocking` task, so a
    /// cancelled request cannot release its slot while the derivation
    /// still runs — the slot stays occupied until the derivation
    /// completes, exactly as the gate's contract states.
    #[tokio::test]
    async fn a_cancelled_derivation_keeps_its_gate_slot_until_the_work_completes()
    -> Result<(), Box<dyn Error>> {
        let _gate = GATE_TEST_LOCK.lock().await;
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let unlock = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &unlock).await?;
        let instance = StandaloneInstance::open(&paths, &unlock).await?;

        let password: SecretString = "correct horse battery staple".to_owned().into();
        // Hold every slot but one, so the spawned derivation takes the
        // last one.
        let mut held = Vec::new();
        for _ in 0..(MAX_CONCURRENT_PASSWORD_DERIVATIONS - 1) {
            let Ok(permit) = PASSWORD_DERIVATION_SLOTS.acquire().await else {
                return Err("the derivation gate is closed".into());
            };
            held.push(permit);
        }
        let state = Arc::clone(&instance.state);
        let password = SecretString::from(password.expose_secret().to_owned());
        let task = tokio::spawn(async move {
            let _ = state.hash_password_async(&password).await;
        });

        // Wait until the derivation holds the last slot: while it is still
        // queued, a probe acquire succeeds and is released again; once the
        // derivation is in flight, the probe times out.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            match tokio::time::timeout(
                Duration::from_millis(10),
                PASSWORD_DERIVATION_SLOTS.acquire(),
            )
            .await
            {
                Ok(Ok(permit)) => drop(permit),
                Ok(Err(_)) => return Err("the derivation gate is closed".into()),
                Err(_elapsed) => break,
            }
            if std::time::Instant::now() > deadline {
                return Err("the spawned derivation never took the last gate slot".into());
            }
        }

        // Cancel the request while its derivation runs.
        task.abort();

        // The slot must stay occupied until the derivation completes: a
        // fresh acquire inside a short probe window cannot succeed.
        let probe = tokio::time::timeout(
            Duration::from_millis(30),
            PASSWORD_DERIVATION_SLOTS.acquire(),
        )
        .await;
        match probe {
            Ok(Ok(_permit)) => {
                return Err(
                    "the cancelled request released its gate slot before the derivation completed"
                        .into(),
                );
            }
            Ok(Err(_)) => return Err("the derivation gate is closed".into()),
            Err(_elapsed) => {}
        }

        // The derivation finishes on the blocking pool, releases its slot,
        // and only then does a fresh acquire succeed.
        let deadline = std::time::Instant::now() + Duration::from_secs(30);
        let freed = loop {
            match tokio::time::timeout(
                Duration::from_millis(20),
                PASSWORD_DERIVATION_SLOTS.acquire(),
            )
            .await
            {
                Ok(Ok(permit)) => break permit,
                Ok(Err(_)) => return Err("the derivation gate is closed".into()),
                Err(_elapsed) => {
                    if std::time::Instant::now() > deadline {
                        return Err("the cancelled derivation never released its gate slot".into());
                    }
                }
            }
        };
        drop(freed);
        drop(held);
        instance.close().await?;
        drop(directory);
        Ok(())
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
            run_initialized_standalone(
                &paths,
                &correct,
                StandaloneRunOptions::new(false, TelemetryRetention::default()),
            )
            .await,
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
            registry: _,
            center_issuer: _,
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

    #[tokio::test]
    async fn restart_backfills_the_audit_tail_from_persisted_history() -> Result<(), Box<dyn Error>>
    {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // V5A-2: the console audit query reads the bounded in-memory tail,
        // so the tail is warmed from the store's newest persisted events at
        // startup — a restart never hides the history.
        reset_audit_globals();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let passphrase = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &passphrase).await?;

        // Session one records one complete audited operation.
        let now = OffsetDateTime::now_utc();
        let context = import_context()?;
        let started = AuditEvent::started(context.clone(), now);
        let succeeded = AuditEvent::succeeded(
            context,
            AuditSequence::FIRST.next()?,
            now + Duration::from_secs(1),
        )?;
        let first = StandaloneInstance::open(&paths, &passphrase).await?;
        first.state().append_audit_event(&started).await?;
        first.state().append_audit_event(&succeeded).await?;
        first.close().await?;

        // The "restart": a fresh instance over the same store warms its tail
        // from the persisted history, and the console query sees both events
        // newest first.
        let second = StandaloneInstance::open(&paths, &passphrase).await?;
        let events =
            AuditEventQuery::list_recent_events(&*second.state(), audit_query_limit()?).await?;
        assert_eq!(events, [succeeded, started]);
        second.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_warm_up_marks_the_tail_and_the_query_reports_it() -> Result<(), Box<dyn Error>>
    {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // V5A-2: corrupt persisted history must be presented truthfully —
        // the console query reports the failure instead of serving a partial
        // view that hides the corruption. (The corruption itself cannot be
        // written through the store's own validated surface, so the test
        // arms the warm-up's fail-closed verdict directly.)
        reset_audit_globals();
        AUDIT_TAIL_WARM_FAILED.store(true, Ordering::Relaxed);
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let passphrase = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &passphrase).await?;
        let instance = StandaloneInstance::open(&paths, &passphrase).await?;

        assert!(matches!(
            AuditEventQuery::list_recent_events(&*instance.state(), audit_query_limit()?).await,
            Err(StandaloneAuditTailError)
        ));
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    // The poison task's panic is the point of the test: it is the only way
    // the mirror can fail, and it happens on a spawned thread, never on the
    // test's own path.
    #[allow(clippy::panic)]
    async fn a_broken_tail_mirror_never_loses_the_persisted_event() -> Result<(), Box<dyn Error>> {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // V5A-6: a poisoned tail lock — the only mirror failure mode — is
        // warned about, the append still reports success (the event is
        // durably stored), and the console query falls back to the persisted
        // store, so the fork never silently hides an event.
        reset_audit_globals();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let passphrase = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &passphrase).await?;
        let instance = StandaloneInstance::open(&paths, &passphrase).await?;

        // Poison the tail lock: a task panics while holding the guard, the
        // only way the mirror can fail.
        let state = Arc::clone(&instance.state);
        let poisoned = std::thread::spawn(move || {
            if let Ok(guard) = state.audit_tail.lock() {
                let _guard = guard;
                panic!("poison the audit tail for the mirror-failure test");
            }
        });
        assert!(
            poisoned.join().is_err(),
            "the poison task must panic while holding the tail lock"
        );

        let context = import_context()?;
        let started = AuditEvent::started(context, OffsetDateTime::now_utc());
        instance.state().append_audit_event(&started).await?;
        let events =
            AuditEventQuery::list_recent_events(&*instance.state(), audit_query_limit()?).await?;
        assert_eq!(
            events,
            [started],
            "the persisted event stays queryable through the store fallback"
        );
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_append_is_queued_for_the_compensation_drain() -> Result<(), Box<dyn Error>> {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // V5A-4: a failed durable append is not left silently dangling — the
        // event is queued for the compensation drain, and a retry that still
        // fails keeps it queued instead of losing it.
        reset_audit_globals();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let passphrase = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &passphrase).await?;
        let instance = StandaloneInstance::open(&paths, &passphrase).await?;

        // A terminal event without its start fails the append validation —
        // the durable append is refused and the event is queued.
        let context = import_context()?;
        let terminal = AuditEvent::succeeded(
            context,
            AuditSequence::FIRST.next()?,
            OffsetDateTime::now_utc(),
        )?;
        assert!(matches!(
            instance.state().append_audit_event(&terminal).await,
            Err(StandaloneAuditWriteError::Store(
                AuditRepositoryError::MissingStart { .. }
            ))
        ));
        {
            let queue = AUDIT_COMPENSATION
                .get_or_init(|| Mutex::new(VecDeque::new()))
                .lock()
                .map_err(|_| std::io::Error::other("the compensation queue is poisoned"))?;
            assert_eq!(queue.len(), 1);
            assert_eq!(queue[0], terminal);
        }

        // The drain retries against the store; the append still cannot
        // succeed, so the event stays queued for a later retry.
        instance.state().drain_audit_compensation().await;
        {
            let queue = AUDIT_COMPENSATION
                .get_or_init(|| Mutex::new(VecDeque::new()))
                .lock()
                .map_err(|_| std::io::Error::other("the compensation queue is poisoned"))?;
            assert_eq!(queue.len(), 1);
            assert_eq!(queue[0], terminal);
        }
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_compensation_drain_persists_and_mirrors_a_queued_event()
    -> Result<(), Box<dyn Error>> {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // V5A-4: a queued event whose append previously failed is retried by
        // the drain and lands in both the persisted trail and the console
        // read surface once the store can take it again.
        reset_audit_globals();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let passphrase = unlock("correct local unlock phrase")?;
        initialize_standalone(&paths, &passphrase).await?;
        let instance = StandaloneInstance::open(&paths, &passphrase).await?;

        let context = import_context()?;
        let started = AuditEvent::started(context.clone(), OffsetDateTime::now_utc());
        {
            let mut queue = AUDIT_COMPENSATION
                .get_or_init(|| Mutex::new(VecDeque::new()))
                .lock()
                .map_err(|_| std::io::Error::other("the compensation queue is poisoned"))?;
            queue.push_back(started.clone());
        }
        instance.state().drain_audit_compensation().await;

        let events =
            AuditEventQuery::list_recent_events(&*instance.state(), audit_query_limit()?).await?;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], started);
        assert_eq!(
            instance
                .state()
                .store
                .find_audit_operation(context.operation_id())
                .await?,
            [started]
        );
        instance.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_compensation_queue_is_bounded() -> Result<(), Box<dyn Error>> {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // V5A-4: the compensation queue drops its oldest entry instead of
        // growing without bound.
        reset_audit_globals();
        let now = OffsetDateTime::now_utc();
        let source = AuditRepositoryError::MissingStart {
            operation_id: AuditOperationId::generate(),
            actual: AuditSequence::try_new(2)?,
        };
        let mut events = Vec::with_capacity(AUDIT_COMPENSATION_EVENTS + 1);
        for _ in 0..=AUDIT_COMPENSATION_EVENTS {
            let event = AuditEvent::started(import_context()?, now);
            enqueue_audit_compensation(&event, &source);
            events.push(event);
        }
        let queue = AUDIT_COMPENSATION
            .get_or_init(|| Mutex::new(VecDeque::new()))
            .lock()
            .map_err(|_| std::io::Error::other("the compensation queue is poisoned"))?;
        assert_eq!(queue.len(), AUDIT_COMPENSATION_EVENTS);
        assert_eq!(
            queue[0].id(),
            events[1].id(),
            "the oldest queued entry must be dropped"
        );
        assert_eq!(
            queue[AUDIT_COMPENSATION_EVENTS - 1].id(),
            events[AUDIT_COMPENSATION_EVENTS].id()
        );
        Ok(())
    }
}
