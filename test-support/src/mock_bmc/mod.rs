//! A runnable HTTPS Mock Redfish BMC (design section 8 `test-support`).
//!
//! [`MockBmc`] binds a loopback HTTPS listener, serves the fixed fixture
//! tree through one request per connection (the product's gateway opens a
//! fresh connection for every request because it disables connection
//! pooling), records each request for wire-sequence assertions, and tracks
//! the Session ledger so tests can prove the product's Session lifecycle.
//!
//! Module layout:
//!
//! - [`tls`]: the deterministic self-signed leaf identity (fixed key, CN,
//!   serial, and validity), plus the SHA-256 fingerprint exposure.
//! - [`profile`]: the vendor fixture profiles ([`MockProfile`]) the mock can
//!   serve, fixing the Service Root identity and the served `Oem` surface.
//! - [`fixtures`]: the static Redfish JSON documents of the fixture tree.
//! - [`http`]: minimal HTTP/1.1 request parsing and response rendering.
//! - [`route`]: method/path dispatch, Session creation/deletion ledger.
//!
//! A connection that never sends HTTP bytes (the product's credential-free
//! TLS probe) or sends an unparseable request is closed without failing the
//! serve loop: the mock must survive the probe before the Pin decision.

mod fixtures;
mod http;
mod profile;
mod route;
mod tls;

pub use http::RequestRecord;
pub use profile::MockProfile;
pub use tls::{MockTlsIdentity, MockTlsIdentityError};

use std::{
    io,
    net::Ipv4Addr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use rutilus_domain::{CertificateFingerprint, EndpointAddress};
use thiserror::Error;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use crate::mock_bmc::route::{AccountLedger, MockAccount, SessionLedger};

#[cfg(test)]
mod tests;

/// Bounded time for one TLS handshake, mirroring the product's own probe
/// handshake timeout so a stalled peer cannot pin a serve-loop task.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Bounded time for one HTTP request on an accepted connection. The
/// credential-free TLS probe never sends HTTP bytes, so this timeout is the
/// probe connection's exit path.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// A running Mock Redfish BMC on IPv4 loopback.
///
/// The serve loop runs in a background Tokio task from [`MockBmc::bind`]
/// until [`MockBmc::stop`] (or the runtime) stops it; the handle is
/// `Send + Sync` so integration tests can drive assertions from anywhere.
pub struct MockBmc {
    address: EndpointAddress,
    identity: MockTlsIdentity,
    state: Arc<MockState>,
    stop: watch::Sender<bool>,
    task: JoinHandle<io::Result<()>>,
}

impl MockBmc {
    /// Binds the Mock BMC to the requested loopback port (`0` selects a
    /// free ephemeral port) and starts serving in the background.
    ///
    /// The listener accepts only IPv4 loopback connections, and the served
    /// certificate is the deterministic [`MockTlsIdentity`], so the
    /// fingerprint is the same on every run. The default
    /// [`MockProfile::Rutilus`] fixture tree is served; use
    /// [`MockBmc::bind_with_profile`] for a vendor profile.
    ///
    /// # Errors
    ///
    /// Returns [`MockBmcError`] when the deterministic TLS identity cannot
    /// be generated, the loopback listener cannot bind, the server TLS
    /// configuration cannot be built, or the local address cannot be
    /// projected into an [`EndpointAddress`].
    pub async fn bind(port: u16) -> Result<Self, MockBmcError> {
        Self::bind_with_profile(port, MockProfile::Rutilus).await
    }

    /// Binds the Mock BMC to the requested loopback port (`0` selects a
    /// free ephemeral port), serving the given vendor [`MockProfile`]
    /// fixture tree.
    ///
    /// # Errors
    ///
    /// See [`MockBmc::bind`].
    pub async fn bind_with_profile(port: u16, profile: MockProfile) -> Result<Self, MockBmcError> {
        let identity = MockTlsIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port))
            .await
            .map_err(|source| MockBmcError::Bind { port, source })?;
        let socket = listener.local_addr().map_err(MockBmcError::LocalAddress)?;
        let config = identity.server_config()?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let state = Arc::new(MockState::with_profile(profile));
        let (stop, receiver) = watch::channel(false);
        let task = tokio::spawn(serve_loop(listener, acceptor, Arc::clone(&state), receiver));
        Ok(Self {
            address: endpoint_address(socket.port())?,
            identity,
            state,
            stop,
            task,
        })
    }

    /// Starts the Mock BMC on a free ephemeral loopback port.
    ///
    /// # Errors
    ///
    /// See [`MockBmc::bind`].
    pub async fn start() -> Result<Self, MockBmcError> {
        Self::start_with_profile(MockProfile::Rutilus).await
    }

    /// Starts the Mock BMC on a free ephemeral loopback port, serving the
    /// given vendor [`MockProfile`] fixture tree.
    ///
    /// # Errors
    ///
    /// See [`MockBmc::bind`].
    pub async fn start_with_profile(profile: MockProfile) -> Result<Self, MockBmcError> {
        Self::bind_with_profile(0, profile).await
    }

    /// Returns the endpoint address the product can enroll
    /// (`https://127.0.0.1:{port}/`).
    #[must_use]
    pub fn endpoint_address(&self) -> EndpointAddress {
        self.address.clone()
    }

    /// Returns the loopback URL as text, for CLI output and demos.
    #[must_use]
    pub fn url(&self) -> String {
        self.address.to_string()
    }

    /// Returns the exact SHA-256 identity of the served leaf certificate,
    /// comparable with the product's observed TLS identity.
    #[must_use]
    pub const fn fingerprint(&self) -> CertificateFingerprint {
        self.identity.fingerprint()
    }

    /// Returns the Pin text in the product's canonical
    /// `CertificateFingerprint` format (colon-separated uppercase SHA-256
    /// bytes), for UI trust dialogs and demo output.
    #[must_use]
    pub fn fingerprint_text(&self) -> String {
        self.identity.fingerprint_text()
    }

    /// Borrows the DER bytes of the served leaf certificate, for building a
    /// pinned [`TlsTrust`](rutilus_domain::TlsTrust) directly in tests.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.identity.certificate_der()
    }

    /// Returns a snapshot of every received request in arrival order, for
    /// wire-sequence assertions.
    #[must_use]
    pub fn requests(&self) -> Vec<RequestRecord> {
        self.state.requests()
    }

    /// Returns how many requests the serve loop has answered, for
    /// request-count assertions.
    #[must_use]
    pub fn requests_served(&self) -> u64 {
        self.state.requests_served()
    }

    /// Returns how many Sessions the mock currently holds. The product
    /// creates one transient Session per operation and deletes it before
    /// returning, so a complete flow leaves this at zero.
    #[must_use]
    pub fn active_sessions(&self) -> usize {
        self.state.active_sessions()
    }

    /// Returns the ids of every account the mock currently holds, starting
    /// with the built-in `admin` account.
    #[must_use]
    pub fn account_ids(&self) -> Vec<String> {
        self.state.lock_accounts().ids()
    }

    /// Returns a snapshot of one account the mock currently holds, by id.
    #[must_use]
    pub fn account(&self, id: &str) -> Option<MockAccount> {
        self.state.lock_accounts().find(id)
    }

    /// Stops the serve loop, releases the loopback port, and waits for the
    /// background task to exit.
    ///
    /// # Errors
    ///
    /// Returns [`MockBmcError`] when the serve task panicked or stopped with
    /// an I/O failure.
    pub async fn stop(self) -> Result<(), MockBmcError> {
        // A failed send only means the serve loop already exited on its own;
        // the discarded `Option` is not `#[must_use]`, so no panic path is
        // needed for a signal that is best-effort by design.
        self.stop.send(true).ok();
        match self.task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(source)) => Err(MockBmcError::Serve(source)),
            Err(source) => Err(MockBmcError::ServeTask(source)),
        }
    }
}

/// A controlled failure while binding or running the Mock BMC.
#[derive(Debug, Error)]
pub enum MockBmcError {
    /// The deterministic leaf identity could not be generated.
    #[error("mock TLS identity generation failed: {0}")]
    TlsIdentity(#[from] MockTlsIdentityError),
    /// The server TLS configuration could not be built from the identity.
    #[error("mock TLS server configuration failed: {0}")]
    TlsConfiguration(#[source] tokio_rustls::rustls::Error),
    /// The loopback listener could not bind the requested port.
    #[error("mock BMC could not bind loopback port {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: io::Error,
    },
    /// The bound listener could not report its local address.
    #[error("mock BMC could not read its bound loopback address: {0}")]
    LocalAddress(#[source] io::Error),
    /// The bound address cannot be represented as an endpoint address.
    #[error("mock BMC loopback address is not a valid endpoint address: {0}")]
    Address(#[source] rutilus_domain::EndpointAddressError),
    /// The background serve task panicked.
    #[error("mock BMC serve task failed: {0}")]
    ServeTask(#[source] tokio::task::JoinError),
    /// The background serve task stopped with an I/O failure.
    #[error("mock BMC serve loop stopped with an I/O failure: {0}")]
    Serve(#[source] io::Error),
}

/// Shared state between the serve loop and the [`MockBmc`] handle.
pub(crate) struct MockState {
    profile: MockProfile,
    ledger: Mutex<SessionLedger>,
    accounts: Mutex<AccountLedger>,
    requests_served: AtomicU64,
    records: Mutex<Vec<RequestRecord>>,
}

impl MockState {
    /// Builds the mock state for the default [`MockProfile::Rutilus`] tree.
    fn new() -> Self {
        Self::with_profile(MockProfile::Rutilus)
    }

    /// Builds the mock state for one vendor profile; the profile fixes the
    /// fixture documents the route table serves and never changes after
    /// bind.
    fn with_profile(profile: MockProfile) -> Self {
        Self {
            profile,
            ledger: Mutex::new(SessionLedger::new()),
            accounts: Mutex::new(AccountLedger::new()),
            requests_served: AtomicU64::new(0),
            records: Mutex::new(Vec::new()),
        }
    }

    /// The vendor profile this mock serves; the route table selects the
    /// profile-specific fixture documents from it.
    pub(crate) fn profile(&self) -> MockProfile {
        self.profile
    }

    fn record_request(&self, method: &str, target: &str, headers: Vec<(String, String)>) {
        let mut records = self
            .records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        records.push(RequestRecord::new(method, target, headers));
        self.requests_served.fetch_add(1, Ordering::Relaxed);
    }

    fn requests(&self) -> Vec<RequestRecord> {
        self.records
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn requests_served(&self) -> u64 {
        self.requests_served.load(Ordering::Relaxed)
    }

    fn active_sessions(&self) -> usize {
        self.lock_ledger().count()
    }

    fn lock_ledger(&self) -> std::sync::MutexGuard<'_, SessionLedger> {
        self.ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn lock_accounts(&self) -> std::sync::MutexGuard<'_, AccountLedger> {
        self.accounts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for MockState {
    fn default() -> Self {
        Self::new()
    }
}

/// Accepts loopback connections until [`MockBmc::stop`] flips the watch.
///
/// Each accepted connection is handled in its own task because the product
/// opens a fresh TLS connection per request; the loop only fails on a
/// listener-level I/O error, never on a per-connection error.
async fn serve_loop(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    state: Arc<MockState>,
    stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let mut stop = stop;
    loop {
        // Resolves on stop (value true) or when the sender drops; either
        // means the handle is gone and the loop must exit.
        let stopped = stop.wait_for(|stopped| *stopped);
        tokio::select! {
            _ = stopped => return Ok(()),
            accepted = listener.accept() => {
                let (tcp, _) = accepted?;
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(error) = handle_connection(tcp, acceptor, state).await {
                        eprintln!("mock-bmc connection error: {error}");
                    }
                });
            }
        }
    }
}

/// Serves one HTTPS connection: TLS handshake, one HTTP request, one
/// response, close.
///
/// The product's credential-free TLS probe never sends HTTP bytes, so a
/// handshake-only connection or an unparseable request closes the
/// connection quietly instead of failing the serve loop.
async fn handle_connection(
    tcp: TcpStream,
    acceptor: TlsAcceptor,
    state: Arc<MockState>,
) -> io::Result<()> {
    let tls = timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mock TLS handshake timed out"))??;
    let mut stream: TlsStream<TcpStream> = tls;
    let Ok(Ok(request)) = timeout(REQUEST_TIMEOUT, http::read_http_request(&mut stream)).await
    else {
        return Ok(());
    };
    state.record_request(request.method.as_str(), &request.target, request.headers);
    let response = route::dispatch(request.method, &request.target, &request.body, &state);
    stream.write_all(&http::render_response(&response)).await?;
    stream.shutdown().await?;
    Ok(())
}

/// Projects a bound loopback port into the product's endpoint address type.
fn endpoint_address(port: u16) -> Result<EndpointAddress, MockBmcError> {
    EndpointAddress::parse(&format!("https://127.0.0.1:{port}/")).map_err(MockBmcError::Address)
}
