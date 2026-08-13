//! The Center posture (design 4.4, §15, 0.7.0 S7): the aggregation service
//! bound sites connect to.
//!
//! The Center runs two listeners on one instance:
//!
//! - the **web console** — the same HTTPS console posture as the Site
//!   ([`SiteBinding`]), serving the `/api/v1/center/*` surface through the
//!   [`CenterServices`] implementation over the instance state;
//! - the **center protocol listener** — the dedicated mTLS port
//!   ([`CenterAcceptor`], TLS 1.3 with the center CA as the only trust
//!   anchor) that bound sites connect to over WebSocket.
//!
//! The center CA is generated at first startup and persisted below `tls/`
//! (`center-ca.crt`/`center-ca.key`); one CA instance is shared by the
//! acceptor and the runtime's certificate-issuer adapter
//! ([`CenterCaIssuer`], the S5 audit follow-up item 2 — the application
//! `SiteCertificateIssuer` boundary over the center CA). Every accepted
//! connection is admitted through the S5 [`CenterSessionAdmission`] — the
//! S3b certificate-identity cross-validation — registered in the shared
//! online registry, and driven by the S5 [`CenterInboundEngine`], whose
//! `CenterInboundSession` boundary is the accepted connection itself. The
//! startup banner prints the §10.4 pin material — the server and CA
//! fingerprints a site operator pins when binding a site.
//!
//! # Local autonomy (§15.7)
//!
//! The center is one active instance: an unreachable or misbehaving site
//! only ends that site's connection. The accept loop never fails the
//! console; a rejected or failed connection is logged and the listener
//! keeps accepting.
//!
//! # Shutdown (§7.8)
//!
//! One stop signal ends the accept loop first — each in-flight connection
//! engine observes the same signal and exits — then the web console drains.
//! Only after both are joined does the instance close `SQLite`, so no task
//! ever touches the store after shutdown begins.

use std::{
    collections::{HashMap, HashSet},
    future::Future,
    io,
    sync::Arc,
};

use rutilus_application::{
    BoundaryFuture, CenterBindingFlow, CenterBindingFlowError, CenterBindingRepository,
    CenterDispatchError, CenterFrameProcessor, CenterInboundEngine, CenterInboundOptions,
    CenterInboundSession, CenterOperationDispatch, CenterOperationRequest, CenterOperationTracking,
    CenterProjection, CenterSessionAdmission, CenterTrustAnchor, Clock, DisconnectOnDrop,
    InstanceRepository, IssuedSiteCertificate, OperationStore, SiteCertificateIssuer,
};
use rutilus_center_protocol::{Envelope, EnvelopeMessage, OperationOffer};
use rutilus_domain::{
    CertificateFingerprint, DeploymentPosture, EndpointId, InstanceId, InstanceKind, OperationId,
    PrincipalId, RedfishCommand, ResourceODataId,
};
use rutilus_persistence::{
    CenterBindingRepositoryError, CenterOutboxRepositoryError, CenterProjectionRepositoryError,
    InstanceRepositoryError, OperationRepositoryError, RevokeOutcome,
};
use rutilus_platform::{RuntimePaths, SystemSecretStore};
use rutilus_web::{
    CenterEndpointView, CenterOperationRefusal, CenterOperationView, CenterServices,
    CenterSiteView, DispatchedCenterOperation, RegisteredCenterSite,
};
use thiserror::Error;
use time::OffsetDateTime;
use tracing::instrument;

use crate::{
    AcceptedCenterConnection, CenterAcceptError, CenterAcceptor, CenterAcceptorError,
    CenterAcceptorOptions, CenterCa, CenterCaError, CenterConnection, CenterConnectionError,
    ListenAddress, SiteBinding, SiteRunError, SiteRunOptions, StandaloneInstance,
    StandaloneInstanceCloseError, StandaloneInstanceError, StandaloneUnlock, SystemClock,
    scheduler,
    standalone_runtime::{GRACEFUL_DRAIN_TIMEOUT, StandaloneState},
};
use rutilus_infra_redfish::RedfishGateway;

/// The Center posture's runtime configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CenterRunOptions {
    console: SiteRunOptions,
    center_listen: ListenAddress,
}

impl CenterRunOptions {
    /// Builds the Center listen configuration.
    ///
    /// # Errors
    ///
    /// Returns [`crate::SiteConfigError::CertificateWithoutKey`] when
    /// exactly one of `cert`/`key` is supplied.
    pub fn new(
        console: SiteRunOptions,
        center_listen: ListenAddress,
    ) -> Result<Self, crate::SiteConfigError> {
        // The console options carry their own pairing validation.
        Ok(Self {
            console,
            center_listen,
        })
    }

    /// The web console listener options (the Site console posture).
    #[must_use]
    pub const fn console(&self) -> &SiteRunOptions {
        &self.console
    }

    /// The center protocol listener address.
    #[must_use]
    pub const fn center_listen(&self) -> &ListenAddress {
        &self.center_listen
    }
}

/// The center's certificate-issuance adapter (S5 audit follow-up item 2):
/// the application [`SiteCertificateIssuer`] boundary over the center CA
/// and its issued server certificate.
///
/// The adapter signs one client certificate per bound site with the site's
/// identity fingerprint bound into the private-arc extension, and answers
/// the §10.4 trust anchor — the pinned server fingerprint and the CA
/// fingerprint — that the binding flow hands the site operator.
#[derive(Clone, Debug)]
pub struct CenterCaIssuer {
    ca: Arc<CenterCa>,
    server_fingerprint: CertificateFingerprint,
}

impl CenterCaIssuer {
    #[must_use]
    pub const fn new(ca: Arc<CenterCa>, server_fingerprint: CertificateFingerprint) -> Self {
        Self {
            ca,
            server_fingerprint,
        }
    }
}

impl SiteCertificateIssuer for CenterCaIssuer {
    type Error = CenterCaError;

    fn issue_site_certificate(
        &self,
        site: InstanceId,
        site_fingerprint: CertificateFingerprint,
    ) -> Result<IssuedSiteCertificate, Self::Error> {
        let issued = self.ca.issue_site_certificate(site, site_fingerprint)?;
        let (certificate_pem, key_pem) = issued.pem_pair();
        Ok(IssuedSiteCertificate::new(
            certificate_pem,
            key_pem,
            issued.fingerprint(),
        ))
    }

    fn center_trust_anchor(&self) -> CenterTrustAnchor {
        CenterTrustAnchor::new(self.server_fingerprint, self.ca.fingerprint())
    }
}

/// The accepted inbound connection as the application's inbound-session
/// boundary (S5 audit follow-up item 2).
///
/// The engine owns the §15.4 durable outbox, so the session delivers the
/// envelope exactly as the engine built it — the connection assigns no
/// sequence of its own — and `receive` is one raw frame at a time, with
/// control frames flushed and a clean close reported as `None`.
impl CenterInboundSession for CenterConnection {
    type Error = CenterConnectionError;

    fn send(&mut self, envelope: Envelope) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move { self.send_envelope(envelope).await })
    }

    fn receive(&mut self) -> BoundaryFuture<'_, Result<Option<Envelope>, Self::Error>> {
        Box::pin(async move { self.receive_envelope().await })
    }
}

/// A controlled failure of one center console service step (0.7.0 S6/S7).
///
/// The variants carry the underlying repository and use-case errors as
/// their sources, so every boundary failure stays reachable in the chain.
#[derive(Debug, Error)]
pub enum CenterServicesError {
    /// This deployment does not run the center posture (the issuer slot is
    /// empty): the center binding surface is refused.
    #[error("this deployment does not run the center posture")]
    NotACenter,
    /// The instance repository failed; carries its own error.
    #[error("the instance repository failed: {0}")]
    Instance(#[source] InstanceRepositoryError),
    /// The binding repository failed; carries its own error.
    #[error("the binding repository failed: {0}")]
    Binding(#[source] CenterBindingRepositoryError),
    /// The projection repository failed; carries its own error.
    #[error("the projection repository failed: {0}")]
    Projection(#[source] CenterProjectionRepositoryError),
    /// The durable outbox failed; carries its own error.
    #[error("the center outbox failed: {0}")]
    Outbox(#[source] CenterOutboxRepositoryError),
    /// The operation store failed; carries its own error.
    #[error("the operation store failed: {0}")]
    Operation(#[source] OperationRepositoryError),
    /// A stored §15.6 offer envelope cannot be decoded.
    #[error("a stored center offer cannot be decoded: {0}")]
    Offer(#[source] serde_json::Error),
    /// The binding flow failed; carries its own error.
    #[error("the binding flow failed: {0}")]
    Flow(
        #[source]
        CenterBindingFlowError<
            InstanceRepositoryError,
            CenterBindingRepositoryError,
            CenterCaError,
        >,
    ),
}

impl InstanceRepository for StandaloneState {
    type Error = InstanceRepositoryError;

    fn create_instance<'a>(
        &'a self,
        instance: &'a rutilus_domain::SiteInstance,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        InstanceRepository::create_instance(&self.store, instance)
    }

    fn find_instance(
        &self,
        instance_id: InstanceId,
    ) -> BoundaryFuture<'_, Result<Option<rutilus_domain::SiteInstance>, Self::Error>> {
        InstanceRepository::find_instance(&self.store, instance_id)
    }
}

impl CenterBindingRepository for StandaloneState {
    type Error = CenterBindingRepositoryError;

    fn create_binding<'a>(
        &'a self,
        binding: &'a rutilus_domain::CenterBinding,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        CenterBindingRepository::create_binding(&self.store, binding)
    }

    fn find_pending_binding_by_code_hash(
        &self,
        code_hash: &[u8; 32],
    ) -> BoundaryFuture<'_, Result<Option<rutilus_domain::CenterBinding>, Self::Error>> {
        CenterBindingRepository::find_pending_binding_by_code_hash(&self.store, code_hash)
    }

    fn bind_with_code<'a>(
        &'a self,
        binding_id: rutilus_domain::CenterBindingId,
        code: &'a rutilus_domain::BindingCode,
        site_cert_fingerprint: Option<CertificateFingerprint>,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        CenterBindingRepository::bind_with_code(
            &self.store,
            binding_id,
            code,
            site_cert_fingerprint,
            now,
        )
    }

    fn find_binding_by_site_fingerprint(
        &self,
        site_fingerprint: CertificateFingerprint,
    ) -> BoundaryFuture<'_, Result<Option<rutilus_domain::CenterBinding>, Self::Error>> {
        CenterBindingRepository::find_binding_by_site_fingerprint(&self.store, site_fingerprint)
    }
}

/// The center console's service boundary over the instance state (0.7.0
/// S6/S7): every `/api/v1/center/*` route reads and writes through this
/// implementation.
///
/// The views are assembled from the registered instances, their bindings,
/// the online registry, the §15.5 projections, and the durable §15.6
/// offers; the binding surface goes through the S5 [`CenterBindingFlow`]
/// (the one-time code is generated there and shown exactly once); the
/// operation dispatch goes through the S5 [`CenterOperationDispatch`], whose
/// §16.1 role re-check runs against the persisted role assignment.
impl CenterServices for StandaloneState {
    type Error = CenterServicesError;

    fn list_center_sites(&self) -> BoundaryFuture<'_, Result<Vec<CenterSiteView>, Self::Error>> {
        Box::pin(async move {
            let instances = self
                .store
                .list_instances()
                .await
                .map_err(CenterServicesError::Instance)?;
            let mut views = Vec::new();
            for instance in instances {
                if instance.kind() != InstanceKind::Site {
                    continue;
                }
                let binding = self
                    .store
                    .find_binding_by_site(instance.id())
                    .await
                    .map_err(CenterServicesError::Binding)?;
                let online = self.registry.is_online(instance.id());
                let (endpoint_count, last_refresh_at) = self
                    .store
                    .center_site_projection_summary(instance.id())
                    .await
                    .map_err(CenterServicesError::Projection)?;
                views.push(CenterSiteView::new(
                    instance.id(),
                    instance.display_name().to_owned(),
                    binding.map(|binding| binding.state()),
                    online,
                    endpoint_count,
                    last_refresh_at,
                ));
            }
            Ok(views)
        })
    }

    fn list_center_endpoints(
        &self,
        site: Option<InstanceId>,
    ) -> BoundaryFuture<'_, Result<Vec<CenterEndpointView>, Self::Error>> {
        Box::pin(async move {
            let rows = self
                .store
                .list_projected_endpoints(site)
                .await
                .map_err(CenterServicesError::Projection)?;
            Ok(rows
                .into_iter()
                .map(|row| {
                    CenterEndpointView::new(
                        row.site_id(),
                        row.endpoint_id(),
                        row.display_name().to_owned(),
                        row.address().to_owned(),
                        row.health().to_owned(),
                        row.refresh_generation(),
                    )
                })
                .collect())
        })
    }

    fn list_center_operations(
        &self,
        site: Option<InstanceId>,
    ) -> BoundaryFuture<'_, Result<Vec<CenterOperationView>, Self::Error>> {
        Box::pin(async move { self.list_center_operations(site).await })
    }

    fn register_center_site(
        &self,
        display_name: &str,
        center_url: &str,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<RegisteredCenterSite, Self::Error>> {
        let issuer = match self.center_issuer.lock() {
            Ok(slot) => slot.as_ref().cloned(),
            Err(_) => None,
        };
        let Some(issuer) = issuer else {
            return Box::pin(async move { Err(CenterServicesError::NotACenter) });
        };
        // The strings are owned before the block so the returned future
        // outlives the caller's borrows.
        let display_name = display_name.to_owned();
        let center_url = center_url.to_owned();
        let flow = CenterBindingFlow::new(&self.store, issuer);
        Box::pin(async move {
            let registered = flow
                .register_site(&center_url, &display_name, now)
                .await
                .map_err(CenterServicesError::Flow)?;
            Ok(RegisteredCenterSite::new(
                registered.instance_id(),
                registered.binding_id(),
                registered.code().to_string(),
                registered.expires_at(),
            ))
        })
    }

    fn revoke_center_binding(
        &self,
        site: InstanceId,
        _now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
        Box::pin(async move {
            // A site without a binding row has nothing to revoke; the
            // revocation is idempotent exactly like the domain's own
            // already-revoked absorption.
            let Some(binding) = self
                .store
                .find_binding_by_site(site)
                .await
                .map_err(CenterServicesError::Binding)?
            else {
                return Ok(());
            };
            match self
                .store
                .revoke_binding(binding.id())
                .await
                .map_err(CenterServicesError::Binding)?
            {
                RevokeOutcome::Revoked | RevokeOutcome::AlreadyRevoked => Ok(()),
            }
        })
    }

    fn dispatch_center_operation(
        &self,
        site: InstanceId,
        endpoint: EndpointId,
        target: &ResourceODataId,
        command: &RedfishCommand,
        actor: PrincipalId,
        now: OffsetDateTime,
    ) -> BoundaryFuture<'_, Result<DispatchedCenterOperation, CenterOperationRefusal>> {
        let dispatch = CenterOperationDispatch::new(&self.store, &self.store, &self.store);
        let target = target.clone();
        let command = command.clone();
        Box::pin(async move {
            let request = CenterOperationRequest::new(site, endpoint, target, command, actor);
            match dispatch.dispatch(&request, now).await {
                Ok(dispatched) => Ok(DispatchedCenterOperation::new(
                    dispatched.operation_id(),
                    dispatched.expires_at(),
                )),
                Err(error) => Err(match error {
                    CenterDispatchError::NotAuthorized => CenterOperationRefusal::NotAuthorized,
                    CenterDispatchError::UnknownEndpoint { endpoint_id } => {
                        CenterOperationRefusal::UnknownEndpoint { endpoint_id }
                    }
                    CenterDispatchError::EndpointNotInSite {
                        endpoint_id,
                        site_id,
                    } => CenterOperationRefusal::EndpointNotInSite {
                        endpoint_id,
                        site_id,
                    },
                    CenterDispatchError::UnknownTarget {
                        endpoint_id,
                        target,
                    } => CenterOperationRefusal::UnknownTarget {
                        endpoint_id,
                        target,
                    },
                    CenterDispatchError::CommandSerialization(_) => {
                        CenterOperationRefusal::CommandSerialization
                    }
                    CenterDispatchError::Projection(_)
                    | CenterDispatchError::Operation(_)
                    | CenterDispatchError::Outbox(_)
                    | CenterDispatchError::Role(_) => CenterOperationRefusal::Store,
                }),
            }
        })
    }
}

impl StandaloneState {
    /// The center's §15.6 operation tracking view.
    ///
    /// The operation records carry the stable ids, the typed command, and
    /// the §13.2 state; the offer facts the records do not persist — the
    /// target, the actor context, and the offer expiry — are rebuilt from
    /// the durable §15.6 offer envelopes in each involved site's outbox,
    /// scanned once per site.
    async fn list_center_operations(
        &self,
        site_filter: Option<InstanceId>,
    ) -> Result<Vec<CenterOperationView>, CenterServicesError> {
        let operations = OperationStore::list_operations(&self.store, None)
            .await
            .map_err(CenterServicesError::Operation)?;
        // The endpoint projection names each operation's site, and the
        // involved sites bound the offer scan.
        let mut operation_sites: HashMap<OperationId, Option<InstanceId>> = HashMap::new();
        let mut involved_sites: HashSet<InstanceId> = HashSet::new();
        let mut offers: HashMap<OperationId, OperationOffer> = HashMap::new();
        for operation in &operations {
            let Some(endpoint_id) = operation
                .targets()
                .first()
                .map(|target| target.endpoint_id())
            else {
                continue;
            };
            let projection = self
                .store
                .find_endpoint_projection(endpoint_id)
                .await
                .map_err(CenterServicesError::Projection)?;
            let site = projection.and_then(|projection| projection.site_id());
            operation_sites.insert(operation.id(), site);
            if let Some(site) = site {
                involved_sites.insert(site);
            }
        }
        for site in involved_sites {
            let entries = self
                .store
                .list_outbox_entries(site)
                .await
                .map_err(CenterServicesError::Outbox)?;
            for entry in entries {
                let envelope = match serde_json::from_str::<Envelope>(entry.payload_json()) {
                    Ok(envelope) => envelope,
                    Err(source) => {
                        // One unreadable row never fails the whole view:
                        // like the flush path (E3-9), the row is logged at
                        // warn and skipped, so the view shows every
                        // envelope that does decode.
                        tracing::warn!(
                            "site {site}: skipping outbox entry {} with an undecodable envelope: \
                             {source}",
                            entry.id()
                        );
                        continue;
                    }
                };
                if let Some(EnvelopeMessage::OperationOffer(offer)) = envelope.message {
                    let Ok(operation_id) = offer.operation_id.parse::<OperationId>() else {
                        continue;
                    };
                    offers.insert(operation_id, offer);
                }
            }
        }
        let mut views = Vec::new();
        for operation in operations {
            let Some(endpoint_id) = operation
                .targets()
                .first()
                .map(|target| target.endpoint_id())
            else {
                continue;
            };
            let site = operation_sites.get(&operation.id()).copied().flatten();
            if site_filter.is_some_and(|filter| site != Some(filter)) {
                continue;
            }
            let offer = offers.get(&operation.id());
            views.push(CenterOperationView::new(
                operation.id(),
                site,
                endpoint_id,
                operation.command().clone(),
                offer.map(|offer| offer.target.clone()),
                operation.state(),
                offer.map(|offer| offer.actor_context.clone()),
                offer.and_then(|offer| {
                    OffsetDateTime::from_unix_timestamp(offer.expires_at_unix).ok()
                }),
                operation.created_at(),
            ));
        }
        Ok(views)
    }
}

/// Runs the Center posture over the initialized instance until the external
/// `stop` future resolves: the web console, the center protocol listener,
/// and the per-connection inbound engines, draining through the §7.8 order
/// before `SQLite` closes.
///
/// `unlock` is `Some` for an interactive passphrase unlock and `None` for
/// the unattended operating-system unlock that services use.
///
/// # Errors
///
/// Returns [`CenterRunError`] while preserving both server and close
/// failures if they occur during the same shutdown.
#[instrument(skip_all, fields(data_directory = %paths.data_directory().display()))]
pub async fn run_center<Stop>(
    paths: &RuntimePaths,
    options: &CenterRunOptions,
    unlock: Option<&StandaloneUnlock>,
    stop: Stop,
) -> Result<(), CenterRunError>
where
    Stop: Future<Output = io::Result<()>> + Send,
{
    let gateway = RedfishGateway::from_system_roots()
        .await
        .map_err(CenterRunError::Gateway)?;
    let gateway = Arc::new(gateway);
    // The CA first-start generation happens exactly once, here: the
    // acceptor and the issuer adapter share the same CA instance.
    let ca = Arc::new(CenterCa::generate_or_load(paths).map_err(CenterRunError::Ca)?);
    let acceptor = CenterAcceptor::bind_with_ca(
        paths,
        &options.center_listen,
        Arc::clone(&ca),
        CenterAcceptorOptions::default(),
    )
    .await
    .map_err(CenterRunError::Accept)?;
    let binding = SiteBinding::bind(paths, &options.console)
        .await
        .map_err(CenterRunError::Console)?;
    let instance = if let Some(passphrase) = unlock {
        StandaloneInstance::open(paths, passphrase)
            .await
            .map_err(CenterRunError::Open)?
    } else {
        let store = SystemSecretStore::new();
        StandaloneInstance::open_system(paths, &store)
            .await
            .map_err(CenterRunError::Open)?
    };
    let state = instance.state();
    arm_center_issuer(&state, ca, acceptor.server_fingerprint())?;
    let run_result = run_center_services(state, binding, acceptor, gateway, stop).await;
    let close_result = instance.close().await;
    match (run_result, close_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(source), Ok(())) => Err(source),
        (Ok(()), Err(source)) => Err(CenterRunError::Close(source)),
        (Err(run), Err(close)) => Err(CenterRunError::RunAndClose {
            run: Box::new(run),
            close,
        }),
    }
}

/// Arms the instance's center issuer slot with the CA and the pinned server
/// fingerprint.
///
/// # Errors
///
/// Returns [`CenterRunError::StatePoisoned`] when the runtime state lock is
/// poisoned.
fn arm_center_issuer(
    state: &StandaloneState,
    ca: Arc<CenterCa>,
    server_fingerprint: CertificateFingerprint,
) -> Result<(), CenterRunError> {
    let mut slot = state
        .center_issuer
        .lock()
        .map_err(|_| CenterRunError::StatePoisoned)?;
    *slot = Some(CenterCaIssuer::new(ca, server_fingerprint));
    Ok(())
}

/// Serves the center console and the center protocol listener until the
/// external `stop` future resolves, draining the accept loop (and its
/// in-flight connection engines) before the console.
#[instrument(skip_all)]
async fn run_center_services<Stop>(
    state: Arc<StandaloneState>,
    binding: SiteBinding,
    acceptor: CenterAcceptor,
    gateway: Arc<RedfishGateway>,
    stop: Stop,
) -> Result<(), CenterRunError>
where
    Stop: Future<Output = io::Result<()>> + Send,
{
    println!("{}", center_banner(binding.url().as_str(), &acceptor));
    let (stop_signal, stop_watch) = scheduler::StopSignal::new();
    let accept_loop = tokio::spawn(run_center_accept_loop(
        stop_watch.clone(),
        Arc::clone(&state),
        acceptor,
    ));
    // The §16.2 first-run lifecycle matches the Edge postures: an
    // unconsumed bootstrap code leaves only the claim surface reachable
    // (the product surface stays closed — S3-2), and the first-run claim
    // arms the gate.
    let policy = match state.store.has_unconsumed_bootstrap_code().await {
        Ok(true) => rutilus_web::AuthPolicy::PendingBootstrap(rutilus_web::AuthGate::open()),
        Ok(false) => rutilus_web::AuthPolicy::Guarded,
        Err(error) => {
            tracing::error!(
                "could not read the bootstrap-code state for the first-run gate, starting guarded: {error}"
            );
            rutilus_web::AuthPolicy::Guarded
        }
    };
    let services = Arc::clone(&state);
    let server = binding.serve_until(
        DeploymentPosture::Center,
        policy,
        services,
        gateway,
        SystemClock,
        async move {
            let mut stop = stop_watch;
            stop.stopped().await;
        },
        GRACEFUL_DRAIN_TIMEOUT,
    );
    tokio::pin!(server);
    tokio::select! {
        result = &mut server => {
            // The console stopped on its own (a serving failure): stop the
            // accept loop too, and wait for the connection engines before
            // closing the store.
            stop_signal.signal();
            if let Err(error) = accept_loop.await {
                tracing::error!("the center accept loop task failed: {error}");
            }
            result.map_err(CenterRunError::Serve)
        }
        signal = stop => {
            signal.map_err(CenterRunError::Signal)?;
            // §7.8: the accept loop stops first; each in-flight connection
            // engine observes the same signal and exits, and only then does
            // the console drain.
            stop_signal.signal();
            if let Err(error) = accept_loop.await {
                tracing::error!("the center accept loop task failed: {error}");
            }
            server.await.map_err(CenterRunError::Serve)
        }
    }
}

/// The center startup banner: the console URL, the center protocol
/// listener, and the §10.4 pin material — the server and CA fingerprints a
/// site operator pins when binding a site.
fn center_banner(console_url: &str, acceptor: &CenterAcceptor) -> String {
    format!(
        "Rutilus Center is listening at {console_url} (console)\n\
         Center protocol listener: {}\n\
         Center server certificate fingerprint: {}\n\
         Center CA certificate fingerprint: {}",
        acceptor.address(),
        acceptor.server_fingerprint(),
        acceptor.ca().fingerprint(),
    )
}

/// The center's inbound accept loop: one admission and engine task per
/// accepted connection, until the stop watch fires, then every in-flight
/// connection is joined.
///
/// The admission is resolved inside the accept (audit follow-up F4): a
/// refused site receives its `NegotiationResult` at negotiation time —
/// `not-bound` when its binding is not in force, so it converges its
/// local binding instead of retrying forever, or `identity-mismatch` when
/// the Hello declared an identity that disagrees with the certificate's
/// binding (C5-10: the binding is in force, so no convergence).
#[instrument(skip_all)]
async fn run_center_accept_loop(
    mut stop: scheduler::StopWatch,
    state: Arc<StandaloneState>,
    acceptor: CenterAcceptor,
) {
    let mut acceptor = acceptor;
    let mut connections = Vec::new();
    // One admission resolver shared by every accept: it reads the store,
    // which the accept loop owns for its whole lifetime.
    let admission = CenterSessionAdmission::new(&state.store);
    loop {
        tokio::select! {
            () = stop.stopped() => break,
            accepted = acceptor.accept_with_admission(&admission) => {
                match accepted {
                    Ok(accepted) => {
                        // The site id is captured before the task takes the
                        // connection, so a task failure is logged with its
                        // site (the join below is the only observation
                        // point left).
                        let site_id = accepted.site().instance_id();
                        connections.push((
                            site_id,
                            tokio::spawn(run_center_connection(
                                Arc::clone(&state),
                                accepted,
                                stop.clone(),
                            )),
                        ));
                    }
                    Err(CenterAcceptError::AdmissionRejected { reason }) => {
                        // The site received its refusal answer already;
                        // one refused site is one client's problem and the
                        // listener keeps accepting (§15.7 local autonomy).
                        tracing::warn!("center refused the connection: {reason}");
                    }
                    Err(error) => {
                        // One failed handshake is one client's problem; the
                        // listener keeps accepting (§15.7 local autonomy).
                        tracing::error!("center accept failed: {error}");
                    }
                }
            }
        }
    }
    for (site_id, connection) in connections {
        // A `JoinError` here means the connection task panicked; its own
        // error paths are already logged inside the task, so only the
        // panic signal is recorded here.
        if let Err(error) = connection.await {
            tracing::error!("the center connection task for site {site_id} failed: {error}");
        }
    }
}

/// Runs one accepted, admitted inbound connection: the online-registry
/// registration and the §15.4 inbound engine loop.
///
/// The admission decision was resolved inside the accept (audit follow-up
/// F4), so the task starts from the resolved site. The connection task
/// owns its Arc clones of the instance state, so every repository
/// reference is built inside the task; the engine observes the shared stop
/// watch, the registry removes the site on every exit, and a
/// [`DisconnectOnDrop`] guard guarantees the same cleanup when the task
/// ends abnormally (N2-4).
#[instrument(skip_all)]
async fn run_center_connection(
    state: Arc<StandaloneState>,
    accepted: AcceptedCenterConnection,
    stop: scheduler::StopWatch,
) {
    let (connection, site) = accepted.into_parts();
    let store = &state.store;
    let processor = CenterFrameProcessor::new(
        CenterProjection::new(store, store),
        CenterOperationTracking::new(store, store),
    );
    if let Err(error) = state
        .registry
        .mark_connected(site.clone(), SystemClock.now())
    {
        tracing::warn!(
            "center refused a second connection for site {}: {error}",
            site.instance_id()
        );
        return;
    }
    // The crash backstop (N2-4): the engine removes the site on every
    // orderly exit, and this guard guarantees the same cleanup when the
    // task ends abnormally — a panic unwind runs the guard's `Drop`. A
    // crashed task must never leave a zombie online entry, or the site's
    // reconnects would be refused as `AlreadyConnected` forever, silently.
    // The cleanup is idempotent, so the guard and the engine's own cleanup
    // never conflict.
    let _disconnect_guard = DisconnectOnDrop::new(Arc::clone(&state.registry), site.instance_id());
    let engine = CenterInboundEngine::new(
        connection,
        store,
        &processor,
        Arc::clone(&state.registry),
        SystemClock,
        site.clone(),
        CenterInboundOptions::default(),
    );
    if let Err(error) = engine
        .run(async move {
            let mut stop = stop;
            stop.stopped().await;
        })
        .await
    {
        tracing::error!(
            "site {} center connection ended: {error}",
            site.instance_id()
        );
    }
}

/// A controlled failure before or during the center server.
#[derive(Debug, Error)]
pub enum CenterRunError {
    #[error("failed to load platform TLS trust for the center server: {0}")]
    Gateway(#[source] rutilus_infra_redfish::TlsProbeInitError),
    #[error("failed to prepare the center CA: {0}")]
    Ca(#[source] CenterCaError),
    #[error("failed to bind the center protocol listener: {0}")]
    Accept(#[from] CenterAcceptorError),
    #[error("failed to prepare the center console listener: {0}")]
    Console(#[from] SiteRunError),
    #[error("failed to open initialized center state: {0}")]
    Open(#[source] StandaloneInstanceError),
    #[error("the center runtime state is poisoned")]
    StatePoisoned,
    #[error("center console server failed: {0}")]
    Serve(#[source] io::Error),
    #[error("the stop signal could not be registered: {0}")]
    Signal(#[source] io::Error),
    #[error("center server stopped but SQLite shutdown failed: {0}")]
    Close(#[source] StandaloneInstanceCloseError),
    #[error("center server and SQLite shutdown both failed (server: {run}; close: {close})")]
    RunAndClose {
        run: Box<Self>,
        close: StandaloneInstanceCloseError,
    },
}

#[cfg(test)]
mod tests {
    use std::{error::Error, net::Ipv4Addr, path::PathBuf, sync::Arc};

    use rutilus_application::{CenterTrustAnchor, SiteCertificateIssuer};
    use rutilus_center_protocol::{EnvelopeMessage, OperationOffer};
    use rutilus_domain::{
        CertificateFingerprint, InstanceId, InstanceKind, Operation, OperationSource,
        OperationTarget, OutboxEntry, OutboxEntryId, ResetType, SiteInstance, SystemCommand,
        TargetId,
    };
    use rutilus_persistence::SqliteStore;
    use rutilus_platform::{RuntimeLock, RuntimePaths};
    use rutilus_security::MasterKey;
    use time::{Duration, OffsetDateTime};
    use tokio::net::TcpListener;

    use super::*;

    /// Probes one free port on the given host and returns it.
    async fn free_port(host: Ipv4Addr) -> io::Result<u16> {
        let listener = TcpListener::bind((host, 0)).await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        Ok(port)
    }

    /// A bind failed because a racer grabbed the probed port between the
    /// probe and the bind; the retry loop moves on to a fresh port.
    fn is_raced_bind(error: &CenterAcceptorError) -> bool {
        matches!(
            error,
            CenterAcceptorError::Bind(inner) if inner.kind() == io::ErrorKind::AddrInUse
        )
    }

    /// Binds a center acceptor on a free loopback port over a fresh CA.
    /// The probe inside `free_port` is released before this bind, so a
    /// racer may grab the port in between; the attempt is then retried on
    /// a fresh port instead of failing the test.
    async fn bind_acceptor(paths: &RuntimePaths) -> Result<CenterAcceptor, Box<dyn Error>> {
        let ca = Arc::new(CenterCa::generate_or_load(paths)?);
        loop {
            let port = free_port(Ipv4Addr::LOCALHOST).await?;
            let listen = ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
            match CenterAcceptor::bind_with_ca(
                paths,
                &listen,
                Arc::clone(&ca),
                CenterAcceptorOptions::default(),
            )
            .await
            {
                Ok(acceptor) => return Ok(acceptor),
                Err(error) if is_raced_bind(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    #[tokio::test]
    async fn the_center_banner_carries_the_console_url_and_the_pin_material()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let acceptor = bind_acceptor(&paths).await?;
        let banner = center_banner("https://127.0.0.1:8443/", &acceptor);
        assert!(
            banner.starts_with("Rutilus Center is listening at https://127.0.0.1:8443/ (console)")
        );
        assert!(banner.contains(&format!("Center protocol listener: {}", acceptor.address())));
        assert!(banner.contains(&format!(
            "Center server certificate fingerprint: {}",
            acceptor.server_fingerprint()
        )));
        assert!(banner.contains(&format!(
            "Center CA certificate fingerprint: {}",
            acceptor.ca().fingerprint()
        )));
        Ok(())
    }

    #[tokio::test]
    async fn binds_and_closes_the_center_listener_and_generates_the_ca()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let acceptor = bind_acceptor(&paths).await?;
        let address = acceptor.address();
        // The CA first-start generation persisted both halves below tls/,
        // and the acceptor issued and persisted its server pair.
        assert!(paths.tls_directory().join("center-ca.crt").is_file());
        assert!(paths.tls_directory().join("center-ca.key").is_file());
        assert!(paths.tls_directory().join("center-cert.pem").is_file());
        assert!(paths.tls_directory().join("center-key.pem").is_file());
        assert_eq!(
            acceptor.server_fingerprint().to_string().split(':').count(),
            32
        );
        drop(acceptor);

        // The listener released its port: a fresh bind on the same address
        // succeeds.
        let listen = ListenAddress::parse(&address.to_string())?;
        let ca = Arc::new(CenterCa::generate_or_load(&paths)?);
        let rebound =
            CenterAcceptor::bind_with_ca(&paths, &listen, ca, CenterAcceptorOptions::default())
                .await?;
        assert_eq!(rebound.address(), address);
        Ok(())
    }

    #[test]
    fn the_center_ca_issuer_speaks_the_site_certificate_issuer_boundary()
    -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("instance"))?;
        let ca = Arc::new(CenterCa::generate_or_load(&paths)?);
        let server_fingerprint = CertificateFingerprint::from_bytes([0xAB; 32]);
        let issuer = CenterCaIssuer::new(ca, server_fingerprint);
        let site = InstanceId::generate();
        let site_fingerprint = CertificateFingerprint::from_bytes([0xCD; 32]);

        let certificate = issuer.issue_site_certificate(site, site_fingerprint)?;
        // The issued certificate's own fingerprint is its SHA-256 identity;
        // the site identity fingerprint is bound into the private-arc
        // extension and cannot be read back as the certificate hash.
        assert_eq!(certificate.fingerprint().to_string().split(':').count(), 32);
        assert!(
            certificate
                .certificate_pem()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(
            certificate
                .key_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----")
        );
        assert_eq!(
            issuer.center_trust_anchor(),
            CenterTrustAnchor::new(server_fingerprint, issuer.ca.fingerprint())
        );
        Ok(())
    }

    #[test]
    fn the_center_console_options_validate_the_certificate_pairing() -> Result<(), Box<dyn Error>> {
        let listen = ListenAddress::parse("127.0.0.1:8443")?;
        let center_listen = ListenAddress::parse("127.0.0.1:8444")?;
        // The pairing validation lives in the console options; a
        // half-supplied pair is refused before any listener binds.
        assert!(matches!(
            SiteRunOptions::new(listen.clone(), Some(PathBuf::from("cert.pem")), None),
            Err(crate::SiteConfigError::CertificateWithoutKey)
        ));
        let options = CenterRunOptions::new(
            SiteRunOptions::new(listen, None, None)?,
            center_listen.clone(),
        )?;
        assert_eq!(options.console().listen().to_string(), "127.0.0.1:8443");
        assert_eq!(options.center_listen(), &center_listen);
        Ok(())
    }

    /// A test instance state over one migrated store.
    async fn test_state(paths: &RuntimePaths) -> Result<Arc<StandaloneState>, Box<dyn Error>> {
        let master_key = Arc::new(MasterKey::generate()?);
        let store =
            SqliteStore::open_with_command_key(paths.database_path(), Arc::clone(&master_key))
                .await?;
        let runtime_lock = RuntimeLock::acquire(paths.runtime_lock_path())?;
        Ok(Arc::new(StandaloneState {
            store,
            master_key,
            _runtime_lock: runtime_lock,
            audit_tail: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            registry: Arc::new(rutilus_application::CenterSessionRegistry::new()),
            center_issuer: std::sync::Mutex::new(None),
        }))
    }

    /// A test subscriber that records every event's level and formatted
    /// message — the same capture shape as the application crate's engine
    /// tests.
    #[derive(Clone)]
    struct CaptureSubscriber {
        events: std::sync::Arc<std::sync::Mutex<Vec<(tracing::Level, String)>>>,
    }

    impl CaptureSubscriber {
        fn new() -> Self {
            Self {
                events: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            }
        }

        fn captured(&self) -> Vec<(tracing::Level, String)> {
            self.events
                .lock()
                .map(|events| events.clone())
                .unwrap_or_default()
        }
    }

    struct CaptureVisitor(Option<String>);

    impl tracing::field::Visit for CaptureVisitor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = Some(format!("{value:?}"));
            }
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "message" {
                self.0 = Some(value.to_owned());
            }
        }
    }

    impl tracing::Subscriber for CaptureSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = CaptureVisitor(None);
            event.record(&mut visitor);
            let message = visitor.0.unwrap_or_default();
            self.events
                .lock()
                .map(|mut events| events.push((*event.metadata().level(), message)))
                .ok();
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[tokio::test]
    async fn list_center_operations_logs_and_skips_an_undecodable_outbox_envelope()
    -> Result<(), Box<dyn Error>> {
        // E3-9: one undecodable outbox row never fails the operation view
        // and never disappears silently — it is reported at warn and
        // skipped, exactly like the flush path, and every envelope that
        // does decode still lands in the view.
        let subscriber = CaptureSubscriber::new();
        let captured = subscriber.clone();
        let _guard = tracing::subscriber::set_default(subscriber);
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Test Site"),
            InstanceKind::Site,
            now,
        );
        state.store.create_instance(&site).await?;
        let endpoint_id = EndpointId::generate();
        let operation = Operation::new(
            OperationId::generate(),
            OperationSource::Center,
            vec![OperationTarget::new(TargetId::generate(), endpoint_id)],
            RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown)),
            now,
        );
        rutilus_operation_engine::OperationStore::create_operation(&state.store, &operation)
            .await?;
        let projection = rutilus_application::EndpointProjectionWrite::new(
            endpoint_id,
            String::from("Rack A PDU"),
            String::from("https://192.0.2.10"),
            rutilus_application::CenterTrustMode::SystemCa,
            1,
            String::from("ok"),
        );
        rutilus_application::CenterProjectionRepository::upsert_endpoint(
            &state.store,
            &projection,
            site.id(),
            now,
        )
        .await?;
        // One valid offer and one row whose payload is not an envelope.
        let offer = EnvelopeMessage::OperationOffer(OperationOffer {
            operation_id: operation.id().to_string(),
            endpoint_id: endpoint_id.to_string(),
            site_id: site.id().to_string(),
            command_json: b"{}".to_vec(),
            target: String::from("/redfish/v1/Systems/1"),
            expires_at_unix: (now + Duration::minutes(15)).unix_timestamp(),
            actor_context: String::from("operator"),
        });
        state
            .store
            .enqueue_outbox_entry(site.id(), &offer, now)
            .await?;
        let bogus = OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            2,
            String::from(r#"{"not":"an envelope"}"#),
            now,
        );
        state.store.create_outbox_entry(&bogus).await?;

        let views = state.list_center_operations(None).await?;
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].operation_id(), operation.id());
        assert_eq!(views[0].target(), Some("/redfish/v1/Systems/1"));

        let events = captured.captured();
        let warns = events
            .iter()
            .filter(|(level, _)| *level == tracing::Level::WARN)
            .collect::<Vec<_>>();
        assert!(
            warns.iter().any(|(_, message)| {
                message.contains(bogus.id().to_string().as_str())
                    && message.contains("undecodable envelope")
            }),
            "the undecodable row is reported at warn, not silently dropped"
        );
        Ok(())
    }
}
