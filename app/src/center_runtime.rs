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
    AdmissionRejection, BoundaryFuture, CenterBindingFlow, CenterBindingFlowError,
    CenterBindingRepository, CenterDispatchError, CenterEndpointProjection, CenterFrameProcessor,
    CenterInboundEngine, CenterInboundOptions, CenterInboundSession, CenterOperationDispatch,
    CenterOperationRequest, CenterOperationTracking, CenterProjection, CenterSessionAdmission,
    CenterTrustAnchor, Clock, DisconnectOnDrop, InstanceRepository, IssuedSiteCertificate,
    OperationStore, SiteCertificateIssuer,
};
use rutilus_center_protocol::{Envelope, EnvelopeMessage, OperationOffer};
use rutilus_domain::{
    CenterBindingState, CertificateFingerprint, DeploymentPosture, EndpointId, InstanceId,
    InstanceKind, OperationId, PrincipalId, RedfishCommand, ResourceODataId,
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
    standalone_runtime::{
        GRACEFUL_DRAIN_TIMEOUT, StandaloneState, drain_audit_compensation_final,
        drain_compensation, run_audit_compensation_drain,
    },
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
            // R6-E-02: only endpoints whose site's binding is in force are
            // listed — a revoked site's projected endpoints must not keep
            // being offered to the console. The involved sites' bindings
            // are read once per site, never per endpoint, and an endpoint
            // without a site association (a broken row) is never shown,
            // exactly like the operation view's site filter.
            let mut involved_sites = HashSet::new();
            for row in &rows {
                if let Some(site) = row.site_id() {
                    involved_sites.insert(site);
                }
            }
            let mut bound_sites = HashMap::new();
            for site in involved_sites {
                let is_bound = self
                    .store
                    .find_binding_by_site(site)
                    .await
                    .map_err(CenterServicesError::Binding)?
                    .is_some_and(|binding| binding.state() == CenterBindingState::Bound);
                bound_sites.insert(site, is_bound);
            }
            Ok(rows
                .into_iter()
                .filter(|row| {
                    row.site_id()
                        .is_some_and(|site| bound_sites.get(&site).copied().unwrap_or(false))
                })
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
            // W7-F-7a: the revocation runs inside the same per-site gate as
            // the dispatch critical section (R6-C-1) — the gate is taken
            // first and the store writes follow, the dispatch's lock order.
            // A dispatch holds the gate across its binding check, its
            // operation creation, and its offer enqueue, so the revocation
            // can never commit between the check and the enqueue: either
            // the dispatch completes before the revocation (the offer
            // predates it), or it observes the revoked binding and produces
            // nothing.
            let gate = {
                let mut gates = self
                    .dispatch_gates
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                gates
                    .entry(site)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone()
            };
            let _revoke_guard = gate.lock().await;
            // A site without a binding row has nothing to revoke; the
            // revocation is idempotent exactly like the domain's own
            // already-revoked absorption.
            let Some(binding) = self
                .store
                .find_binding_by_site(site)
                .await
                .map_err(CenterServicesError::Binding)?
            else {
                // The site is not bound; its gate key is garbage.
                self.drop_dispatch_gate(site);
                return Ok(());
            };
            match self
                .store
                .revoke_binding(binding.id())
                .await
                .map_err(CenterServicesError::Binding)?
            {
                RevokeOutcome::Revoked | RevokeOutcome::AlreadyRevoked => {}
            }
            // R6-C-6: the revocation ends the site's established session —
            // the registry entry is removed and the connection task's
            // disconnect signal fires, so the revoked site's connection
            // closes instead of keeping its flush and its reply path alive
            // (the V5E-5 retirement premise).
            self.registry.disconnect(site);
            // W7-P-7: the gate key is reclaimed with the revocation — a
            // revoke/re-enroll cycle mints a fresh instance id, and the
            // revoked site's key would otherwise stay in the map forever.
            // Any in-flight dispatch still holds its `Arc` clone, so the
            // removal never races a lock holder; a later dispatch simply
            // re-creates the key.
            self.drop_dispatch_gate(site);
            Ok(())
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
            // R6-C-1: the §17.5 idempotency scan and the operation creation
            // of one site are one critical section — two concurrent
            // identical dispatches must produce one operation, one offer,
            // one execution. The gate is held only inside this dispatch: no
            // path it covers dispatches again, so the non-reentrant mutex
            // cannot deadlock.
            let gate = {
                let mut gates = self
                    .dispatch_gates
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                gates
                    .entry(site)
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                    .clone()
            };
            let _dispatch_guard = gate.lock().await;
            // R6-E-02: the target site's binding must be in force — a
            // revoked (or not yet bound) site must never receive a new
            // dispatch. The web layer audits the refusal outcome, exactly
            // like every other dispatch refusal.
            let binding = self
                .store
                .find_binding_by_site(site)
                .await
                .map_err(|_| CenterOperationRefusal::Store)?;
            let binding_in_force =
                binding.is_some_and(|binding| binding.state() == CenterBindingState::Bound);
            if !binding_in_force {
                // The typed verdict is the site-binding refusal (R6-E-02):
                // the actor may be fully authorized, but the addressed
                // site's binding is no longer in force, so the dispatch
                // conflicts with the site's state. The web layer maps it to
                // 409 with the stable `site_binding_revoked` code.
                return Err(CenterOperationRefusal::SiteBindingRevoked);
            }
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
                    // The typed verdict carries the existing operation id
                    // (R6-E-01): a retry of an undecided dispatch is refused
                    // with the identity the site's deduplication already
                    // knows, and the web layer maps it to 409 with the
                    // stable `unknown_outcome_pending` code.
                    CenterDispatchError::UnknownOutcomePending { operation_id } => {
                        CenterOperationRefusal::UnknownOutcomePending { operation_id }
                    }
                }),
            }
        })
    }
}

/// The offer-scan bound of the center's operation tracking view (V4P-2):
/// at most the newest 256 outbox entries of each involved site are
/// decrypted per view, so a pathological queue can never make one console
/// page decrypt its whole history.
///
/// The value matches the dispatch retry's offer-scan bound
/// (`CENTER_DISPATCH_OFFER_SCAN_LIMIT`, 256): the same working-set argument
/// — each undecided operation holds at most one pending offer, so the
/// realistic per-site offer window stays far below the bound. The bound is
/// deliberately not a visibility guarantee:
/// an operation whose newest offer lies beyond the window renders without
/// its offer facts (the target, the actor context, and the offer expiry),
/// while its tracking record — the ids, the command, and the state — never
/// depends on the scan. There is no `operation_id` column to direct the
/// read at the offers of the displayed operations (the payload is a
/// ciphertext envelope), so the newest-`limit` window is the smallest
/// honest decryption surface.
const CENTER_VIEW_OFFER_SCAN_LIMIT: u64 = 256;

impl StandaloneState {
    /// Re-verifies one site's binding after its connection registered
    /// (W7-C-1): `Ok(true)` when the binding row exists and is in force.
    ///
    /// The admission resolves the binding before the connection task is
    /// even spawned, so a revocation that lands in the registration window
    /// is invisible to it; this fresh store read is the post-registration
    /// re-check that closes the window — a revoked site's just-registered
    /// session is closed instead of staying online with a disconnect
    /// signal that can never fire.
    async fn center_binding_still_in_force(
        &self,
        site: InstanceId,
    ) -> Result<bool, CenterBindingRepositoryError> {
        let Some(binding) = self.store.find_binding_by_site(site).await? else {
            return Ok(false);
        };
        Ok(binding.state() == CenterBindingState::Bound)
    }

    /// Removes one site's per-site dispatch gate key (W7-P-7). The removal
    /// is safe under in-flight dispatches: the map only guards the lookup,
    /// and a dispatch that already holds the gate keeps its `Arc` clone of
    /// the lock object alive.
    fn drop_dispatch_gate(&self, site: InstanceId) {
        let mut gates = self
            .dispatch_gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        gates.remove(&site);
    }

    /// The center's §15.6 operation tracking view.
    ///
    /// The operation records carry the stable ids, the typed command, and
    /// the §13.2 state; the offer facts the records do not persist — the
    /// target, the actor context, and the offer expiry — are rebuilt from
    /// the durable §15.6 offer envelopes in each involved site's outbox,
    /// scanned once per site within the bounded window
    /// ([`CENTER_VIEW_OFFER_SCAN_LIMIT`]).
    async fn list_center_operations(
        &self,
        site_filter: Option<InstanceId>,
    ) -> Result<Vec<CenterOperationView>, CenterServicesError> {
        let operations = OperationStore::list_operations(&self.store, None)
            .await
            .map_err(CenterServicesError::Operation)?;
        // The endpoint projection names each operation's site, and the
        // involved sites bound the offer scan. The projection rows of all
        // involved endpoints resolve in one `IN` query (V4P-2), never one
        // lookup per listed operation.
        let mut endpoint_ids: Vec<EndpointId> = Vec::with_capacity(operations.len());
        let mut operation_endpoints: HashMap<OperationId, EndpointId> = HashMap::new();
        for operation in &operations {
            let Some(endpoint_id) = operation
                .targets()
                .first()
                .map(|target| target.endpoint_id())
            else {
                continue;
            };
            endpoint_ids.push(endpoint_id);
            operation_endpoints.insert(operation.id(), endpoint_id);
        }
        let projections = self
            .store
            .find_endpoint_projections(&endpoint_ids)
            .await
            .map_err(CenterServicesError::Projection)?;
        let mut operation_sites: HashMap<OperationId, Option<InstanceId>> = HashMap::new();
        let mut involved_sites: HashSet<InstanceId> = HashSet::new();
        let mut offers: HashMap<OperationId, OperationOffer> = HashMap::new();
        for (operation_id, endpoint_id) in operation_endpoints {
            let site = projections
                .get(&endpoint_id)
                .and_then(CenterEndpointProjection::site_id);
            operation_sites.insert(operation_id, site);
            if let Some(site) = site {
                involved_sites.insert(site);
            }
        }
        for site in involved_sites {
            let entries = self
                .store
                .list_outbox_entries_bounded(site, CENTER_VIEW_OFFER_SCAN_LIMIT)
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
                    offers.entry(operation_id).or_insert(offer);
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
    // W7-C-3: the center posture's terminal audit facts enqueue into the
    // same process-wide compensation queue as the Edge postures, so the
    // drain task must run here too — without it, a transient store failure
    // would leave the event queued for the whole center run and the
    // shutdown would discard the queue wholesale.
    let mut compensation = tokio::spawn(run_audit_compensation_drain(
        stop_watch.clone(),
        Arc::clone(&state),
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
            // W8-C-1: the compensation drain task is joined BEFORE the
            // bounded final drain — the W7-C-4 discipline of the Edge
            // postures' `run_background_services`. The stop signal cannot
            // interrupt a drain pass that is already in flight (the task's
            // select only fires between passes), so an append that fails
            // during the shutdown is requeued by the in-flight pass; joining
            // first lets every such requeue land in the queue, and the final
            // drain then applies its bounded budget to the full remaining
            // set. Draining first would let those in-flight requeues bypass
            // the final drain's budget entirely and be dropped without a
            // replay attempt.
            drain_compensation(&mut compensation).await;
            drain_audit_compensation_final(&state).await;
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
            // W8-C-1: the compensation drain task is joined BEFORE the
            // bounded final drain — the W7-C-4 discipline of the Edge
            // postures: the stop signal cannot interrupt an in-flight drain
            // pass, so joining first lets the pass's requeues land in the
            // queue and the final drain's bounded budget cover the full
            // remaining set (draining first would let those in-flight
            // requeues bypass the budget and be dropped without a replay
            // attempt).
            drain_compensation(&mut compensation).await;
            drain_audit_compensation_final(&state).await;
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

/// The throttle window of the refused-connection warn (W3S-8): within one
/// window, the first refusal of each class is a warn and every repeat a
/// debug — so a peer that hammers the listener with refused connections
/// cannot storm the log, while each class's first refusal keeps its
/// diagnostic value.
const REFUSAL_WARN_WINDOW: time::Duration = time::Duration::seconds(60);

/// One class of admission rejection, for the refused-connection warn
/// throttle: each class keeps its own window, so one class's repeats never
/// suppress the other classes' first warns.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum RejectionClass {
    /// The certificate matches no bound binding.
    UnknownSite,
    /// The certificate disagrees with its binding record (S3b audit item
    /// 1).
    Identity,
    /// The `Hello` declared a different instance than the binding record
    /// (C5-10).
    HelloIdentityMismatch,
}

impl RejectionClass {
    fn of(reason: &AdmissionRejection) -> Self {
        match reason {
            AdmissionRejection::UnknownSite => Self::UnknownSite,
            AdmissionRejection::Identity(_) => Self::Identity,
            AdmissionRejection::HelloIdentityMismatch { .. } => Self::HelloIdentityMismatch,
        }
    }
}

/// The refused-connection warn throttle of one accept loop (W3S-8): the
/// first refusal of each class within one [`REFUSAL_WARN_WINDOW`] is a
/// warn, every repeat a debug. The state is a plain field of the accept
/// loop — the loop is a single task, so no synchronization is needed — and
/// the elapsed check saturates, so a regressed product clock can never
/// re-open a window early.
#[derive(Clone, Debug, Default)]
struct RefusalWarnThrottle {
    last_warned_at: HashMap<RejectionClass, OffsetDateTime>,
}

impl RefusalWarnThrottle {
    /// Reports one refused connection: `true` when it should be a warn —
    /// the first refusal of its class in the window, or the window elapsed
    /// since the last warn — and `false` when it is a throttled debug
    /// repeat.
    fn report(&mut self, class: RejectionClass, now: OffsetDateTime) -> bool {
        let within_window = self
            .last_warned_at
            .get(&class)
            .is_some_and(|last| now.saturating_sub(REFUSAL_WARN_WINDOW) <= *last);
        if within_window {
            false
        } else {
            self.last_warned_at.insert(class, now);
            true
        }
    }
}

/// The center's inbound accept loop: one admission and engine task per
/// accepted connection, until the stop watch fires, then every in-flight
/// connection is joined.
///
/// Finished connection tasks are reaped as new connections are accepted
/// (W8-P-5): the tracking Vec never accumulates every historical handle,
/// staying bounded by the number of concurrent connections instead of
/// growing with the total number of accepted connections over the run.
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
    // The refused-connection warn throttle (W3S-8): a peer that hammers
    // the listener with refused connections must not storm the log, while
    // each rejection class's first warn per window keeps its diagnostic
    // value.
    let mut refusal_warn_throttle = RefusalWarnThrottle::default();
    loop {
        tokio::select! {
            () = stop.stopped() => break,
            accepted = acceptor.accept_with_admission(&admission) => {
                match accepted {
                    Ok(accepted) => {
                        // The site id is captured before the task takes the
                        // connection, so a task failure is logged with its
                        // site (the reap and the shutdown join are the
                        // observation points).
                        let site_id = accepted.site().instance_id();
                        connections.push((
                            site_id,
                            tokio::spawn(run_center_connection(
                                Arc::clone(&state),
                                accepted,
                                stop.clone(),
                            )),
                        ));
                        // W8-P-5: the finished handles are reaped after
                        // every accept, so the Vec stays bounded by the
                        // concurrent connections plus this one — a site
                        // reconnecting on a fixed cadence (the W7-C-2
                        // generation guard legitimizes fast reconnects)
                        // can no longer accumulate one stale handle per
                        // reconnect for the whole run. The shutdown join
                        // below then awaits only the still-running
                        // connections, exactly once.
                        reap_finished_connections(&mut connections).await;
                    }
                    Err(CenterAcceptError::AdmissionRejected { reason }) => {
                        // The site received its refusal answer already;
                        // one refused site is one client's problem and the
                        // listener keeps accepting (§15.7 local autonomy).
                        // The report is throttled (W3S-8): the first
                        // refusal of each class within one 60-second window
                        // is a warn and every repeat a debug, so a peer
                        // that hammers the listener with refused
                        // connections cannot storm the log while each
                        // class's first refusal keeps its diagnostic value
                        // (an operator who enables debug sees every
                        // refusal).
                        let class = RejectionClass::of(&reason);
                        if refusal_warn_throttle.report(class, SystemClock.now()) {
                            tracing::warn!("center refused the connection: {reason}");
                        } else {
                            tracing::debug!("center refused the connection: {reason}");
                        }
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

/// Reaps the finished connection handles of the accept loop (W8-P-5): each
/// finished task's handle is awaited and removed from the Vec, so the Vec
/// stays bounded by the number of concurrent connections instead of
/// accumulating one handle per accepted connection for the whole run.
///
/// The outcome is observed exactly like the shutdown join — a `JoinError`
/// (a panic or a cancel) is logged with the site id, so the periodic reap
/// loses no observability: the connection task's own error paths are
/// already logged inside the task, and the panic/cancel signal is the only
/// thing the join reports. Awaiting a finished task's handle resolves
/// immediately (its output is already stored), so the reap never suspends
/// the accept loop.
async fn reap_finished_connections(
    connections: &mut Vec<(InstanceId, tokio::task::JoinHandle<()>)>,
) {
    let mut index = 0;
    while index < connections.len() {
        if connections[index].1.is_finished() {
            let (site_id, connection) = connections.swap_remove(index);
            if let Err(error) = connection.await {
                tracing::error!("the center connection task for site {site_id} failed: {error}");
            }
        } else {
            index += 1;
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
    // The registration generation (W7-C-2): the engine's exit cleanup and
    // the crash guard carry it, so one connection's cleanup can never
    // remove the entry of the site's next connection.
    let generation = match state
        .registry
        .mark_connected(site.clone(), SystemClock.now())
    {
        Ok(generation) => generation,
        Err(error) => {
            tracing::warn!(
                "center refused a second connection for site {}: {error}",
                site.instance_id()
            );
            return;
        }
    };
    // R6-C-6: the registry's per-site disconnect signal lets a binding
    // revocation end this connection. The signal is armed inside
    // `mark_connected`, so a revocation racing this setup still fires: the
    // `Notify` stores the notification for the first `notified()` await.
    let disconnect = state.registry.disconnect_watch(site.instance_id());
    // W7-C-1: a revocation that landed before the registration — while the
    // admission answer was on the wire and the connection task was spawned
    // — was a no-op against an empty registry, so the entry registered
    // above would carry a disconnect signal that can never fire and keep
    // the revoked site online and flushing. The fresh store read re-checks
    // the binding in force; a revoked site's just-registered session is
    // closed here instead. A revocation that lands after this re-check
    // removes the entry and fires the signal the task already holds, so
    // every ordering is covered exactly once. A store failure cannot
    // verify the binding, so the connection is closed too (fail closed:
    // a session whose binding state is unknown must not stay online).
    let binding_in_force = match state
        .center_binding_still_in_force(site.instance_id())
        .await
    {
        Ok(in_force) => in_force,
        Err(error) => {
            tracing::error!(
                "site {}: could not re-verify the binding after registration, closing the \
                 connection: {error}",
                site.instance_id()
            );
            false
        }
    };
    if !binding_in_force {
        tracing::warn!(
            "site {}: the binding was revoked before the connection registered; closing the \
             connection",
            site.instance_id()
        );
        state.registry.disconnect(site.instance_id());
        return;
    }
    // The crash backstop (N2-4): the engine removes the site on every
    // orderly exit, and this guard guarantees the same cleanup when the
    // task ends abnormally — a panic unwind runs the guard's `Drop`. A
    // crashed task must never leave a zombie online entry, or the site's
    // reconnects would be refused as `AlreadyConnected` forever, silently.
    // The cleanup is generation-guarded, so the guard and the engine's own
    // cleanup never conflict and a stale guard never removes the site's
    // next connection (W7-C-2).
    let site_id = site.instance_id();
    let _disconnect_guard = DisconnectOnDrop::new(Arc::clone(&state.registry), site_id, generation);
    let engine = CenterInboundEngine::new(
        connection,
        store,
        &processor,
        Arc::clone(&state.registry),
        SystemClock,
        site.clone(),
        generation,
        CenterInboundOptions::default(),
    );
    if let Err(error) = engine
        .run(async move {
            let mut stop = stop;
            match disconnect {
                Some(disconnect) => {
                    tokio::select! {
                        () = stop.stopped() => {}
                        () = disconnect.notified() => {
                            tracing::warn!(
                                "site {site_id}: the center revoked the binding; closing the connection"
                            );
                        }
                    }
                }
                None => stop.stopped().await,
            }
        })
        .await
    {
        tracing::error!("site {site_id} center connection ended: {error}");
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
    use std::{error::Error, io, net::Ipv4Addr, path::PathBuf, sync::Arc};

    use rutilus_application::{
        AuditEventWriter, CenterProjectionRepository, CenterTrustAnchor, EndpointProjectionWrite,
        ResolvedSite, ResourceProjectionWrite, SiteCertificateIssuer,
    };
    use rutilus_center_protocol::{EnvelopeMessage, OperationOffer};
    use rutilus_domain::{
        AuditAction, AuditActor, AuditEvent, AuditOperationContext, AuditOperationId,
        AuditParameterSummary, AuditRedfishOperation, AuditTarget, CenterBinding, CenterBindingId,
        CertificateFingerprint, EndpointId, InstanceId, InstanceKind, Operation, OperationSource,
        OperationTarget, OutboxEntry, OutboxEntryId, Principal, PrincipalId, PrincipalName,
        ProductPermission, RedfishCommand, ResetType, ResourceFeature, ResourceODataId, Role,
        RoleAssignment, SiteInstance, SystemCommand, TargetId,
    };
    use rutilus_persistence::SqliteStore;
    use rutilus_platform::{RuntimeLock, RuntimePaths};
    use rutilus_security::{MasterKey, generate_binding_code};
    // The W7-C-3 integration test holds the instance database's write lock
    // through a raw sqlx connection to inject a transient append failure
    // that heals when the lock is released; sea-orm is the app crate's
    // dev-dependency.
    use sea_orm::sqlx::{SqlitePool, sqlite::SqliteConnectOptions};
    use time::{Duration, OffsetDateTime};
    use tokio::net::TcpListener;

    use super::*;
    use crate::standalone_runtime::{
        AUDIT_GLOBALS_TEST_LOCK, capture_warn_diagnostics, captured_text,
        queue_audit_compensation_events, reset_audit_globals, wait_for_in_flight_drain_event,
    };

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

    #[test]
    fn refused_connection_warns_are_throttled_to_once_per_window_per_class() {
        // W3S-8: the first refusal of each class within one 60-second
        // window is a warn and every repeat a debug, so a peer that
        // hammers the listener with refused connections cannot storm the
        // log with one warn per connection. The window is per class, so
        // one class's repeats never suppress the other classes' first
        // warns, and each class warns again once the window elapses.
        let base = OffsetDateTime::UNIX_EPOCH;
        let mut throttle = RefusalWarnThrottle::default();
        let mismatch = RejectionClass::HelloIdentityMismatch;
        let unknown = RejectionClass::UnknownSite;

        assert!(
            throttle.report(mismatch, base),
            "the first refusal of a class is a warn"
        );
        assert!(
            !throttle.report(mismatch, base + Duration::SECOND),
            "a repeat within the window is a debug"
        );
        assert!(
            throttle.report(unknown, base + Duration::SECOND),
            "the other class's first refusal is a warn: the windows are per class"
        );
        assert!(
            throttle.report(mismatch, base + Duration::seconds(61)),
            "once the window elapses, the first refusal of the class warns again"
        );
        // A regressed product clock must not re-open a window: the elapsed
        // check saturates, so an earlier `now` still counts as within the
        // window of the last warn.
        assert!(
            !throttle.report(mismatch, base + Duration::seconds(30)),
            "a regressed clock still counts as within the window"
        );
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
            dispatch_gates: std::sync::Mutex::new(std::collections::HashMap::new()),
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

    /// Seeds one fully dispatchable site: the instance row, a `Bound`
    /// binding, an administrator role assignment, and the endpoint and
    /// resource projections of the `/redfish/v1/Systems/1` target.
    async fn seed_dispatchable_site(
        state: &StandaloneState,
        now: OffsetDateTime,
    ) -> Result<(SiteInstance, CenterBindingId, PrincipalId, EndpointId), Box<dyn Error>> {
        let site = SiteInstance::new(
            InstanceId::generate(),
            String::from("Test Site"),
            InstanceKind::Site,
            now,
        );
        state.store.create_instance(&site).await?;
        let code = generate_binding_code()?;
        let binding = CenterBinding::new_pending(
            CenterBindingId::generate(),
            String::from("https://center.example"),
            site.id(),
            &code,
            now + Duration::minutes(10),
            now,
        );
        state.store.create_binding(&binding).await?;
        state
            .store
            .bind_with_code(
                binding.id(),
                &code,
                Some(CertificateFingerprint::from_bytes([0x42; 32])),
                now,
            )
            .await?;
        let principal =
            Principal::new(PrincipalId::generate(), PrincipalName::parse("admin")?, now);
        state.store.create_principal(&principal).await?;
        state
            .store
            .assign_role(&RoleAssignment::new(
                principal.id(),
                Role::Administrator,
                None,
                now,
                None,
            ))
            .await?;
        let endpoint_id = EndpointId::generate();
        let projection = EndpointProjectionWrite::new(
            endpoint_id,
            String::from("Rack A PDU"),
            String::from("https://192.0.2.10"),
            rutilus_application::CenterTrustMode::SystemCa,
            1,
            String::from("ok"),
        );
        CenterProjectionRepository::upsert_endpoint(&state.store, &projection, site.id(), now)
            .await?;
        let resource = ResourceProjectionWrite::new(
            endpoint_id,
            String::from("/redfish/v1/Systems/1"),
            ResourceFeature::Systems,
            None,
            None,
            1,
            None,
            now,
        );
        CenterProjectionRepository::upsert_resource(&state.store, &resource, site.id(), now)
            .await?;
        Ok((site, binding.id(), principal.id(), endpoint_id))
    }

    #[tokio::test]
    async fn two_concurrent_identical_dispatches_create_one_operation() -> Result<(), Box<dyn Error>>
    {
        // R6-C-1: the §17.5 idempotency scan and the operation creation of
        // one site are one critical section — two concurrent identical
        // dispatches must produce one operation, one offer, one execution,
        // not a double-minted identity the site would execute twice.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let (site, _binding_id, actor, endpoint_id) = seed_dispatchable_site(&state, now).await?;
        let target = ResourceODataId::parse("/redfish/v1/Systems/1")?;
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));

        let (first, second) = tokio::join!(
            state.dispatch_center_operation(site.id(), endpoint_id, &target, &command, actor, now,),
            state.dispatch_center_operation(site.id(), endpoint_id, &target, &command, actor, now,),
        );
        let first = first.unwrap_or_else(|_| unreachable!("the concurrent dispatch must succeed"));
        let second =
            second.unwrap_or_else(|_| unreachable!("the concurrent dispatch must succeed"));
        assert_eq!(
            first.operation_id(),
            second.operation_id(),
            "both concurrent dispatches must resolve to the same operation"
        );
        let operations =
            rutilus_operation_engine::OperationStore::list_operations(&state.store, None).await?;
        assert_eq!(
            operations.len(),
            1,
            "exactly one tracking record is created"
        );
        assert!(
            !operations[0].state().is_terminal(),
            "the one operation is the in-flight dispatch, never a terminal row"
        );
        Ok(())
    }

    #[tokio::test]
    async fn dispatch_to_a_revoked_site_is_refused_and_the_revocation_ends_the_session()
    -> Result<(), Box<dyn Error>> {
        // R6-E-02: a revoked site's binding is not in force, so the
        // dispatch gate refuses it (the web layer audits the refusal
        // outcome); R6-C-6: the revocation also ends the site's established
        // session — the registry entry is removed and the connection task's
        // disconnect signal fires.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let (site, binding_id, actor, endpoint_id) = seed_dispatchable_site(&state, now).await?;
        let target = ResourceODataId::parse("/redfish/v1/Systems/1")?;
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));

        // The site holds an established session when the revocation lands.
        state.registry.mark_connected(
            ResolvedSite::new(
                site.id(),
                binding_id,
                CertificateFingerprint::from_bytes([0x42; 32]),
            ),
            now,
        )?;
        let watch = state
            .registry
            .disconnect_watch(site.id())
            .ok_or("the online site must expose its disconnect signal")?;
        let connection = tokio::spawn(async move {
            watch.notified().await;
        });
        state.revoke_center_binding(site.id(), now).await?;
        assert!(
            !state.registry.is_online(site.id()),
            "the revocation must remove the site from the online registry"
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), connection)
            .await
            .map_err(|_| "the revocation never closed the session")??;

        // The dispatch gate refuses the revoked site with the typed
        // site-binding verdict (R6-E-02), not an authorization refusal —
        // the actor is authorized; the site's binding state is the obstacle.
        let Err(refusal) = state
            .dispatch_center_operation(site.id(), endpoint_id, &target, &command, actor, now)
            .await
        else {
            unreachable!("a revoked site must refuse dispatch")
        };
        assert!(matches!(
            refusal,
            CenterOperationRefusal::SiteBindingRevoked
        ));
        assert!(
            rutilus_operation_engine::OperationStore::list_operations(&state.store, None)
                .await?
                .is_empty(),
            "no operation may be created for a revoked site"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_revocation_landing_before_registration_closes_the_new_connection()
    -> Result<(), Box<dyn Error>> {
        // W7-C-1: a revocation that lands between the admission (which
        // verified the binding) and the connection task's registration is a
        // no-op against an empty registry, so the entry that registers
        // afterwards would carry a disconnect signal that can never fire —
        // the revoked site would stay online and keep flushing. The
        // post-registration binding re-check closes the window: the
        // session is closed instead.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let (site, binding_id, _actor, _endpoint_id) = seed_dispatchable_site(&state, now).await?;

        // The revocation lands before the connection task registers: the
        // store commit happens, and the registry disconnect is a no-op for
        // a site that is not online yet.
        state.revoke_center_binding(site.id(), now).await?;
        assert!(!state.registry.is_online(site.id()));

        // The racer's connection task then registers — the revoked site is
        // online with a disconnect signal nothing will ever fire.
        state.registry.mark_connected(
            ResolvedSite::new(
                site.id(),
                binding_id,
                CertificateFingerprint::from_bytes([0x42; 32]),
            ),
            now,
        )?;
        assert!(state.registry.is_online(site.id()));

        // The post-registration re-check sees the revoked binding, and the
        // caller's self-disconnect closes the just-registered session.
        assert!(!state.center_binding_still_in_force(site.id()).await?);
        state.registry.disconnect(site.id());
        assert!(
            !state.registry.is_online(site.id()),
            "the revoked site's just-registered session is closed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_bound_site_passes_the_post_registration_recheck() -> Result<(), Box<dyn Error>> {
        // W7-C-1, the healthy side: a site whose binding is still in force
        // passes the post-registration re-check and its session proceeds —
        // the re-check is a read of the binding, never a fresh admission.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let (site, binding_id, _actor, _endpoint_id) = seed_dispatchable_site(&state, now).await?;
        let generation = state.registry.mark_connected(
            ResolvedSite::new(
                site.id(),
                binding_id,
                CertificateFingerprint::from_bytes([0x42; 32]),
            ),
            now,
        )?;
        assert!(state.center_binding_still_in_force(site.id()).await?);
        assert!(state.registry.is_online(site.id()));
        // The session's own cleanup still removes its entry.
        state.registry.mark_disconnected(site.id(), generation);
        assert!(!state.registry.is_online(site.id()));
        Ok(())
    }

    /// The site keys currently in the per-site dispatch gate map.
    fn gate_keys(state: &StandaloneState) -> Vec<InstanceId> {
        state
            .dispatch_gates
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .copied()
            .collect()
    }

    #[tokio::test]
    async fn revoke_and_dispatch_serialize_through_the_site_gate() -> Result<(), Box<dyn Error>> {
        // W7-F-7a: the revocation and the dispatch of one site run through
        // the same per-site gate, so a revocation can never commit between
        // the dispatch's binding check and its operation/offer creation —
        // the gate makes the two orders total: a revocation that wins the
        // race leaves the dispatch to observe the revoked binding and
        // produce nothing.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let (site, _binding_id, actor, endpoint_id) = seed_dispatchable_site(&state, now).await?;
        let target = ResourceODataId::parse("/redfish/v1/Systems/1")?;
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));

        // The test holds the gate so both tasks queue behind it; tokio
        // mutexes are FIFO, so the revoke — queued first — acquires it
        // first, deterministically.
        let held_gate = {
            let mut gates = state
                .dispatch_gates
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            gates
                .entry(site.id())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let site_id = site.id();
        let gate_guard = held_gate.lock().await;
        let revoke = tokio::spawn({
            let state = Arc::clone(&state);
            async move { state.revoke_center_binding(site_id, now).await }
        });
        tokio::task::yield_now().await;
        let dispatch = tokio::spawn({
            let state = Arc::clone(&state);
            let target = target.clone();
            let command = command.clone();
            async move {
                state
                    .dispatch_center_operation(site_id, endpoint_id, &target, &command, actor, now)
                    .await
            }
        });
        tokio::task::yield_now().await;
        drop(gate_guard);

        revoke.await.map_err(io::Error::other)??;
        let refused = dispatch.await.map_err(io::Error::other)?;
        assert!(
            matches!(refused, Err(CenterOperationRefusal::SiteBindingRevoked)),
            "the dispatch queued behind the revocation must observe the revoked binding"
        );
        assert!(
            rutilus_operation_engine::OperationStore::list_operations(&state.store, None)
                .await?
                .is_empty(),
            "no operation row may be created after the revocation committed"
        );
        assert!(
            state
                .store
                .list_outbox_entries_bounded(site.id(), 256)
                .await?
                .is_empty(),
            "no offer row may be created after the revocation committed"
        );
        Ok(())
    }

    #[tokio::test]
    async fn revoke_releases_the_sites_dispatch_gate_key() -> Result<(), Box<dyn Error>> {
        // W7-P-7: the per-site dispatch gate key is reclaimed with the
        // revocation — a revoke/re-enroll cycle mints a fresh instance id,
        // and the revoked site's key would otherwise stay in the map
        // forever.
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let now = OffsetDateTime::now_utc();
        let (site, _binding_id, actor, endpoint_id) = seed_dispatchable_site(&state, now).await?;
        let target = ResourceODataId::parse("/redfish/v1/Systems/1")?;
        let command = RedfishCommand::System(SystemCommand::Reset(ResetType::GracefulShutdown));

        // A first dispatch creates the gate key.
        let dispatched = state
            .dispatch_center_operation(site.id(), endpoint_id, &target, &command, actor, now)
            .await;
        assert!(
            dispatched.is_ok(),
            "the first dispatch to the bound site must succeed"
        );
        assert!(gate_keys(&state).contains(&site.id()));

        // The revocation removes it.
        state.revoke_center_binding(site.id(), now).await?;
        assert!(
            !gate_keys(&state).contains(&site.id()),
            "the revoked site's gate key is reclaimed"
        );
        Ok(())
    }

    /// One legal audit context for the center runtime test: a CSV import by
    /// the local operator — the vocabulary shape every runtime audit helper
    /// can append.
    fn audit_context() -> Result<AuditOperationContext, Box<dyn Error>> {
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

    /// Binds the center console on a free loopback port (the plaintext
    /// posture — a loopback listen without TLS material), retrying a raced
    /// probe like the other bind helpers.
    async fn bind_console(paths: &RuntimePaths) -> Result<SiteBinding, Box<dyn Error>> {
        loop {
            let port = free_port(Ipv4Addr::LOCALHOST).await?;
            let listen = ListenAddress::parse(&format!("127.0.0.1:{port}"))?;
            let options = SiteRunOptions::new(listen, None, None)?;
            match SiteBinding::bind(paths, &options).await {
                Ok(binding) => return Ok(binding),
                Err(SiteRunError::Bind(inner)) if inner.kind() == io::ErrorKind::AddrInUse => {}
                Err(error) => return Err(error.into()),
            }
        }
    }

    #[tokio::test]
    async fn the_center_runtime_retries_queued_audit_appends() -> Result<(), Box<dyn Error>> {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // W7-C-3: the center posture spawns the audit compensation drain
        // like the Edge postures — a terminal audit fact whose durable
        // append failed during the center run is retried by the drain
        // instead of sitting in the queue until the shutdown discards it.
        reset_audit_globals();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let binding = bind_console(&paths).await?;
        let acceptor = bind_acceptor(&paths).await?;
        let gateway = Arc::new(RedfishGateway::from_system_roots().await?);

        // A terminal fact whose durable append fails transiently: a raw
        // connection holds the database's write lock, so the store's append
        // waits out its busy timeout and fails with a database condition —
        // the transient class the compensation drain must keep retrying.
        let raw_pool = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(paths.database_path())
                .create_if_missing(false),
        )
        .await?;
        let mut raw_connection = raw_pool.acquire().await?;
        sea_orm::sqlx::query("BEGIN IMMEDIATE")
            .execute(&mut *raw_connection)
            .await?;
        let event = AuditEvent::started(audit_context()?, OffsetDateTime::now_utc());
        let append = state.append_audit_event(&event).await;
        assert!(
            append.is_err(),
            "the write lock must fail the append transiently"
        );
        // The lock is released: the queued event can now be retried.
        sea_orm::sqlx::query("ROLLBACK")
            .execute(&mut *raw_connection)
            .await?;
        drop(raw_connection);
        raw_pool.close().await;

        // The runtime runs with the compensation drain spawned — its first
        // tick is immediate, so the queued event is retried during the run —
        // and the stop then exercises the shutdown final drain.
        let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
        let stop = async move {
            let _ = stop_receiver.await;
            Ok::<(), io::Error>(())
        };
        let runtime = tokio::spawn(run_center_services(
            Arc::clone(&state),
            binding,
            acceptor,
            gateway,
            stop,
        ));
        // Wait for the drain's retry to land the event durably.
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                if !state
                    .store
                    .find_audit_operation(event.context().operation_id())
                    .await?
                    .is_empty()
                {
                    return Ok::<(), Box<dyn Error>>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "the compensation drain never retried the queued event")??;
        stop_sender
            .send(())
            .map_err(|()| io::Error::other("the center runtime already stopped"))?;
        runtime.await.map_err(io::Error::other)??;

        assert_eq!(
            state
                .store
                .find_audit_operation(event.context().operation_id())
                .await?,
            [event],
            "the queued terminal fact is durably persisted by the center drain"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_center_shutdown_requeue_from_the_background_drain_reaches_the_final_drain()
    -> Result<(), Box<dyn Error>> {
        let _audit_globals_guard = AUDIT_GLOBALS_TEST_LOCK.lock().await;
        // W8-C-1: the center shutdown path joins the background
        // compensation drain BEFORE the bounded final drain, the W7-C-4
        // discipline of the Edge postures. The stop signal cannot interrupt
        // an in-flight drain pass, so an append that fails during the
        // shutdown is requeued by that pass; joining first lets every such
        // requeue land in the queue, and the final drain then applies its
        // budget to it. The observable is the final drain's
        // budget-exhausted warning with `remaining=2`: both queued events
        // must reach the final drain. Under the reversed pre-fix order the
        // final drain ran first, exhausted its budget against the one event
        // already in the queue, and the drain task's in-flight requeue
        // landed only after it — the warning reported `remaining=1` and the
        // requeued event bypassed the final drain's budget entirely.
        reset_audit_globals();
        let directory = tempfile::tempdir()?;
        let paths = RuntimePaths::from_root(directory.path().join("center"))?;
        let state = test_state(&paths).await?;
        let binding = bind_console(&paths).await?;
        let acceptor = bind_acceptor(&paths).await?;
        let gateway = Arc::new(RedfishGateway::from_system_roots().await?);

        let now = OffsetDateTime::now_utc();
        let first = AuditEvent::started(audit_context()?, now);
        let second = AuditEvent::started(audit_context()?, now + Duration::seconds(1));
        queue_audit_compensation_events(&[first.clone(), second.clone()])?;

        // Hold the store's write gate so the drain's first pass blocks with
        // the first event in flight — the stop signal cannot interrupt it.
        let gate_permit = state.store.acquire_write_gate().await?;
        let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
        let stop = async move {
            let _ = stop_receiver.await;
            Ok::<(), io::Error>(())
        };
        let runtime = tokio::spawn(run_center_services(
            Arc::clone(&state),
            binding,
            acceptor,
            gateway,
            stop,
        ));

        // Wait deterministically for the drain task to have popped the
        // first event and blocked on the gate: the queue then holds exactly
        // the second event.
        wait_for_in_flight_drain_event(&second).await?;

        // Sabotage the store underneath the in-flight append: every append
        // now fails with a transient database condition, so the in-flight
        // pass fails and requeues its events during the shutdown.
        let writer = SqlitePool::connect_with(
            SqliteConnectOptions::new()
                .filename(paths.database_path())
                .create_if_missing(false),
        )
        .await?;
        sea_orm::sqlx::query("DROP TABLE audit_events")
            .execute(&writer)
            .await?;
        writer.close().await;

        let (dispatch, buffer) = capture_warn_diagnostics();
        let _guard = tracing::dispatcher::set_default(&dispatch);
        stop_sender
            .send(())
            .map_err(|()| io::Error::other("the test stop receiver was dropped"))?;
        // Hold the gate for longer than the final drain's budget: the drain
        // task's in-flight append can only fail (and requeue the first
        // event) once the gate is released, and the shutdown path joins the
        // drain task first — so both events are in the queue when the final
        // drain starts, and its budget-exhausted warning reports
        // `remaining=2`. Under the pre-fix order the final drain ran before
        // the join and exhausted its 2-second budget while the first event
        // was still in flight on the gate — `remaining=1`.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        drop(gate_permit);
        drop(state);
        let result = runtime
            .await
            .map_err(|error| -> Box<dyn Error> { error.into() })?;

        assert!(
            result.is_ok(),
            "the shutdown run must complete, got: {result:?}"
        );
        let captured = captured_text(&buffer)?;
        assert!(
            captured.contains("remaining=2"),
            "both requeued events must reach the bounded final drain (remaining=2), captured: \
             {captured}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn the_accept_loop_reaping_keeps_the_connection_tracking_bounded()
    -> Result<(), Box<dyn Error>> {
        // W8-P-5: finished connection handles are reaped as new connections
        // are accepted, so the accept loop's tracking Vec stays bounded by
        // the number of concurrent connections instead of accumulating one
        // handle per accepted connection for the whole run — a site
        // reconnecting on a fixed cadence (the W7-C-2 generation guard
        // legitimizes fast reconnects) can no longer grow the Vec without
        // bound. The reap observes the outcome exactly like the shutdown
        // join: a `JoinError` (a panic or a cancel) is logged with the site
        // id, so no observability is lost to the reap.
        let subscriber = CaptureSubscriber::new();
        let captured = subscriber.clone();
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut connections: Vec<(InstanceId, tokio::task::JoinHandle<()>)> = Vec::new();
        let finished = tokio::spawn(async {});
        let aborted = tokio::spawn(async { std::future::pending::<()>().await });
        let running =
            tokio::spawn(async { tokio::time::sleep(std::time::Duration::from_hours(1)).await });
        // The abort happens before the handle is pushed; the handle in the
        // Vec then observes the cancellation as a finished task.
        aborted.abort();
        let finished_site = InstanceId::generate();
        let aborted_site = InstanceId::generate();
        let running_site = InstanceId::generate();
        connections.push((finished_site, finished));
        connections.push((aborted_site, aborted));
        connections.push((running_site, running));
        // Let the finished and aborted tasks actually complete, so the reap
        // sees both as finished.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        reap_finished_connections(&mut connections).await;
        assert_eq!(
            connections.len(),
            1,
            "the finished and aborted handles must be reaped; only the still-running \
             connection remains"
        );
        assert_eq!(
            connections[0].0, running_site,
            "the survivor is the still-running connection"
        );
        assert!(
            captured
                .captured()
                .iter()
                .any(|(level, message)| *level == tracing::Level::ERROR
                    && message.contains(&aborted_site.to_string())),
            "the aborted task's JoinError is logged with its site id, exactly like the \
             shutdown join would"
        );
        // The shutdown join would now await the survivor; the test cancels
        // it through the same handle instead.
        if let Some((_, survivor)) = connections.pop() {
            survivor.abort();
        }
        Ok(())
    }
}
