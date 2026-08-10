//! The Center console's service boundary over the instance state (0.7.0
//! S6/S7): every `/api/v1/center/*` route reads and writes through this
//! implementation.
//!
//! The views are assembled from the registered instances, their bindings,
//! the online registry, the §15.5 projections, and the durable §15.6
//! offers; the binding surface goes through the S5 [`CenterBindingFlow`]
//! (the one-time code is generated there and shown exactly once); the
//! operation dispatch goes through the S5 [`CenterOperationDispatch`], whose
//! §16.1 role re-check runs against the persisted role assignment.
//!
//! The center certificate-issuance adapter ([`CenterCaIssuer`], the S5
//! audit follow-up item 2) answers the application `SiteCertificateIssuer`
//! boundary over the center CA: it signs one client certificate per bound
//! site and answers the §10.4 trust anchor.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use rutilus_application::{
    BoundaryFuture, CenterBindingFlow, CenterBindingFlowError, CenterDispatchError,
    CenterOperationDispatch, CenterOperationRequest, CenterTrustAnchor, IssuedSiteCertificate,
    OperationStore, SiteCertificateIssuer,
};
use rutilus_center_protocol::{Envelope, EnvelopeMessage, OperationOffer};
use rutilus_domain::{
    CertificateFingerprint, EndpointId, InstanceId, InstanceKind, OperationId, PrincipalId,
    RedfishCommand, ResourceODataId,
};
use rutilus_persistence::{
    CenterBindingRepositoryError, CenterOutboxRepositoryError, CenterProjectionRepositoryError,
    InstanceRepositoryError, OperationRepositoryError, RevokeOutcome,
};
use rutilus_web::{
    CenterEndpointView, CenterOperationRefusal, CenterOperationView, CenterServices,
    CenterSiteView, DispatchedCenterOperation, RegisteredCenterSite,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::{CenterCa, CenterCaError, standalone_runtime::StandaloneState};

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
                let Ok(envelope) = serde_json::from_str::<Envelope>(entry.payload_json()) else {
                    continue;
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
