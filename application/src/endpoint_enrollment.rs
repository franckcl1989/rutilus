use std::error::Error;

use rutilus_domain::{AuditActor, DeploymentPosture, EndpointId, PrincipalId, ResourceSnapshot};
use thiserror::Error;

use crate::{
    AuditEventWriter, AuditedEndpointOnboarding, AuditedEndpointRefresh,
    AuditedEndpointRefreshError, AuditedOnboardEndpointError, BoundaryFuture,
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialResolver,
    DiscoveredEndpointRepository, EndpointRefreshRepository, OnboardEndpointRequest,
    OnboardedEndpoint, RedfishDiscovery, batch_refresh::endpoint_read_gate,
};

/// Enrolls one already trusted endpoint and returns its stable identity.
pub trait EndpointEnroller: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn enroll(
        &self,
        request: OnboardEndpointRequest,
    ) -> BoundaryFuture<'_, Result<EndpointId, Self::Error>>;
}

impl<Enroller> EndpointEnroller for &Enroller
where
    Enroller: EndpointEnroller + ?Sized,
{
    type Error = Enroller::Error;

    fn enroll(
        &self,
        request: OnboardEndpointRequest,
    ) -> BoundaryFuture<'_, Result<EndpointId, Self::Error>> {
        Enroller::enroll(*self, request)
    }
}

/// A newly persisted endpoint together with its first complete resource
/// Generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrolledEndpoint {
    onboarded: OnboardedEndpoint,
    snapshots: Vec<ResourceSnapshot>,
}

impl EnrolledEndpoint {
    /// Borrows the endpoint and capability result created before refresh.
    #[must_use]
    pub const fn onboarded(&self) -> &OnboardedEndpoint {
        &self.onboarded
    }

    /// Borrows every snapshot in the first complete Generation.
    #[must_use]
    pub fn snapshots(&self) -> &[ResourceSnapshot] {
        &self.snapshots
    }
}

/// Coordinates the documented post-trust enrollment sequence through
/// mandatory, independently closed onboarding and complete-refresh audits.
pub struct EndpointEnrollment<Repository, Credentials, Gateway, Time> {
    repository: Repository,
    credentials: Credentials,
    gateway: Gateway,
    clock: Time,
    actor: AuditActor,
    actor_principal_id: Option<PrincipalId>,
    origin: DeploymentPosture,
}

impl<Repository, Credentials, Gateway, Time>
    EndpointEnrollment<Repository, Credentials, Gateway, Time>
where
    Repository: DiscoveredEndpointRepository
        + EndpointRefreshRepository
        + CapabilitySnapshotRepository
        + AuditEventWriter,
    Credentials: CredentialResolver,
    Gateway: RedfishDiscovery + CoreResourceReader,
    Time: Clock,
{
    #[must_use]
    pub fn new(
        repository: Repository,
        credentials: Credentials,
        gateway: Gateway,
        clock: Time,
        actor: AuditActor,
        actor_principal_id: Option<PrincipalId>,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            repository,
            credentials,
            gateway,
            clock,
            actor,
            actor_principal_id,
            origin,
        }
    }

    /// Persists one trusted, discovered endpoint and then commits its first
    /// complete resource Generation.
    ///
    /// The two transactions intentionally have different outcomes. If the
    /// first refresh fails, the endpoint remains managed and the error reports
    /// its stable identifier so a caller can present or retry that state.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointEnrollmentError::Onboarding`] before an endpoint
    /// exists, [`EndpointEnrollmentError::OnboardingAuditAfterCreation`] when
    /// endpoint persistence precedes an onboarding-audit failure,
    /// [`EndpointEnrollmentError::InitialRefreshCoordination`] when the
    /// process-wide endpoint read gate cannot be acquired before the first
    /// refresh starts, [`EndpointEnrollmentError::InitialRefresh`] when the
    /// first refresh does not commit, or
    /// [`EndpointEnrollmentError::InitialRefreshAuditAfterCommit`] when the
    /// Generation commits but its audit cannot be finalized.
    pub async fn execute(
        &self,
        request: OnboardEndpointRequest,
    ) -> Result<
        EnrolledEndpoint,
        EndpointEnrollmentError<
            Credentials::Error,
            <Gateway as RedfishDiscovery>::Error,
            <Repository as DiscoveredEndpointRepository>::Error,
            <Repository as EndpointRefreshRepository>::Error,
            <Repository as CapabilitySnapshotRepository>::Error,
            <Gateway as CoreResourceReader>::Error,
            <Repository as AuditEventWriter>::Error,
        >,
    > {
        let onboarding = AuditedEndpointOnboarding::new(
            &self.repository,
            &self.credentials,
            &self.gateway,
            &self.repository,
            &self.clock,
            self.actor,
            self.actor_principal_id,
            self.origin,
        );
        let onboarded = onboarding.execute(request).await.map_err(|source| {
            if let Some(endpoint_id) = source.persisted_endpoint_id() {
                EndpointEnrollmentError::OnboardingAuditAfterCreation {
                    endpoint_id,
                    source: Box::new(source),
                }
            } else {
                EndpointEnrollmentError::Onboarding(Box::new(source))
            }
        })?;
        let endpoint_id = onboarded.endpoint().id();
        // The initial refresh is a refresh like any other, so it passes
        // through the process-wide endpoint-level read gate (design §7.8)
        // before it starts: one permit per endpoint, held for the whole
        // refresh exactly like the batch refresh entrance, so an enrollment
        // first refresh and a concurrent batch refresh of the same endpoint
        // can never overlap and race the §9.5 Generation order. The gate is
        // never closed, so a failed acquire is the same process-level break
        // the batch reports as its Coordination outcome — the enrollment
        // reports its own classified coordination failure instead of
        // starting an uncoordinated refresh.
        let Some(gate) = endpoint_read_gate(endpoint_id) else {
            return Err(EndpointEnrollmentError::InitialRefreshCoordination {
                endpoint_id,
                source: EndpointReadGateError::RegistryUnavailable,
            });
        };
        let Ok(_endpoint_permit) = gate.acquire().await else {
            return Err(EndpointEnrollmentError::InitialRefreshCoordination {
                endpoint_id,
                source: EndpointReadGateError::GateClosed,
            });
        };
        let refresh = AuditedEndpointRefresh::new(
            &self.repository,
            &self.credentials,
            &self.gateway,
            &self.repository,
            &self.clock,
            self.actor,
            self.actor_principal_id,
            self.origin,
        );
        let snapshots = refresh.execute(endpoint_id).await.map_err(|source| {
            if source.resources_committed() {
                EndpointEnrollmentError::InitialRefreshAuditAfterCommit {
                    endpoint_id,
                    source: Box::new(source),
                }
            } else {
                EndpointEnrollmentError::InitialRefresh {
                    endpoint_id,
                    source: Box::new(source),
                }
            }
        })?;
        Ok(EnrolledEndpoint {
            onboarded,
            snapshots,
        })
    }
}

impl<Repository, Credentials, Gateway, Time> EndpointEnroller
    for EndpointEnrollment<Repository, Credentials, Gateway, Time>
where
    Repository: DiscoveredEndpointRepository
        + EndpointRefreshRepository
        + CapabilitySnapshotRepository
        + AuditEventWriter,
    Credentials: CredentialResolver,
    Gateway: RedfishDiscovery + CoreResourceReader,
    Time: Clock,
{
    type Error = EndpointEnrollmentError<
        Credentials::Error,
        <Gateway as RedfishDiscovery>::Error,
        <Repository as DiscoveredEndpointRepository>::Error,
        <Repository as EndpointRefreshRepository>::Error,
        <Repository as CapabilitySnapshotRepository>::Error,
        <Gateway as CoreResourceReader>::Error,
        <Repository as AuditEventWriter>::Error,
    >;

    fn enroll(
        &self,
        request: OnboardEndpointRequest,
    ) -> BoundaryFuture<'_, Result<EndpointId, Self::Error>> {
        Box::pin(async move {
            self.execute(request)
                .await
                .map(|enrolled| enrolled.onboarded().endpoint().id())
        })
    }
}

/// A controlled failure before or after an endpoint becomes persistent.
#[derive(Debug, Error)]
pub enum EndpointEnrollmentError<
    CredentialError,
    DiscoveryError,
    OnboardingRepositoryError,
    RefreshRepositoryError,
    CapabilityError,
    ReaderError,
    AuditError,
> where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    OnboardingRepositoryError: Error + 'static,
    RefreshRepositoryError: Error + 'static,
    CapabilityError: Error + 'static,
    ReaderError: Error + 'static,
    AuditError: Error + 'static,
{
    #[error("endpoint onboarding failed before enrollment completed: {0}")]
    Onboarding(
        #[source]
        Box<
            AuditedOnboardEndpointError<
                CredentialError,
                DiscoveryError,
                OnboardingRepositoryError,
                AuditError,
            >,
        >,
    ),
    #[error(
        "endpoint {endpoint_id} was created but onboarding audit finalization failed: {source}"
    )]
    OnboardingAuditAfterCreation {
        endpoint_id: EndpointId,
        #[source]
        source: Box<
            AuditedOnboardEndpointError<
                CredentialError,
                DiscoveryError,
                OnboardingRepositoryError,
                AuditError,
            >,
        >,
    },
    #[error(
        "endpoint {endpoint_id} was created but its initial complete refresh could not be scheduled: {source}"
    )]
    InitialRefreshCoordination {
        endpoint_id: EndpointId,
        #[source]
        source: EndpointReadGateError,
    },
    #[error("endpoint {endpoint_id} was created but its initial complete refresh failed: {source}")]
    InitialRefresh {
        endpoint_id: EndpointId,
        #[source]
        source: Box<
            AuditedEndpointRefreshError<
                RefreshRepositoryError,
                CapabilityError,
                CredentialError,
                ReaderError,
                DiscoveryError,
                AuditError,
            >,
        >,
    },
    #[error(
        "endpoint {endpoint_id} committed its initial resource Generation but refresh audit finalization failed: {source}"
    )]
    InitialRefreshAuditAfterCommit {
        endpoint_id: EndpointId,
        #[source]
        source: Box<
            AuditedEndpointRefreshError<
                RefreshRepositoryError,
                CapabilityError,
                CredentialError,
                ReaderError,
                DiscoveryError,
                AuditError,
            >,
        >,
    },
}

/// A controlled failure to acquire the process-wide endpoint read gate
/// before the initial refresh could start (design §7.8).
///
/// Mirrors the batch refresh entrance's Coordination outcome: the gate is
/// process-wide and never closed, so both variants are controlled dead-ends
/// reported as classified coordination failures instead of panics.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum EndpointReadGateError {
    /// The gate registry could not be locked.
    #[error("the endpoint refresh gate registry is unavailable")]
    RegistryUnavailable,
    /// The endpoint's one-permit read gate is closed.
    #[error("the endpoint refresh gate is closed")]
    GateClosed,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{
            Arc, Mutex, MutexGuard,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use rutilus_domain::{
        AuditAction, AuditEvent, CapabilityState, CredentialId, CredentialUsername, Endpoint,
        EndpointAddress, EndpointCapability, EndpointCapabilityObservation, EndpointDisplayName,
        RefreshGeneration, ResourceFeature, ResourceId, ResourceODataId, ResourceSnapshotPayload,
        TlsCertificate, TlsTrust,
    };
    use secrecy::SecretString;
    use time::OffsetDateTime;

    use crate::{
        AuditRecordError, BatchEndpointRefresh, BoundaryFuture, EndpointDiscovery,
        EndpointRefreshError, OnboardEndpointError, ResolvedCredential, ResourceObservation,
        TrustedEndpoint,
    };

    use super::*;

    #[tokio::test]
    async fn creates_endpoint_then_commits_its_first_complete_generation()
    -> Result<(), Box<dyn Error>> {
        fn assert_enroller<Enroller: EndpointEnroller>(_enroller: &Enroller) {}

        let state = Arc::new(Mutex::new(MockState::default()));
        let now = OffsetDateTime::now_utc();
        let service = EndpointEnrollment::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::available(Arc::clone(&state)),
            MockGateway::succeed(Arc::clone(&state)),
            FixedClock(now),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        );
        assert_enroller(&service);

        let enrolled = service
            .execute(request(CredentialId::generate(), now)?)
            .await?;

        assert_eq!(enrolled.snapshots().len(), 1);
        assert_eq!(
            enrolled.snapshots()[0].endpoint_id(),
            enrolled.onboarded().endpoint().id()
        );
        assert_eq!(
            events(&state)?,
            [
                "audit",
                "credential",
                "discover",
                "create",
                "audit",
                "audit",
                "audit",
                "load",
                "credential",
                "read",
                "commit",
                "discover",
                "snapshot",
                "audit",
            ]
        );
        let audit_events = audit_events(&state)?;
        assert_eq!(audit_events.len(), 5);
        assert_eq!(
            audit_events[0].context().action(),
            AuditAction::EnrollEndpoint
        );
        assert_eq!(
            audit_events[3].context().action(),
            AuditAction::RefreshEndpoint
        );
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_failure_before_endpoint_creation() -> Result<(), Box<dyn Error>> {
        let state = Arc::new(Mutex::new(MockState::default()));
        let now = OffsetDateTime::now_utc();
        let credential_id = CredentialId::generate();
        let service = EndpointEnrollment::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::missing(Arc::clone(&state)),
            MockGateway::succeed(Arc::clone(&state)),
            FixedClock(now),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        );

        let result = service.execute(request(credential_id, now)?).await;

        assert!(matches!(
            result,
            Err(EndpointEnrollmentError::Onboarding(source))
                if matches!(
                    &*source,
                    AuditedOnboardEndpointError::Onboarding(onboarding)
                        if matches!(
                            &**onboarding,
                            OnboardEndpointError::CredentialNotFound {
                                credential_id: missing,
                            } if *missing == credential_id
                        )
                )
        ));
        assert_eq!(events(&state)?, ["audit", "credential", "audit"]);
        assert!(lock_state(&state)?.endpoint.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn reports_created_endpoint_when_initial_refresh_fails() -> Result<(), Box<dyn Error>> {
        let state = Arc::new(Mutex::new(MockState::default()));
        let now = OffsetDateTime::now_utc();
        let service = EndpointEnrollment::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::available(Arc::clone(&state)),
            MockGateway::fail_read(Arc::clone(&state)),
            FixedClock(now),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        );

        let result = service
            .execute(request(CredentialId::generate(), now)?)
            .await;
        let persisted_id = lock_state(&state)?
            .endpoint
            .as_ref()
            .map(Endpoint::id)
            .ok_or(MockError::State)?;

        assert!(matches!(
            result,
            Err(EndpointEnrollmentError::InitialRefresh {
                endpoint_id,
                source,
            }) if endpoint_id == persisted_id
                && matches!(
                    &*source,
                    AuditedEndpointRefreshError::Refresh {
                        source: refresh,
                        ..
                    } if matches!(&**refresh, EndpointRefreshError::Read(MockError::Read))
                )
        ));
        assert_eq!(
            events(&state)?,
            [
                "audit",
                "credential",
                "discover",
                "create",
                "audit",
                "audit",
                "audit",
                "load",
                "credential",
                "read",
                "audit",
            ]
        );
        assert_eq!(lock_state(&state)?.commits, 0);
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_onboarding_audit_failure_after_endpoint_creation()
    -> Result<(), Box<dyn Error>> {
        let state = Arc::new(Mutex::new(MockState::default()));
        lock_state(&state)?.fail_audit_on = Some(2);
        let now = OffsetDateTime::now_utc();
        let service = EndpointEnrollment::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::available(Arc::clone(&state)),
            MockGateway::succeed(Arc::clone(&state)),
            FixedClock(now),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        );

        let result = service
            .execute(request(CredentialId::generate(), now)?)
            .await;
        let persisted_id = lock_state(&state)?
            .endpoint
            .as_ref()
            .map(Endpoint::id)
            .ok_or(MockError::State)?;

        assert!(matches!(
            result,
            Err(EndpointEnrollmentError::OnboardingAuditAfterCreation {
                endpoint_id,
                source,
            }) if endpoint_id == persisted_id
                && matches!(
                    &*source,
                    AuditedOnboardEndpointError::Audit {
                        source: AuditRecordError::Write(MockError::Audit),
                        ..
                    }
                )
        ));
        assert_eq!(
            events(&state)?,
            ["audit", "credential", "discover", "create", "audit"]
        );
        assert_eq!(audit_events(&state)?.len(), 1);
        assert_eq!(lock_state(&state)?.commits, 0);
        Ok(())
    }

    #[tokio::test]
    async fn distinguishes_refresh_audit_failure_after_generation_commit()
    -> Result<(), Box<dyn Error>> {
        let state = Arc::new(Mutex::new(MockState::default()));
        lock_state(&state)?.fail_audit_on = Some(5);
        let now = OffsetDateTime::now_utc();
        let service = EndpointEnrollment::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::available(Arc::clone(&state)),
            MockGateway::succeed(Arc::clone(&state)),
            FixedClock(now),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        );

        let result = service
            .execute(request(CredentialId::generate(), now)?)
            .await;
        let persisted_id = lock_state(&state)?
            .endpoint
            .as_ref()
            .map(Endpoint::id)
            .ok_or(MockError::State)?;

        assert!(matches!(
            result,
            Err(EndpointEnrollmentError::InitialRefreshAuditAfterCommit {
                endpoint_id,
                source,
            }) if endpoint_id == persisted_id
                && source.resources_committed()
                && matches!(
                    &*source,
                    AuditedEndpointRefreshError::Audit {
                        source: AuditRecordError::Write(MockError::Audit),
                        ..
                    }
                )
        ));
        assert_eq!(lock_state(&state)?.commits, 1);
        assert_eq!(audit_events(&state)?.len(), 4);
        assert_eq!(
            events(&state)?,
            [
                "audit",
                "credential",
                "discover",
                "create",
                "audit",
                "audit",
                "audit",
                "load",
                "credential",
                "read",
                "commit",
                "discover",
                "snapshot",
                "audit",
            ]
        );
        Ok(())
    }

    // The test drives an enrollment initial refresh and a concurrent batch
    // refresh through a blocked read and asserts the full serialized
    // lifecycle, so the line count is the coverage, not a signal.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn initial_refresh_and_concurrent_batch_refresh_of_the_same_endpoint_never_overlap()
    -> Result<(), Box<dyn Error>> {
        // The enrollment first refresh and a concurrent batch refresh of the
        // same endpoint must never overlap (design §7.8 endpoint-level gate):
        // the initial refresh passes through the same process-wide one-permit
        // gate as every batch refresh, so a batch started while the initial
        // refresh is in flight must wait at the gate instead of reading, and
        // the two refreshes then run back to back with no interleaved phase.
        let state = Arc::new(Mutex::new(MockState::default()));
        let now = OffsetDateTime::now_utc();
        let (reached_tx, reached_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let block = Arc::new(FirstReadBlock::new(reached_tx, release_rx));
        let request = request(CredentialId::generate(), now)?;

        let enrollment = EndpointEnrollment::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::available(Arc::clone(&state)),
            MockGateway::succeed(Arc::clone(&state)).with_first_read_block(Arc::clone(&block)),
            FixedClock(now),
            AuditActor::LocalOperator,
            None,
            DeploymentPosture::Standalone,
        );
        // The batch shares the enrollment's mocks — the repository doubles
        // as its audit writer and the gateway as its reader — so both
        // entrances observe the same events and the same persisted endpoint.
        let batch = BatchEndpointRefresh::new(
            MockRepository::new(Arc::clone(&state)),
            MockCredentials::available(Arc::clone(&state)),
            MockGateway::succeed(Arc::clone(&state)),
            MockRepository::new(Arc::clone(&state)),
            FixedClock(now),
            AuditActor::System,
            None,
            DeploymentPosture::Site,
        );

        let enrollment_task = tokio::spawn(async move { enrollment.execute(request).await });
        // The enrollment first refresh is now provably in flight inside its
        // read.
        reached_rx.await.map_err(|_| MockError::State)?;
        let endpoint_id = lock_state(&state)?
            .endpoint
            .as_ref()
            .map(Endpoint::id)
            .ok_or(MockError::State)?;
        let batch_task = tokio::spawn(async move { batch.execute(vec![endpoint_id]).await });
        // Give the batch time to reach the endpoint-level gate. While the
        // initial refresh's observation is still in flight there must be
        // exactly one read and no commit: the batch waits at the gate
        // instead of overlapping the enrollment's initial refresh.
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let events = events(&state)?;
            assert_eq!(
                events.iter().filter(|event| **event == "read").count(),
                1,
                "the batch refresh must wait at the endpoint gate instead of reading"
            );
            assert_eq!(
                events.iter().filter(|event| **event == "commit").count(),
                0,
                "no Generation may commit while an observation is still in flight"
            );
        }
        let _ = release_tx.send(());
        let enrolled = enrollment_task.await.map_err(|_| MockError::State)??;
        let outcomes = batch_task.await.map_err(|_| MockError::State)??;
        assert_eq!(enrolled.snapshots().len(), 1);
        assert_eq!(outcomes.len(), 1);
        assert!(outcomes[0].is_success());

        // Serialization proof: from the first read onward, the two refresh
        // phases are contiguous blocks — read, Generation commit, capability
        // re-probe, snapshot replace — with the batch's read starting only
        // after the initial refresh's whole phase completed. The gate is
        // held for the entire refresh, not just for the read.
        let events = events(&state)?;
        let first_read = events
            .iter()
            .position(|event| *event == "read")
            .ok_or(MockError::State)?;
        let refresh_tail = events[first_read..]
            .iter()
            .filter(|event| matches!(**event, "read" | "commit" | "discover" | "snapshot"))
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            refresh_tail,
            [
                "read", "commit", "discover", "snapshot", "read", "commit", "discover", "snapshot",
            ]
        );
        Ok(())
    }

    #[derive(Debug, Default)]
    struct MockState {
        events: Vec<&'static str>,
        audit_events: Vec<AuditEvent>,
        audit_attempts: usize,
        fail_audit_on: Option<usize>,
        endpoint: Option<Endpoint>,
        commits: usize,
    }

    #[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
    enum MockError {
        #[error("mock state is unavailable")]
        State,
        #[error("mock resource read failed")]
        Read,
        #[error("mock audit append failed")]
        Audit,
    }

    struct MockRepository {
        state: Arc<Mutex<MockState>>,
    }

    impl MockRepository {
        fn new(state: Arc<Mutex<MockState>>) -> Self {
            Self { state }
        }
    }

    impl AuditEventWriter for MockRepository {
        type Error = MockError;

        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut state = lock_state(&self.state)?;
                state.events.push("audit");
                state.audit_attempts += 1;
                if state.fail_audit_on == Some(state.audit_attempts) {
                    return Err(MockError::Audit);
                }
                state.audit_events.push(event.clone());
                Ok(())
            })
        }
    }

    impl DiscoveredEndpointRepository for MockRepository {
        type Error = MockError;

        fn create_discovered_endpoint<'a>(
            &'a self,
            endpoint: Endpoint,
            _observations: &'a [EndpointCapabilityObservation],
        ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
            Box::pin(async move {
                let mut state = lock_state(&self.state)?;
                state.events.push("create");
                state.endpoint = Some(endpoint.clone());
                Ok(endpoint)
            })
        }
    }

    impl CapabilitySnapshotRepository for MockRepository {
        type Error = MockError;

        fn replace_endpoint_capabilities<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [EndpointCapabilityObservation],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                lock_state(&self.state)?.events.push("snapshot");
                Ok(())
            })
        }
    }

    impl EndpointRefreshRepository for MockRepository {
        type Error = MockError;

        fn find_endpoint(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async move {
                let mut state = lock_state(&self.state)?;
                state.events.push("load");
                Ok(state.endpoint.clone())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            endpoint_id: EndpointId,
            observations: &'a [ResourceObservation],
            _decode_failures: &'a [crate::ResourceDecodeFailure],
            observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async move {
                let mut state = lock_state(&self.state)?;
                state.events.push("commit");
                state.commits += 1;
                let generation = RefreshGeneration::new(1).map_err(|_| MockError::State)?;
                Ok(observations
                    .iter()
                    .map(|observation| {
                        ResourceSnapshot::new(
                            ResourceId::generate(),
                            endpoint_id,
                            observation.feature(),
                            observation.odata_id().clone(),
                            observation.payload().clone(),
                            observed_at,
                            generation,
                        )
                    })
                    .collect())
            })
        }
    }

    struct MockCredentials {
        state: Arc<Mutex<MockState>>,
        available: bool,
    }

    impl MockCredentials {
        fn available(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                available: true,
            }
        }

        fn missing(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                available: false,
            }
        }
    }

    impl CredentialResolver for MockCredentials {
        type Error = MockError;

        fn resolve(
            &self,
            _credential_id: CredentialId,
        ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
            Box::pin(async move {
                lock_state(&self.state)?.events.push("credential");
                if self.available {
                    Ok(Some(ResolvedCredential::new(
                        CredentialUsername::parse("administrator").map_err(|_| MockError::State)?,
                        String::from("secret").into(),
                    )))
                } else {
                    Ok(None)
                }
            })
        }
    }

    /// Deterministically holds one test's first read in flight until the
    /// test releases it: the armed read signals `reached` and then waits on
    /// `release`, so the test can pin one refresh inside its read while a
    /// second refresh is expected to wait at the endpoint-level gate.
    struct FirstReadBlock {
        armed: AtomicBool,
        reached: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl FirstReadBlock {
        fn new(
            reached: tokio::sync::oneshot::Sender<()>,
            release: tokio::sync::oneshot::Receiver<()>,
        ) -> Self {
            Self {
                armed: AtomicBool::new(true),
                reached: Mutex::new(Some(reached)),
                release: Mutex::new(Some(release)),
            }
        }
    }

    struct MockGateway {
        state: Arc<Mutex<MockState>>,
        read_succeeds: bool,
        first_read_block: Option<Arc<FirstReadBlock>>,
    }

    impl MockGateway {
        fn succeed(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                read_succeeds: true,
                first_read_block: None,
            }
        }

        fn fail_read(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                read_succeeds: false,
                first_read_block: None,
            }
        }

        /// Holds the first read of this gateway in flight until the test
        /// releases it.
        fn with_first_read_block(mut self, block: Arc<FirstReadBlock>) -> Self {
            self.first_read_block = Some(block);
            self
        }
    }

    impl RedfishDiscovery for MockGateway {
        type Error = MockError;

        fn probe_core_capabilities<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
            Box::pin(async move {
                lock_state(&self.state)?.events.push("discover");
                Ok(EndpointDiscovery::new(vec![
                    EndpointCapabilityObservation::new(
                        EndpointCapability::Systems,
                        CapabilityState::Supported,
                    ),
                ]))
            })
        }
    }

    impl CoreResourceReader for MockGateway {
        type Error = MockError;

        fn read_core_resources<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<crate::CoreResourceReadOutcome, Self::Error>> {
            let state = Arc::clone(&self.state);
            let read_succeeds = self.read_succeeds;
            let first_read_block = self.first_read_block.clone();
            Box::pin(async move {
                lock_state(&state)?.events.push("read");
                if let Some(block) = &first_read_block
                    && block.armed.swap(false, Ordering::SeqCst)
                {
                    if let Some(reached) =
                        block.reached.lock().map_err(|_| MockError::State)?.take()
                    {
                        let _ = reached.send(());
                    }
                    let release = block.release.lock().map_err(|_| MockError::State)?.take();
                    if let Some(release) = release {
                        let _ = release.await;
                    }
                }
                if !read_succeeds {
                    return Err(MockError::Read);
                }
                Ok(crate::CoreResourceReadOutcome::new(
                    vec![ResourceObservation::new(
                        ResourceFeature::ServiceRoot,
                        ResourceODataId::parse("/redfish/v1/").map_err(|_| MockError::State)?,
                        ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)
                            .map_err(|_| MockError::State)?,
                    )],
                    Vec::new(),
                ))
            })
        }
    }

    #[derive(Clone, Copy)]
    struct FixedClock(OffsetDateTime);

    impl Clock for FixedClock {
        fn now(&self) -> OffsetDateTime {
            self.0
        }
    }

    fn request(
        credential_id: CredentialId,
        trusted_at: OffsetDateTime,
    ) -> Result<OnboardEndpointRequest, Box<dyn Error>> {
        Ok(OnboardEndpointRequest::new(
            EndpointDisplayName::parse("Enrollment test BMC")?,
            TrustedEndpoint::new(
                EndpointAddress::parse("https://192.0.2.120")?,
                TlsTrust::PinnedCertificate {
                    certificate: TlsCertificate::from_der(b"enrollment certificate".to_vec())?,
                    trusted_at,
                },
            ),
            credential_id,
        ))
    }

    fn lock_state(state: &Mutex<MockState>) -> Result<MutexGuard<'_, MockState>, MockError> {
        state.lock().map_err(|_| MockError::State)
    }

    fn events(state: &Mutex<MockState>) -> Result<Vec<&'static str>, MockError> {
        Ok(lock_state(state)?.events.clone())
    }

    fn audit_events(state: &Mutex<MockState>) -> Result<Vec<AuditEvent>, MockError> {
        Ok(lock_state(state)?.audit_events.clone())
    }
}
