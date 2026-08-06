use std::error::Error;

use rutilus_domain::{AuditActor, DeploymentPosture, EndpointId, ResourceSnapshot};
use thiserror::Error;

use crate::{
    AuditEventWriter, AuditedEndpointOnboarding, AuditedEndpointRefresh,
    AuditedEndpointRefreshError, AuditedOnboardEndpointError, BoundaryFuture,
    CapabilitySnapshotRepository, Clock, CoreResourceReader, CredentialResolver,
    DiscoveredEndpointRepository, EndpointRefreshRepository, OnboardEndpointRequest,
    OnboardedEndpoint, RedfishDiscovery,
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
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            repository,
            credentials,
            gateway,
            clock,
            actor,
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
    /// [`EndpointEnrollmentError::InitialRefresh`] when the first refresh does
    /// not commit, or
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
        let refresh = AuditedEndpointRefresh::new(
            &self.repository,
            &self.credentials,
            &self.gateway,
            &self.repository,
            &self.clock,
            self.actor,
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex, MutexGuard};

    use rutilus_domain::{
        AuditAction, AuditEvent, CapabilityState, CredentialId, CredentialUsername, Endpoint,
        EndpointAddress, EndpointCapability, EndpointCapabilityObservation, EndpointDisplayName,
        RefreshGeneration, ResourceFeature, ResourceId, ResourceODataId, ResourceSnapshotPayload,
        TlsCertificate, TlsTrust,
    };
    use secrecy::SecretString;
    use time::OffsetDateTime;

    use crate::{
        AuditRecordError, BoundaryFuture, EndpointDiscovery, EndpointRefreshError,
        OnboardEndpointError, ResolvedCredential, ResourceObservation, TrustedEndpoint,
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

    struct MockGateway {
        state: Arc<Mutex<MockState>>,
        read_succeeds: bool,
    }

    impl MockGateway {
        fn succeed(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                read_succeeds: true,
            }
        }

        fn fail_read(state: Arc<Mutex<MockState>>) -> Self {
            Self {
                state,
                read_succeeds: false,
            }
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
        ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
            Box::pin(async move {
                lock_state(&self.state)?.events.push("read");
                if !self.read_succeeds {
                    return Err(MockError::Read);
                }
                Ok(vec![ResourceObservation::new(
                    ResourceFeature::ServiceRoot,
                    ResourceODataId::parse("/redfish/v1/").map_err(|_| MockError::State)?,
                    ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)
                        .map_err(|_| MockError::State)?,
                )])
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
