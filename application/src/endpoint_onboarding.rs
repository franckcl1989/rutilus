use std::{error::Error, fmt, future::Future, pin::Pin};

use rutilus_domain::{
    AuditAction, AuditActor, AuditEvent, AuditFailure, AuditFailureVerification,
    AuditOperationContext, AuditOperationContextError, AuditOperationId, AuditParameterSummary,
    AuditProgress, AuditRedfishOperation, AuditSequence, AuditTarget, AuditTlsTrust, CredentialId,
    CredentialUsername, DeploymentPosture, Endpoint, EndpointAddress,
    EndpointCapabilityObservation, EndpointDisplayName, EndpointId, EndpointTimelineError,
    ProductPermission, TlsTrust,
};
use secrecy::SecretString;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{AuditEventWriter, AuditRecordError, TrustedEndpoint};

/// A sendable boundary operation tied to the lifetime of its collaborators.
pub type BoundaryFuture<'a, Output> = Pin<Box<dyn Future<Output = Output> + Send + 'a>>;

/// Resolves the explicitly selected active credential without trying fallbacks.
pub trait CredentialResolver: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn resolve(
        &self,
        credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>>;
}

/// Probes a trusted endpoint through the standard Redfish boundary.
pub trait RedfishDiscovery: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn probe_core_capabilities<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>>;
}

/// Persists a successfully discovered endpoint as one atomic aggregate.
pub trait DiscoveredEndpointRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn create_discovered_endpoint<'a>(
        &'a self,
        endpoint: Endpoint,
        observations: &'a [EndpointCapabilityObservation],
    ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>>;
}

/// Supplies testable wall-clock observations to application use cases.
pub trait Clock: Send + Sync {
    fn now(&self) -> OffsetDateTime;
}

impl<Resolver> CredentialResolver for &Resolver
where
    Resolver: CredentialResolver + ?Sized,
{
    type Error = Resolver::Error;

    fn resolve(
        &self,
        credential_id: CredentialId,
    ) -> BoundaryFuture<'_, Result<Option<ResolvedCredential>, Self::Error>> {
        Resolver::resolve(*self, credential_id)
    }
}

impl<Gateway> RedfishDiscovery for &Gateway
where
    Gateway: RedfishDiscovery + ?Sized,
{
    type Error = Gateway::Error;

    fn probe_core_capabilities<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
        Gateway::probe_core_capabilities(*self, address, trust, username, password)
    }
}

impl<Repository> DiscoveredEndpointRepository for &Repository
where
    Repository: DiscoveredEndpointRepository + ?Sized,
{
    type Error = Repository::Error;

    fn create_discovered_endpoint<'a>(
        &'a self,
        endpoint: Endpoint,
        observations: &'a [EndpointCapabilityObservation],
    ) -> BoundaryFuture<'a, Result<Endpoint, Self::Error>> {
        Repository::create_discovered_endpoint(*self, endpoint, observations)
    }
}

impl<Time> Clock for &Time
where
    Time: Clock + ?Sized,
{
    fn now(&self) -> OffsetDateTime {
        Time::now(*self)
    }
}

/// A selected username and its in-memory-only plaintext secret.
pub struct ResolvedCredential {
    username: CredentialUsername,
    password: SecretString,
}

impl ResolvedCredential {
    #[must_use]
    pub fn new(username: CredentialUsername, password: SecretString) -> Self {
        Self { username, password }
    }

    #[must_use]
    pub const fn username(&self) -> &CredentialUsername {
        &self.username
    }

    #[must_use]
    pub const fn password(&self) -> &SecretString {
        &self.password
    }
}

impl fmt::Debug for ResolvedCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResolvedCredential")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

/// A typed discovery projection returned by the Redfish boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndpointDiscovery {
    capabilities: Vec<EndpointCapabilityObservation>,
}

impl EndpointDiscovery {
    #[must_use]
    pub fn new(capabilities: Vec<EndpointCapabilityObservation>) -> Self {
        Self { capabilities }
    }

    #[must_use]
    pub fn capabilities(&self) -> &[EndpointCapabilityObservation] {
        &self.capabilities
    }

    #[must_use]
    pub fn into_capabilities(self) -> Vec<EndpointCapabilityObservation> {
        self.capabilities
    }
}

/// Validated input for the trusted, credentialed part of BMC onboarding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnboardEndpointRequest {
    display_name: EndpointDisplayName,
    target: TrustedEndpoint,
    credential_id: CredentialId,
}

impl OnboardEndpointRequest {
    #[must_use]
    pub fn new(
        display_name: EndpointDisplayName,
        target: TrustedEndpoint,
        credential_id: CredentialId,
    ) -> Self {
        Self {
            display_name,
            target,
            credential_id,
        }
    }

    /// Borrows the address-bound TLS decision without exposing credentials.
    #[must_use]
    pub const fn target(&self) -> &TrustedEndpoint {
        &self.target
    }

    /// Returns the explicitly selected credential identifier.
    #[must_use]
    pub const fn credential_id(&self) -> CredentialId {
        self.credential_id
    }
}

/// A new endpoint and the exact capability snapshot persisted with it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OnboardedEndpoint {
    endpoint: Endpoint,
    capabilities: Vec<EndpointCapabilityObservation>,
}

impl OnboardedEndpoint {
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    #[must_use]
    pub fn capabilities(&self) -> &[EndpointCapabilityObservation] {
        &self.capabilities
    }
}

/// Coordinates the post-trust portion of the documented BMC onboarding flow.
pub struct EndpointOnboarding<Repository, Credentials, Gateway, Time> {
    repository: Repository,
    credentials: Credentials,
    gateway: Gateway,
    clock: Time,
}

impl<Repository, Credentials, Gateway, Time>
    EndpointOnboarding<Repository, Credentials, Gateway, Time>
where
    Repository: DiscoveredEndpointRepository,
    Credentials: CredentialResolver,
    Gateway: RedfishDiscovery,
    Time: Clock,
{
    #[must_use]
    pub fn new(
        repository: Repository,
        credentials: Credentials,
        gateway: Gateway,
        clock: Time,
    ) -> Self {
        Self {
            repository,
            credentials,
            gateway,
            clock,
        }
    }

    /// Authenticates only after explicit trust exists, probes core features,
    /// and atomically persists the resulting endpoint and capability snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`OnboardEndpointError`] when credential resolution, Redfish
    /// discovery, endpoint timeline construction, or atomic persistence fails.
    pub async fn execute(
        &self,
        request: OnboardEndpointRequest,
    ) -> Result<
        OnboardedEndpoint,
        OnboardEndpointError<Credentials::Error, Gateway::Error, Repository::Error>,
    > {
        let OnboardEndpointRequest {
            display_name,
            target,
            credential_id,
        } = request;
        let (address, trust) = target.into_parts();
        let credential = self
            .credentials
            .resolve(credential_id)
            .await
            .map_err(OnboardEndpointError::Credential)?
            .ok_or(OnboardEndpointError::CredentialNotFound { credential_id })?;
        let discovery = self
            .gateway
            .probe_core_capabilities(
                &address,
                &trust,
                credential.username(),
                credential.password(),
            )
            .await
            .map_err(OnboardEndpointError::Discovery)?;
        let created_at = trust.established_at();
        let endpoint = Endpoint::try_new(
            EndpointId::generate(),
            display_name,
            address,
            trust,
            credential_id,
            created_at,
            self.clock.now(),
        )
        .map_err(OnboardEndpointError::InvalidTimeline)?;
        let capabilities = discovery.into_capabilities();
        let endpoint = self
            .repository
            .create_discovered_endpoint(endpoint, &capabilities)
            .await
            .map_err(OnboardEndpointError::Repository)?;
        Ok(OnboardedEndpoint {
            endpoint,
            capabilities,
        })
    }
}

/// Performs endpoint onboarding only inside a durable, append-only audit
/// lifecycle.
pub struct AuditedEndpointOnboarding<Repository, Credentials, Gateway, Audit, Time> {
    repository: Repository,
    credentials: Credentials,
    gateway: Gateway,
    audit: Audit,
    clock: Time,
    actor: AuditActor,
    origin: DeploymentPosture,
}

impl<Repository, Credentials, Gateway, Audit, Time>
    AuditedEndpointOnboarding<Repository, Credentials, Gateway, Audit, Time>
where
    Repository: DiscoveredEndpointRepository,
    Credentials: CredentialResolver,
    Gateway: RedfishDiscovery,
    Audit: AuditEventWriter,
    Time: Clock,
{
    #[must_use]
    pub fn new(
        repository: Repository,
        credentials: Credentials,
        gateway: Gateway,
        audit: Audit,
        clock: Time,
        actor: AuditActor,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            repository,
            credentials,
            gateway,
            audit,
            clock,
            actor,
            origin,
        }
    }

    /// Writes the start fact before any credential or network activity, then
    /// records either a typed failure or the Endpoint-created milestone and a
    /// confirmed terminal result.
    ///
    /// # Errors
    ///
    /// Returns [`AuditedOnboardEndpointError`] when audit preparation or
    /// writing fails, or when the wrapped onboarding use case fails. When both
    /// onboarding and its terminal audit append fail, both causes are retained.
    pub async fn execute(
        &self,
        request: OnboardEndpointRequest,
    ) -> Result<
        OnboardedEndpoint,
        AuditedOnboardEndpointError<
            Credentials::Error,
            Gateway::Error,
            Repository::Error,
            Audit::Error,
        >,
    > {
        let context =
            onboarding_audit_context(&request, self.actor, self.origin).map_err(|source| {
                AuditedOnboardEndpointError::Audit {
                    stage: OnboardingAuditStage::Start,
                    endpoint_id: None,
                    source: AuditRecordError::Context(source),
                }
            })?;
        let second =
            AuditSequence::FIRST
                .next()
                .map_err(|source| AuditedOnboardEndpointError::Audit {
                    stage: OnboardingAuditStage::Start,
                    endpoint_id: None,
                    source: AuditRecordError::Sequence(source),
                })?;
        let third = second
            .next()
            .map_err(|source| AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::Start,
                endpoint_id: None,
                source: AuditRecordError::Sequence(source),
            })?;
        let started_at = self.clock.now();
        let started = AuditEvent::started(context.clone(), started_at);
        self.audit
            .append_audit_event(&started)
            .await
            .map_err(|source| AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::Start,
                endpoint_id: None,
                source: AuditRecordError::Write(source),
            })?;

        let onboarding = EndpointOnboarding::new(
            &self.repository,
            &self.credentials,
            &self.gateway,
            &self.clock,
        );
        let onboarded = match onboarding.execute(request).await {
            Ok(onboarded) => onboarded,
            Err(source) => {
                return Err(self
                    .record_onboarding_failure(context, second, started_at, source)
                    .await);
            }
        };

        let endpoint_id = onboarded.endpoint().id();
        self.record_onboarding_success(context, second, third, started_at, endpoint_id)
            .await?;
        Ok(onboarded)
    }

    async fn record_onboarding_failure(
        &self,
        context: AuditOperationContext,
        sequence: AuditSequence,
        started_at: OffsetDateTime,
        onboarding: OnboardEndpointError<Credentials::Error, Gateway::Error, Repository::Error>,
    ) -> AuditedOnboardEndpointError<
        Credentials::Error,
        Gateway::Error,
        Repository::Error,
        Audit::Error,
    > {
        let (failure, verification) = classify_onboarding_failure(&onboarding);
        let failed = match AuditEvent::failed(
            context,
            sequence,
            failure,
            verification,
            at_or_after(started_at, self.clock.now()),
        ) {
            Ok(failed) => failed,
            Err(audit) => {
                return AuditedOnboardEndpointError::OnboardingAndAudit {
                    onboarding: Box::new(onboarding),
                    audit: AuditRecordError::Event(audit),
                };
            }
        };
        match self.audit.append_audit_event(&failed).await {
            Ok(()) => AuditedOnboardEndpointError::Onboarding(Box::new(onboarding)),
            Err(audit) => AuditedOnboardEndpointError::OnboardingAndAudit {
                onboarding: Box::new(onboarding),
                audit: AuditRecordError::Write(audit),
            },
        }
    }

    async fn record_onboarding_success(
        &self,
        context: AuditOperationContext,
        progress_sequence: AuditSequence,
        completion_sequence: AuditSequence,
        started_at: OffsetDateTime,
        endpoint_id: EndpointId,
    ) -> Result<
        (),
        AuditedOnboardEndpointError<
            Credentials::Error,
            Gateway::Error,
            Repository::Error,
            Audit::Error,
        >,
    > {
        let progress_at = at_or_after(started_at, self.clock.now());
        let progress = AuditEvent::progress(
            context.clone(),
            progress_sequence,
            AuditProgress::EndpointCreated,
            progress_at,
        )
        .map_err(|source| AuditedOnboardEndpointError::Audit {
            stage: OnboardingAuditStage::EndpointCreated,
            endpoint_id: Some(endpoint_id),
            source: AuditRecordError::Event(source),
        })?;
        self.audit
            .append_audit_event(&progress)
            .await
            .map_err(|source| AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::EndpointCreated,
                endpoint_id: Some(endpoint_id),
                source: AuditRecordError::Write(source),
            })?;

        let succeeded = AuditEvent::succeeded(
            context,
            completion_sequence,
            at_or_after(progress_at, self.clock.now()),
        )
        .map_err(|source| AuditedOnboardEndpointError::Audit {
            stage: OnboardingAuditStage::Completion,
            endpoint_id: Some(endpoint_id),
            source: AuditRecordError::Event(source),
        })?;
        self.audit
            .append_audit_event(&succeeded)
            .await
            .map_err(|source| AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::Completion,
                endpoint_id: Some(endpoint_id),
                source: AuditRecordError::Write(source),
            })?;
        Ok(())
    }
}

fn onboarding_audit_context(
    request: &OnboardEndpointRequest,
    actor: AuditActor,
    origin: DeploymentPosture,
) -> Result<AuditOperationContext, AuditOperationContextError> {
    let trust = match request.target().trust() {
        TlsTrust::SystemCa { .. } => AuditTlsTrust::SystemCa,
        TlsTrust::PinnedCertificate { .. } => AuditTlsTrust::PinnedCertificate,
    };
    AuditOperationContext::try_new(
        AuditOperationId::generate(),
        actor,
        origin,
        AuditTarget::EndpointAddress(request.target().address().clone()),
        AuditParameterSummary::EndpointEnrollment {
            credential_id: request.credential_id(),
            trust,
        },
        ProductPermission::ManageEndpoints,
        AuditAction::EnrollEndpoint,
        AuditRedfishOperation::ProbeCoreCapabilities,
    )
}

fn classify_onboarding_failure<CredentialError, DiscoveryError, RepositoryError>(
    failure: &OnboardEndpointError<CredentialError, DiscoveryError, RepositoryError>,
) -> (AuditFailure, AuditFailureVerification)
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    RepositoryError: Error + 'static,
{
    match failure {
        OnboardEndpointError::CredentialNotFound { .. } | OnboardEndpointError::Credential(_) => (
            AuditFailure::CredentialUnavailable,
            AuditFailureVerification::Rejected,
        ),
        OnboardEndpointError::Discovery(_) => (
            AuditFailure::RedfishDiscoveryFailed,
            AuditFailureVerification::Inconclusive,
        ),
        OnboardEndpointError::InvalidTimeline(_) | OnboardEndpointError::Repository(_) => (
            AuditFailure::EndpointPersistenceFailed,
            AuditFailureVerification::Rejected,
        ),
    }
}

fn at_or_after(previous: OffsetDateTime, observed: OffsetDateTime) -> OffsetDateTime {
    previous.max(observed)
}

/// The point in the onboarding audit lifecycle that could not be recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OnboardingAuditStage {
    Start,
    EndpointCreated,
    Completion,
}

impl fmt::Display for OnboardingAuditStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => formatter.write_str("start"),
            Self::EndpointCreated => formatter.write_str("Endpoint-created milestone"),
            Self::Completion => formatter.write_str("completion"),
        }
    }
}

/// A controlled failure while onboarding an endpoint under mandatory audit.
#[derive(Debug, Error)]
pub enum AuditedOnboardEndpointError<CredentialError, DiscoveryError, RepositoryError, AuditError>
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    RepositoryError: Error + 'static,
    AuditError: Error + 'static,
{
    #[error("endpoint onboarding audit {stage} failed before a reliable result could be returned")]
    Audit {
        stage: OnboardingAuditStage,
        endpoint_id: Option<EndpointId>,
        #[source]
        source: AuditRecordError<AuditError>,
    },
    #[error("audited endpoint onboarding failed: {0}")]
    Onboarding(
        #[source] Box<OnboardEndpointError<CredentialError, DiscoveryError, RepositoryError>>,
    ),
    #[error("endpoint onboarding failed and its terminal audit fact also failed: {audit}")]
    OnboardingAndAudit {
        #[source]
        onboarding: Box<OnboardEndpointError<CredentialError, DiscoveryError, RepositoryError>>,
        audit: AuditRecordError<AuditError>,
    },
}

impl<CredentialError, DiscoveryError, RepositoryError, AuditError>
    AuditedOnboardEndpointError<CredentialError, DiscoveryError, RepositoryError, AuditError>
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    RepositoryError: Error + 'static,
    AuditError: Error + 'static,
{
    /// Returns the stable Endpoint identifier when persistence already
    /// succeeded before an audit append failed.
    #[must_use]
    pub const fn persisted_endpoint_id(&self) -> Option<EndpointId> {
        match self {
            Self::Audit { endpoint_id, .. } => *endpoint_id,
            Self::Onboarding(_) | Self::OnboardingAndAudit { .. } => None,
        }
    }
}

/// A controlled failure while onboarding one trusted BMC endpoint.
#[derive(Debug, Error)]
pub enum OnboardEndpointError<CredentialError, DiscoveryError, RepositoryError>
where
    CredentialError: Error + 'static,
    DiscoveryError: Error + 'static,
    RepositoryError: Error + 'static,
{
    #[error("selected credential {credential_id} was not found")]
    CredentialNotFound { credential_id: CredentialId },
    #[error("failed to resolve the selected endpoint credential: {0}")]
    Credential(#[source] CredentialError),
    #[error("trusted Redfish endpoint discovery failed: {0}")]
    Discovery(#[source] DiscoveryError),
    #[error("endpoint timeline is invalid after discovery: {0}")]
    InvalidTimeline(#[source] EndpointTimelineError),
    #[error("failed to persist the discovered endpoint: {0}")]
    Repository(#[source] RepositoryError),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use rutilus_domain::{
        AuditOutcomeKind, CapabilityState, EndpointCapability, EndpointDisplayName, TlsCertificate,
    };
    use secrecy::SecretString;
    use time::Duration;

    use super::*;

    #[tokio::test]
    async fn resolves_credentials_then_probes_before_persisting() -> Result<(), Box<dyn Error>> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let trusted_at = OffsetDateTime::now_utc();
        let observed_at = trusted_at + Duration::SECOND;
        let credential_id = CredentialId::generate();
        let service = EndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&events)),
            MockCredentials::available(Arc::clone(&events)),
            MockGateway::succeed(Arc::clone(&events)),
            FixedClock(observed_at),
        );

        let result = service.execute(request(credential_id, trusted_at)?).await?;

        assert_eq!(result.endpoint().credential_id(), credential_id);
        assert_eq!(result.endpoint().created_at(), trusted_at);
        assert_eq!(result.endpoint().updated_at(), observed_at);
        assert_eq!(result.capabilities(), &expected_capabilities());
        assert_eq!(
            recorded_events(&events)?,
            ["credential", "gateway", "repository"]
        );
        let debug = format!("{:?}", resolved_credential()?);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("\"secret\""));
        Ok(())
    }

    #[tokio::test]
    async fn stops_before_network_when_the_selected_credential_is_missing()
    -> Result<(), Box<dyn Error>> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let trusted_at = OffsetDateTime::now_utc();
        let credential_id = CredentialId::generate();
        let service = EndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&events)),
            MockCredentials::missing(Arc::clone(&events)),
            MockGateway::succeed(Arc::clone(&events)),
            FixedClock(trusted_at),
        );

        assert!(matches!(
            service.execute(request(credential_id, trusted_at)?).await,
            Err(OnboardEndpointError::CredentialNotFound { credential_id: id })
                if id == credential_id
        ));
        assert_eq!(recorded_events(&events)?, ["credential"]);
        Ok(())
    }

    #[tokio::test]
    async fn discovery_or_repository_failure_never_reports_a_created_endpoint()
    -> Result<(), Box<dyn Error>> {
        let trusted_at = OffsetDateTime::now_utc();
        let credential_id = CredentialId::generate();
        let discovery_events = Arc::new(Mutex::new(Vec::new()));
        let discovery_failure = EndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&discovery_events)),
            MockCredentials::available(Arc::clone(&discovery_events)),
            MockGateway::fail(Arc::clone(&discovery_events)),
            FixedClock(trusted_at),
        );
        assert!(matches!(
            discovery_failure
                .execute(request(credential_id, trusted_at)?)
                .await,
            Err(OnboardEndpointError::Discovery(MockError::Gateway))
        ));
        assert_eq!(
            recorded_events(&discovery_events)?,
            ["credential", "gateway"]
        );

        let repository_events = Arc::new(Mutex::new(Vec::new()));
        let repository_failure = EndpointOnboarding::new(
            MockRepository::fail(Arc::clone(&repository_events)),
            MockCredentials::available(Arc::clone(&repository_events)),
            MockGateway::succeed(Arc::clone(&repository_events)),
            FixedClock(trusted_at),
        );
        assert!(matches!(
            repository_failure
                .execute(request(credential_id, trusted_at)?)
                .await,
            Err(OnboardEndpointError::Repository(MockError::Repository))
        ));
        assert_eq!(
            recorded_events(&repository_events)?,
            ["credential", "gateway", "repository"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn audited_onboarding_records_start_creation_and_confirmed_completion()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let trusted_at = OffsetDateTime::now_utc();
        let observed_at = trusted_at + Duration::SECOND;
        let credential_id = CredentialId::generate();
        let service = AuditedEndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockGateway::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
            FixedClock(observed_at),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
        );

        let onboarded = service.execute(request(credential_id, trusted_at)?).await?;

        assert_eq!(
            recorded_events(&lifecycle)?,
            [
                "audit",
                "credential",
                "gateway",
                "repository",
                "audit",
                "audit",
            ]
        );
        let audit = recorded_audit_events(&audit_state)?;
        assert_eq!(audit.len(), 3);
        assert_eq!(audit[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(
            audit[1].outcome().progress(),
            Some(AuditProgress::EndpointCreated)
        );
        assert_eq!(audit[2].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(audit[0].sequence(), AuditSequence::FIRST);
        assert_eq!(audit[1].sequence(), AuditSequence::FIRST.next()?);
        assert_eq!(audit[0].context(), audit[2].context());
        assert_eq!(
            audit[0].context().target(),
            &AuditTarget::EndpointAddress(onboarded.endpoint().address().clone())
        );
        assert!(matches!(
            audit[0].context().parameters(),
            AuditParameterSummary::EndpointEnrollment {
                credential_id: id,
                trust: AuditTlsTrust::PinnedCertificate,
            } if id == credential_id
        ));
        Ok(())
    }

    #[tokio::test]
    async fn audit_start_failure_prevents_credentials_and_redfish() -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let trusted_at = OffsetDateTime::now_utc();
        let service = AuditedEndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockGateway::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), audit_state, 1),
            FixedClock(trusted_at),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
        );

        let result = service
            .execute(request(CredentialId::generate(), trusted_at)?)
            .await;

        assert!(matches!(
            result,
            Err(AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::Start,
                endpoint_id: None,
                source: AuditRecordError::Write(MockError::Audit),
            })
        ));
        assert_eq!(recorded_events(&lifecycle)?, ["audit"]);
        Ok(())
    }

    #[tokio::test]
    async fn retains_business_and_audit_failures_when_terminal_append_fails()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let trusted_at = OffsetDateTime::now_utc();
        let credential_id = CredentialId::generate();
        let service = AuditedEndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&lifecycle)),
            MockCredentials::missing(Arc::clone(&lifecycle)),
            MockGateway::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), audit_state, 2),
            FixedClock(trusted_at),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
        );

        let result = service.execute(request(credential_id, trusted_at)?).await;

        assert!(matches!(
            result,
            Err(AuditedOnboardEndpointError::OnboardingAndAudit {
                onboarding,
                audit: AuditRecordError::Write(MockError::Audit),
            }) if matches!(
                *onboarding,
                OnboardEndpointError::CredentialNotFound { credential_id: id }
                    if id == credential_id
            )
        ));
        assert_eq!(
            recorded_events(&lifecycle)?,
            ["audit", "credential", "audit"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn records_typed_credential_failure_when_onboarding_is_rejected()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let trusted_at = OffsetDateTime::now_utc();
        let credential_id = CredentialId::generate();
        let service = AuditedEndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&lifecycle)),
            MockCredentials::missing(Arc::clone(&lifecycle)),
            MockGateway::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
            FixedClock(trusted_at),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
        );

        let result = service.execute(request(credential_id, trusted_at)?).await;

        assert!(matches!(
            result,
            Err(AuditedOnboardEndpointError::Onboarding(onboarding))
                if matches!(
                    *onboarding,
                    OnboardEndpointError::CredentialNotFound { credential_id: id }
                        if id == credential_id
                )
        ));
        let audit = recorded_audit_events(&audit_state)?;
        assert_eq!(audit.len(), 2);
        assert_eq!(
            audit[1].outcome().failure(),
            Some(AuditFailure::CredentialUnavailable)
        );
        assert_eq!(
            audit[1].outcome().verification(),
            Some(rutilus_domain::AuditVerification::Rejected)
        );
        assert_eq!(
            recorded_events(&lifecycle)?,
            ["audit", "credential", "audit"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_persisted_endpoint_when_creation_audit_append_fails()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let trusted_at = OffsetDateTime::now_utc();
        let service = AuditedEndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockGateway::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), audit_state, 2),
            FixedClock(trusted_at),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
        );

        let result = service
            .execute(request(CredentialId::generate(), trusted_at)?)
            .await;

        assert!(
            result
                .as_ref()
                .err()
                .and_then(AuditedOnboardEndpointError::persisted_endpoint_id)
                .is_some()
        );
        assert!(matches!(
            result,
            Err(AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::EndpointCreated,
                endpoint_id: Some(_),
                source: AuditRecordError::Write(MockError::Audit),
            })
        ));
        assert_eq!(
            recorded_events(&lifecycle)?,
            ["audit", "credential", "gateway", "repository", "audit"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_persisted_endpoint_when_completion_audit_append_fails()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let trusted_at = OffsetDateTime::now_utc();
        let service = AuditedEndpointOnboarding::new(
            MockRepository::succeed(Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockGateway::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), Arc::clone(&audit_state), 3),
            FixedClock(trusted_at),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
        );

        let result = service
            .execute(request(CredentialId::generate(), trusted_at)?)
            .await;

        assert!(
            result
                .as_ref()
                .err()
                .and_then(AuditedOnboardEndpointError::persisted_endpoint_id)
                .is_some()
        );
        assert!(matches!(
            result,
            Err(AuditedOnboardEndpointError::Audit {
                stage: OnboardingAuditStage::Completion,
                endpoint_id: Some(_),
                source: AuditRecordError::Write(MockError::Audit),
            })
        ));
        assert_eq!(recorded_audit_events(&audit_state)?.len(), 2);
        assert_eq!(
            recorded_events(&lifecycle)?,
            [
                "audit",
                "credential",
                "gateway",
                "repository",
                "audit",
                "audit",
            ]
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Error)]
    enum MockError {
        #[error("mock event log is unavailable")]
        Events,
        #[error("mock gateway failure")]
        Gateway,
        #[error("mock repository failure")]
        Repository,
        #[error("mock audit failure")]
        Audit,
    }

    #[derive(Default)]
    struct MockAuditState {
        attempts: usize,
        events: Vec<AuditEvent>,
    }

    struct MockAudit {
        lifecycle: Arc<Mutex<Vec<&'static str>>>,
        state: Arc<Mutex<MockAuditState>>,
        fail_on: Option<usize>,
    }

    impl MockAudit {
        fn succeed(
            lifecycle: Arc<Mutex<Vec<&'static str>>>,
            state: Arc<Mutex<MockAuditState>>,
        ) -> Self {
            Self {
                lifecycle,
                state,
                fail_on: None,
            }
        }

        fn fail_on(
            lifecycle: Arc<Mutex<Vec<&'static str>>>,
            state: Arc<Mutex<MockAuditState>>,
            attempt: usize,
        ) -> Self {
            Self {
                lifecycle,
                state,
                fail_on: Some(attempt),
            }
        }
    }

    impl AuditEventWriter for MockAudit {
        type Error = MockError;

        fn append_audit_event<'a>(
            &'a self,
            event: &'a AuditEvent,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                record(&self.lifecycle, "audit")?;
                let mut state = self.state.lock().map_err(|_| MockError::Events)?;
                state.attempts += 1;
                if self.fail_on == Some(state.attempts) {
                    return Err(MockError::Audit);
                }
                state.events.push(event.clone());
                Ok(())
            })
        }
    }

    struct MockCredentials {
        events: Arc<Mutex<Vec<&'static str>>>,
        available: bool,
    }

    impl MockCredentials {
        fn available(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                available: true,
            }
        }

        fn missing(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
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
                record(&self.events, "credential")?;
                if self.available {
                    Ok(Some(resolved_credential()?))
                } else {
                    Ok(None)
                }
            })
        }
    }

    struct MockGateway {
        events: Arc<Mutex<Vec<&'static str>>>,
        succeeds: bool,
    }

    impl MockGateway {
        fn succeed(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                succeeds: true,
            }
        }

        fn fail(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                succeeds: false,
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
                record(&self.events, "gateway")?;
                if self.succeeds {
                    Ok(EndpointDiscovery::new(expected_capabilities()))
                } else {
                    Err(MockError::Gateway)
                }
            })
        }
    }

    struct MockRepository {
        events: Arc<Mutex<Vec<&'static str>>>,
        succeeds: bool,
    }

    impl MockRepository {
        fn succeed(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                succeeds: true,
            }
        }

        fn fail(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events,
                succeeds: false,
            }
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
                record(&self.events, "repository")?;
                if self.succeeds {
                    Ok(endpoint)
                } else {
                    Err(MockError::Repository)
                }
            })
        }
    }

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
            EndpointDisplayName::parse("Rack A BMC")?,
            TrustedEndpoint::new(
                EndpointAddress::parse("https://192.0.2.20")?,
                TlsTrust::PinnedCertificate {
                    certificate: TlsCertificate::from_der(b"trusted certificate".to_vec())?,
                    trusted_at,
                },
            ),
            credential_id,
        ))
    }

    fn resolved_credential() -> Result<ResolvedCredential, MockError> {
        let username = CredentialUsername::parse("administrator").map_err(|_| MockError::Events)?;
        Ok(ResolvedCredential::new(
            username,
            String::from("secret").into(),
        ))
    }

    fn expected_capabilities() -> Vec<EndpointCapabilityObservation> {
        vec![EndpointCapabilityObservation::new(
            EndpointCapability::Systems,
            CapabilityState::Supported,
        )]
    }

    fn record(events: &Mutex<Vec<&'static str>>, event: &'static str) -> Result<(), MockError> {
        let mut events = events.lock().map_err(|_| MockError::Events)?;
        events.push(event);
        Ok(())
    }

    fn recorded_events(events: &Mutex<Vec<&'static str>>) -> Result<Vec<&'static str>, MockError> {
        events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| MockError::Events)
    }

    fn recorded_audit_events(state: &Mutex<MockAuditState>) -> Result<Vec<AuditEvent>, MockError> {
        state
            .lock()
            .map(|state| state.events.clone())
            .map_err(|_| MockError::Events)
    }
}
