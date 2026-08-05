use std::{error::Error, fmt, future::Future, pin::Pin};

use rutilus_domain::{
    CredentialId, CredentialUsername, Endpoint, EndpointAddress, EndpointCapabilityObservation,
    EndpointDisplayName, EndpointId, EndpointTimelineError, TlsTrust,
};
use secrecy::SecretString;
use thiserror::Error;
use time::OffsetDateTime;

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
    address: EndpointAddress,
    trust: TlsTrust,
    credential_id: CredentialId,
}

impl OnboardEndpointRequest {
    #[must_use]
    pub fn new(
        display_name: EndpointDisplayName,
        address: EndpointAddress,
        trust: TlsTrust,
        credential_id: CredentialId,
    ) -> Self {
        Self {
            display_name,
            address,
            trust,
            credential_id,
        }
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
            address,
            trust,
            credential_id,
        } = request;
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
        CapabilityState, EndpointCapability, EndpointDisplayName, TlsCertificate,
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

    #[derive(Clone, Copy, Debug, Error)]
    enum MockError {
        #[error("mock event log is unavailable")]
        Events,
        #[error("mock gateway failure")]
        Gateway,
        #[error("mock repository failure")]
        Repository,
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
            EndpointAddress::parse("https://192.0.2.20")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"trusted certificate".to_vec())?,
                trusted_at,
            },
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
}
