use std::error::Error;

use rutilus_domain::{
    CredentialId, CredentialUsername, Endpoint, EndpointAddress, EndpointId, ResourceEtag,
    ResourceFeature, ResourceODataId, ResourceODataType, ResourceSnapshot, ResourceSnapshotPayload,
    TlsTrust,
};
use secrecy::SecretString;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{BoundaryFuture, Clock, CredentialResolver};

/// A typed Redfish resource projection returned by the BMC boundary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResourceObservation {
    feature: ResourceFeature,
    odata_id: ResourceODataId,
    odata_type: Option<ResourceODataType>,
    etag: Option<ResourceEtag>,
    payload: ResourceSnapshotPayload,
}

impl ResourceObservation {
    #[must_use]
    pub fn new(
        feature: ResourceFeature,
        odata_id: ResourceODataId,
        payload: ResourceSnapshotPayload,
    ) -> Self {
        Self {
            feature,
            odata_id,
            odata_type: None,
            etag: None,
            payload,
        }
    }

    #[must_use]
    pub fn with_odata_type(mut self, odata_type: ResourceODataType) -> Self {
        self.odata_type = Some(odata_type);
        self
    }

    #[must_use]
    pub fn with_etag(mut self, etag: ResourceEtag) -> Self {
        self.etag = Some(etag);
        self
    }

    #[must_use]
    pub const fn feature(&self) -> ResourceFeature {
        self.feature
    }

    #[must_use]
    pub const fn odata_id(&self) -> &ResourceODataId {
        &self.odata_id
    }

    #[must_use]
    pub const fn odata_type(&self) -> Option<&ResourceODataType> {
        self.odata_type.as_ref()
    }

    #[must_use]
    pub const fn etag(&self) -> Option<&ResourceEtag> {
        self.etag.as_ref()
    }

    #[must_use]
    pub const fn payload(&self) -> &ResourceSnapshotPayload {
        &self.payload
    }
}

/// Reads the complete 0.1 resource surface through typed Redfish navigation.
pub trait CoreResourceReader: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn read_core_resources<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>>;
}

/// Loads an endpoint and atomically commits one complete resource Generation.
pub trait EndpointRefreshRepository: Send + Sync {
    type Error: Error + Send + Sync + 'static;

    fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>>;

    fn commit_resource_generation<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [ResourceObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>>;
}

impl<Reader> CoreResourceReader for &Reader
where
    Reader: CoreResourceReader + ?Sized,
{
    type Error = Reader::Error;

    fn read_core_resources<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
        Reader::read_core_resources(*self, address, trust, username, password)
    }
}

impl<Repository> EndpointRefreshRepository for &Repository
where
    Repository: EndpointRefreshRepository + ?Sized,
{
    type Error = Repository::Error;

    fn find_endpoint(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
        Repository::find_endpoint(*self, endpoint_id)
    }

    fn commit_resource_generation<'a>(
        &'a self,
        endpoint_id: EndpointId,
        observations: &'a [ResourceObservation],
        observed_at: OffsetDateTime,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
        Repository::commit_resource_generation(*self, endpoint_id, observations, observed_at)
    }
}

/// Coordinates an authenticated, complete refresh of one managed endpoint.
pub struct EndpointRefresh<Repository, Credentials, Reader, Time> {
    repository: Repository,
    credentials: Credentials,
    reader: Reader,
    clock: Time,
}

impl<Repository, Credentials, Reader, Time> EndpointRefresh<Repository, Credentials, Reader, Time>
where
    Repository: EndpointRefreshRepository,
    Credentials: CredentialResolver,
    Reader: CoreResourceReader,
    Time: Clock,
{
    #[must_use]
    pub fn new(
        repository: Repository,
        credentials: Credentials,
        reader: Reader,
        clock: Time,
    ) -> Self {
        Self {
            repository,
            credentials,
            reader,
            clock,
        }
    }

    /// Loads the exact endpoint and selected credential, performs a typed core
    /// read, then commits all observations as one new Generation.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointRefreshError`] when endpoint lookup, credential
    /// resolution, typed Redfish reading, or Generation commit fails.
    pub async fn execute(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<
        Vec<ResourceSnapshot>,
        EndpointRefreshError<Repository::Error, Credentials::Error, Reader::Error>,
    > {
        let endpoint = self
            .repository
            .find_endpoint(endpoint_id)
            .await
            .map_err(EndpointRefreshError::LoadEndpoint)?
            .ok_or(EndpointRefreshError::EndpointNotFound { endpoint_id })?;
        let credential_id = endpoint.credential_id();
        let credential = self
            .credentials
            .resolve(credential_id)
            .await
            .map_err(EndpointRefreshError::Credential)?
            .ok_or(EndpointRefreshError::CredentialNotFound { credential_id })?;
        let observations = self
            .reader
            .read_core_resources(
                endpoint.address(),
                endpoint.trust(),
                credential.username(),
                credential.password(),
            )
            .await
            .map_err(EndpointRefreshError::Read)?;
        self.repository
            .commit_resource_generation(endpoint_id, &observations, self.clock.now())
            .await
            .map_err(EndpointRefreshError::Commit)
    }
}

/// A controlled failure while refreshing one managed endpoint.
#[derive(Debug, Error)]
pub enum EndpointRefreshError<RepositoryError, CredentialError, ReaderError>
where
    RepositoryError: Error + 'static,
    CredentialError: Error + 'static,
    ReaderError: Error + 'static,
{
    #[error("failed to load endpoint for refresh: {0}")]
    LoadEndpoint(#[source] RepositoryError),
    #[error("endpoint {endpoint_id} was not found")]
    EndpointNotFound { endpoint_id: EndpointId },
    #[error("failed to resolve the endpoint's selected credential: {0}")]
    Credential(#[source] CredentialError),
    #[error("selected credential {credential_id} was not found")]
    CredentialNotFound { credential_id: CredentialId },
    #[error("typed core resource read failed: {0}")]
    Read(#[source] ReaderError),
    #[error("failed to commit the complete resource Generation: {0}")]
    Commit(#[source] RepositoryError),
}

#[cfg(test)]
mod tests {
    use std::{
        fmt,
        sync::{Arc, Mutex},
    };

    use rutilus_domain::{
        CredentialId, CredentialUsername, EndpointDisplayName, RefreshGeneration, ResourceId,
        TlsCertificate,
    };
    use time::Duration;

    use crate::ResolvedCredential;

    use super::*;

    #[tokio::test]
    async fn loads_resolves_reads_then_commits_one_generation() -> Result<(), Box<dyn Error>> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let endpoint = endpoint()?;
        let observed_at = endpoint.updated_at() + Duration::SECOND;
        let service = EndpointRefresh::new(
            MockRepository::succeed(endpoint.clone(), Arc::clone(&events)),
            MockCredentials::available(Arc::clone(&events)),
            MockReader::succeed(Arc::clone(&events)),
            FixedClock(observed_at),
        );

        let snapshots = service.execute(endpoint.id()).await?;

        assert_eq!(recorded(&events)?, ["load", "credential", "read", "commit"]);
        assert_eq!(snapshots.len(), 2);
        assert!(
            snapshots
                .iter()
                .all(|snapshot| snapshot.observed_at() == observed_at)
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_endpoint_or_credential_stops_before_redfish() -> Result<(), Box<dyn Error>> {
        let events = Arc::new(Mutex::new(Vec::new()));
        let endpoint = endpoint()?;
        let missing_endpoint = EndpointRefresh::new(
            MockRepository::missing(Arc::clone(&events)),
            MockCredentials::available(Arc::clone(&events)),
            MockReader::succeed(Arc::clone(&events)),
            FixedClock(endpoint.updated_at()),
        );
        assert!(matches!(
            missing_endpoint.execute(endpoint.id()).await,
            Err(EndpointRefreshError::EndpointNotFound { .. })
        ));
        assert_eq!(recorded(&events)?, ["load"]);

        clear(&events)?;
        let credential_id = endpoint.credential_id();
        let missing_credential = EndpointRefresh::new(
            MockRepository::succeed(endpoint.clone(), Arc::clone(&events)),
            MockCredentials::missing(Arc::clone(&events)),
            MockReader::succeed(Arc::clone(&events)),
            FixedClock(endpoint.updated_at()),
        );
        assert!(matches!(
            missing_credential.execute(endpoint.id()).await,
            Err(EndpointRefreshError::CredentialNotFound { credential_id: id })
                if id == credential_id
        ));
        assert_eq!(recorded(&events)?, ["load", "credential"]);
        Ok(())
    }

    #[tokio::test]
    async fn read_or_commit_failure_never_reports_a_generation() -> Result<(), Box<dyn Error>> {
        let endpoint = endpoint()?;
        let read_events = Arc::new(Mutex::new(Vec::new()));
        let read_failure = EndpointRefresh::new(
            MockRepository::succeed(endpoint.clone(), Arc::clone(&read_events)),
            MockCredentials::available(Arc::clone(&read_events)),
            MockReader::fail(Arc::clone(&read_events)),
            FixedClock(endpoint.updated_at()),
        );
        assert!(matches!(
            read_failure.execute(endpoint.id()).await,
            Err(EndpointRefreshError::Read(MockError::Reader))
        ));
        assert_eq!(recorded(&read_events)?, ["load", "credential", "read"]);

        let commit_events = Arc::new(Mutex::new(Vec::new()));
        let commit_failure = EndpointRefresh::new(
            MockRepository::fail_commit(endpoint.clone(), Arc::clone(&commit_events)),
            MockCredentials::available(Arc::clone(&commit_events)),
            MockReader::succeed(Arc::clone(&commit_events)),
            FixedClock(endpoint.updated_at()),
        );
        assert!(matches!(
            commit_failure.execute(endpoint.id()).await,
            Err(EndpointRefreshError::Commit(MockError::Repository))
        ));
        assert_eq!(
            recorded(&commit_events)?,
            ["load", "credential", "read", "commit"]
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Repository,
        Credential,
        Reader,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock {self:?} failure")
        }
    }

    impl Error for MockError {}

    struct MockRepository {
        endpoint: Option<Endpoint>,
        events: Arc<Mutex<Vec<&'static str>>>,
        commit_succeeds: bool,
    }

    impl MockRepository {
        fn succeed(endpoint: Endpoint, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                endpoint: Some(endpoint),
                events,
                commit_succeeds: true,
            }
        }

        fn missing(events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                endpoint: None,
                events,
                commit_succeeds: true,
            }
        }

        fn fail_commit(endpoint: Endpoint, events: Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                endpoint: Some(endpoint),
                events,
                commit_succeeds: false,
            }
        }
    }

    impl EndpointRefreshRepository for MockRepository {
        type Error = MockError;

        fn find_endpoint(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async move {
                record(&self.events, "load")?;
                Ok(self.endpoint.clone())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            endpoint_id: EndpointId,
            observations: &'a [ResourceObservation],
            observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async move {
                record(&self.events, "commit")?;
                if !self.commit_succeeds {
                    return Err(MockError::Repository);
                }
                let generation = RefreshGeneration::new(1).map_err(|_| MockError::Repository)?;
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
                    Ok(Some(ResolvedCredential::new(
                        CredentialUsername::parse("administrator")
                            .map_err(|_| MockError::Credential)?,
                        String::from("secret").into(),
                    )))
                } else {
                    Ok(None)
                }
            })
        }
    }

    struct MockReader {
        events: Arc<Mutex<Vec<&'static str>>>,
        succeeds: bool,
    }

    impl MockReader {
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

    impl CoreResourceReader for MockReader {
        type Error = MockError;

        fn read_core_resources<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
            Box::pin(async move {
                record(&self.events, "read")?;
                if self.succeeds {
                    observations().map_err(|_| MockError::Reader)
                } else {
                    Err(MockError::Reader)
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

    fn endpoint() -> Result<Endpoint, Box<dyn Error>> {
        let now = OffsetDateTime::now_utc();
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Refresh test BMC")?,
            EndpointAddress::parse("https://192.0.2.100")?,
            TlsTrust::SystemCa {
                certificate: TlsCertificate::from_der(b"refresh certificate".to_vec())?,
                verified_at: now,
            },
            CredentialId::generate(),
            now,
            now,
        )?)
    }

    fn observations() -> Result<Vec<ResourceObservation>, Box<dyn Error>> {
        Ok(vec![
            ResourceObservation::new(
                ResourceFeature::ServiceRoot,
                ResourceODataId::parse("/redfish/v1/")?,
                ResourceSnapshotPayload::parse(r#"{"Name":"Root"}"#)?,
            ),
            ResourceObservation::new(
                ResourceFeature::Systems,
                ResourceODataId::parse("/redfish/v1/Systems/1")?,
                ResourceSnapshotPayload::parse(r#"{"Name":"System"}"#)?,
            ),
        ])
    }

    fn record(events: &Mutex<Vec<&'static str>>, value: &'static str) -> Result<(), MockError> {
        events.lock().map_err(|_| MockError::Events)?.push(value);
        Ok(())
    }

    fn recorded(events: &Mutex<Vec<&'static str>>) -> Result<Vec<&'static str>, MockError> {
        events
            .lock()
            .map(|events| events.clone())
            .map_err(|_| MockError::Events)
    }

    fn clear(events: &Mutex<Vec<&'static str>>) -> Result<(), MockError> {
        events.lock().map_err(|_| MockError::Events)?.clear();
        Ok(())
    }
}
