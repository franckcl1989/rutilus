use std::{error::Error, fmt};

use rutilus_domain::{
    AuditAction, AuditActor, AuditEvent, AuditFailure, AuditFailureVerification,
    AuditOperationContext, AuditOperationContextError, AuditOperationId, AuditParameterSummary,
    AuditRedfishOperation, AuditSequence, AuditTarget, CredentialId, CredentialUsername,
    DeploymentPosture, Endpoint, EndpointAddress, EndpointId, ProductPermission, ResourceEtag,
    ResourceFeature, ResourceODataId, ResourceODataType, ResourceSnapshot, ResourceSnapshotPayload,
    TlsTrust,
};
use secrecy::SecretString;
use thiserror::Error;
use time::OffsetDateTime;

use crate::{AuditEventWriter, AuditRecordError, BoundaryFuture, Clock, CredentialResolver};

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

/// Performs one complete endpoint refresh inside a mandatory append-only
/// audit lifecycle.
pub struct AuditedEndpointRefresh<Repository, Credentials, Reader, Audit, Time> {
    repository: Repository,
    credentials: Credentials,
    reader: Reader,
    audit: Audit,
    clock: Time,
    actor: AuditActor,
    origin: DeploymentPosture,
}

impl<Repository, Credentials, Reader, Audit, Time>
    AuditedEndpointRefresh<Repository, Credentials, Reader, Audit, Time>
where
    Repository: EndpointRefreshRepository,
    Credentials: CredentialResolver,
    Reader: CoreResourceReader,
    Audit: AuditEventWriter,
    Time: Clock,
{
    #[must_use]
    pub fn new(
        repository: Repository,
        credentials: Credentials,
        reader: Reader,
        audit: Audit,
        clock: Time,
        actor: AuditActor,
        origin: DeploymentPosture,
    ) -> Self {
        Self {
            repository,
            credentials,
            reader,
            audit,
            clock,
            actor,
            origin,
        }
    }

    /// Writes the start fact before endpoint lookup, then records a typed
    /// failure or confirms completion only after the resource Generation has
    /// committed.
    ///
    /// # Errors
    ///
    /// Returns [`AuditedEndpointRefreshError`] when audit preparation or
    /// writing fails, or when the wrapped refresh use case fails. Both causes
    /// are retained if a failed refresh cannot append its terminal fact.
    pub async fn execute(
        &self,
        endpoint_id: EndpointId,
    ) -> Result<
        Vec<ResourceSnapshot>,
        AuditedEndpointRefreshError<
            Repository::Error,
            Credentials::Error,
            Reader::Error,
            Audit::Error,
        >,
    > {
        let context =
            refresh_audit_context(endpoint_id, self.actor, self.origin).map_err(|source| {
                AuditedEndpointRefreshError::Audit {
                    stage: RefreshAuditStage::Start,
                    endpoint_id,
                    resources_committed: false,
                    source: AuditRecordError::Context(source),
                }
            })?;
        let terminal_sequence =
            AuditSequence::FIRST
                .next()
                .map_err(|source| AuditedEndpointRefreshError::Audit {
                    stage: RefreshAuditStage::Start,
                    endpoint_id,
                    resources_committed: false,
                    source: AuditRecordError::Sequence(source),
                })?;
        let started_at = self.clock.now();
        let started = AuditEvent::started(context.clone(), started_at);
        self.audit
            .append_audit_event(&started)
            .await
            .map_err(|source| AuditedEndpointRefreshError::Audit {
                stage: RefreshAuditStage::Start,
                endpoint_id,
                resources_committed: false,
                source: AuditRecordError::Write(source),
            })?;

        let refresh = EndpointRefresh::new(
            &self.repository,
            &self.credentials,
            &self.reader,
            &self.clock,
        );
        let snapshots = match refresh.execute(endpoint_id).await {
            Ok(snapshots) => snapshots,
            Err(source) => {
                return Err(self
                    .record_refresh_failure(
                        context,
                        terminal_sequence,
                        started_at,
                        endpoint_id,
                        source,
                    )
                    .await);
            }
        };
        self.record_refresh_success(context, terminal_sequence, started_at, endpoint_id)
            .await?;
        Ok(snapshots)
    }

    async fn record_refresh_failure(
        &self,
        context: AuditOperationContext,
        sequence: AuditSequence,
        started_at: OffsetDateTime,
        endpoint_id: EndpointId,
        refresh: EndpointRefreshError<Repository::Error, Credentials::Error, Reader::Error>,
    ) -> AuditedEndpointRefreshError<
        Repository::Error,
        Credentials::Error,
        Reader::Error,
        Audit::Error,
    > {
        let (failure, verification) = classify_refresh_failure(&refresh);
        let failed = match AuditEvent::failed(
            context,
            sequence,
            failure,
            verification,
            at_or_after(started_at, self.clock.now()),
        ) {
            Ok(failed) => failed,
            Err(audit) => {
                return AuditedEndpointRefreshError::RefreshAndAudit {
                    endpoint_id,
                    refresh: Box::new(refresh),
                    audit: AuditRecordError::Event(audit),
                };
            }
        };
        match self.audit.append_audit_event(&failed).await {
            Ok(()) => AuditedEndpointRefreshError::Refresh {
                endpoint_id,
                source: Box::new(refresh),
            },
            Err(audit) => AuditedEndpointRefreshError::RefreshAndAudit {
                endpoint_id,
                refresh: Box::new(refresh),
                audit: AuditRecordError::Write(audit),
            },
        }
    }

    async fn record_refresh_success(
        &self,
        context: AuditOperationContext,
        sequence: AuditSequence,
        started_at: OffsetDateTime,
        endpoint_id: EndpointId,
    ) -> Result<
        (),
        AuditedEndpointRefreshError<
            Repository::Error,
            Credentials::Error,
            Reader::Error,
            Audit::Error,
        >,
    > {
        let succeeded =
            AuditEvent::succeeded(context, sequence, at_or_after(started_at, self.clock.now()))
                .map_err(|source| AuditedEndpointRefreshError::Audit {
                    stage: RefreshAuditStage::Completion,
                    endpoint_id,
                    resources_committed: true,
                    source: AuditRecordError::Event(source),
                })?;
        self.audit
            .append_audit_event(&succeeded)
            .await
            .map_err(|source| AuditedEndpointRefreshError::Audit {
                stage: RefreshAuditStage::Completion,
                endpoint_id,
                resources_committed: true,
                source: AuditRecordError::Write(source),
            })
    }
}

fn refresh_audit_context(
    endpoint_id: EndpointId,
    actor: AuditActor,
    origin: DeploymentPosture,
) -> Result<AuditOperationContext, AuditOperationContextError> {
    AuditOperationContext::try_new(
        AuditOperationId::generate(),
        actor,
        origin,
        AuditTarget::Endpoint(endpoint_id),
        AuditParameterSummary::EndpointRefresh,
        ProductPermission::RefreshEndpoints,
        AuditAction::RefreshEndpoint,
        AuditRedfishOperation::ReadCoreResources,
    )
}

fn classify_refresh_failure<RepositoryError, CredentialError, ReaderError>(
    failure: &EndpointRefreshError<RepositoryError, CredentialError, ReaderError>,
) -> (AuditFailure, AuditFailureVerification)
where
    RepositoryError: Error + 'static,
    CredentialError: Error + 'static,
    ReaderError: Error + 'static,
{
    match failure {
        EndpointRefreshError::LoadEndpoint(_) | EndpointRefreshError::EndpointNotFound { .. } => (
            AuditFailure::EndpointPersistenceFailed,
            AuditFailureVerification::Rejected,
        ),
        EndpointRefreshError::Credential(_) | EndpointRefreshError::CredentialNotFound { .. } => (
            AuditFailure::CredentialUnavailable,
            AuditFailureVerification::Rejected,
        ),
        EndpointRefreshError::Read(_) => (
            AuditFailure::CoreResourceReadFailed,
            AuditFailureVerification::Inconclusive,
        ),
        EndpointRefreshError::Commit(_) => (
            AuditFailure::SnapshotPersistenceFailed,
            AuditFailureVerification::Inconclusive,
        ),
    }
}

fn at_or_after(previous: OffsetDateTime, observed: OffsetDateTime) -> OffsetDateTime {
    previous.max(observed)
}

/// The point in the refresh audit lifecycle that could not be recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefreshAuditStage {
    Start,
    Completion,
}

impl fmt::Display for RefreshAuditStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => formatter.write_str("start"),
            Self::Completion => formatter.write_str("completion"),
        }
    }
}

/// A controlled failure while refreshing an endpoint under mandatory audit.
#[derive(Debug, Error)]
pub enum AuditedEndpointRefreshError<RepositoryError, CredentialError, ReaderError, AuditError>
where
    RepositoryError: Error + 'static,
    CredentialError: Error + 'static,
    ReaderError: Error + 'static,
    AuditError: Error + 'static,
{
    #[error("endpoint {endpoint_id} refresh audit {stage} failed")]
    Audit {
        stage: RefreshAuditStage,
        endpoint_id: EndpointId,
        resources_committed: bool,
        #[source]
        source: AuditRecordError<AuditError>,
    },
    #[error("audited endpoint {endpoint_id} refresh failed: {source}")]
    Refresh {
        endpoint_id: EndpointId,
        #[source]
        source: Box<EndpointRefreshError<RepositoryError, CredentialError, ReaderError>>,
    },
    #[error(
        "endpoint {endpoint_id} refresh failed and its terminal audit fact also failed: {audit}"
    )]
    RefreshAndAudit {
        endpoint_id: EndpointId,
        #[source]
        refresh: Box<EndpointRefreshError<RepositoryError, CredentialError, ReaderError>>,
        audit: AuditRecordError<AuditError>,
    },
}

impl<RepositoryError, CredentialError, ReaderError, AuditError>
    AuditedEndpointRefreshError<RepositoryError, CredentialError, ReaderError, AuditError>
where
    RepositoryError: Error + 'static,
    CredentialError: Error + 'static,
    ReaderError: Error + 'static,
    AuditError: Error + 'static,
{
    /// Reports whether the resource Generation committed before audit
    /// finalization failed.
    #[must_use]
    pub const fn resources_committed(&self) -> bool {
        matches!(
            self,
            Self::Audit {
                resources_committed: true,
                ..
            }
        )
    }

    /// Returns the stable Endpoint targeted by this refresh attempt.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        match self {
            Self::Audit { endpoint_id, .. }
            | Self::Refresh { endpoint_id, .. }
            | Self::RefreshAndAudit { endpoint_id, .. } => *endpoint_id,
        }
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
        AuditOutcomeKind, AuditVerification, CredentialId, CredentialUsername, EndpointDisplayName,
        RefreshGeneration, ResourceId, TlsCertificate,
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

    #[tokio::test]
    async fn audited_refresh_records_start_and_confirmed_generation_commit()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let service = AuditedEndpointRefresh::new(
            MockRepository::succeed(endpoint, Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::System,
            DeploymentPosture::Site,
        );

        let snapshots = service.execute(endpoint_id).await?;

        assert_eq!(snapshots.len(), 2);
        assert_eq!(
            recorded(&lifecycle)?,
            ["audit", "load", "credential", "read", "commit", "audit"]
        );
        let audit = recorded_audit_events(&audit_state)?;
        assert_eq!(audit.len(), 2);
        assert_eq!(audit[0].outcome().kind(), AuditOutcomeKind::Started);
        assert_eq!(audit[1].outcome().kind(), AuditOutcomeKind::Succeeded);
        assert_eq!(audit[0].context(), audit[1].context());
        assert_eq!(
            audit[0].context().target(),
            &AuditTarget::Endpoint(endpoint_id)
        );
        assert_eq!(
            audit[0].context().redfish_operation(),
            AuditRedfishOperation::ReadCoreResources
        );
        Ok(())
    }

    #[tokio::test]
    async fn refresh_audit_start_failure_prevents_endpoint_lookup() -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let service = AuditedEndpointRefresh::new(
            MockRepository::succeed(endpoint, Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), audit_state, 1),
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::System,
            DeploymentPosture::Site,
        );

        let result = service.execute(endpoint_id).await;

        assert!(matches!(
            result,
            Err(AuditedEndpointRefreshError::Audit {
                stage: RefreshAuditStage::Start,
                endpoint_id: id,
                resources_committed: false,
                source: AuditRecordError::Write(MockError::Audit),
            }) if id == endpoint_id
        ));
        assert_eq!(recorded(&lifecycle)?, ["audit"]);
        Ok(())
    }

    #[tokio::test]
    async fn audited_refresh_records_typed_inconclusive_read_failure() -> Result<(), Box<dyn Error>>
    {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let service = AuditedEndpointRefresh::new(
            MockRepository::succeed(endpoint, Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::fail(Arc::clone(&lifecycle)),
            MockAudit::succeed(Arc::clone(&lifecycle), Arc::clone(&audit_state)),
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::System,
            DeploymentPosture::Site,
        );

        let result = service.execute(endpoint_id).await;

        assert!(matches!(
            result,
            Err(AuditedEndpointRefreshError::Refresh {
                endpoint_id: id,
                source,
            }) if id == endpoint_id
                && matches!(*source, EndpointRefreshError::Read(MockError::Reader))
        ));
        let audit = recorded_audit_events(&audit_state)?;
        assert_eq!(audit.len(), 2);
        assert_eq!(
            audit[1].outcome().failure(),
            Some(AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(
            audit[1].outcome().verification(),
            Some(AuditVerification::Inconclusive)
        );
        assert_eq!(
            recorded(&lifecycle)?,
            ["audit", "load", "credential", "read", "audit"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn retains_refresh_and_audit_failures_when_terminal_append_fails()
    -> Result<(), Box<dyn Error>> {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let service = AuditedEndpointRefresh::new(
            MockRepository::succeed(endpoint, Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::fail(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), audit_state, 2),
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::System,
            DeploymentPosture::Site,
        );

        let result = service.execute(endpoint_id).await;

        assert!(matches!(
            result,
            Err(AuditedEndpointRefreshError::RefreshAndAudit {
                endpoint_id: id,
                refresh,
                audit: AuditRecordError::Write(MockError::Audit),
            }) if id == endpoint_id
                && matches!(*refresh, EndpointRefreshError::Read(MockError::Reader))
        ));
        assert_eq!(
            recorded(&lifecycle)?,
            ["audit", "load", "credential", "read", "audit"]
        );
        Ok(())
    }

    #[tokio::test]
    async fn reports_committed_generation_when_completion_audit_fails() -> Result<(), Box<dyn Error>>
    {
        let lifecycle = Arc::new(Mutex::new(Vec::new()));
        let audit_state = Arc::new(Mutex::new(MockAuditState::default()));
        let endpoint = endpoint()?;
        let endpoint_id = endpoint.id();
        let service = AuditedEndpointRefresh::new(
            MockRepository::succeed(endpoint, Arc::clone(&lifecycle)),
            MockCredentials::available(Arc::clone(&lifecycle)),
            MockReader::succeed(Arc::clone(&lifecycle)),
            MockAudit::fail_on(Arc::clone(&lifecycle), Arc::clone(&audit_state), 2),
            FixedClock(OffsetDateTime::now_utc()),
            AuditActor::System,
            DeploymentPosture::Site,
        );

        let result = service.execute(endpoint_id).await;

        assert!(result.as_ref().err().is_some_and(|error| {
            error.endpoint_id() == endpoint_id && error.resources_committed()
        }));
        assert!(matches!(
            result,
            Err(AuditedEndpointRefreshError::Audit {
                stage: RefreshAuditStage::Completion,
                endpoint_id: id,
                resources_committed: true,
                source: AuditRecordError::Write(MockError::Audit),
            }) if id == endpoint_id
        ));
        assert_eq!(recorded_audit_events(&audit_state)?.len(), 1);
        assert_eq!(
            recorded(&lifecycle)?,
            ["audit", "load", "credential", "read", "commit", "audit"]
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Events,
        Repository,
        Credential,
        Reader,
        Audit,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "mock {self:?} failure")
        }
    }

    impl Error for MockError {}

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

    fn recorded_audit_events(state: &Mutex<MockAuditState>) -> Result<Vec<AuditEvent>, MockError> {
        state
            .lock()
            .map(|state| state.events.clone())
            .map_err(|_| MockError::Events)
    }
}
