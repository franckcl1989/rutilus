use std::error::Error as StdError;

use nv_redfish::core::ODataId;
use rutilus_application::{
    BoundaryFuture, CommandExecutor, CommandOutcome, CommandVerifier, CoreResourceReader,
    CredentialResolver, DispatchVerdict, DispatchVerdictClassifier, EndpointDiscovery,
    EndpointRefreshRepository, RedfishDiscovery, ResourceObservation, SystemCaEvaluation,
    TaskObservation as ApplicationTaskObservation, TaskReader, TlsIdentityObservation,
    TlsIdentityProbe, VerificationVerdict,
};
use rutilus_domain::{
    CredentialUsername, EndpointAddress, EndpointId, RedfishCommand, ResourceODataId,
    ResourceODataIdError, TlsTrust,
};
use rutilus_operation_engine::{RemoteTaskState, TaskUri, TaskUriError};
use secrecy::SecretString;
use thiserror::Error;

use crate::{
    CommandExecutionError, CommandExecutionOutcome, CommandVerificationError,
    CommandVerificationOutcome, CoreResourceReadError, RedfishGateway, RedfishServiceRootError,
    SystemCaStatus, TaskMessageObservation, TaskObservation, TaskReadError, TlsProbeError,
};

impl TlsIdentityProbe for RedfishGateway {
    type Error = TlsProbeError;

    fn observe<'a>(
        &'a self,
        address: &'a EndpointAddress,
    ) -> BoundaryFuture<'a, Result<TlsIdentityObservation, Self::Error>> {
        Box::pin(async move {
            let observation = RedfishGateway::observe_tls(self, address).await?;
            let (certificate, system_ca_status) = observation.into_parts();
            let system_ca = match system_ca_status {
                SystemCaStatus::Verified => SystemCaEvaluation::Verified,
                SystemCaStatus::Rejected => SystemCaEvaluation::Rejected,
            };
            Ok(TlsIdentityObservation::new(certificate, system_ca))
        })
    }
}

impl RedfishDiscovery for RedfishGateway {
    type Error = RedfishServiceRootError;

    fn probe_core_capabilities<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<EndpointDiscovery, Self::Error>> {
        Box::pin(async move {
            let discovery =
                RedfishGateway::probe_core_capabilities(self, address, trust, username, password)
                    .await?;
            Ok(EndpointDiscovery::new(discovery.capabilities().to_vec()))
        })
    }
}

impl CoreResourceReader for RedfishGateway {
    type Error = CoreResourceReadError;

    fn read_core_resources<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
    ) -> BoundaryFuture<'a, Result<Vec<ResourceObservation>, Self::Error>> {
        Box::pin(async move {
            let projections =
                RedfishGateway::read_core_resources(self, address, trust, username, password)
                    .await?;
            Ok(projections
                .into_iter()
                .map(|projection| {
                    let mut observation = ResourceObservation::new(
                        projection.feature(),
                        projection.odata_id().clone(),
                        projection.payload().clone(),
                    );
                    if let Some(etag) = projection.etag() {
                        observation = observation.with_etag(etag.clone());
                    }
                    observation
                })
                .collect())
        })
    }
}

/// The Redfish gateway surface the command executor delegates to.
///
/// The seam exists so the boundary mappings — dispatch verdicts,
/// verification verdicts, and the Task disappearance signal — are
/// unit-testable against a fake gateway instead of a live BMC. The concrete
/// [`RedfishGateway`] implements it by forwarding to its inherent methods,
/// and the composition root passes the concrete gateway.
pub trait CommandGateway: Send + Sync {
    /// Executes one typed write command (§13.3 step 7).
    fn execute_command<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandExecutionOutcome, CommandExecutionError>>;

    /// Re-reads the target of one accepted write (§13.3 steps 9–10).
    fn verify_command<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandVerificationOutcome, CommandVerificationError>>;

    /// Reads one asynchronous Task resource by its identifier (§13.6).
    fn read_task<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
        task_uri: &'a ResourceODataId,
    ) -> BoundaryFuture<'a, Result<TaskObservation, TaskReadError>>;
}

impl CommandGateway for RedfishGateway {
    fn execute_command<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandExecutionOutcome, CommandExecutionError>> {
        Box::pin(async move {
            RedfishGateway::execute_command(self, address, trust, username, password, command).await
        })
    }

    fn verify_command<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandVerificationOutcome, CommandVerificationError>> {
        Box::pin(async move {
            RedfishGateway::verify_command(self, address, trust, username, password, command).await
        })
    }

    fn read_task<'a>(
        &'a self,
        address: &'a EndpointAddress,
        trust: &'a TlsTrust,
        username: &'a CredentialUsername,
        password: &'a SecretString,
        task_uri: &'a ResourceODataId,
    ) -> BoundaryFuture<'a, Result<TaskObservation, TaskReadError>> {
        Box::pin(async move {
            RedfishGateway::read_task(self, address, trust, username, password, task_uri).await
        })
    }
}

/// The application-boundary write dispatcher and Task reader (§13.3 step 7,
/// §13.6).
///
/// [`CommandExecutor`], [`CommandVerifier`], and [`TaskReader`] resolve the
/// endpoint row (address, TLS trust, credential) from the endpoint id and
/// delegate the typed work to [`CommandGateway`], so the operation scheduler
/// never sees credentials, addresses, or `nv-redfish` types (design §7.2).
/// The endpoint lookup reuses the refresh repository's `find_endpoint` — the
/// only application boundary that resolves an endpoint by id — and the
/// credential lookup reuses the onboarding credential resolver. The gateway
/// is a generic parameter so the boundary mappings are testable against a
/// fake gateway; production passes the concrete [`RedfishGateway`].
pub struct RedfishCommandExecutor<Gateway, Repository, Credentials> {
    gateway: Gateway,
    endpoints: Repository,
    credentials: Credentials,
}

impl<Gateway, Repository, Credentials> RedfishCommandExecutor<Gateway, Repository, Credentials> {
    /// Binds the gateway to the endpoint and credential lookups it resolves
    /// per dispatch.
    #[must_use]
    pub const fn new(gateway: Gateway, endpoints: Repository, credentials: Credentials) -> Self {
        Self {
            gateway,
            endpoints,
            credentials,
        }
    }
}

impl<Gateway, Repository, Credentials> CommandExecutor
    for RedfishCommandExecutor<Gateway, Repository, Credentials>
where
    Gateway: CommandGateway,
    Repository: EndpointRefreshRepository,
    Credentials: CredentialResolver,
{
    type Error = CommandDispatchError;

    fn execute<'a>(
        &'a self,
        endpoint_id: EndpointId,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<CommandOutcome, Self::Error>> {
        Box::pin(async move {
            let endpoint = match self.endpoints.find_endpoint(endpoint_id).await {
                Ok(Some(endpoint)) => endpoint,
                Ok(None) => return Err(CommandDispatchError::EndpointUnknown),
                Err(source) => {
                    return Err(CommandDispatchError::EndpointResolution(Box::new(source)));
                }
            };
            let credential = match self.credentials.resolve(endpoint.credential_id()).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return Err(CommandDispatchError::CredentialUnknown),
                Err(source) => {
                    return Err(CommandDispatchError::CredentialResolution(Box::new(source)));
                }
            };
            match self
                .gateway
                .execute_command(
                    endpoint.address(),
                    endpoint.trust(),
                    credential.username(),
                    credential.password(),
                    command,
                )
                .await
            {
                Ok(CommandExecutionOutcome::Accepted) => Ok(CommandOutcome::Accepted),
                // Every provable rejection maps onto the application's
                // `Rejected` outcome; the verdict class is only consulted
                // for dispatch failures.
                Err(CommandExecutionError::Rejected(_)) => Ok(CommandOutcome::Rejected),
                // A `202` acceptance surfaces as the application's
                // `AsyncTaskAccepted` outcome so the scheduler persists the
                // Task and moves the operation to `WaitingRemote` (§13.6).
                Err(CommandExecutionError::AsyncTaskAccepted { task_location }) => {
                    map_async_task_outcome(&task_location)
                }
                Err(source) => Err(CommandDispatchError::Dispatch(source)),
            }
        })
    }
}

/// Maps a `202` Task acceptance onto the application's async outcome.
///
/// The `Location` value is an exact identifier validated before it reaches
/// the boundary — the BMC's own Task URI, never a vendor URL the product
/// follows (§15.6) — and is re-validated as a [`TaskUri`] so only a safely
/// persistable identifier is accepted. An unrepresentable value is an
/// outcome-unknown failure: the BMC accepted the write, but the product
/// cannot track the Task that would prove its result (§13.5).
fn map_async_task_outcome(task_location: &ODataId) -> Result<CommandOutcome, CommandDispatchError> {
    match TaskUri::parse(&task_location.to_string()) {
        Ok(task_uri) => Ok(CommandOutcome::AsyncTaskAccepted {
            task_location: task_uri,
        }),
        Err(source) => Err(CommandDispatchError::AsyncTaskUriInvalid(source)),
    }
}

/// A controlled failure while dispatching one command at the application
/// boundary.
///
/// The §13.5 verdict classification lives here so the operation scheduler
/// never interprets opaque gateway errors: endpoint and credential lookup
/// failures prove the write was never dispatched, and a gateway failure
/// keeps the gateway's own outcome-unknown classification (the gateway error
/// distinguishes "provably refused or never dispatched" from "the BMC may
/// already have applied the write").
#[derive(Debug, Error)]
pub enum CommandDispatchError {
    #[error("the command endpoint could not be resolved: {0}")]
    EndpointResolution(#[source] Box<dyn StdError + Send + Sync>),
    #[error("the command endpoint is not managed")]
    EndpointUnknown,
    #[error("the command credential could not be resolved: {0}")]
    CredentialResolution(#[source] Box<dyn StdError + Send + Sync>),
    #[error("the command credential is not available")]
    CredentialUnknown,
    #[error("the Redfish write dispatch failed: {0}")]
    Dispatch(#[source] CommandExecutionError),
    #[error("the accepted Task URI cannot be represented safely: {0}")]
    AsyncTaskUriInvalid(#[source] TaskUriError),
}

impl DispatchVerdictClassifier for CommandDispatchError {
    fn verdict(&self) -> DispatchVerdict {
        match self {
            Self::EndpointResolution(_)
            | Self::EndpointUnknown
            | Self::CredentialResolution(_)
            | Self::CredentialUnknown => DispatchVerdict::NotExecuted,
            // A `202` acceptance whose `Location` cannot be represented is
            // outcome-unknown: the BMC accepted the write, and only the Task
            // could prove its result (§13.5).
            Self::AsyncTaskUriInvalid(_) => DispatchVerdict::OutcomeUnknown,
            Self::Dispatch(source) => {
                if source.outcome_is_unknown() {
                    DispatchVerdict::OutcomeUnknown
                } else {
                    DispatchVerdict::NotExecuted
                }
            }
        }
    }
}

impl<Gateway, Repository, Credentials> CommandVerifier
    for RedfishCommandExecutor<Gateway, Repository, Credentials>
where
    Gateway: CommandGateway,
    Repository: EndpointRefreshRepository,
    Credentials: CredentialResolver,
{
    type Error = CommandVerifyError;

    fn verify<'a>(
        &'a self,
        endpoint_id: EndpointId,
        command: &'a RedfishCommand,
    ) -> BoundaryFuture<'a, Result<VerificationVerdict, Self::Error>> {
        Box::pin(async move {
            let endpoint = match self.endpoints.find_endpoint(endpoint_id).await {
                Ok(Some(endpoint)) => endpoint,
                Ok(None) => return Err(CommandVerifyError::EndpointUnknown),
                Err(source) => {
                    return Err(CommandVerifyError::EndpointResolution(Box::new(source)));
                }
            };
            let credential = match self.credentials.resolve(endpoint.credential_id()).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return Err(CommandVerifyError::CredentialUnknown),
                Err(source) => {
                    return Err(CommandVerifyError::CredentialResolution(Box::new(source)));
                }
            };
            match self
                .gateway
                .verify_command(
                    endpoint.address(),
                    endpoint.trust(),
                    credential.username(),
                    credential.password(),
                    command,
                )
                .await
            {
                Ok(CommandVerificationOutcome::Confirmed) => Ok(VerificationVerdict::Confirmed),
                Ok(CommandVerificationOutcome::Mismatched) => Ok(VerificationVerdict::Mismatched),
                Err(source) => Err(CommandVerifyError::ReRead(source)),
            }
        })
    }
}

/// A controlled failure while verifying one accepted command at the
/// application boundary.
///
/// The endpoint and credential lookup variants mirror [`CommandDispatchError`]:
/// both boundaries resolve the same endpoint row, and both lookup failures
/// prove the write was never dispatched. The re-read failure needs no §13.5
/// verdict: the verifier only runs after an `Accepted` dispatch, so every
/// verification failure records `Unknown` regardless of its cause.
#[derive(Debug, Error)]
pub enum CommandVerifyError {
    #[error("the command endpoint could not be resolved: {0}")]
    EndpointResolution(#[source] Box<dyn StdError + Send + Sync>),
    #[error("the command endpoint is not managed")]
    EndpointUnknown,
    #[error("the command credential could not be resolved: {0}")]
    CredentialResolution(#[source] Box<dyn StdError + Send + Sync>),
    #[error("the command credential is not available")]
    CredentialUnknown,
    #[error("the post-execution verification re-read failed: {0}")]
    ReRead(#[source] CommandVerificationError),
}

impl<Gateway, Repository, Credentials> TaskReader
    for RedfishCommandExecutor<Gateway, Repository, Credentials>
where
    Gateway: CommandGateway,
    Repository: EndpointRefreshRepository,
    Credentials: CredentialResolver,
{
    type Error = CommandTaskReadError;

    fn read_task<'a>(
        &'a self,
        endpoint_id: EndpointId,
        task_uri: &'a TaskUri,
    ) -> BoundaryFuture<'a, Result<Option<ApplicationTaskObservation>, Self::Error>> {
        Box::pin(async move {
            let endpoint = match self.endpoints.find_endpoint(endpoint_id).await {
                Ok(Some(endpoint)) => endpoint,
                Ok(None) => return Err(CommandTaskReadError::EndpointUnknown),
                Err(source) => {
                    return Err(CommandTaskReadError::EndpointResolution(Box::new(source)));
                }
            };
            let credential = match self.credentials.resolve(endpoint.credential_id()).await {
                Ok(Some(credential)) => credential,
                Ok(None) => return Err(CommandTaskReadError::CredentialUnknown),
                Err(source) => {
                    return Err(CommandTaskReadError::CredentialResolution(Box::new(source)));
                }
            };
            // The persisted Task URI is the exact identifier the BMC returned
            // (§13.6), re-validated as a resource `@odata.id` before it is
            // issued to the transport.
            let task_odata_id =
                task_uri_to_odata_id(task_uri).map_err(CommandTaskReadError::InvalidTaskUri)?;
            match self
                .gateway
                .read_task(
                    endpoint.address(),
                    endpoint.trust(),
                    credential.username(),
                    credential.password(),
                    &task_odata_id,
                )
                .await
            {
                Ok(observation) => Ok(Some(map_task_observation(
                    observation.task_state(),
                    observation
                        .messages()
                        .last()
                        .and_then(TaskMessageObservation::message),
                    observation.percent_complete(),
                    observation.task_monitor(),
                ))),
                // The BMC no longer tracks the Task (404): the distinct
                // disappearance signal the monitor records as an outcome it
                // cannot prove (§13.5, §13.6) instead of a transient failure.
                Err(TaskReadError::TaskGone { .. }) => Ok(None),
                Err(source) => Err(CommandTaskReadError::Read(source)),
            }
        })
    }
}

/// A controlled failure while reading one asynchronous Task at the
/// application boundary.
///
/// The endpoint and credential lookup variants mirror
/// [`CommandDispatchError`] and [`CommandVerifyError`]: all three boundaries
/// resolve the same endpoint row. A read failure is deliberately not
/// classified: the Task monitor treats every failed read as transient and
/// defers the poll, because a Task read is a side-effect-free GET (§13.5).
#[derive(Debug, Error)]
pub enum CommandTaskReadError {
    #[error("the command endpoint could not be resolved: {0}")]
    EndpointResolution(#[source] Box<dyn StdError + Send + Sync>),
    #[error("the command endpoint is not managed")]
    EndpointUnknown,
    #[error("the command credential could not be resolved: {0}")]
    CredentialResolution(#[source] Box<dyn StdError + Send + Sync>),
    #[error("the command credential is not available")]
    CredentialUnknown,
    #[error("the persisted Task URI cannot be represented as a Redfish resource identifier: {0}")]
    InvalidTaskUri(#[source] ResourceODataIdError),
    #[error("the Task read failed: {0}")]
    Read(#[source] TaskReadError),
}

/// Converts the persisted Task URI onto the gateway's resource identifier.
///
/// The two validators share the same exact-text rules (non-empty, no
/// surrounding whitespace, no control characters, bounded length), so the
/// conversion is total for every representable [`TaskUri`]; the error arm is
/// defensive and exists only because the parse must be handled — it can fire
/// only if the two validators ever diverge.
fn task_uri_to_odata_id(task_uri: &TaskUri) -> Result<ResourceODataId, ResourceODataIdError> {
    ResourceODataId::parse(task_uri.as_str())
}

/// Projects one gateway Task observation onto the application boundary
/// (§13.6).
///
/// The pieces are passed as extracted values so the projection stays a pure
/// function of the wire facts. The state code is classified through
/// [`RemoteTaskState`]'s `FromStr`: a code this build cannot classify — a
/// newer CSDL value, or `unsupported_value` — is `None`, which the monitor
/// treats as an outcome it cannot prove instead of a known state (§7.6). A
/// corrupt completion percentage (outside `0..=100`) is dropped and recorded
/// as no progress, never displayed as progress; the same for a `TaskMonitor`
/// URI that cannot be represented as exact text.
#[must_use]
fn map_task_observation(
    state_code: Option<&str>,
    last_message: Option<&str>,
    percent_complete: Option<i64>,
    task_monitor: Option<&ResourceODataId>,
) -> ApplicationTaskObservation {
    ApplicationTaskObservation::new(
        map_task_state(state_code),
        last_message.map(str::to_owned),
        map_percent_complete(percent_complete),
        task_monitor.and_then(|uri| TaskUri::parse(uri.as_str()).ok()),
    )
}

/// Classifies the gateway's stable Task state code onto the engine's
/// enumeration; an unclassifiable code is `None`.
#[must_use]
fn map_task_state(code: Option<&str>) -> Option<RemoteTaskState> {
    code.and_then(|code| code.parse().ok())
}

/// Converts the gateway's `Int64` completion percentage onto the engine's
/// `u64`, dropping values outside the CSDL `0..=100` range.
#[must_use]
fn map_percent_complete(percent: Option<i64>) -> Option<u64> {
    percent
        .and_then(|percent| u64::try_from(percent).ok())
        .filter(|percent| *percent <= 100)
}

#[cfg(test)]
mod tests {
    use std::{error::Error, pin::Pin};

    use nv_redfish::core::ODataId;
    use rutilus_application::{
        CommandExecutor, CommandOutcome, CommandVerifier, CoreResourceReader, DispatchVerdict,
        DispatchVerdictClassifier, EndpointRefreshRepository, RedfishDiscovery,
        ResourceObservation, TaskReader, TlsIdentityProbe,
    };
    use rutilus_domain::{
        CredentialId, CredentialUsername, Endpoint, EndpointAddress, EndpointDisplayName,
        EndpointId, RedfishCommand, ResourceODataId, TlsCertificate, TlsTrust,
    };
    use rutilus_operation_engine::{RemoteTaskState, TaskUri, TaskUriError};
    use secrecy::SecretString;
    use time::OffsetDateTime;

    use super::{
        CommandGateway, map_async_task_outcome, map_percent_complete, map_task_observation,
        map_task_state, task_uri_to_odata_id,
    };
    use crate::{
        CommandDispatchError, CommandExecutionError, CommandExecutionOutcome, CommandTaskReadError,
        CommandVerificationError, CommandVerificationOutcome, CommandVerifyError,
        RedfishCommandExecutor, RedfishGateway, RedfishServiceRootError, TaskObservation,
        TaskReadError,
    };

    #[test]
    fn gateway_implements_the_application_discovery_boundary() {
        fn assert_discovery<Gateway: RedfishDiscovery>() {}

        assert_discovery::<RedfishGateway>();
    }

    #[test]
    fn gateway_implements_the_application_tls_identity_boundary() {
        fn assert_tls_identity_probe<Gateway: TlsIdentityProbe>() {}

        assert_tls_identity_probe::<RedfishGateway>();
    }

    #[test]
    fn gateway_implements_the_application_core_resource_boundary() {
        fn assert_core_resource_reader<Gateway: CoreResourceReader>() {}

        assert_core_resource_reader::<RedfishGateway>();
    }

    /// The test doubles for the executor's repository, resolver, and gateway
    /// bounds.
    ///
    /// The doubles implement every method of the reused boundaries; the
    /// executor only calls `find_endpoint`, `resolve`, and the command
    /// surfaces, so the remaining methods return inert values.
    struct TestEndpointRepository {
        endpoint: Option<Endpoint>,
    }

    impl TestEndpointRepository {
        const fn empty() -> Self {
            Self { endpoint: None }
        }
    }

    impl EndpointRefreshRepository for TestEndpointRepository {
        type Error = TestRepositoryError;

        fn find_endpoint(
            &self,
            _endpoint_id: EndpointId,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<Option<Endpoint>, Self::Error>> + Send + '_,
            >,
        > {
            Box::pin(async move { Ok(self.endpoint.clone()) })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [ResourceObservation],
            _observed_at: time::OffsetDateTime,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<Vec<rutilus_domain::ResourceSnapshot>, Self::Error>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    struct TestCredentialResolver {
        credential: Option<(CredentialUsername, SecretString)>,
    }

    impl TestCredentialResolver {
        const fn empty() -> Self {
            Self { credential: None }
        }
    }

    impl rutilus_application::CredentialResolver for TestCredentialResolver {
        type Error = TestRepositoryError;

        fn resolve(
            &self,
            _credential_id: rutilus_domain::CredentialId,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<
                            Option<rutilus_application::ResolvedCredential>,
                            Self::Error,
                        >,
                    > + Send
                    + '_,
            >,
        > {
            // `ResolvedCredential` is not `Clone`, so the double stores the
            // parts and rebuilds the value per call.
            Box::pin(async move {
                Ok(self.credential.as_ref().map(|(username, password)| {
                    rutilus_application::ResolvedCredential::new(username.clone(), password.clone())
                }))
            })
        }
    }

    /// The scripted gateway double for the executor's boundary tests.
    ///
    /// `read_task` always reports the `TaskGone` disappearance signal, which
    /// is the branch the adapter tests pin; the execute and verify surfaces
    /// are inert because no test in this module drives them.
    struct FakeGateway {
        gone_task_uri: ResourceODataId,
        gone_url: url::Url,
    }

    impl FakeGateway {
        fn task_gone() -> Result<Self, Box<dyn Error>> {
            Ok(Self {
                gone_task_uri: ResourceODataId::parse("/redfish/v1/TaskService/Tasks/42")?,
                gone_url: url::Url::parse("https://192.0.2.1/redfish/v1/TaskService/Tasks/42")?,
            })
        }
    }

    impl CommandGateway for FakeGateway {
        fn execute_command<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
            _command: &'a RedfishCommand,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<CommandExecutionOutcome, CommandExecutionError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                Err(CommandExecutionError::NotDispatched(Box::new(
                    RedfishServiceRootError::SessionCleanupFailed,
                )))
            })
        }

        fn verify_command<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
            _command: &'a RedfishCommand,
        ) -> Pin<
            Box<
                dyn std::future::Future<
                        Output = Result<CommandVerificationOutcome, CommandVerificationError>,
                    > + Send
                    + 'a,
            >,
        > {
            Box::pin(async move { Err(CommandVerificationError::CapabilityUnavailable) })
        }

        fn read_task<'a>(
            &'a self,
            _address: &'a EndpointAddress,
            _trust: &'a TlsTrust,
            _username: &'a CredentialUsername,
            _password: &'a SecretString,
            _task_uri: &'a ResourceODataId,
        ) -> Pin<
            Box<
                dyn std::future::Future<Output = Result<TaskObservation, TaskReadError>>
                    + Send
                    + 'a,
            >,
        > {
            Box::pin(async move {
                Err(TaskReadError::TaskGone {
                    task_uri: self.gone_task_uri.clone(),
                    source: nv_redfish::bmc_http::reqwest::BmcError::InvalidResponse {
                        url: self.gone_url.clone(),
                        status: reqwest::StatusCode::NOT_FOUND,
                        text: String::new(),
                    },
                })
            })
        }
    }

    /// One managed endpoint fixture the repository double can serve.
    fn managed_endpoint() -> Result<Endpoint, Box<dyn Error>> {
        let now = OffsetDateTime::now_utc();
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("fixture")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(vec![1, 2, 3])?,
                trusted_at: now,
            },
            CredentialId::generate(),
            now,
            now,
        )?)
    }

    /// One resolved credential fixture the resolver double can serve.
    fn resolved_credential() -> Result<(CredentialUsername, SecretString), Box<dyn Error>> {
        Ok((
            CredentialUsername::parse("admin")?,
            SecretString::from("password"),
        ))
    }

    #[derive(Debug)]
    struct TestRepositoryError;

    impl std::fmt::Display for TestRepositoryError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("test repository error")
        }
    }

    impl std::error::Error for TestRepositoryError {}

    #[test]
    fn executor_implements_the_application_command_executor_boundary() {
        fn assert_executor<Executor: CommandExecutor<Error = CommandDispatchError>>() {}

        assert_executor::<
            RedfishCommandExecutor<RedfishGateway, TestEndpointRepository, TestCredentialResolver>,
        >();
    }

    #[test]
    fn executor_implements_the_application_command_verifier_boundary() {
        fn assert_verifier<Verifier: CommandVerifier<Error = CommandVerifyError>>() {}

        assert_verifier::<
            RedfishCommandExecutor<RedfishGateway, TestEndpointRepository, TestCredentialResolver>,
        >();
    }

    #[test]
    fn executor_implements_the_application_task_reader_boundary() {
        fn assert_task_reader<Reader: TaskReader<Error = CommandTaskReadError>>() {}

        assert_task_reader::<
            RedfishCommandExecutor<RedfishGateway, TestEndpointRepository, TestCredentialResolver>,
        >();
    }

    #[tokio::test]
    async fn read_task_maps_a_disappeared_task_onto_the_distinct_none_signal()
    -> Result<(), Box<dyn Error>> {
        let executor = RedfishCommandExecutor::new(
            FakeGateway::task_gone()?,
            TestEndpointRepository {
                endpoint: Some(managed_endpoint()?),
            },
            TestCredentialResolver {
                credential: Some(resolved_credential()?),
            },
        );

        let observed = executor
            .read_task(
                EndpointId::generate(),
                &TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
            )
            .await?;

        assert_eq!(
            observed, None,
            "a 404 from the Task URI is the disappearance signal, not an observation"
        );
        Ok(())
    }

    #[tokio::test]
    async fn read_task_reports_unknown_endpoints_without_touching_the_gateway()
    -> Result<(), Box<dyn Error>> {
        let executor = RedfishCommandExecutor::new(
            FakeGateway::task_gone()?,
            TestEndpointRepository::empty(),
            TestCredentialResolver::empty(),
        );

        let result = executor
            .read_task(
                EndpointId::generate(),
                &TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
            )
            .await;

        assert!(
            matches!(result, Err(CommandTaskReadError::EndpointUnknown)),
            "an unmanaged endpoint must be rejected before any Task request: {result:?}"
        );
        Ok(())
    }

    #[test]
    fn task_uri_conversion_is_total_across_representative_persisted_uris()
    -> Result<(), Box<dyn Error>> {
        // `TaskUri` and `ResourceODataId` share the same exact-text rules, so
        // the conversion the reader performs before every poll can never fail
        // for a representable Task URI; this pins that totality across the
        // boundary values of the shared validation.
        for raw in [
            "/redfish/v1/TaskService/Tasks/42",
            "/redfish/v1/TaskService/TaskMonitors/1",
            "/redfish/v1/TaskService/Tasks/任务-42",
            &format!(
                "/redfish/v1/TaskService/Tasks/{}",
                "x".repeat(4 * 1024 - 30)
            ),
        ] {
            let task_uri = TaskUri::parse(raw)?;
            assert_eq!(
                task_uri_to_odata_id(&task_uri)?.as_str(),
                raw,
                "the persisted Task URI must convert losslessly"
            );
        }
        Ok(())
    }

    #[test]
    fn dispatch_error_verdicts_follow_the_design_13_5_classification()
    -> Result<(), Box<dyn std::error::Error>> {
        let not_executed = [
            CommandDispatchError::EndpointUnknown,
            CommandDispatchError::CredentialUnknown,
            CommandDispatchError::Dispatch(CommandExecutionError::Rejected(
                crate::CommandRejection::CapabilityUnavailable,
            )),
            CommandDispatchError::Dispatch(CommandExecutionError::NotDispatched(Box::new(
                crate::RedfishServiceRootError::SessionCleanupFailed,
            ))),
        ];
        for error in not_executed {
            assert_eq!(
                error.verdict(),
                DispatchVerdict::NotExecuted,
                "{error} proves the write was never executed"
            );
        }

        let url = url::Url::parse("https://192.0.2.1/redfish/v1")?;
        let outcome_unknown = [
            CommandDispatchError::Dispatch(CommandExecutionError::OutcomeUnknown(Box::new(
                crate::RedfishServiceRootError::Network {
                    source: nv_redfish::bmc_http::reqwest::BmcError::InvalidResponse {
                        url: url.clone(),
                        status: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                        text: String::new(),
                    },
                },
            ))),
            CommandDispatchError::Dispatch(CommandExecutionError::AsyncTaskAccepted {
                task_location: nv_redfish::core::ODataId::from(
                    "/redfish/v1/TaskService/Tasks/42".to_owned(),
                ),
            }),
            // An unrepresentable `Location` still means the BMC accepted the
            // write: only the Task could prove the result (§13.5).
            CommandDispatchError::AsyncTaskUriInvalid(TaskUriError::Empty),
        ];
        for error in outcome_unknown {
            assert_eq!(
                error.verdict(),
                DispatchVerdict::OutcomeUnknown,
                "{error} may already have been applied by the BMC"
            );
        }
        Ok(())
    }

    #[test]
    fn async_task_acceptance_maps_onto_the_application_async_outcome()
    -> Result<(), Box<dyn std::error::Error>> {
        let mapped = map_async_task_outcome(&ODataId::from(
            "/redfish/v1/TaskService/Tasks/42".to_owned(),
        ))?;

        assert_eq!(
            mapped,
            CommandOutcome::AsyncTaskAccepted {
                task_location: TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
            }
        );

        // A `Location` the TaskUri validation refuses (empty, padded, control
        // characters, oversized) is an outcome-unknown failure, never a
        // fabricated acceptance.
        let unrepresentable = map_async_task_outcome(&ODataId::from(" \t".to_owned()));
        assert!(matches!(
            unrepresentable,
            Err(CommandDispatchError::AsyncTaskUriInvalid(_))
        ));
        Ok(())
    }

    #[test]
    fn task_state_mapping_classifies_only_known_codes() {
        for (code, expected) in [
            ("new", Some(RemoteTaskState::New)),
            ("starting", Some(RemoteTaskState::Starting)),
            ("running", Some(RemoteTaskState::Running)),
            ("suspended", Some(RemoteTaskState::Suspended)),
            ("interrupted", Some(RemoteTaskState::Interrupted)),
            ("pending", Some(RemoteTaskState::Pending)),
            ("stopping", Some(RemoteTaskState::Stopping)),
            ("completed", Some(RemoteTaskState::Completed)),
            ("killed", Some(RemoteTaskState::Killed)),
            ("exception", Some(RemoteTaskState::Exception)),
            ("service", Some(RemoteTaskState::Service)),
            ("cancelling", Some(RemoteTaskState::Cancelling)),
            ("cancelled", Some(RemoteTaskState::Cancelled)),
        ] {
            assert_eq!(map_task_state(Some(code)), expected, "code {code}");
        }
        // A code this build cannot classify — the gateway's
        // `unsupported_value` for a newer CSDL value, or an absent state —
        // is `None`, never disguised as a known state (§7.6).
        assert_eq!(map_task_state(Some("unsupported_value")), None);
        assert_eq!(map_task_state(Some("definitely_newer_state")), None);
        assert_eq!(map_task_state(None), None);
    }

    #[test]
    fn percent_complete_mapping_drops_values_outside_the_csdl_range() {
        for (wire, expected) in [
            (None, None),
            (Some(0), Some(0)),
            (Some(42), Some(42)),
            (Some(100), Some(100)),
            // Negative and oversized wire values are corrupt: recorded as no
            // progress, never displayed as progress.
            (Some(-1), None),
            (Some(101), None),
            (Some(i64::MAX), None),
            (Some(i64::MIN), None),
        ] {
            assert_eq!(map_percent_complete(wire), expected, "wire {wire:?}");
        }
    }

    #[test]
    fn task_observation_mapping_projects_all_wire_facts() -> Result<(), Box<dyn std::error::Error>>
    {
        let monitor = ResourceODataId::parse("/redfish/v1/TaskService/TaskMonitors/42")?;

        let projected = map_task_observation(
            Some("running"),
            Some("applying firmware"),
            Some(42),
            Some(&monitor),
        );

        assert_eq!(projected.state(), Some(RemoteTaskState::Running));
        assert_eq!(projected.message(), Some("applying firmware"));
        assert_eq!(projected.percent_complete(), Some(42));
        assert_eq!(
            projected.task_monitor_uri(),
            Some(&TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/42")?)
        );

        // An unclassifiable state and a corrupt percent both project as
        // absent, so the monitor records an outcome it cannot prove instead
        // of a fabricated one.
        let degraded = map_task_observation(Some("unsupported_value"), None, Some(101), None);
        assert_eq!(degraded.state(), None);
        assert_eq!(degraded.message(), None);
        assert_eq!(degraded.percent_complete(), None);
        assert_eq!(degraded.task_monitor_uri(), None);
        Ok(())
    }
}
