use std::error::Error as StdError;

use rutilus_application::{
    BoundaryFuture, CommandExecutor, CommandOutcome, CommandVerifier, CoreResourceReader,
    CredentialResolver, DispatchVerdict, DispatchVerdictClassifier, EndpointDiscovery,
    EndpointRefreshRepository, RedfishDiscovery, ResourceObservation, SystemCaEvaluation,
    TlsIdentityObservation, TlsIdentityProbe, VerificationVerdict,
};
use rutilus_domain::{CredentialUsername, EndpointAddress, EndpointId, RedfishCommand, TlsTrust};
use secrecy::SecretString;
use thiserror::Error;

use crate::{
    CommandExecutionError, CommandExecutionOutcome, CommandVerificationError,
    CommandVerificationOutcome, CoreResourceReadError, RedfishGateway, RedfishServiceRootError,
    SystemCaStatus, TlsProbeError,
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

/// The application-boundary write dispatcher (§13.3 step 7).
///
/// [`CommandExecutor`] resolves the endpoint row (address, TLS trust,
/// credential) from the endpoint id and delegates the typed write to
/// [`RedfishGateway::execute_command`], so the operation scheduler never
/// sees credentials, addresses, or `nv-redfish` types (design §7.2). The
/// endpoint lookup reuses the refresh repository's `find_endpoint` — the
/// only application boundary that resolves an endpoint by id — and the
/// credential lookup reuses the onboarding credential resolver.
pub struct RedfishCommandExecutor<Repository, Credentials> {
    gateway: RedfishGateway,
    endpoints: Repository,
    credentials: Credentials,
}

impl<Repository, Credentials> RedfishCommandExecutor<Repository, Credentials> {
    /// Binds the gateway to the endpoint and credential lookups it resolves
    /// per dispatch.
    #[must_use]
    pub const fn new(
        gateway: RedfishGateway,
        endpoints: Repository,
        credentials: Credentials,
    ) -> Self {
        Self {
            gateway,
            endpoints,
            credentials,
        }
    }
}

impl<Repository, Credentials> CommandExecutor for RedfishCommandExecutor<Repository, Credentials>
where
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
                Err(source) => Err(CommandDispatchError::Dispatch(source)),
            }
        })
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
}

impl DispatchVerdictClassifier for CommandDispatchError {
    fn verdict(&self) -> DispatchVerdict {
        match self {
            Self::EndpointResolution(_)
            | Self::EndpointUnknown
            | Self::CredentialResolution(_)
            | Self::CredentialUnknown => DispatchVerdict::NotExecuted,
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

impl<Repository, Credentials> CommandVerifier for RedfishCommandExecutor<Repository, Credentials>
where
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

#[cfg(test)]
mod tests {
    use std::pin::Pin;

    use rutilus_application::{
        CommandExecutor, CommandVerifier, CoreResourceReader, DispatchVerdict,
        DispatchVerdictClassifier, EndpointRefreshRepository, RedfishDiscovery,
        ResourceObservation, TlsIdentityProbe,
    };
    use rutilus_domain::{Endpoint, EndpointId};

    use crate::{
        CommandDispatchError, CommandExecutionError, CommandVerifyError, RedfishCommandExecutor,
        RedfishGateway,
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

    /// The test doubles for the executor's repository and resolver bounds.
    ///
    /// The doubles implement every method of the reused boundaries; the
    /// executor only calls `find_endpoint` and `resolve`, so the remaining
    /// methods return inert values.
    struct TestEndpointRepository;

    impl EndpointRefreshRepository for TestEndpointRepository {
        type Error = TestRepositoryError;

        fn find_endpoint(
            &self,
            _endpoint_id: EndpointId,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Option<Endpoint>, Self::Error>> + Send>>
        {
            Box::pin(async { Ok(None) })
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

    struct TestCredentialResolver;

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
                    > + Send,
            >,
        > {
            Box::pin(async { Ok(None) })
        }
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

        assert_executor::<RedfishCommandExecutor<TestEndpointRepository, TestCredentialResolver>>();
    }

    #[test]
    fn executor_implements_the_application_command_verifier_boundary() {
        fn assert_verifier<Verifier: CommandVerifier<Error = CommandVerifyError>>() {}

        assert_verifier::<RedfishCommandExecutor<TestEndpointRepository, TestCredentialResolver>>();
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
}
