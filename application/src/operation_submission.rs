//! Submits one persisted product operation (design sections 13.1 and 13.3).
//!
//! Design section 13.1 turns every write — from the Standalone GUI, the Site
//! GUI, or the Center — into one persisted [`Operation`] carrying the typed
//! [`RedfishCommand`]. This use case is the submission entry point of that
//! rule: it validates the caller's target list against the managed endpoint
//! inventory, then persists a `Queued` operation through the
//! [`OperationEngine`].
//!
//! # Why the endpoint lookup reuses `EndpointRefreshRepository`
//!
//! The existence check reuses the same `find_endpoint` boundary that
//! [`crate::OperationExecutor`] uses for its §13.3 step-1 pre-flight check,
//! instead of loading the full endpoint inventory or defining a duplicate
//! minimal trait: one bounded lookup per target, one established boundary,
//! and no new implementation surface for the embedding runtime. The lookup
//! happens before any persistence, so a rejected submission never touches
//! the operation store.

use std::{collections::BTreeSet, error::Error};

use rutilus_domain::{
    EndpointId, Operation, OperationId, OperationSource, OperationState, OperationTarget,
    RedfishCommand,
};
use rutilus_operation_engine::{EngineError, OperationEngine, OperationStore};
use thiserror::Error;
use time::OffsetDateTime;

use crate::EndpointRefreshRepository;

/// Persists validated operation submissions and answers operation queries.
///
/// `Store` is the [`OperationStore`] behind the engine and `Lookup` the
/// endpoint-existence boundary; the runtime composes one `SqliteStore`
/// implementing both, exactly like every other application use case.
pub struct OperationSubmission<Store, Lookup> {
    store: Store,
    lookup: Lookup,
}

impl<Store, Lookup> OperationSubmission<Store, Lookup>
where
    Store: OperationStore,
    Lookup: EndpointRefreshRepository,
{
    #[must_use]
    pub const fn new(store: Store, lookup: Lookup) -> Self {
        Self { store, lookup }
    }

    /// Validates the targets and persists one `Queued` operation (§13.1).
    ///
    /// # Why the validation order matters
    ///
    /// The target list must contain at least one target (a zero-target
    /// operation could never execute, §13.7) and no repeated endpoint (one
    /// operation is one intent; executing the same write twice against the
    /// same endpoint would be two intents wearing one operation id). Every
    /// referenced endpoint must be a managed endpoint — a write to an
    /// unmanaged BMC is a misconfigured request, not a queued job. Only after
    /// all three checks pass is the operation persisted, so a rejected
    /// submission never leaves a durable row.
    ///
    /// `now` is the caller-supplied creation time, exactly like the engine's
    /// contract: the caller owns a monotonic clock and must never move it
    /// backwards, because the domain trusts it without re-checking.
    ///
    /// # Errors
    ///
    /// Returns [`SubmissionError::EmptyTargets`] for an empty target list,
    /// [`SubmissionError::DuplicateEndpoint`] for a repeated endpoint id,
    /// [`SubmissionError::UnknownEndpoint`] when a referenced endpoint is not
    /// managed, [`SubmissionError::Inventory`] when the endpoint lookup fails,
    /// and [`SubmissionError::Store`] when the engine cannot persist the
    /// operation.
    pub async fn submit(
        &self,
        source: OperationSource,
        targets: Vec<OperationTarget>,
        command: RedfishCommand,
        now: OffsetDateTime,
    ) -> Result<Operation, SubmissionError<Store::Error, Lookup::Error>> {
        if targets.is_empty() {
            return Err(SubmissionError::EmptyTargets);
        }
        let mut seen = BTreeSet::new();
        for target in &targets {
            let endpoint_id = target.endpoint_id();
            if !seen.insert(endpoint_id) {
                return Err(SubmissionError::DuplicateEndpoint { endpoint_id });
            }
        }
        for target in &targets {
            let found = self
                .lookup
                .find_endpoint(target.endpoint_id())
                .await
                .map_err(SubmissionError::Inventory)?;
            if found.is_none() {
                return Err(SubmissionError::UnknownEndpoint {
                    endpoint_id: target.endpoint_id(),
                });
            }
        }
        let engine = OperationEngine::new(&self.store);
        engine
            .create(source, targets, command, now)
            .await
            .map_err(SubmissionError::Store)
    }

    /// Lists persisted operations, optionally filtered by exact state.
    ///
    /// The optional filter is forwarded unchanged to the engine; `None` lists
    /// every operation. Batch reporting (design section 13.7) filters per
    /// state to summarize outcomes.
    ///
    /// # Errors
    ///
    /// Returns [`SubmissionError::Store`] when the engine cannot read the
    /// operation store.
    pub async fn list(
        &self,
        state: Option<OperationState>,
    ) -> Result<Vec<Operation>, SubmissionError<Store::Error, Lookup::Error>> {
        let engine = OperationEngine::new(&self.store);
        engine.list(state).await.map_err(SubmissionError::Store)
    }

    /// Reads one operation by id; `None` when the id is unknown.
    ///
    /// The engine has no single-record read (its `apply` path reads before a
    /// transition), so this use case forwards the id to the store boundary
    /// directly — the same read the engine itself relies on. The raw store
    /// failure is wrapped in the engine's `Store` verdict so the submission
    /// error surface stays one variant per boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SubmissionError::Store`] when the operation store read fails.
    pub async fn find(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<Operation>, SubmissionError<Store::Error, Lookup::Error>> {
        self.store
            .find_operation(operation_id)
            .await
            .map_err(|source| SubmissionError::Store(EngineError::Store(source)))
    }
}

/// A controlled failure while submitting or querying one operation.
///
/// The two generic parameters are the store's and the lookup boundary's error
/// types, so every persistence and lookup failure stays reachable as the
/// source of an error chain. The `Store` variant carries the engine's own
/// verdict (not the raw store error) because the submission paths only ever
/// trigger the engine's `Store` outcome; the engine's read-path verdicts are
/// unreachable here and would surface inside `Store` instead of being
/// invented at this layer.
#[derive(Debug, Error)]
pub enum SubmissionError<StoreError, LookupError>
where
    StoreError: Error + 'static,
    LookupError: Error + 'static,
{
    /// The operation would have no target and could never execute.
    #[error("an operation must target at least one endpoint")]
    EmptyTargets,
    /// The same endpoint is referenced more than once in one operation.
    #[error("operation targets endpoint {endpoint_id} more than once")]
    DuplicateEndpoint { endpoint_id: EndpointId },
    /// A referenced endpoint is not a managed endpoint.
    #[error("endpoint {endpoint_id} is not a managed endpoint")]
    UnknownEndpoint { endpoint_id: EndpointId },
    /// The endpoint existence check failed.
    #[error("failed to check the target endpoints: {0}")]
    Inventory(#[source] LookupError),
    /// The operation engine could not persist or read the operation.
    #[error("operation persistence failed: {0}")]
    Store(#[source] EngineError<StoreError>),
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, sync::Mutex};

    use rutilus_domain::{
        CredentialId, Endpoint, EndpointAddress, EndpointDisplayName, OperationState,
        OperationTarget, ResourceSnapshot, TargetId, TlsCertificate, TlsTrust,
    };
    use rutilus_operation_engine::BoundaryFuture;
    use thiserror::Error as ThisError;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::ResourceObservation;

    #[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
    enum MockError {
        #[error("simulated persistence failure")]
        Store,
        #[error("simulated endpoint lookup failure")]
        Lookup,
    }

    /// In-memory fake behind the `OperationStore` boundary, recording every
    /// persisted row exactly like the production `SqliteStore`.
    struct MockStore {
        rows: Mutex<HashMap<OperationId, Operation>>,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
            }
        }

        fn find_owned(&self, operation_id: OperationId) -> Result<Option<Operation>, MockError> {
            self.rows
                .lock()
                .map_err(|_| MockError::Store)
                .map(|rows| rows.get(&operation_id).cloned())
        }
    }

    impl OperationStore for MockStore {
        type Error = MockError;

        fn create_operation<'a>(
            &'a self,
            operation: &'a Operation,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.rows
                    .lock()
                    .map_err(|_| MockError::Store)?
                    .entry(operation.id())
                    .or_insert_with(|| operation.clone());
                Ok(())
            })
        }

        fn find_operation(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<Operation>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| MockError::Store)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn apply_transition(
            &self,
            operation_id: OperationId,
            new_state: OperationState,
            occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.rows.lock().map_err(|_| MockError::Store)?;
                let row = rows.get(&operation_id).ok_or(MockError::Store)?.clone();
                if row.is_terminal() {
                    return Err(MockError::Store);
                }
                rows.insert(
                    operation_id,
                    Operation::try_from_parts(
                        row.id(),
                        row.source(),
                        row.targets().to_vec(),
                        row.command(),
                        new_state,
                        row.created_at(),
                        occurred_at,
                    )
                    .map_err(|_| MockError::Store)?,
                );
                Ok(())
            })
        }

        fn list_operations(
            &self,
            state: Option<OperationState>,
        ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move {
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| MockError::Store)?
                    .values()
                    .filter(|operation| state.is_none_or(|state| operation.state() == state))
                    .cloned()
                    .collect())
            })
        }
    }

    /// Fake endpoint lookup backed by a fixed managed endpoint list.
    struct MockLookup {
        endpoints: Vec<Endpoint>,
        fail_lookup: bool,
    }

    impl EndpointRefreshRepository for MockLookup {
        type Error = MockError;

        fn find_endpoint(
            &self,
            endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Option<Endpoint>, Self::Error>> {
            Box::pin(async move {
                if self.fail_lookup {
                    return Err(MockError::Lookup);
                }
                Ok(self
                    .endpoints
                    .iter()
                    .find(|endpoint| endpoint.id() == endpoint_id)
                    .cloned())
            })
        }

        fn commit_resource_generation<'a>(
            &'a self,
            _endpoint_id: EndpointId,
            _observations: &'a [ResourceObservation],
            _observed_at: OffsetDateTime,
        ) -> BoundaryFuture<'a, Result<Vec<ResourceSnapshot>, Self::Error>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    #[tokio::test]
    async fn submit_rejects_empty_targets_without_touching_any_boundary()
    -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let lookup = MockLookup {
            endpoints: Vec::new(),
            fail_lookup: false,
        };
        let submission = OperationSubmission::new(&store, &lookup);

        let error = submission
            .submit(
                OperationSource::Standalone,
                Vec::new(),
                one_command(),
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("empty-target submit must fail"))?;
        assert_eq!(
            error.to_string(),
            "an operation must target at least one endpoint"
        );
        assert!(matches!(error, SubmissionError::EmptyTargets));
        assert_eq!(submission.list(None).await?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn submit_rejects_repeated_endpoints_without_touching_the_store()
    -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let endpoint = managed_endpoint()?;
        let lookup = MockLookup {
            endpoints: vec![endpoint.clone()],
            fail_lookup: false,
        };
        let submission = OperationSubmission::new(&store, &lookup);
        let repeated = endpoint.id();

        let error = submission
            .submit(
                OperationSource::Standalone,
                vec![
                    OperationTarget::new(TargetId::generate(), repeated),
                    OperationTarget::new(TargetId::generate(), repeated),
                ],
                one_command(),
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("duplicate-target submit must fail"))?;
        assert!(
            matches!(error, SubmissionError::DuplicateEndpoint { endpoint_id } if endpoint_id == repeated)
        );
        assert_eq!(submission.list(None).await?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn submit_propagates_endpoint_lookup_failures() -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let lookup = MockLookup {
            endpoints: Vec::new(),
            fail_lookup: true,
        };
        let submission = OperationSubmission::new(&store, &lookup);

        let error = submission
            .submit(
                OperationSource::Standalone,
                vec![OperationTarget::new(
                    TargetId::generate(),
                    EndpointId::generate(),
                )],
                one_command(),
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("failing-lookup submit must fail"))?;
        assert!(matches!(
            error,
            SubmissionError::Inventory(MockError::Lookup)
        ));
        assert_eq!(submission.list(None).await?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn submit_rejects_unmanaged_endpoints_without_touching_the_store()
    -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let lookup = MockLookup {
            endpoints: Vec::new(),
            fail_lookup: false,
        };
        let submission = OperationSubmission::new(&store, &lookup);
        let unknown = EndpointId::generate();

        let error = submission
            .submit(
                OperationSource::Standalone,
                vec![OperationTarget::new(TargetId::generate(), unknown)],
                one_command(),
                OffsetDateTime::now_utc(),
            )
            .await
            .err()
            .ok_or_else(|| std::io::Error::other("unknown-endpoint submit must fail"))?;
        assert!(
            matches!(error, SubmissionError::UnknownEndpoint { endpoint_id } if endpoint_id == unknown)
        );
        assert_eq!(submission.list(None).await?, Vec::new());
        Ok(())
    }

    #[tokio::test]
    async fn submit_persists_a_queued_operation_with_the_exact_command()
    -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let endpoint = managed_endpoint()?;
        let lookup = MockLookup {
            endpoints: vec![endpoint.clone()],
            fail_lookup: false,
        };
        let submission = OperationSubmission::new(&store, &lookup);
        let target = OperationTarget::new(TargetId::generate(), endpoint.id());
        let command = one_command();
        let now = OffsetDateTime::UNIX_EPOCH;

        let operation = submission
            .submit(OperationSource::Center, vec![target], command.clone(), now)
            .await?;

        assert_eq!(operation.state(), OperationState::Queued);
        assert_eq!(operation.source(), OperationSource::Center);
        assert_eq!(operation.targets(), &[target]);
        assert_eq!(operation.command(), command);
        assert_eq!(operation.created_at(), now);
        assert_eq!(operation.updated_at(), now);
        let stored = store
            .find_owned(operation.id())?
            .ok_or_else(|| std::io::Error::other("submitted operation must be stored"))?;
        assert_eq!(stored, operation);
        assert_eq!(stored.command(), command);
        Ok(())
    }

    #[tokio::test]
    async fn list_filters_by_exact_state_and_find_reads_one_record() -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let endpoint = managed_endpoint()?;
        let lookup = MockLookup {
            endpoints: vec![endpoint.clone()],
            fail_lookup: false,
        };
        let submission = OperationSubmission::new(&store, &lookup);
        let now = OffsetDateTime::UNIX_EPOCH;
        let target = OperationTarget::new(TargetId::generate(), endpoint.id());
        let queued = submission
            .submit(
                OperationSource::Standalone,
                vec![target],
                one_command(),
                now,
            )
            .await?;
        let succeeded = Operation::try_from_parts(
            OperationId::generate(),
            OperationSource::Site,
            vec![OperationTarget::new(TargetId::generate(), endpoint.id())],
            one_command(),
            OperationState::Succeeded,
            now,
            now + Duration::SECOND,
        )?;
        store.create_operation(&succeeded).await?;

        let all = submission.list(None).await?;
        assert_eq!(all.len(), 2);
        let queued_only = submission.list(Some(OperationState::Queued)).await?;
        assert_eq!(queued_only.len(), 1);
        assert_eq!(queued_only[0], queued);
        let succeeded_only = submission.list(Some(OperationState::Succeeded)).await?;
        assert_eq!(succeeded_only.len(), 1);
        assert_eq!(succeeded_only[0], succeeded);
        assert_eq!(
            submission.list(Some(OperationState::Failed)).await?,
            Vec::new()
        );

        assert_eq!(submission.find(queued.id()).await?, Some(queued));
        assert_eq!(
            submission.find(OperationId::generate()).await?,
            None,
            "an unknown operation id must read back as None"
        );
        Ok(())
    }

    fn managed_endpoint() -> Result<Endpoint, Box<dyn Error>> {
        let now = OffsetDateTime::UNIX_EPOCH;
        Ok(Endpoint::try_new(
            EndpointId::generate(),
            EndpointDisplayName::parse("Rack A BMC")?,
            EndpointAddress::parse("https://192.0.2.10")?,
            TlsTrust::PinnedCertificate {
                certificate: TlsCertificate::from_der(b"submission test certificate".to_vec())?,
                trusted_at: now,
            },
            CredentialId::generate(),
            now,
            now,
        )?)
    }

    fn one_command() -> RedfishCommand {
        RedfishCommand::System(rutilus_domain::SystemCommand::Reset(
            rutilus_domain::ResetType::PowerCycle,
        ))
    }
}
