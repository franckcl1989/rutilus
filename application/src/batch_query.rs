//! The §13.7 batch reporting queries.
//!
//! Design section 13.7 derives every batch-level fact from the children: the
//! batch state is [`derive_batch_state`] over the children's individual
//! states, and the outcome summary is [`summarize`] over each child's state
//! and persisted failure kind. This use case is the reporting entry point of
//! that rule — it reads the persisted parents and children through the
//! [`OperationStore`] boundary and projects the derived facts, so the Web
//! layer never derives a batch verdict itself.
//!
//! The store boundary is used directly (not through the engine): the engine
//! owns the operation lifecycle and adds no projection, exactly like the
//! submission use case's `find` read.

use std::error::Error;

use rutilus_domain::{
    BatchOperation, BatchOperationId, BatchOperationState, BatchOutcomeCounts, FailureKind,
    Operation, OperationOutcome, derive_batch_state, summarize,
};
use thiserror::Error;

use crate::OperationStore;

/// Answers the §13.7 batch reporting queries.
///
/// `Store` is the same [`OperationStore`] the engine and the submission use
/// case compose; the runtime supplies one `SqliteStore` implementing it.
pub struct BatchQuery<Store> {
    store: Store,
}

/// One batch parent projected with its derived state and outcome summary
/// (§13.7).
///
/// The state and counts are derived from the children at query time and are
/// never stored, so this value is a pure snapshot of the moment it was read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchSummary {
    batch: BatchOperation,
    state: BatchOperationState,
    outcomes: BatchOutcomeCounts,
}

impl BatchSummary {
    #[must_use]
    pub const fn new(
        batch: BatchOperation,
        state: BatchOperationState,
        outcomes: BatchOutcomeCounts,
    ) -> Self {
        Self {
            batch,
            state,
            outcomes,
        }
    }

    /// Returns the parent record the summary was derived from.
    #[must_use]
    pub const fn batch(&self) -> &BatchOperation {
        &self.batch
    }

    #[must_use]
    pub const fn state(&self) -> BatchOperationState {
        self.state
    }

    /// Returns the outcome buckets of the batch's children.
    #[must_use]
    pub const fn outcomes(&self) -> BatchOutcomeCounts {
        self.outcomes
    }
}

/// One batch's full report: the summary plus every child operation with its
/// persisted failure classification (§13.7).
///
/// The children are ordinary persisted operations in target order, each
/// paired with its persisted failure kind (`None` for every child that is
/// not a classified failure). The summary's buckets derive from the same
/// pairs, and the response projection carries the per-child classification
/// (E3-4) so the console can render a provably-unsupported refusal instead
/// of an ordinary failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchDetail {
    summary: BatchSummary,
    children: Vec<(Operation, Option<FailureKind>)>,
}

impl BatchDetail {
    #[must_use]
    pub const fn new(
        summary: BatchSummary,
        children: Vec<(Operation, Option<FailureKind>)>,
    ) -> Self {
        Self { summary, children }
    }

    #[must_use]
    pub const fn summary(&self) -> &BatchSummary {
        &self.summary
    }

    /// Returns the batch's children in target order, each paired with its
    /// persisted failure classification.
    #[must_use]
    pub fn children(&self) -> &[(Operation, Option<FailureKind>)] {
        &self.children
    }
}

impl<Store> BatchQuery<Store>
where
    Store: OperationStore,
{
    #[must_use]
    pub const fn new(store: Store) -> Self {
        Self { store }
    }

    /// Lists every batch parent with its derived state and outcome summary,
    /// in acceptance order (creation time, then identity — the same
    /// deterministic order as the operation listing).
    ///
    /// Each batch's children are loaded once here and never again for the
    /// same call, so the summary of a batch that finishes mid-listing is
    /// still a single consistent snapshot per batch.
    ///
    /// The listing reads one child batch per parent (the `B+1` shape, V4P-4,
    /// registered): each child read is indexed by the batch id, the batch
    /// count of one console page is small, and a merged read — one parents
    /// query plus one children query over the whole id set — needs a store
    /// boundary that does not exist yet (`OperationStore` has no
    /// batch-listing-with-children method), so the merge is a follow-up on
    /// the store boundary rather than a query-shape change this use case
    /// can make.
    ///
    /// # Errors
    ///
    /// Returns [`BatchQueryError::Store`] when the store rejects a read; one
    /// corrupt parent or child poisons the whole listing, exactly like the
    /// operation listing's corrupt-aggregate rule.
    pub async fn list_batches(&self) -> Result<Vec<BatchSummary>, BatchQueryError<Store::Error>> {
        let batches = self
            .store
            .list_batches()
            .await
            .map_err(BatchQueryError::Store)?;
        let mut summaries = Vec::with_capacity(batches.len());
        for batch in batches {
            summaries.push(self.summarize_batch(batch).await?);
        }
        Ok(summaries)
    }

    /// Reads one batch's full report; `None` when the batch id is unknown.
    ///
    /// The summary and the children are read in one call so a report never
    /// mixes two moments: the state and counts derive from exactly the
    /// children the report carries.
    ///
    /// # Errors
    ///
    /// Returns [`BatchQueryError::Store`] when the store rejects a read.
    pub async fn batch_detail(
        &self,
        batch_id: BatchOperationId,
    ) -> Result<Option<BatchDetail>, BatchQueryError<Store::Error>> {
        let Some(batch) = self
            .store
            .find_batch(batch_id)
            .await
            .map_err(BatchQueryError::Store)?
        else {
            return Ok(None);
        };
        let classified = self
            .store
            .list_batch_children(batch_id)
            .await
            .map_err(BatchQueryError::Store)?;
        let states = classified
            .iter()
            .map(|(operation, _)| operation.state())
            .collect::<Vec<_>>();
        let outcomes = classified
            .iter()
            .map(|(operation, kind)| OperationOutcome::new(operation.state(), *kind))
            .collect::<Vec<_>>();
        // The classified children are carried whole into the report: the
        // response projection pairs each child with its persisted failure
        // kind (E3-4), so the classification is never dropped between the
        // store read and the console wire.
        Ok(Some(BatchDetail::new(
            BatchSummary::new(batch, derive_batch_state(&states), summarize(&outcomes)),
            classified,
        )))
    }

    /// Derives one batch's summary from its persisted children.
    ///
    /// # Errors
    ///
    /// Returns [`BatchQueryError::Store`] when the store rejects the child
    /// read.
    async fn summarize_batch(
        &self,
        batch: BatchOperation,
    ) -> Result<BatchSummary, BatchQueryError<Store::Error>> {
        let classified = self
            .store
            .list_batch_children(batch.id())
            .await
            .map_err(BatchQueryError::Store)?;
        let states = classified
            .iter()
            .map(|(operation, _)| operation.state())
            .collect::<Vec<_>>();
        let outcomes = classified
            .iter()
            .map(|(operation, kind)| OperationOutcome::new(operation.state(), *kind))
            .collect::<Vec<_>>();
        Ok(BatchSummary::new(
            batch,
            derive_batch_state(&states),
            summarize(&outcomes),
        ))
    }
}

/// A controlled failure while answering one §13.7 batch reporting query.
///
/// The single generic parameter is the injected store's error type, so every
/// persistence failure stays reachable as the source of an error chain.
#[derive(Debug, Error)]
pub enum BatchQueryError<StoreError>
where
    StoreError: Error + 'static,
{
    /// The operation store rejected a read.
    #[error("batch reporting store read failed: {0}")]
    Store(#[source] StoreError),
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, sync::Mutex};

    use rutilus_domain::{
        BatchOperation, BatchOperationId, BatchOperationState, EndpointId, FailureKind,
        OperationId, OperationSource, OperationState, OperationTarget, RedfishCommand, ResetType,
        SystemCommand, TargetId,
    };
    use rutilus_operation_engine::{BoundaryFuture, ClassifiedBatchChild};
    use thiserror::Error as ThisError;
    use time::{Duration, OffsetDateTime};

    use super::*;

    /// The single mock store failure mode.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, ThisError)]
    #[error("simulated batch reporting store failure")]
    enum MockError {
        Store,
    }

    /// In-memory fake behind the [`OperationStore`] boundary, recording every
    /// persisted row exactly like the production `SqliteStore`, including the
    /// per-child failure kinds of the batch reporting read.
    struct MockStore {
        rows: Mutex<HashMap<OperationId, Operation>>,
        batch_rows: Mutex<HashMap<BatchOperationId, BatchOperation>>,
        batch_children: Mutex<HashMap<BatchOperationId, Vec<ClassifiedBatchChild>>>,
        fail_reads: bool,
    }

    impl MockStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                batch_rows: Mutex::new(HashMap::new()),
                batch_children: Mutex::new(HashMap::new()),
                fail_reads: false,
            }
        }

        fn with_failing_reads(mut self) -> Self {
            self.fail_reads = true;
            self
        }

        fn insert_batch(
            &self,
            batch: BatchOperation,
            children: &[(OperationState, Option<FailureKind>)],
        ) -> Result<(BatchOperation, Vec<Operation>), MockError> {
            let mut operations = Vec::with_capacity(children.len());
            for (state, _) in children {
                // Rehydration builds the exact child record the store would
                // hold: one single-target operation at the given state with
                // the transition time mirroring the persisted timeline.
                let operation = Operation::try_from_parts(
                    OperationId::generate(),
                    batch.source(),
                    vec![OperationTarget::new(
                        TargetId::generate(),
                        EndpointId::generate(),
                    )],
                    batch.command(),
                    *state,
                    batch.created_at(),
                    batch.created_at() + Duration::SECOND,
                )
                .map_err(|_| MockError::Store)?;
                operations.push(operation);
            }
            operations.sort_by_key(|child| child.targets()[0].target_id());
            let pairs = operations
                .iter()
                .cloned()
                .zip(children.iter().map(|(_, kind)| *kind))
                .collect::<Vec<_>>();
            self.batch_rows
                .lock()
                .map_err(|_| MockError::Store)?
                .insert(batch.id(), batch.clone());
            self.batch_children
                .lock()
                .map_err(|_| MockError::Store)?
                .insert(batch.id(), pairs);
            Ok((batch, operations))
        }

        fn find_batch_owned(
            &self,
            batch_id: BatchOperationId,
        ) -> Result<Option<BatchOperation>, MockError> {
            if self.fail_reads {
                return Err(MockError::Store);
            }
            Ok(self
                .batch_rows
                .lock()
                .map_err(|_| MockError::Store)?
                .get(&batch_id)
                .cloned())
        }

        fn list_batches_owned(&self) -> Result<Vec<BatchOperation>, MockError> {
            if self.fail_reads {
                return Err(MockError::Store);
            }
            let mut batches = self
                .batch_rows
                .lock()
                .map_err(|_| MockError::Store)?
                .values()
                .cloned()
                .collect::<Vec<_>>();
            batches.sort_by_key(|batch| (batch.created_at(), batch.id()));
            Ok(batches)
        }

        fn list_batch_children_owned(
            &self,
            batch_id: BatchOperationId,
        ) -> Result<Vec<ClassifiedBatchChild>, MockError> {
            if self.fail_reads {
                return Err(MockError::Store);
            }
            Ok(self
                .batch_children
                .lock()
                .map_err(|_| MockError::Store)?
                .get(&batch_id)
                .cloned()
                .unwrap_or_default())
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
                if self.fail_reads {
                    return Err(MockError::Store);
                }
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

        fn apply_transition_if_current(
            &self,
            operation_id: OperationId,
            expected_state: OperationState,
            new_state: OperationState,
            occurred_at: OffsetDateTime,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut rows = self.rows.lock().map_err(|_| MockError::Store)?;
                let row = rows.get(&operation_id).ok_or(MockError::Store)?.clone();
                if row.state() != expected_state {
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

        fn record_failure_kind(
            &self,
            _operation_id: OperationId,
            _kind: FailureKind,
        ) -> BoundaryFuture<'_, Result<(), Self::Error>> {
            // The reporting query never classifies; the executor's refusal
            // path owns that write, so this stub is unreachable here.
            Box::pin(async move { Ok(()) })
        }

        fn list_operations(
            &self,
            _state: Option<OperationState>,
        ) -> BoundaryFuture<'_, Result<Vec<Operation>, Self::Error>> {
            Box::pin(async move { Ok(Vec::new()) })
        }

        fn create_batch<'a>(
            &'a self,
            batch: &'a BatchOperation,
            children: &'a [Operation],
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                let mut batch_rows = self.batch_rows.lock().map_err(|_| MockError::Store)?;
                if batch_rows.contains_key(&batch.id()) {
                    return Ok(());
                }
                batch_rows.insert(batch.id(), batch.clone());
                for child in children {
                    self.rows
                        .lock()
                        .map_err(|_| MockError::Store)?
                        .entry(child.id())
                        .or_insert_with(|| child.clone());
                }
                self.batch_children
                    .lock()
                    .map_err(|_| MockError::Store)?
                    .insert(
                        batch.id(),
                        children
                            .iter()
                            .cloned()
                            .map(|child| (child, None))
                            .collect(),
                    );
                Ok(())
            })
        }

        fn find_batch(
            &self,
            batch_id: BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Option<BatchOperation>, Self::Error>> {
            Box::pin(async move { self.find_batch_owned(batch_id) })
        }

        fn list_batches(&self) -> BoundaryFuture<'_, Result<Vec<BatchOperation>, Self::Error>> {
            Box::pin(async move { self.list_batches_owned() })
        }

        fn list_batch_children(
            &self,
            batch_id: BatchOperationId,
        ) -> BoundaryFuture<'_, Result<Vec<ClassifiedBatchChild>, Self::Error>> {
            Box::pin(async move { self.list_batch_children_owned(batch_id) })
        }
    }

    /// One representative write command for every query test.
    fn one_command() -> RedfishCommand {
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
    }

    /// One batch parent at the given acceptance time.
    fn batch_at(created_at: OffsetDateTime) -> BatchOperation {
        BatchOperation::new(
            BatchOperationId::generate(),
            OperationSource::Site,
            one_command(),
            created_at,
        )
    }

    #[tokio::test]
    async fn list_batches_derives_state_and_buckets_outcomes() -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let query = BatchQuery::new(&store);
        let base = OffsetDateTime::UNIX_EPOCH;

        // All succeeded: the batch achieved its whole intent.
        let (succeeded, _) = store.insert_batch(
            batch_at(base),
            &[
                (OperationState::Succeeded, None),
                (OperationState::Succeeded, None),
            ],
        )?;
        // One in-flight child: the batch is still running, and the partial
        // sum is below total.
        let (running, _) = store.insert_batch(
            batch_at(base + Duration::SECOND),
            &[
                (OperationState::Succeeded, None),
                (OperationState::Queued, None),
            ],
        )?;
        // A classified failure: the batch failed and the failed bucket
        // separates the unsupported verdict from the ordinary failure.
        let (failed, _) = store.insert_batch(
            batch_at(base + Duration::SECOND * 2),
            &[
                (
                    OperationState::Failed,
                    Some(FailureKind::CapabilityUnsupported),
                ),
                (OperationState::Failed, None),
                (OperationState::Succeeded, None),
            ],
        )?;
        // A cancellation mix: every child cancelled is the honest fifth
        // bucket; a cancelled-and-failed mix derives failed.
        let (cancelled, _) = store.insert_batch(
            batch_at(base + Duration::SECOND * 3),
            &[
                (OperationState::Cancelled, None),
                (OperationState::Cancelled, None),
            ],
        )?;
        let (mixed, _) = store.insert_batch(
            batch_at(base + Duration::SECOND * 4),
            &[
                (OperationState::Cancelled, None),
                (OperationState::Unknown, None),
            ],
        )?;

        let summaries = query.list_batches().await?;

        assert_eq!(summaries.len(), 5);
        // Acceptance order, exactly like the parent listing.
        assert_eq!(summaries[0].batch().id(), succeeded.id());
        assert_eq!(summaries[4].batch().id(), mixed.id());

        assert_eq!(summaries[0].state(), BatchOperationState::Succeeded);
        assert_eq!(summaries[0].outcomes().succeeded(), 2);
        assert_eq!(summaries[0].outcomes().total(), 2);

        assert_eq!(summaries[1].batch().id(), running.id());
        assert_eq!(summaries[1].state(), BatchOperationState::Running);
        assert_eq!(summaries[1].outcomes().succeeded(), 1);
        assert_eq!(
            summaries[1].outcomes().total(),
            2,
            "in-flight children are counted in total but in no bucket"
        );

        assert_eq!(summaries[2].batch().id(), failed.id());
        assert_eq!(summaries[2].state(), BatchOperationState::Failed);
        assert_eq!(summaries[2].outcomes().failed(), 1);
        assert_eq!(summaries[2].outcomes().unsupported(), 1);
        assert_eq!(summaries[2].outcomes().succeeded(), 1);
        assert_eq!(summaries[2].outcomes().total(), 3);

        assert_eq!(summaries[3].batch().id(), cancelled.id());
        assert_eq!(summaries[3].state(), BatchOperationState::Cancelled);
        assert_eq!(summaries[3].outcomes().cancelled(), 2);

        assert_eq!(summaries[4].state(), BatchOperationState::Unknown);
        assert_eq!(summaries[4].outcomes().cancelled(), 1);
        assert_eq!(summaries[4].outcomes().unknown(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn batch_detail_returns_the_summary_and_every_child() -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let query = BatchQuery::new(&store);
        let base = OffsetDateTime::UNIX_EPOCH;
        let (batch, _) = store.insert_batch(
            batch_at(base),
            &[
                (
                    OperationState::Failed,
                    Some(FailureKind::CapabilityUnsupported),
                ),
                (OperationState::Succeeded, None),
                (OperationState::Running, None),
            ],
        )?;

        let detail = query
            .batch_detail(batch.id())
            .await?
            .ok_or("the stored batch must read back")?;

        assert_eq!(detail.summary().batch().id(), batch.id());
        // One child still running: the batch derives Running, and the
        // classified failure sits in the unsupported bucket.
        assert_eq!(detail.summary().state(), BatchOperationState::Running);
        assert_eq!(detail.summary().outcomes().unsupported(), 1);
        assert_eq!(detail.summary().outcomes().succeeded(), 1);
        assert_eq!(detail.summary().outcomes().total(), 3);
        // The full child list in target order, each paired with its persisted
        // failure classification (E3-4): the provably-unsupported refusal
        // keeps its kind, and the ordinary outcomes carry none.
        assert_eq!(detail.children().len(), 3);
        let ids = detail
            .children()
            .iter()
            .map(|(child, _)| child.targets()[0].target_id())
            .collect::<Vec<_>>();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted, "children must read back in target order");
        let classified = detail
            .children()
            .iter()
            .filter(|(_, kind)| kind.is_some())
            .collect::<Vec<_>>();
        assert_eq!(classified.len(), 1, "exactly one child is classified");
        let (child, kind) = classified[0];
        assert_eq!(*kind, Some(FailureKind::CapabilityUnsupported));
        assert_eq!(
            child.state(),
            OperationState::Failed,
            "the classification is a fact of a failed child"
        );
        assert_eq!(
            detail
                .children()
                .iter()
                .filter(|(_, kind)| kind.is_none())
                .count(),
            2,
            "every ordinary outcome reads back unclassified"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unknown_batch_id_reads_back_as_none() -> Result<(), Box<dyn Error>> {
        let store = MockStore::new();
        let query = BatchQuery::new(&store);

        assert!(
            query
                .batch_detail(BatchOperationId::generate())
                .await?
                .is_none()
        );
        Ok(())
    }

    #[tokio::test]
    async fn store_failures_propagate_with_their_source() -> Result<(), Box<dyn Error>> {
        let store = MockStore::new().with_failing_reads();
        let query = BatchQuery::new(&store);

        let list_error = query
            .list_batches()
            .await
            .err()
            .ok_or("a failing store must surface from the listing")?;
        assert!(matches!(
            list_error,
            BatchQueryError::Store(MockError::Store)
        ));
        let chain_source = std::error::Error::source(&list_error)
            .ok_or("the query error must expose its boundary source")?;
        assert_eq!(chain_source.to_string(), MockError::Store.to_string());

        let detail_error = query
            .batch_detail(BatchOperationId::generate())
            .await
            .err()
            .ok_or("a failing store must surface from the detail read")?;
        assert!(matches!(
            detail_error,
            BatchQueryError::Store(MockError::Store)
        ));
        Ok(())
    }
}
