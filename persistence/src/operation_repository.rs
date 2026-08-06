use rutilus_domain::{
    Operation, OperationId, OperationSource, OperationSourceParseError, OperationState,
    OperationStateParseError, OperationTarget, OperationTimelineError,
};
use rutilus_entity::{operation, operation_target};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Atomically persists one operation and all of its targets.
    ///
    /// Delivery is at-least-once (design §15.4), so re-creating an operation
    /// id that is already stored is a no-op: the persisted row is
    /// authoritative and is never rewritten, which is what keeps a Center
    /// re-delivery from re-executing a finished operation. The operation and
    /// its targets commit in one transaction, so a target can never be
    /// persisted without its operation (or half of a batch without the rest).
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when write coordination fails, the
    /// transaction cannot commit, or a stored row violates an aggregate
    /// invariant.
    pub async fn create_operation(
        &self,
        operation: &Operation,
    ) -> Result<(), OperationRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(OperationRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        insert_operation_aggregate(&transaction, operation).await?;
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one complete operation aggregate by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when the query fails or any
    /// persisted component violates domain invariants.
    pub async fn find_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<Operation>, OperationRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        let Some(model) = operation::Entity::find_by_id(operation_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(OperationRepositoryError::Database)?;
            return Ok(None);
        };
        let domain = map_stored_operation(&transaction, operation_id, model).await?;
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(Some(domain))
    }

    /// Persists one state step of an operation (design §13.3).
    ///
    /// `occurred_at` becomes the row's update time, so the persisted timeline
    /// records exactly when each state took effect. A step is refused with a
    /// conflict-style error when the operation id is unknown or the persisted
    /// state is terminal: a finished operation (`Succeeded`/`Failed`/
    /// `Cancelled`/`Unknown`) can never be resurrected, which protects a
    /// restart recovery sweep racing an in-flight execution from overwriting
    /// an already-final result. Non-terminal steps overwrite freely; the
    /// legality of the step itself is the domain state machine's decision,
    /// which the engine applies before calling this method.
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError::NotFound`] for an unknown id,
    /// [`OperationRepositoryError::TerminalConflict`] when the persisted state
    /// is terminal, and [`OperationRepositoryError`] variants for coordination
    /// or database failures.
    pub async fn apply_transition(
        &self,
        operation_id: OperationId,
        new_state: OperationState,
        occurred_at: OffsetDateTime,
    ) -> Result<(), OperationRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(OperationRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        let model = operation::Entity::find_by_id(operation_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?
            .ok_or(OperationRepositoryError::NotFound { operation_id })?;
        let current_state = model
            .state
            .parse::<OperationState>()
            .map_err(StoredOperationError::InvalidState)
            .map_err(|source| corrupt(operation_id, source))?;
        if current_state.is_terminal() {
            return Err(OperationRepositoryError::TerminalConflict {
                operation_id,
                state: current_state,
            });
        }
        let mut active = model.into_active_model();
        active.state = Set(new_state.as_str().to_owned());
        active.updated_at = Set(occurred_at);
        active
            .update(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?;
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(())
    }

    /// Lists every operation, optionally restricted to one exact state.
    ///
    /// The optional state filter backs the §13.6 restart recovery scan
    /// (`WaitingRemote` and other in-flight states) and the §13.7 batch
    /// outcome summary, both of which need one exact-state query. Results are
    /// ordered by creation time and identity so recovery replays in
    /// acceptance order.
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when the query fails or any
    /// persisted operation violates domain invariants.
    pub async fn list_operations(
        &self,
        state: Option<OperationState>,
    ) -> Result<Vec<Operation>, OperationRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        let mut query = operation::Entity::find();
        if let Some(state) = state {
            query = query.filter(operation::Column::State.eq(state.as_str()));
        }
        let models = query
            .order_by_asc(operation::Column::CreatedAt)
            .order_by_asc(operation::Column::Id)
            .all(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?;
        let mut operations = Vec::with_capacity(models.len());
        for model in models {
            let operation_id = OperationId::from_uuid(model.id);
            operations.push(map_stored_operation(&transaction, operation_id, model).await?);
        }
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(operations)
    }
}

async fn insert_operation_aggregate<C>(
    database: &C,
    domain: &Operation,
) -> Result<(), OperationRepositoryError>
where
    C: ConnectionTrait,
{
    let operation_id = domain.id();
    if operation::Entity::find_by_id(operation_id.into_uuid())
        .one(database)
        .await
        .map_err(OperationRepositoryError::Database)?
        .is_some()
    {
        // At-least-once delivery (design §15.4): the stored row is
        // authoritative and must not be rewritten.
        return Ok(());
    }
    operation::ActiveModel {
        id: Set(operation_id.into_uuid()),
        source: Set(domain.source().as_str().to_owned()),
        state: Set(domain.state().as_str().to_owned()),
        created_at: Set(domain.created_at()),
        updated_at: Set(domain.updated_at()),
    }
    .insert(database)
    .await
    .map_err(OperationRepositoryError::Database)?;
    for target in domain.targets() {
        operation_target::ActiveModel {
            operation_id: Set(operation_id.into_uuid()),
            target_id: Set(target.target_id().into_uuid()),
            endpoint_id: Set(target.endpoint_id().into_uuid()),
        }
        .insert(database)
        .await
        .map_err(OperationRepositoryError::Database)?;
    }
    Ok(())
}

async fn map_stored_operation<C>(
    database: &C,
    operation_id: OperationId,
    model: operation::Model,
) -> Result<Operation, OperationRepositoryError>
where
    C: ConnectionTrait,
{
    let source = model
        .source
        .parse::<OperationSource>()
        .map_err(StoredOperationError::InvalidSource)
        .map_err(|source| corrupt(operation_id, source))?;
    let state = model
        .state
        .parse::<OperationState>()
        .map_err(StoredOperationError::InvalidState)
        .map_err(|source| corrupt(operation_id, source))?;
    // Targets are reconstructed in target-identity order so the recovery
    // scan and batch reporting always see the same deterministic list.
    let targets = operation_target::Entity::find()
        .filter(operation_target::Column::OperationId.eq(operation_id.into_uuid()))
        .order_by_asc(operation_target::Column::TargetId)
        .all(database)
        .await
        .map_err(OperationRepositoryError::Database)?;
    let mut domain_targets = Vec::with_capacity(targets.len());
    for target in targets {
        domain_targets.push(OperationTarget::new(
            rutilus_domain::TargetId::from_uuid(target.target_id),
            rutilus_domain::EndpointId::from_uuid(target.endpoint_id),
        ));
    }
    Operation::try_from_parts(
        operation_id,
        source,
        domain_targets,
        state,
        model.created_at,
        model.updated_at,
    )
    .map_err(StoredOperationError::InvalidTimeline)
    .map_err(|source| corrupt(operation_id, source))
}

fn corrupt(operation_id: OperationId, source: StoredOperationError) -> OperationRepositoryError {
    OperationRepositoryError::Corrupt {
        operation_id,
        source,
    }
}

/// A controlled failure while creating, reading, or advancing operations.
#[derive(Debug, Error)]
pub enum OperationRepositoryError {
    #[error("operation write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("operation {operation_id} was not found")]
    NotFound { operation_id: OperationId },
    #[error(
        "operation {operation_id} is already in terminal state {state} and cannot be overwritten"
    )]
    TerminalConflict {
        operation_id: OperationId,
        state: OperationState,
    },
    #[error("stored operation {operation_id} is invalid: {source}")]
    Corrupt {
        operation_id: OperationId,
        #[source]
        source: StoredOperationError,
    },
    #[error("operation database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted operation data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredOperationError {
    #[error("operation state code is invalid: {0}")]
    InvalidState(#[source] OperationStateParseError),
    #[error("operation source code is invalid: {0}")]
    InvalidSource(#[source] OperationSourceParseError),
    #[error("operation timeline is invalid: {0}")]
    InvalidTimeline(#[source] OperationTimelineError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{EndpointId, TargetId};
    use rutilus_entity::{operation, operation_target};
    use sea_orm::{ActiveModelTrait, ColumnTrait, EntityTrait, QueryFilter, Set};
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    /// Every §13.2 state, so the stable-code round trip cannot miss a variant.
    const ALL_STATES: [OperationState; 9] = [
        OperationState::Queued,
        OperationState::Validating,
        OperationState::Running,
        OperationState::WaitingRemote,
        OperationState::Verifying,
        OperationState::Succeeded,
        OperationState::Failed,
        OperationState::Unknown,
        OperationState::Cancelled,
    ];

    /// Every §13.1 source, so the stable-code round trip cannot miss a variant.
    const ALL_SOURCES: [OperationSource; 3] = [
        OperationSource::Standalone,
        OperationSource::Site,
        OperationSource::Center,
    ];

    #[tokio::test]
    async fn creates_and_loads_operations_with_all_targets() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let operation = queued_operation(
            OperationSource::Standalone,
            &three_sorted_targets(),
            OffsetDateTime::now_utc(),
        );

        store.create_operation(&operation).await?;
        assert_eq!(
            store.find_operation(operation.id()).await?,
            Some(operation.clone())
        );
        assert!(
            store
                .find_operation(OperationId::generate())
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn repeated_delivery_never_rewrites_the_stored_row() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let operation =
            queued_operation(OperationSource::Center, &three_sorted_targets(), created_at);

        store.create_operation(&operation).await?;
        store.create_operation(&operation).await?;
        assert_eq!(
            store.find_operation(operation.id()).await?,
            Some(operation.clone())
        );

        // The re-delivered queued aggregate must not resurrect a row that has
        // already moved forward (design §15.4 single business effect).
        let transitioned_at = created_at + Duration::SECOND;
        store
            .apply_transition(operation.id(), OperationState::Validating, transitioned_at)
            .await?;
        store.create_operation(&operation).await?;
        let stored = store
            .find_operation(operation.id())
            .await?
            .ok_or("stored operation is missing")?;
        assert_eq!(stored.state(), OperationState::Validating);
        assert_eq!(stored.updated_at(), transitioned_at);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn apply_transition_records_each_step_and_its_time() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let operation =
            queued_operation(OperationSource::Site, &three_sorted_targets(), created_at);
        store.create_operation(&operation).await?;
        let operation_id = operation.id();

        let validated_at = created_at + Duration::SECOND;
        store
            .apply_transition(operation_id, OperationState::Validating, validated_at)
            .await?;
        let validating = store
            .find_operation(operation_id)
            .await?
            .ok_or("validating operation is missing")?;
        assert_eq!(validating.state(), OperationState::Validating);
        assert_eq!(validating.updated_at(), validated_at);
        assert_eq!(validating.targets(), operation.targets());

        let running_at = validated_at + Duration::SECOND;
        store
            .apply_transition(operation_id, OperationState::Running, running_at)
            .await?;
        let running = store
            .find_operation(operation_id)
            .await?
            .ok_or("running operation is missing")?;
        assert_eq!(running.state(), OperationState::Running);
        assert_eq!(running.updated_at(), running_at);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn apply_transition_rejects_unknown_ids_and_terminal_resurrection()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let unknown = OperationId::generate();
        assert!(matches!(
            store
                .apply_transition(unknown, OperationState::Running, OffsetDateTime::now_utc())
                .await,
            Err(OperationRepositoryError::NotFound { operation_id })
                if operation_id == unknown
        ));

        let created_at = OffsetDateTime::now_utc();
        let operation = queued_operation(
            OperationSource::Standalone,
            &three_sorted_targets(),
            created_at,
        );
        store.create_operation(&operation).await?;
        let operation_id = operation.id();
        let succeeded_at = created_at + Duration::SECOND;
        store
            .apply_transition(operation_id, OperationState::Succeeded, succeeded_at)
            .await?;
        assert!(matches!(
            store
                .apply_transition(
                    operation_id,
                    OperationState::Running,
                    succeeded_at + Duration::SECOND,
                )
                .await,
            Err(OperationRepositoryError::TerminalConflict {
                operation_id: id,
                state: OperationState::Succeeded,
            }) if id == operation_id
        ));
        let stored = store
            .find_operation(operation_id)
            .await?
            .ok_or("stored operation is missing")?;
        assert_eq!(stored.state(), OperationState::Succeeded);
        assert_eq!(stored.updated_at(), succeeded_at);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// The write gate serializes writers, so two racing terminal verdicts
    /// (a restart recovery sweep and the in-flight execution both confirming
    /// the same outcome, §13.6) land exactly once: the loser must observe the
    /// already-terminal row and fail with a conflict instead of writing.
    #[tokio::test]
    async fn serializes_competing_terminal_transitions_without_resurrection()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let operation =
            queued_operation(OperationSource::Site, &three_sorted_targets(), created_at);
        store.create_operation(&operation).await?;
        let operation_id = operation.id();
        let first_at = created_at + Duration::SECOND;
        let second_at = created_at + Duration::SECOND * 2;

        let (first, second) = tokio::join!(
            store.apply_transition(operation_id, OperationState::Succeeded, first_at),
            store.apply_transition(operation_id, OperationState::Succeeded, second_at),
        );
        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            1,
            "exactly one racing terminal verdict may land"
        );
        for result in [first, second] {
            if let Err(error) = result {
                assert!(matches!(
                    error,
                    OperationRepositoryError::TerminalConflict {
                        operation_id: id,
                        state: OperationState::Succeeded,
                    } if id == operation_id
                ));
            }
        }

        let stored = store
            .find_operation(operation_id)
            .await?
            .ok_or("stored operation is missing")?;
        assert_eq!(stored.state(), OperationState::Succeeded);
        let winner_at = stored.updated_at();
        assert!(
            winner_at == first_at || winner_at == second_at,
            "the winning transition's occurred_at must be recorded"
        );

        // The terminal row can never be reopened by the losing side.
        assert!(matches!(
            store
                .apply_transition(
                    operation_id,
                    OperationState::Running,
                    created_at + Duration::SECOND * 3,
                )
                .await,
            Err(OperationRepositoryError::TerminalConflict { .. })
        ));
        let stored = store
            .find_operation(operation_id)
            .await?
            .ok_or("stored operation is missing")?;
        assert_eq!(stored.state(), OperationState::Succeeded);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// Non-terminal steps overwrite freely (§13.3), so two concurrent
    /// advances both land; the final row must pair the winning state with the
    /// winning transition's time and never tear the two apart.
    #[tokio::test]
    async fn serializes_competing_non_terminal_transitions_last_write_wins()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let operation =
            queued_operation(OperationSource::Site, &three_sorted_targets(), created_at);
        store.create_operation(&operation).await?;
        let operation_id = operation.id();
        let first_at = created_at + Duration::SECOND;
        let second_at = created_at + Duration::SECOND * 2;

        let (first, second) = tokio::join!(
            store.apply_transition(operation_id, OperationState::Validating, first_at),
            store.apply_transition(operation_id, OperationState::Running, second_at),
        );
        assert_eq!(
            usize::from(first.is_ok()) + usize::from(second.is_ok()),
            2,
            "non-terminal steps must overwrite freely"
        );

        let stored = store
            .find_operation(operation_id)
            .await?
            .ok_or("stored operation is missing")?;
        let state = stored.state();
        let updated_at = stored.updated_at();
        let consistent = matches!(
            (state, updated_at),
            (OperationState::Validating, t) if t == first_at
        ) || matches!(
            (state, updated_at),
            (OperationState::Running, t) if t == second_at
        );
        assert!(
            consistent,
            "state {state} must pair with its own occurred_at {updated_at}"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn list_operations_filters_by_state_in_acceptance_order() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let waiting_a = queued_operation(OperationSource::Site, &three_sorted_targets(), base);
        let queued = queued_operation(
            OperationSource::Standalone,
            &three_sorted_targets(),
            base + Duration::SECOND,
        );
        let waiting_b = queued_operation(
            OperationSource::Center,
            &three_sorted_targets(),
            base + Duration::SECOND * 2,
        );
        let succeeded = queued_operation(
            OperationSource::Site,
            &three_sorted_targets(),
            base + Duration::SECOND * 3,
        );
        for operation in [&waiting_a, &queued, &waiting_b, &succeeded] {
            store.create_operation(operation).await?;
        }
        store
            .apply_transition(
                waiting_a.id(),
                OperationState::WaitingRemote,
                base + Duration::SECOND,
            )
            .await?;
        store
            .apply_transition(
                waiting_b.id(),
                OperationState::WaitingRemote,
                base + Duration::SECOND * 2,
            )
            .await?;
        store
            .apply_transition(
                succeeded.id(),
                OperationState::Succeeded,
                base + Duration::SECOND * 3,
            )
            .await?;

        let all = store.list_operations(None).await?;
        assert_eq!(
            all.iter().map(Operation::id).collect::<Vec<_>>(),
            vec![waiting_a.id(), queued.id(), waiting_b.id(), succeeded.id()],
            "listing without a filter must return every operation in acceptance order"
        );
        let waiting = store
            .list_operations(Some(OperationState::WaitingRemote))
            .await?;
        assert_eq!(
            waiting.iter().map(Operation::id).collect::<Vec<_>>(),
            vec![waiting_a.id(), waiting_b.id()]
        );
        let finished = store
            .list_operations(Some(OperationState::Succeeded))
            .await?;
        assert_eq!(
            finished.iter().map(Operation::id).collect::<Vec<_>>(),
            vec![succeeded.id()]
        );
        assert!(
            store
                .list_operations(Some(OperationState::Verifying))
                .await?
                .is_empty()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_an_operation_cascades_to_its_targets() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let operation = queued_operation(
            OperationSource::Standalone,
            &three_sorted_targets(),
            OffsetDateTime::now_utc(),
        );
        store.create_operation(&operation).await?;
        let operation_id = operation.id();
        let uuid = operation_id.into_uuid();

        operation::Entity::delete_by_id(uuid)
            .exec(&store.database)
            .await?;

        assert!(
            store.find_operation(operation_id).await?.is_none(),
            "deleting an operation must remove the operation row"
        );
        assert_eq!(
            operation_target::Entity::find()
                .filter(operation_target::Column::OperationId.eq(uuid))
                .all(&store.database)
                .await?
                .len(),
            0,
            "deleting an operation must cascade to its targets"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn stable_source_and_state_codes_round_trip() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let mut created_at = OffsetDateTime::now_utc();
        for source in ALL_SOURCES {
            let operation = queued_operation(source, &three_sorted_targets(), created_at);
            store.create_operation(&operation).await?;
            assert_eq!(
                store.find_operation(operation.id()).await?,
                Some(operation),
                "source {} must survive persistence unchanged",
                source.as_str()
            );
            created_at += Duration::SECOND;
        }
        for state in ALL_STATES {
            let operation =
                queued_operation(OperationSource::Center, &three_sorted_targets(), created_at);
            store.create_operation(&operation).await?;
            store
                .apply_transition(operation.id(), state, created_at + Duration::SECOND)
                .await?;
            let stored = store
                .find_operation(operation.id())
                .await?
                .ok_or("stored operation is missing")?;
            assert_eq!(
                stored.state(),
                state,
                "state code {} must survive persistence unchanged",
                state.as_str()
            );
            created_at += Duration::SECOND;
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn reports_an_inverted_timeline_as_corrupt() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        // The database has no timeline constraint, so a row with a backwards
        // update time is written directly; reading it back must refuse it.
        let operation_id = OperationId::generate();
        operation::ActiveModel {
            id: Set(operation_id.into_uuid()),
            source: Set(String::from("standalone")),
            state: Set(String::from("queued")),
            created_at: Set(created_at),
            updated_at: Set(created_at - Duration::SECOND),
        }
        .insert(&store.database)
        .await?;

        assert!(matches!(
            store.find_operation(operation_id).await,
            Err(OperationRepositoryError::Corrupt {
                operation_id: id,
                source: StoredOperationError::InvalidTimeline(_),
            }) if id == operation_id
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// Three targets with sorted target identities, so the deterministic
    /// target-identity read order restores the aggregate exactly.
    fn three_sorted_targets() -> Vec<OperationTarget> {
        let endpoint_a = EndpointId::generate();
        let endpoint_b = EndpointId::generate();
        let mut target_ids = vec![
            TargetId::generate(),
            TargetId::generate(),
            TargetId::generate(),
        ];
        target_ids.sort();
        let mut targets = Vec::with_capacity(target_ids.len());
        for (index, target_id) in target_ids.into_iter().enumerate() {
            let endpoint_id = if index % 2 == 0 {
                endpoint_a
            } else {
                endpoint_b
            };
            targets.push(OperationTarget::new(target_id, endpoint_id));
        }
        targets
    }

    fn queued_operation(
        source: OperationSource,
        targets: &[OperationTarget],
        created_at: OffsetDateTime,
    ) -> Operation {
        Operation::new(
            OperationId::generate(),
            source,
            targets.to_vec(),
            created_at,
        )
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
