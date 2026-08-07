use rutilus_domain::{
    BatchOperation, BatchOperationId, FailureKind, FailureKindParseError, Operation, OperationId,
    OperationSource, OperationSourceParseError, OperationState, OperationStateParseError,
    OperationTarget, OperationTimelineError, RedfishCommand,
};
use rutilus_entity::{batch_operation, operation, operation_target};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, IntoActiveModel,
    QueryFilter, QueryOrder, Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::SqliteStore;

impl SqliteStore {
    /// Atomically persists one operation and all of its targets.
    ///
    /// The typed command is stored as its serde JSON serialization — the §9.4
    /// `TypedPayloadJson` rule applied to commands: the column can only ever
    /// hold JSON produced by a type successfully serialized, never arbitrary
    /// hand-written JSON, and the database does not parse the structure.
    /// Reading it back goes through the domain type again (see
    /// [`Self::find_operation`]).
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
    /// transaction cannot commit, the command cannot be serialized, or a
    /// stored row violates an aggregate invariant.
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
        insert_operation_aggregate(&transaction, operation, None).await?;
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(())
    }

    /// Atomically persists one batch parent and every child operation
    /// (design §13.7).
    ///
    /// The parent row carries the submission facts — source, the typed
    /// command as its §9.4 serde JSON serialization, and the acceptance
    /// time — and each child is persisted through the same
    /// [`Self::create_operation`] aggregate write with its `batch_id` link
    /// set, so a child can never exist without its batch (or half a batch
    /// without the rest): the parent and all children commit in one
    /// transaction.
    ///
    /// Delivery is at-least-once (design §15.4), exactly like
    /// [`Self::create_operation`]: a batch id that is already stored is a
    /// no-op — the persisted batch and its children are authoritative and
    /// are never rewritten, which is what keeps a re-delivered batch from
    /// re-inserting its children (single business effect per batch).
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when write coordination fails, the
    /// transaction cannot commit, a command cannot be serialized, or a stored
    /// row violates an aggregate invariant.
    pub async fn create_batch(
        &self,
        batch: &BatchOperation,
        children: &[Operation],
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
        let batch_id = batch.id().into_uuid();
        if batch_operation::Entity::find_by_id(batch_id)
            .one(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?
            .is_some()
        {
            // At-least-once delivery (design §15.4): the stored batch is
            // authoritative and must never be rewritten, and its children
            // must never be re-inserted.
            transaction
                .commit()
                .await
                .map_err(OperationRepositoryError::Database)?;
            return Ok(());
        }
        batch_operation::ActiveModel {
            id: Set(batch_id),
            source: Set(batch.source().as_str().to_owned()),
            command: Set(serialize_command(&batch.command())?),
            created_at: Set(batch.created_at()),
        }
        .insert(&transaction)
        .await
        .map_err(OperationRepositoryError::Database)?;
        for child in children {
            insert_operation_aggregate(&transaction, child, Some(batch_id)).await?;
        }
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one batch parent by stable identity.
    ///
    /// The stored command JSON is rehydrated through the domain
    /// [`RedfishCommand`] deserializer with the same corrupt-aggregate rule
    /// as [`Self::find_operation`]: a payload this build cannot deserialize,
    /// or a source code it cannot classify, makes the whole parent
    /// [`OperationRepositoryError::BatchCorrupt`] instead of being
    /// half-understood.
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when the query fails or any
    /// persisted component violates domain invariants.
    pub async fn find_batch(
        &self,
        batch_id: BatchOperationId,
    ) -> Result<Option<BatchOperation>, OperationRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        let Some(model) = batch_operation::Entity::find_by_id(batch_id.into_uuid())
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
        let domain = map_stored_batch(batch_id, &model)?;
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(Some(domain))
    }

    /// Lists every batch parent in acceptance order.
    ///
    /// Results are ordered by creation time and identity so batch reporting
    /// (design §13.7) replays the same deterministic order as the operation
    /// listing. Each listed row is rehydrated as a complete parent — including
    /// its command — so one corrupt command poisons the whole listing, exactly
    /// like [`Self::list_operations`].
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when the query fails or any
    /// persisted batch violates domain invariants.
    pub async fn list_batches(&self) -> Result<Vec<BatchOperation>, OperationRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        let models = batch_operation::Entity::find()
            .order_by_asc(batch_operation::Column::CreatedAt)
            .order_by_asc(batch_operation::Column::Id)
            .all(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?;
        let mut batches = Vec::with_capacity(models.len());
        for model in models {
            let batch_id = BatchOperationId::from_uuid(model.id);
            batches.push(map_stored_batch(batch_id, &model)?);
        }
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(batches)
    }

    /// Lists one batch's child operations in target order, paired with each
    /// child's persisted failure classification (§13.7).
    ///
    /// The children are ordinary persisted operations, so each is rehydrated
    /// as a complete aggregate through [`Self::find_operation`]'s mapping —
    /// including its command — and one corrupt child poisons the whole
    /// listing. Each child carries exactly one target, so ordering by that
    /// target's identity is a total order; batch reporting (design §13.7)
    /// pairs every endpoint with its child in this deterministic order. The
    /// failure kind is rehydrated through the domain [`FailureKind`]
    /// deserializer with the same corrupt-aggregate rule as the state and
    /// source codes: a stored code this build cannot classify makes the
    /// whole listing [`OperationRepositoryError::Corrupt`]. An unknown batch
    /// id returns an empty list; the parent existence is a separate
    /// [`Self::find_batch`] read.
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError`] when the query fails or any
    /// persisted child violates domain invariants.
    pub async fn list_batch_children(
        &self,
        batch_id: BatchOperationId,
    ) -> Result<Vec<(Operation, Option<FailureKind>)>, OperationRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(OperationRepositoryError::Database)?;
        let models = operation::Entity::find()
            .filter(operation::Column::BatchId.eq(batch_id.into_uuid()))
            .all(&transaction)
            .await
            .map_err(OperationRepositoryError::Database)?;
        let mut children = Vec::with_capacity(models.len());
        for model in models {
            let operation_id = OperationId::from_uuid(model.id);
            let failure_kind = model
                .failure_kind
                .as_deref()
                .map(|code| {
                    code.parse::<FailureKind>()
                        .map_err(StoredOperationError::InvalidFailureKind)
                        .map_err(|source| corrupt(operation_id, source))
                })
                .transpose()?;
            let operation = map_stored_operation(&transaction, operation_id, model).await?;
            children.push((operation, failure_kind));
        }
        // Target order: each child carries exactly one target, so the target
        // identity orders the batch; a corrupt zero-target row (impossible
        // through the engine) sorts first by `None` instead of panicking.
        children.sort_by_key(|(child, _)| child.targets().first().map(|target| target.target_id()));
        transaction
            .commit()
            .await
            .map_err(OperationRepositoryError::Database)?;
        Ok(children)
    }

    /// Persists the §13.7 failure classification of one operation, written
    /// by the refusal path before the `Failed` transition.
    ///
    /// The write is a single-column update and deliberately does not touch
    /// `updated_at`: the timeline records state transitions, and the kind is
    /// a classification fact, not a state step. The crash window between
    /// this write and the `Failed` transition is harmless by design —
    /// reporting reads the kind only to bucket a `Failed` child, and the
    /// domain state machine never treats the column as a state.
    ///
    /// # Errors
    ///
    /// Returns [`OperationRepositoryError::NotFound`] for an unknown id and
    /// [`OperationRepositoryError`] variants for coordination or database
    /// failures.
    pub async fn record_failure_kind(
        &self,
        operation_id: OperationId,
        kind: FailureKind,
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
        let mut active = model.into_active_model();
        active.failure_kind = Set(Some(kind.as_str().to_owned()));
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

    /// Reads one complete operation aggregate by stable identity.
    ///
    /// The stored command JSON is rehydrated through the domain
    /// [`RedfishCommand`] deserializer. A payload this build cannot
    /// deserialize — a family, payload shape, or member this build does not
    /// know — makes the whole aggregate [`OperationRepositoryError::Corrupt`]
    /// instead of being half-understood, exactly like an unknown state or
    /// source code (`InvalidState` precedent). Upgrade order therefore
    /// matters: records written by a newer build must not be read by an older
    /// one, so in-flight operations must be drained (or the product must not
    /// be rolled back) before a downgrade — the same discipline as the §0.5.0
    /// OEM records, which only builds with the OEM mapping compiled in can
    /// interpret.
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
    /// acceptance order. Each listed row is rehydrated as a complete
    /// aggregate — including its command — so one corrupt command poisons the
    /// whole listing; recovery must surface that rather than silently drop
    /// the unreadable operation.
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
    batch_id: Option<Uuid>,
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
        command: Set(serialize_command(&domain.command())?),
        // A batch child carries its parent link at the persistence layer
        // only; the domain `Operation` aggregate has no batch concept. New
        // operations are never born classified: the failure kind is written
        // by the refusal path before a `Failed` transition.
        batch_id: Set(batch_id),
        failure_kind: Set(None),
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

fn map_stored_batch(
    batch_id: BatchOperationId,
    model: &batch_operation::Model,
) -> Result<BatchOperation, OperationRepositoryError> {
    let source = model
        .source
        .parse::<OperationSource>()
        .map_err(StoredBatchError::InvalidSource)
        .map_err(|source| corrupt_batch(batch_id, source))?;
    // Rehydration goes through the domain type, never through string
    // inspection: the deserializer is the only judge of what the stored JSON
    // means, and anything it refuses corrupts the whole parent (§9.4).
    let command = serde_json::from_str(&model.command)
        .map_err(StoredBatchError::InvalidCommand)
        .map_err(|source| corrupt_batch(batch_id, source))?;
    Ok(BatchOperation::try_from_parts(
        batch_id,
        source,
        command,
        model.created_at,
    ))
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
    // Rehydration goes through the domain type, never through string
    // inspection: the deserializer is the only judge of what the stored JSON
    // means, and anything it refuses corrupts the whole aggregate (§9.4).
    let command = serde_json::from_str(&model.command)
        .map_err(StoredOperationError::InvalidCommand)
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
        command,
        state,
        model.created_at,
        model.updated_at,
    )
    .map_err(StoredOperationError::InvalidTimeline)
    .map_err(|source| corrupt(operation_id, source))
}

/// Encodes the typed command as its §9.4 serde JSON form.
///
/// # Errors
///
/// Returns [`OperationRepositoryError::CommandEncode`] when the command value
/// cannot be serialized. The domain command types are plain value types, so
/// this is only reachable through a serde contract violation; it exists for
/// totality — persistence never writes a string it could not produce.
fn serialize_command(command: &RedfishCommand) -> Result<String, OperationRepositoryError> {
    serde_json::to_string(command).map_err(OperationRepositoryError::CommandEncode)
}

fn corrupt(operation_id: OperationId, source: StoredOperationError) -> OperationRepositoryError {
    OperationRepositoryError::Corrupt {
        operation_id,
        source,
    }
}

fn corrupt_batch(batch_id: BatchOperationId, source: StoredBatchError) -> OperationRepositoryError {
    OperationRepositoryError::BatchCorrupt { batch_id, source }
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
    #[error("stored batch {batch_id} is invalid: {source}")]
    BatchCorrupt {
        batch_id: BatchOperationId,
        #[source]
        source: StoredBatchError,
    },
    #[error("operation database operation failed: {0}")]
    Database(#[source] DbErr),
    /// The typed command could not be serialized before writing. The domain
    /// command types are plain value types, so this is a totality guard that
    /// no value written by this product can actually trigger.
    #[error("operation command cannot be serialized as JSON: {0}")]
    CommandEncode(#[source] serde_json::Error),
}

/// Why persisted operation data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredOperationError {
    #[error("operation state code is invalid: {0}")]
    InvalidState(#[source] OperationStateParseError),
    #[error("operation source code is invalid: {0}")]
    InvalidSource(#[source] OperationSourceParseError),
    /// The stored command JSON cannot be deserialized by this build: a
    /// malformed document, an unknown command family, or a payload shape this
    /// build does not know. The whole aggregate is refused rather than
    /// half-understood; see [`super::SqliteStore::find_operation`] for the
    /// upgrade-order consequence.
    #[error("operation command JSON is invalid: {0}")]
    InvalidCommand(#[source] serde_json::Error),
    #[error("operation timeline is invalid: {0}")]
    InvalidTimeline(#[source] OperationTimelineError),
    #[error("operation failure kind code is invalid: {0}")]
    InvalidFailureKind(#[source] FailureKindParseError),
}

/// Why persisted batch data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredBatchError {
    #[error("batch source code is invalid: {0}")]
    InvalidSource(#[source] OperationSourceParseError),
    /// The stored command JSON cannot be deserialized by this build: a
    /// malformed document, an unknown command family, or a payload shape this
    /// build does not know. The whole parent is refused rather than
    /// half-understood; see [`super::SqliteStore::find_batch`] for the
    /// upgrade-order consequence.
    #[error("batch command JSON is invalid: {0}")]
    InvalidCommand(#[source] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        ArtifactId, BatchOperation, BatchOperationId, BootCommand, BootSource,
        BootSourceOverrideEnabled, BootSourceOverrideMode, ChassisCommand, CreateSubscription,
        EndpointId, EventCommand, EventDestinationProtocol, EventSubscriptionError, EventType,
        FailureKind, ManagerCommand, RedfishCommand, ResetKeysType, ResetType, SecureBootCommand,
        SetBootSourceOverride, StartUpdate, SystemCommand, TargetId, UpdateCommand,
    };
    use rutilus_entity::{batch_operation, operation, operation_target};
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
            one_command(),
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
        let operation = queued_operation(
            OperationSource::Center,
            &three_sorted_targets(),
            one_command(),
            created_at,
        );

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
        let operation = queued_operation(
            OperationSource::Site,
            &three_sorted_targets(),
            one_command(),
            created_at,
        );
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
            one_command(),
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
        let operation = queued_operation(
            OperationSource::Site,
            &three_sorted_targets(),
            one_command(),
            created_at,
        );
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
        let operation = queued_operation(
            OperationSource::Site,
            &three_sorted_targets(),
            one_command(),
            created_at,
        );
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
        let waiting_a = queued_operation(
            OperationSource::Site,
            &three_sorted_targets(),
            one_command(),
            base,
        );
        let queued = queued_operation(
            OperationSource::Standalone,
            &three_sorted_targets(),
            one_command(),
            base + Duration::SECOND,
        );
        let waiting_b = queued_operation(
            OperationSource::Center,
            &three_sorted_targets(),
            one_command(),
            base + Duration::SECOND * 2,
        );
        let succeeded = queued_operation(
            OperationSource::Site,
            &three_sorted_targets(),
            one_command(),
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
            one_command(),
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
            let operation =
                queued_operation(source, &three_sorted_targets(), one_command(), created_at);
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
            let operation = queued_operation(
                OperationSource::Center,
                &three_sorted_targets(),
                one_command(),
                created_at,
            );
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
        // The command JSON is valid on purpose, so the failure is exactly the
        // timeline error and not a command deserialization error.
        let operation_id = OperationId::generate();
        operation::ActiveModel {
            id: Set(operation_id.into_uuid()),
            source: Set(String::from("standalone")),
            state: Set(String::from("queued")),
            command: Set(serialize_command(&one_command())?),
            batch_id: Set(None),
            failure_kind: Set(None),
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

    #[tokio::test]
    async fn commands_round_trip_across_every_family() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let mut created_at = OffsetDateTime::now_utc();
        for command in all_commands()? {
            let operation = queued_operation(
                OperationSource::Standalone,
                &three_sorted_targets(),
                command.clone(),
                created_at,
            );
            let operation_id = operation.id();
            store.create_operation(&operation).await?;
            assert_eq!(
                store.find_operation(operation_id).await?,
                Some(operation),
                "command family {} must survive persistence unchanged",
                command.as_str()
            );
            let stored = store
                .find_operation(operation_id)
                .await?
                .ok_or("stored operation is missing")?;
            assert_eq!(stored.command(), command);
            created_at += Duration::SECOND;
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_command_json_this_build_cannot_deserialize() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        // A deferred family (design section 7.5: `Account`, `Bios`, `Storage`,
        // `Telemetry`, `Oem`) and a truncated document are both
        // written directly, bypassing the repository's serializer — exactly
        // what a future build's row would look like to this build. Rehydration
        // must refuse the whole aggregate, never guess at the command.
        for command in ["{\"Storage\": {}}", r#"{"System":"PowerCycle"}"#] {
            let operation_id = OperationId::generate();
            operation::ActiveModel {
                id: Set(operation_id.into_uuid()),
                source: Set(String::from("standalone")),
                state: Set(String::from("queued")),
                command: Set(String::from(command)),
                batch_id: Set(None),
                failure_kind: Set(None),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(&store.database)
            .await?;
            assert!(matches!(
                store.find_operation(operation_id).await,
                Err(OperationRepositoryError::Corrupt {
                    operation_id: id,
                    source: StoredOperationError::InvalidCommand(_),
                }) if id == operation_id
            ));
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn one_corrupt_command_poisons_the_whole_listing() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        // A readable row next to the unreadable one proves the poisoning is
        // caused by the corrupt command, not by an empty table: the §13.6
        // recovery scan reads back complete aggregates, so it must surface
        // the corruption instead of silently dropping the unreadable
        // operation (promised by `list_operations`).
        let valid = queued_operation(
            OperationSource::Standalone,
            &three_sorted_targets(),
            one_command(),
            now,
        );
        store.create_operation(&valid).await?;
        let corrupt_id = OperationId::generate();
        operation::ActiveModel {
            id: Set(corrupt_id.into_uuid()),
            source: Set(String::from("standalone")),
            state: Set(String::from("queued")),
            command: Set(String::from(r#"{"Storage": {}}"#)),
            batch_id: Set(None),
            failure_kind: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(&store.database)
        .await?;

        assert!(matches!(
            store.list_operations(None).await,
            Err(OperationRepositoryError::Corrupt {
                operation_id,
                source: StoredOperationError::InvalidCommand(_),
            }) if operation_id == corrupt_id
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn create_batch_round_trips_parent_and_single_target_children()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let batch = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Site,
            one_command(),
            created_at,
        );
        let children = (0..3)
            .map(|index| {
                queued_operation(
                    OperationSource::Site,
                    &[OperationTarget::new(
                        TargetId::generate(),
                        EndpointId::generate(),
                    )],
                    one_command(),
                    created_at + Duration::SECOND * index,
                )
            })
            .collect::<Vec<_>>();

        store.create_batch(&batch, &children).await?;

        // The parent reads back with its submission facts intact.
        let stored_batch = store
            .find_batch(batch.id())
            .await?
            .ok_or("stored batch is missing")?;
        assert_eq!(stored_batch, batch);
        assert_eq!(stored_batch.command(), one_command());

        // Every child is an ordinary operation: readable by its own
        // OperationId with exactly the one target the batch bound.
        let mut stored_children = Vec::with_capacity(children.len());
        for child in &children {
            let stored = store
                .find_operation(child.id())
                .await?
                .ok_or("stored child is missing")?;
            assert_eq!(stored, *child);
            assert_eq!(stored.targets().len(), 1);
            assert_eq!(stored.targets()[0], child.targets()[0]);
            stored_children.push(stored);
        }
        // The batch listing returns its children in target order; fresh
        // children are never born classified, so every pair reads back with
        // no failure kind.
        let mut expected = stored_children;
        expected.sort_by_key(|child| child.targets().first().map(|target| target.target_id()));
        assert_eq!(
            store.list_batch_children(batch.id()).await?,
            expected
                .iter()
                .cloned()
                .map(|child| (child, None))
                .collect::<Vec<_>>()
        );
        assert!(
            store
                .find_batch(BatchOperationId::generate())
                .await?
                .is_none()
        );
        assert!(
            store
                .list_batch_children(BatchOperationId::generate())
                .await?
                .is_empty()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn repeated_batch_delivery_never_rewrites_or_duplicates_children()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let batch = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Center,
            one_command(),
            created_at,
        );
        let children = (0..2)
            .map(|index| {
                queued_operation(
                    OperationSource::Center,
                    &[OperationTarget::new(
                        TargetId::generate(),
                        EndpointId::generate(),
                    )],
                    one_command(),
                    created_at + Duration::SECOND * index,
                )
            })
            .collect::<Vec<_>>();

        store.create_batch(&batch, &children).await?;
        store.create_batch(&batch, &children).await?;
        assert_eq!(store.list_batch_children(batch.id()).await?.len(), 2);

        // A re-delivered batch must not resurrect children that have already
        // moved forward (design §15.4 single business effect): transition one
        // child, then re-deliver the whole batch, and both the state and the
        // child count must stay untouched.
        let child_id = children[0].id();
        let transitioned_at = created_at + Duration::SECOND;
        store
            .apply_transition(child_id, OperationState::Validating, transitioned_at)
            .await?;
        store.create_batch(&batch, &children).await?;
        let stored = store
            .find_operation(child_id)
            .await?
            .ok_or("stored child is missing")?;
        assert_eq!(stored.state(), OperationState::Validating);
        assert_eq!(stored.updated_at(), transitioned_at);
        assert_eq!(store.list_batch_children(batch.id()).await?.len(), 2);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn recorded_failure_kinds_round_trip_with_batch_children() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let batch = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Site,
            one_command(),
            created_at,
        );
        let mut children = (0..2)
            .map(|index| {
                queued_operation(
                    OperationSource::Site,
                    &[OperationTarget::new(
                        TargetId::generate(),
                        EndpointId::generate(),
                    )],
                    one_command(),
                    created_at + Duration::SECOND * index,
                )
            })
            .collect::<Vec<_>>();
        children.sort_by_key(|child| child.targets().first().map(|target| target.target_id()));
        store.create_batch(&batch, &children).await?;

        // The classified child reads back with its kind; the unclassified
        // child reads back with None — the kind is only ever written by the
        // refusal path, so the pairing is per child, never invented.
        let classified_id = children[0].id();
        let unclassified_id = children[1].id();
        store
            .record_failure_kind(classified_id, FailureKind::CapabilityUnsupported)
            .await?;
        let stored = store.list_batch_children(batch.id()).await?;
        assert_eq!(stored.len(), 2);
        let classified = stored
            .iter()
            .find(|(child, _)| child.id() == classified_id)
            .ok_or("the classified child is missing")?;
        assert_eq!(classified.1, Some(FailureKind::CapabilityUnsupported));
        let unclassified = stored
            .iter()
            .find(|(child, _)| child.id() == unclassified_id)
            .ok_or("the unclassified child is missing")?;
        assert_eq!(unclassified.1, None);

        // The classification write is not a state step: the timeline is
        // untouched by the kind.
        let stored_classified = store
            .find_operation(classified_id)
            .await?
            .ok_or("the classified operation is missing")?;
        assert_eq!(stored_classified.state(), OperationState::Queued);
        assert_eq!(stored_classified.updated_at(), created_at);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn record_failure_kind_rejects_unknown_ids() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let unknown = OperationId::generate();

        assert!(matches!(
            store
                .record_failure_kind(unknown, FailureKind::CapabilityUnsupported)
                .await,
            Err(OperationRepositoryError::NotFound { operation_id })
                if operation_id == unknown
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_failure_kind_codes_this_build_cannot_classify() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();
        let batch = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Site,
            one_command(),
            now,
        );
        let child = queued_operation(
            OperationSource::Site,
            &[OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            one_command(),
            now,
        );
        store
            .create_batch(&batch, std::slice::from_ref(&child))
            .await?;

        // A kind code no product build can classify is refused at the
        // database (the CHECK constraint), so rehydration never has to guess
        // a kind — the same guard as the source-code precedent. The
        // repository's InvalidFailureKind rehydration arm stays as
        // defense-in-depth for rows written before the CHECK existed.
        let child_id = child.id();
        let invalid_kind = operation::ActiveModel {
            id: Set(child_id.into_uuid()),
            source: Set(String::from("site")),
            state: Set(String::from("failed")),
            command: Set(serialize_command(&one_command())?),
            batch_id: Set(Some(batch.id().into_uuid())),
            failure_kind: Set(Some(String::from("capability-missing"))),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .update(&store.database)
        .await;
        assert!(
            invalid_kind.is_err(),
            "an unknown failure-kind code must be refused by the database"
        );

        // The refused write changed nothing: the child still reads back as
        // the untouched queued row.
        let stored = store.list_batch_children(batch.id()).await?;
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, child);
        assert_eq!(stored[0].1, None);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn list_batches_orders_parents_in_acceptance_order() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let earlier = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Standalone,
            one_command(),
            base,
        );
        let later = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Site,
            one_command(),
            base + Duration::SECOND,
        );
        store.create_batch(&earlier, &[]).await?;
        store.create_batch(&later, &[]).await?;

        let batches = store.list_batches().await?;
        assert_eq!(
            batches.iter().map(BatchOperation::id).collect::<Vec<_>>(),
            vec![earlier.id(), later.id()],
            "listing without a filter must return every batch in acceptance order"
        );
        assert_eq!(store.find_batch(later.id()).await?, Some(later));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_a_batch_cascades_to_its_children_only() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let created_at = OffsetDateTime::now_utc();
        let batch = BatchOperation::try_from_parts(
            BatchOperationId::generate(),
            OperationSource::Standalone,
            one_command(),
            created_at,
        );
        let child = queued_operation(
            OperationSource::Standalone,
            &[OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            one_command(),
            created_at,
        );
        let unlinked = queued_operation(
            OperationSource::Standalone,
            &[OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            one_command(),
            created_at,
        );
        store
            .create_batch(&batch, std::slice::from_ref(&child))
            .await?;
        store.create_operation(&unlinked).await?;
        let batch_uuid = batch.id().into_uuid();

        batch_operation::Entity::delete_by_id(batch_uuid)
            .exec(&store.database)
            .await?;

        assert!(
            store.find_batch(batch.id()).await?.is_none(),
            "deleting a batch must remove the parent row"
        );
        assert_eq!(
            operation::Entity::find()
                .filter(operation::Column::BatchId.eq(batch_uuid))
                .all(&store.database)
                .await?
                .len(),
            0,
            "deleting a batch must cascade to its children"
        );
        assert!(
            store.find_operation(child.id()).await?.is_none(),
            "a batch child must not outlive its batch"
        );
        assert!(
            store.find_operation(unlinked.id()).await?.is_some(),
            "deleting a batch must not touch unlinked operations"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn refuses_batch_data_this_build_cannot_classify() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let now = OffsetDateTime::now_utc();

        // A deferred command family (design section 7.5) written directly,
        // bypassing the repository's serializer — exactly what a future
        // build's row would look like to this build. Rehydration must refuse
        // the whole parent, never guess at the command.
        let corrupt_id = BatchOperationId::generate();
        batch_operation::ActiveModel {
            id: Set(corrupt_id.into_uuid()),
            source: Set(String::from("standalone")),
            command: Set(String::from(r#"{"Storage": {}}"#)),
            created_at: Set(now),
        }
        .insert(&store.database)
        .await?;
        assert!(matches!(
            store.find_batch(corrupt_id).await,
            Err(OperationRepositoryError::BatchCorrupt {
                batch_id,
                source: StoredBatchError::InvalidCommand(_),
            }) if batch_id == corrupt_id
        ));

        // A source code no product build can classify is refused at the
        // database (the CHECK constraint), so rehydration never has to guess
        // an origin — the same guard as the operations.source precedent. The
        // repository's InvalidSource rehydration arm stays as defense-in-depth
        // for rows written before the CHECK existed.
        let invalid_source_id = BatchOperationId::generate();
        let invalid_source = batch_operation::ActiveModel {
            id: Set(invalid_source_id.into_uuid()),
            source: Set(String::from("cluster")),
            command: Set(serialize_command(&one_command())?),
            created_at: Set(now),
        }
        .insert(&store.database)
        .await;
        assert!(
            invalid_source.is_err(),
            "an unknown source code must be refused by the database"
        );

        // One corrupt parent poisons the whole batch listing, exactly like
        // the operation listing's corrupt-command rule.
        assert!(matches!(
            store.list_batches().await,
            Err(OperationRepositoryError::BatchCorrupt { .. })
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
        command: RedfishCommand,
        created_at: OffsetDateTime,
    ) -> Operation {
        Operation::new(
            OperationId::generate(),
            source,
            targets.to_vec(),
            command,
            created_at,
        )
    }

    /// One representative command for tests whose subject is not the command
    /// itself; the command round-trip across every family is covered by
    /// [`commands_round_trip_across_every_family`].
    fn one_command() -> RedfishCommand {
        RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle))
    }

    /// One representative command per §7.5 family, mirroring the domain's
    /// exhaustive family list so a newly added family cannot hide from
    /// persistence tests.
    fn all_commands() -> Result<Vec<RedfishCommand>, EventSubscriptionError> {
        Ok(vec![
            one_command(),
            RedfishCommand::Manager(ManagerCommand::Reset(ResetType::GracefulRestart)),
            RedfishCommand::Chassis(ChassisCommand::Reset(ResetType::ForceOff)),
            RedfishCommand::Boot(BootCommand::SetBootSourceOverride(
                SetBootSourceOverride::new(
                    BootSource::Pxe,
                    BootSourceOverrideEnabled::Once,
                    BootSourceOverrideMode::Uefi,
                ),
            )),
            RedfishCommand::SecureBoot(SecureBootCommand::ResetKeys(
                ResetKeysType::ResetAllKeysToDefault,
            )),
            RedfishCommand::Event(EventCommand::CreateSubscription(
                CreateSubscription::try_new(
                    "https://192.0.2.10/events".to_owned(),
                    EventDestinationProtocol::Redfish,
                    vec![EventType::Alert],
                )?,
            )),
            RedfishCommand::Update(UpdateCommand::StartUpdate(StartUpdate::new(
                ArtifactId::generate(),
                None,
            ))),
        ])
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
