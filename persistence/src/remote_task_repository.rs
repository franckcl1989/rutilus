use rutilus_domain::{EndpointId, OperationId};
use rutilus_entity::remote_task;
use rutilus_operation_engine::{
    RemoteTask, RemoteTaskError, RemoteTaskState, RemoteTaskStateParseError, TaskUri, TaskUriError,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DbErr, EntityTrait, QueryFilter, QueryOrder, Set,
    TransactionTrait,
};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists the newest observation of one remote task (design §13.6).
    ///
    /// The row is an observation log, not a state machine: every Task poll
    /// overwrites it with the newest observation, so a save whose operation
    /// id already exists replaces the stored row in full and a new id
    /// inserts — the idempotent upsert contract the engine's
    /// [`RemoteTaskStore`](rutilus_operation_engine::RemoteTaskStore) trait
    /// promises. Repeating the same observation is a harmless rewrite, which
    /// is what makes delivering observations at-least-once safe (design
    /// §15.4). Saving never moves the operation's §13.2 state; the write gate
    /// serializes writers, so the existence check and the insert/update land
    /// atomically, and the foreign key refuses a task whose operation does
    /// not exist.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteTaskRepositoryError`] when write coordination fails,
    /// the transaction cannot commit, the operation is unknown (foreign key),
    /// or the percent complete cannot be represented in the INTEGER column.
    pub async fn save_remote_task(
        &self,
        task: &RemoteTask,
    ) -> Result<(), RemoteTaskRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(RemoteTaskRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        let operation_id = task.operation_id().into_uuid();
        let exists = remote_task::Entity::find_by_id(operation_id)
            .one(&transaction)
            .await
            .map_err(RemoteTaskRepositoryError::Database)?
            .is_some();
        let percent_complete = task
            .percent_complete()
            .map(percent_complete_i32)
            .transpose()?;
        let active = remote_task::ActiveModel {
            operation_id: Set(operation_id),
            endpoint_id: Set(task.endpoint_id().into_uuid()),
            task_uri: Set(task.task_uri().as_str().to_owned()),
            task_monitor_uri: Set(task.task_monitor_uri().map(|uri| uri.as_str().to_owned())),
            last_state: Set(task.last_state().as_str().to_owned()),
            last_message: Set(task.last_message().map(ToOwned::to_owned)),
            percent_complete: Set(percent_complete),
            last_checked_at: Set(task.last_checked_at()),
        };
        if exists {
            active
                .update(&transaction)
                .await
                .map_err(RemoteTaskRepositoryError::Database)?;
        } else {
            active
                .insert(&transaction)
                .await
                .map_err(RemoteTaskRepositoryError::Database)?;
        }
        transaction
            .commit()
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        Ok(())
    }

    /// Reads one remote task row by operation id; `None` when the operation
    /// has no row — it never reached `WaitingRemote`, or its row was never
    /// written.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteTaskRepositoryError::Corrupt`] when the stored state
    /// code, a stored URI, or the percent complete cannot be mapped into the
    /// engine types — for example a state code a newer build's migration
    /// widened the CHECK to accept, read back by this build. The whole row is
    /// refused rather than half-understood, exactly like an unknown operation
    /// state (`InvalidState` precedent), so in-flight tasks must be drained
    /// before a downgrade.
    pub async fn find_remote_task(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<RemoteTask>, RemoteTaskRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        let Some(model) = remote_task::Entity::find_by_id(operation_id.into_uuid())
            .one(&transaction)
            .await
            .map_err(RemoteTaskRepositoryError::Database)?
        else {
            transaction
                .commit()
                .await
                .map_err(RemoteTaskRepositoryError::Database)?;
            return Ok(None);
        };
        let task = map_stored_remote_task(operation_id, model)?;
        transaction
            .commit()
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        Ok(Some(task))
    }

    /// Lists remote tasks whose last observation is exactly `state`, oldest
    /// check first.
    ///
    /// The §13.6 restart recovery scan uses this to resume polling the tasks
    /// that were still in flight when the process died: tasks observed in
    /// [`RemoteTaskState::Completed`], `Killed`, `Exception`, or `Cancelled`
    /// are terminal and need no re-poll, while every other state still has
    /// work. Check-time ordering keeps the scan in staleness order — the
    /// tasks blocked longest are resumed first — with the operation id as
    /// the deterministic tiebreak.
    ///
    /// # Errors
    ///
    /// Returns [`RemoteTaskRepositoryError::Corrupt`] when any listed row
    /// violates engine invariants; one unreadable row surfaces instead of
    /// being silently dropped, exactly like [`super::SqliteStore::list_operations`].
    pub async fn list_remote_tasks_by_state(
        &self,
        state: RemoteTaskState,
    ) -> Result<Vec<RemoteTask>, RemoteTaskRepositoryError> {
        let transaction = self
            .database
            .begin()
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        let models = remote_task::Entity::find()
            .filter(remote_task::Column::LastState.eq(state.as_str()))
            .order_by_asc(remote_task::Column::LastCheckedAt)
            .order_by_asc(remote_task::Column::OperationId)
            .all(&transaction)
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        let mut tasks = Vec::with_capacity(models.len());
        for model in models {
            tasks.push(map_stored_remote_task(
                OperationId::from_uuid(model.operation_id),
                model,
            )?);
        }
        transaction
            .commit()
            .await
            .map_err(RemoteTaskRepositoryError::Database)?;
        Ok(tasks)
    }
}

/// Stores the CSDL percent complete in the INTEGER column.
///
/// The domain restricts the value to `0..=100` (validated in
/// `RemoteTask::try_from_parts`), which always fits the column; the failure
/// arm is a totality guard for a contract violation, mirroring the
/// [`super::OperationRepositoryError::CommandEncode`] precedent — persistence
/// never writes a value it could not represent.
fn percent_complete_i32(percent_complete: u64) -> Result<i32, RemoteTaskRepositoryError> {
    i32::try_from(percent_complete)
        .map_err(|_| RemoteTaskRepositoryError::PercentCompleteOutOfRange { percent_complete })
}

fn map_stored_remote_task(
    operation_id: OperationId,
    model: remote_task::Model,
) -> Result<RemoteTask, RemoteTaskRepositoryError> {
    let state = model
        .last_state
        .parse::<RemoteTaskState>()
        .map_err(StoredRemoteTaskError::InvalidState)
        .map_err(|source| corrupt(operation_id, source))?;
    // Rehydration goes through the engine types, never through string
    // inspection: the URI validator and the state parser are the only judges
    // of what the stored text means, and anything they refuse corrupts the
    // whole row — the database stores URIs verbatim with no format CHECK,
    // exactly like the §9.4 `TypedPayloadJson` rule.
    let task_uri = TaskUri::parse(&model.task_uri)
        .map_err(StoredRemoteTaskError::InvalidUri)
        .map_err(|source| corrupt(operation_id, source))?;
    let task_monitor_uri = model
        .task_monitor_uri
        .as_deref()
        .map(TaskUri::parse)
        .transpose()
        .map_err(StoredRemoteTaskError::InvalidUri)
        .map_err(|source| corrupt(operation_id, source))?;
    let percent_complete = model
        .percent_complete
        .map(|percent| {
            u64::try_from(percent).map_err(|_| {
                corrupt(
                    operation_id,
                    StoredRemoteTaskError::InvalidPercentComplete { percent },
                )
            })
        })
        .transpose()?;
    // The CSDL `0..=100` range verdict is the engine's own: `try_from_parts`
    // refuses a stored 150 as corrupt progress exactly like a value read off
    // the wire, so both persistence and the wire share one rule.
    RemoteTask::try_from_parts(
        operation_id,
        EndpointId::from_uuid(model.endpoint_id),
        task_uri,
        task_monitor_uri,
        state,
        model.last_message,
        percent_complete,
        model.last_checked_at,
    )
    .map_err(StoredRemoteTaskError::InvalidTask)
    .map_err(|source| corrupt(operation_id, source))
}

fn corrupt(operation_id: OperationId, source: StoredRemoteTaskError) -> RemoteTaskRepositoryError {
    RemoteTaskRepositoryError::Corrupt {
        operation_id,
        source,
    }
}

/// A controlled failure while creating, reading, or listing remote task rows.
#[derive(Debug, Error)]
pub enum RemoteTaskRepositoryError {
    #[error("remote task write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("stored remote task {operation_id} is invalid: {source}")]
    Corrupt {
        operation_id: OperationId,
        #[source]
        source: StoredRemoteTaskError,
    },
    /// The percent complete cannot be represented in the INTEGER column. The
    /// domain restricts the value to the CSDL `0..=100` range, so this is a
    /// totality guard that no value written by this product can trigger.
    #[error("remote task percent complete {percent_complete} cannot be stored as an integer")]
    PercentCompleteOutOfRange { percent_complete: u64 },
    #[error("remote task database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why a persisted remote task row cannot be mapped into valid engine types.
#[derive(Debug, Error)]
pub enum StoredRemoteTaskError {
    #[error("remote task state code is invalid: {0}")]
    InvalidState(#[source] RemoteTaskStateParseError),
    #[error("remote task URI is invalid: {0}")]
    InvalidUri(#[source] TaskUriError),
    #[error("remote task percent complete {percent} cannot be represented as a percentage")]
    InvalidPercentComplete { percent: i32 },
    #[error("remote task record violates engine invariants: {0}")]
    InvalidTask(#[source] RemoteTaskError),
}

#[cfg(test)]
mod tests {
    use std::{error::Error, sync::Arc};

    use rutilus_domain::{
        EndpointId, Operation, OperationId, OperationSource, OperationTarget, RedfishCommand,
        ResetType, SystemCommand, TargetId,
    };
    use rutilus_entity::{operation, remote_task};
    use rutilus_operation_engine::{RemoteTask, RemoteTaskState, TaskUri};
    use rutilus_security::MasterKey;
    use sea_orm::EntityTrait;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    /// Every engine `RemoteTaskState`, so the stable-code round trip cannot
    /// miss a variant.
    const ALL_STATES: [RemoteTaskState; 13] = [
        RemoteTaskState::New,
        RemoteTaskState::Starting,
        RemoteTaskState::Running,
        RemoteTaskState::Suspended,
        RemoteTaskState::Interrupted,
        RemoteTaskState::Pending,
        RemoteTaskState::Stopping,
        RemoteTaskState::Completed,
        RemoteTaskState::Killed,
        RemoteTaskState::Exception,
        RemoteTaskState::Service,
        RemoteTaskState::Cancelling,
        RemoteTaskState::Cancelled,
    ];

    #[tokio::test]
    async fn save_upserts_one_row_per_operation() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let operation = queued_operation();
        store.create_operation(&operation).await?;
        let operation_id = operation.id();
        let acceptance = task_in(operation_id, OffsetDateTime::now_utc())?;

        // First save inserts the acceptance record (§13.6: persisted before
        // the first poll).
        store.save_remote_task(&acceptance).await?;
        assert_eq!(
            store.find_remote_task(operation_id).await?,
            Some(acceptance.clone())
        );

        // The poll replaces the same operation's row; a second save must
        // update, never duplicate — the upsert contract the engine trait
        // promises and the at-least-once delivery (§15.4) relies on.
        let observed = observed_task(
            &acceptance,
            RemoteTaskState::Running,
            Some("power cycle in progress"),
            Some(40),
            acceptance.last_checked_at() + Duration::MINUTE,
        )?;
        store.save_remote_task(&observed).await?;
        assert_eq!(
            store.find_remote_task(operation_id).await?,
            Some(observed.clone())
        );
        assert_eq!(
            remote_task::Entity::find()
                .filter(remote_task::Column::OperationId.eq(operation_id.into_uuid()))
                .all(&store.database)
                .await?
                .len(),
            1,
            "re-saving one operation must never duplicate its task row"
        );

        // Repeating the same observation is a harmless rewrite.
        store.save_remote_task(&observed).await?;
        assert_eq!(store.find_remote_task(operation_id).await?, Some(observed));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn find_reports_none_for_operations_without_a_row() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;

        assert!(
            store
                .find_remote_task(OperationId::generate())
                .await?
                .is_none()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn list_remote_tasks_filters_by_the_exact_state_in_staleness_order()
    -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let running_a = save_observed(&store, RemoteTaskState::Running, base).await?;
        let running_b =
            save_observed(&store, RemoteTaskState::Running, base + Duration::SECOND).await?;
        let completed = save_observed(
            &store,
            RemoteTaskState::Completed,
            base + Duration::SECOND * 2,
        )
        .await?;

        let running = store
            .list_remote_tasks_by_state(RemoteTaskState::Running)
            .await?;
        assert_eq!(
            running
                .iter()
                .map(RemoteTask::operation_id)
                .collect::<Vec<_>>(),
            vec![running_a, running_b],
            "only the exact state is listed, oldest check first"
        );
        let terminal = store
            .list_remote_tasks_by_state(RemoteTaskState::Completed)
            .await?;
        assert_eq!(
            terminal
                .iter()
                .map(RemoteTask::operation_id)
                .collect::<Vec<_>>(),
            vec![completed]
        );
        assert!(
            store
                .list_remote_tasks_by_state(RemoteTaskState::Cancelled)
                .await?
                .is_empty()
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn deleting_an_operation_cascades_to_its_remote_task() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let operation = queued_operation();
        store.create_operation(&operation).await?;
        let operation_id = operation.id();
        let uuid = operation_id.into_uuid();
        store
            .save_remote_task(&task_in(operation_id, OffsetDateTime::now_utc())?)
            .await?;

        operation::Entity::delete_by_id(uuid)
            .exec(&store.database)
            .await?;

        assert!(
            store.find_remote_task(operation_id).await?.is_none(),
            "deleting an operation must remove the operation row"
        );
        assert_eq!(
            remote_task::Entity::find()
                .filter(remote_task::Column::OperationId.eq(uuid))
                .all(&store.database)
                .await?
                .len(),
            0,
            "deleting an operation must cascade to its remote task"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn every_task_state_code_round_trips_unchanged() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let mut checked_at = OffsetDateTime::now_utc();
        for state in ALL_STATES {
            let operation_id = create_observed(&store, state, checked_at).await?;
            let stored = store
                .find_remote_task(operation_id)
                .await?
                .ok_or("stored remote task is missing")?;
            assert_eq!(
                stored.last_state(),
                state,
                "state code {} must survive persistence unchanged",
                state.as_str()
            );
            checked_at += Duration::SECOND;
        }

        store.close().await?;
        drop(directory);
        Ok(())
    }

    /// A state code no build can classify is refused as corrupt. The state
    /// CHECK constraint makes the code unreachable through SQL today, but a
    /// newer build's migration can widen the CHECK, and this build must then
    /// refuse the row instead of half-understanding it (the same
    /// upgrade-order discipline as `OperationRepositoryError::Corrupt`), so
    /// the mapping is exercised directly on a hand-built model.
    #[test]
    fn refuses_a_stored_state_this_build_cannot_classify() {
        let operation_id = OperationId::generate();
        let model = remote_task::Model {
            operation_id: operation_id.into_uuid(),
            endpoint_id: EndpointId::generate().into_uuid(),
            task_uri: String::from("/redfish/v1/TaskService/Tasks/42"),
            task_monitor_uri: None,
            last_state: String::from("stopped"),
            last_message: None,
            percent_complete: None,
            last_checked_at: OffsetDateTime::now_utc(),
        };

        assert!(matches!(
            map_stored_remote_task(operation_id, model),
            Err(RemoteTaskRepositoryError::Corrupt {
                operation_id: id,
                source: StoredRemoteTaskError::InvalidState(_),
            }) if id == operation_id
        ));
    }

    /// Percent complete outside the CSDL `0..=100` range is corrupt data,
    /// never displayed as progress.
    #[test]
    fn refuses_a_corrupt_percent_complete() {
        let operation_id = OperationId::generate();
        let row = |percent| remote_task::Model {
            operation_id: operation_id.into_uuid(),
            endpoint_id: EndpointId::generate().into_uuid(),
            task_uri: String::from("/redfish/v1/TaskService/Tasks/42"),
            task_monitor_uri: None,
            last_state: String::from("running"),
            last_message: None,
            percent_complete: Some(percent),
            last_checked_at: OffsetDateTime::now_utc(),
        };

        // Above the range: the engine's own PercentOutOfRange verdict.
        assert!(matches!(
            map_stored_remote_task(operation_id, row(150)),
            Err(RemoteTaskRepositoryError::Corrupt {
                operation_id: id,
                source: StoredRemoteTaskError::InvalidTask(
                    rutilus_operation_engine::RemoteTaskError::PercentOutOfRange {
                        percent_complete: 150,
                    },
                ),
            }) if id == operation_id
        ));
        // Below zero: unrepresentable as a domain percent at all.
        assert!(matches!(
            map_stored_remote_task(operation_id, row(-1)),
            Err(RemoteTaskRepositoryError::Corrupt {
                operation_id: id,
                source: StoredRemoteTaskError::InvalidPercentComplete { percent: -1 },
            }) if id == operation_id
        ));
    }

    /// A malformed stored URI is refused rather than issued verbatim in a
    /// later poll request.
    #[test]
    fn refuses_a_malformed_stored_task_uri() {
        let operation_id = OperationId::generate();
        let model = remote_task::Model {
            operation_id: operation_id.into_uuid(),
            endpoint_id: EndpointId::generate().into_uuid(),
            task_uri: String::from(" /redfish/v1/TaskService/Tasks/42"),
            task_monitor_uri: None,
            last_state: String::from("running"),
            last_message: None,
            percent_complete: None,
            last_checked_at: OffsetDateTime::now_utc(),
        };

        assert!(matches!(
            map_stored_remote_task(operation_id, model),
            Err(RemoteTaskRepositoryError::Corrupt {
                operation_id: id,
                source: StoredRemoteTaskError::InvalidUri(_),
            }) if id == operation_id
        ));
    }

    /// Saves an observed row for a fresh operation and returns its id.
    async fn create_observed(
        store: &SqliteStore,
        state: RemoteTaskState,
        checked_at: OffsetDateTime,
    ) -> Result<OperationId, Box<dyn Error>> {
        let operation = queued_operation();
        store.create_operation(&operation).await?;
        let task = observed_task(
            &task_in(operation.id(), checked_at)?,
            state,
            None,
            None,
            checked_at,
        )?;
        store.save_remote_task(&task).await?;
        Ok(operation.id())
    }

    /// Creates one operation, saves an observed task for it, and returns the
    /// task's operation id.
    async fn save_observed(
        store: &SqliteStore,
        state: RemoteTaskState,
        checked_at: OffsetDateTime,
    ) -> Result<OperationId, Box<dyn Error>> {
        create_observed(store, state, checked_at).await
    }

    fn queued_operation() -> Operation {
        Operation::new(
            OperationId::generate(),
            OperationSource::Standalone,
            vec![OperationTarget::new(
                TargetId::generate(),
                EndpointId::generate(),
            )],
            RedfishCommand::System(SystemCommand::Reset(ResetType::PowerCycle)),
            OffsetDateTime::now_utc(),
        )
    }

    /// One acceptance record for `operation_id` with a monitor URI, so the
    /// optional column is exercised by the default test path.
    fn task_in(
        operation_id: OperationId,
        checked_at: OffsetDateTime,
    ) -> Result<RemoteTask, Box<dyn Error>> {
        Ok(RemoteTask::new(
            operation_id,
            EndpointId::generate(),
            TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
            Some(TaskUri::parse("/redfish/v1/TaskService/TaskMonitors/42")?),
            checked_at,
        ))
    }

    /// The newest observation replacing `task` in the given state.
    fn observed_task(
        task: &RemoteTask,
        state: RemoteTaskState,
        message: Option<&str>,
        percent_complete: Option<u64>,
        checked_at: OffsetDateTime,
    ) -> Result<RemoteTask, Box<dyn Error>> {
        Ok(RemoteTask::try_from_parts(
            task.operation_id(),
            task.endpoint_id(),
            task.task_uri().clone(),
            task.task_monitor_uri().cloned(),
            state,
            message.map(ToOwned::to_owned),
            percent_complete,
            checked_at,
        )?)
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        // The remote-task tests seed operations, so the store carries the
        // command encryption key like the production runtime.
        let store = SqliteStore::open_with_command_key(
            directory.path().join("rutilus.db"),
            Arc::new(MasterKey::from_boxed_bytes(Box::new([0x5a; 32]))),
        )
        .await?;
        Ok((directory, store))
    }
}
