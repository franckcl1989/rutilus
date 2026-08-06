//! The persistence boundary for the remote Task observation model (design
//! section 13.6).
//!
//! [`RemoteTaskStore`] mirrors [`OperationStore`]: the trait is defined
//! here, implemented by `rutilus-persistence` in production and by an
//! in-memory fake in tests, and the engine never sees `SQLite` or `SeaORM`
//! (design section 7.3). One [`RemoteTask`] row exists per operation that
//! reached `WaitingRemote` (§9.3 `remote_tasks`); the operation id is the
//! natural key, which is why every method takes it directly.

use std::error::Error;

use rutilus_domain::OperationId;

use crate::{BoundaryFuture, RemoteTask, RemoteTaskState};

/// The persistence boundary for the §13.6 remote Task observation rows.
///
/// # Why this is a separate boundary from [`OperationStore`]
///
/// The two tables answer different questions: the operation store persists
/// the §13.2 state-machine steps, and the remote-task store persists the
/// observation log that lets Task polling resume after a restart (§13.6).
/// The production `rutilus-persistence` implements both on one connection
/// pool, but the traits stay separate so each contract stays honest about
/// what it may overwrite.
///
/// # Concurrency contract
///
/// All three methods must be safe to call concurrently. Implementations do
/// not need an internal queue: each method documents the exact semantics it
/// requires.
pub trait RemoteTaskStore: Send + Sync {
    /// The persistence layer's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists the newest observation of one remote task.
    ///
    /// # Update semantics (idempotent upsert)
    ///
    /// Unlike [`OperationStore::create_operation`] — whose business effect
    /// is exactly one and must never re-execute — the remote-task row is an
    /// observation log: every Task poll overwrites it with the newest
    /// observation (§13.6 `LastState`, `LastMessage`, `PercentComplete`,
    /// `LastCheckedAt`). A call whose `operation_id` already exists MUST
    /// replace the stored row in full; a call with a new id inserts.
    /// Repeating the same observation is a harmless rewrite, which is what
    /// makes delivering observations at-least-once safe (design section
    /// 15.4).
    ///
    /// # Why saving never conflicts with the operation state machine
    ///
    /// Saving an observation never moves the operation: the §13.2 state is
    /// advanced only through `OperationEngine::apply`. A stale poll can
    /// therefore overwrite the observation row without resurrecting a
    /// finished operation, and no terminal operation verdict ever depends
    /// on this row — the row is the durable log the §13.6 recovery scan
    /// resumes from, nothing more. Concurrent writers on one row are
    /// last-write-wins by design; the upper layer serializes polling per
    /// operation.
    fn save_remote_task<'a>(
        &'a self,
        task: &'a RemoteTask,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Reads one remote task row by operation id.
    ///
    /// `None` when the operation has no row — it never reached
    /// `WaitingRemote`, or its row was never written.
    fn find_remote_task(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<RemoteTask>, Self::Error>>;

    /// Lists remote tasks currently observed in the exact task state.
    ///
    /// The §13.6 recovery scan lists the in-flight task states after a
    /// restart and resumes polling each returned row; the running-task
    /// projection of the home page (design section 14.2) reads the same
    /// listing.
    fn list_remote_tasks_by_state(
        &self,
        state: RemoteTaskState,
    ) -> BoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>>;
}

impl<Store> RemoteTaskStore for &Store
where
    Store: RemoteTaskStore + ?Sized,
{
    type Error = Store::Error;

    fn save_remote_task<'a>(
        &'a self,
        task: &'a RemoteTask,
    ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Store::save_remote_task(*self, task)
    }

    fn find_remote_task(
        &self,
        operation_id: OperationId,
    ) -> BoundaryFuture<'_, Result<Option<RemoteTask>, Self::Error>> {
        Store::find_remote_task(*self, operation_id)
    }

    fn list_remote_tasks_by_state(
        &self,
        state: RemoteTaskState,
    ) -> BoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>> {
        Store::list_remote_tasks_by_state(*self, state)
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, error::Error, sync::Mutex};

    use rutilus_domain::{EndpointId, OperationId};
    use thiserror::Error;
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::TaskUri;

    /// One recorded store call, in order.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Call {
        Save(OperationId),
        Find(OperationId),
        List(RemoteTaskState),
    }

    /// The fake's controlled failure mode.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
    enum FakeStoreError {
        #[error("simulated remote task store failure")]
        Failure,
    }

    /// In-memory fake that models the upsert contract: saving the same
    /// operation id replaces the stored row.
    struct FakeStore {
        rows: Mutex<HashMap<OperationId, RemoteTask>>,
        calls: Mutex<Vec<Call>>,
    }

    impl FakeStore {
        fn new() -> Self {
            Self {
                rows: Mutex::new(HashMap::new()),
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Result<Vec<Call>, FakeStoreError> {
            self.calls
                .lock()
                .map(|calls| calls.clone())
                .map_err(|_| FakeStoreError::Failure)
        }
    }

    impl RemoteTaskStore for FakeStore {
        type Error = FakeStoreError;

        fn save_remote_task<'a>(
            &'a self,
            task: &'a RemoteTask,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::Save(task.operation_id()));
                self.rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .insert(task.operation_id(), task.clone());
                Ok(())
            })
        }

        fn find_remote_task(
            &self,
            operation_id: OperationId,
        ) -> BoundaryFuture<'_, Result<Option<RemoteTask>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::Find(operation_id));
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .get(&operation_id)
                    .cloned())
            })
        }

        fn list_remote_tasks_by_state(
            &self,
            state: RemoteTaskState,
        ) -> BoundaryFuture<'_, Result<Vec<RemoteTask>, Self::Error>> {
            Box::pin(async move {
                self.calls
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .push(Call::List(state));
                Ok(self
                    .rows
                    .lock()
                    .map_err(|_| FakeStoreError::Failure)?
                    .values()
                    .filter(|task| task.last_state() == state)
                    .cloned()
                    .collect())
            })
        }
    }

    /// Builds one acceptance record for `operation_id`.
    fn acceptance(operation_id: OperationId, task_uri: TaskUri) -> RemoteTask {
        RemoteTask::new(
            operation_id,
            EndpointId::generate(),
            task_uri,
            None,
            OffsetDateTime::UNIX_EPOCH,
        )
    }

    /// Builds one observed record replacing `task` with `state`.
    fn observed(task: &RemoteTask, state: RemoteTaskState) -> Result<RemoteTask, Box<dyn Error>> {
        Ok(RemoteTask::try_from_parts(
            task.operation_id(),
            task.endpoint_id(),
            task.task_uri().clone(),
            task.task_monitor_uri().cloned(),
            state,
            Some("newest observation".to_owned()),
            Some(60),
            task.last_checked_at() + Duration::MINUTE,
        )?)
    }

    #[tokio::test]
    async fn save_upserts_by_operation_id_and_records_the_call_order() -> Result<(), Box<dyn Error>>
    {
        let store = FakeStore::new();
        let operation_id = OperationId::generate();
        let task_uri = TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?;
        let acceptance = acceptance(operation_id, task_uri);
        store.save_remote_task(&acceptance).await?;

        // The poll replaces the acceptance placeholder with an observation;
        // the row keeps its operation id (one row per operation).
        let observed = observed(&acceptance, RemoteTaskState::Running)?;
        store.save_remote_task(&observed).await?;

        assert_eq!(store.find_remote_task(operation_id).await?, Some(observed));
        assert_eq!(
            store.calls()?,
            [
                Call::Save(operation_id),
                Call::Save(operation_id),
                Call::Find(operation_id),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn find_reports_none_for_operations_without_a_row() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let unknown = OperationId::generate();

        assert_eq!(store.find_remote_task(unknown).await?, None);
        assert_eq!(store.calls()?, [Call::Find(unknown)]);
        Ok(())
    }

    #[tokio::test]
    async fn list_filters_by_the_exact_task_state() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let running_id = OperationId::generate();
        let running = observed(
            &acceptance(
                running_id,
                TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
            ),
            RemoteTaskState::Running,
        )?;
        let pending_id = OperationId::generate();
        let pending = acceptance(
            pending_id,
            TaskUri::parse("/redfish/v1/TaskService/Tasks/43")?,
        );
        store.save_remote_task(&running).await?;
        store.save_remote_task(&pending).await?;

        let listed = store
            .list_remote_tasks_by_state(RemoteTaskState::Running)
            .await?;

        assert_eq!(listed, [running]);
        assert_eq!(
            store.calls()?,
            [
                Call::Save(running_id),
                Call::Save(pending_id),
                Call::List(RemoteTaskState::Running),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn shared_reference_implementations_forward_unchanged() -> Result<(), Box<dyn Error>> {
        let store = FakeStore::new();
        let task = acceptance(
            OperationId::generate(),
            TaskUri::parse("/redfish/v1/TaskService/Tasks/42")?,
        );

        // The application composes over `&T` exactly like `OperationStore`;
        // the forwarding impl must behave identically.
        let borrowed: &FakeStore = &store;
        borrowed.save_remote_task(&task).await?;
        let read_back = borrowed.find_remote_task(task.operation_id()).await?;
        assert_eq!(read_back, Some(task.clone()));
        assert_eq!(
            store.calls()?,
            [
                Call::Save(task.operation_id()),
                Call::Find(task.operation_id()),
            ]
        );
        Ok(())
    }
}
