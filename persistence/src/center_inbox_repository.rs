use rutilus_domain::{
    IdempotencyDecision, InboxEntry, InboxEntryId, InboxEntryState, InboxEntryStateParseError,
    InboxEvent, InstanceId, OperationId, decide_inbox_duplicate,
};
use rutilus_entity::center_inbox;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, Set,
    TransactionTrait,
};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one received envelope under the §17.5 idempotency rule.
    ///
    /// The operation id is the idempotency key: the row is re-read inside
    /// the transaction (never trusted from a stale read), and a stored row
    /// with the same operation id is decided by the domain pure function —
    /// an in-progress duplicate is parked without a second insertion, and a
    /// resolved duplicate returns the recorded outcome — so the same
    /// operation id can never have two business effects, even across
    /// re-deliveries.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::Corrupt`] when the stored
    /// duplicate row violates domain invariants, and
    /// [`CenterInboxRepositoryError`] variants for coordination or database
    /// failures.
    pub async fn create_inbox_entry(
        &self,
        entry: &InboxEntry,
    ) -> Result<CreateInboxOutcome, CenterInboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterInboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let existing = center_inbox::Entity::find()
            .filter(center_inbox::Column::OperationId.eq(entry.operation_id().to_string()))
            .one(&transaction)
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let outcome = if let Some(model) = existing {
            let stored = map_stored_inbox_entry(InboxEntryId::from_uuid(model.id), &model)?;
            match decide_inbox_duplicate(Some(stored.state())) {
                IdempotencyDecision::Proceed => CreateInboxOutcome::Created,
                IdempotencyDecision::InProgress => CreateInboxOutcome::DuplicateInProgress,
                IdempotencyDecision::AlreadyResolved(state) => {
                    CreateInboxOutcome::DuplicateResolved(state)
                }
            }
        } else {
            insert_inbox_entry(&transaction, entry).await?;
            CreateInboxOutcome::Created
        };
        transaction
            .commit()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        Ok(outcome)
    }

    /// Reads one received envelope by its operation id — the §17.5
    /// idempotency lookup.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_inbox_entry_by_operation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<InboxEntry>, CenterInboxRepositoryError> {
        let Some(model) = center_inbox::Entity::find()
            .filter(center_inbox::Column::OperationId.eq(operation_id.to_string()))
            .one(&self.database)
            .await
            .map_err(CenterInboxRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_inbox_entry(InboxEntryId::from_uuid(model.id), &model).map(Some)
    }

    /// Applies one inbox state-machine event (§17, D4).
    ///
    /// The from-state and to-state come from the domain event, and the
    /// conditional update makes the write idempotent: an entry that already
    /// carries the target state is reported as
    /// [`InboxAdvanceOutcome::AlreadyInState`] instead of failing (the
    /// center may deliver progress envelopes more than once), and an entry
    /// in any other state is refused as a conflict.
    ///
    /// # Errors
    ///
    /// Returns [`CenterInboxRepositoryError::NotFound`] for an unknown
    /// operation id and
    /// [`CenterInboxRepositoryError::StateConflict`] when the stored state
    /// makes the event illegal.
    pub async fn advance_inbox_entry(
        &self,
        operation_id: OperationId,
        event: InboxEvent,
    ) -> Result<InboxAdvanceOutcome, CenterInboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterInboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let update = center_inbox::Entity::update_many()
            .filter(center_inbox::Column::OperationId.eq(operation_id.to_string()))
            .filter(center_inbox::Column::State.eq(event.from_state().as_str()))
            .set(center_inbox::ActiveModel {
                state: Set(event.to_state().as_str().to_owned()),
                ..Default::default()
            })
            .exec(&transaction)
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        let outcome = if update.rows_affected == 1 {
            InboxAdvanceOutcome::Advanced(event.to_state())
        } else {
            let model = center_inbox::Entity::find()
                .filter(center_inbox::Column::OperationId.eq(operation_id.to_string()))
                .one(&transaction)
                .await
                .map_err(CenterInboxRepositoryError::Database)?
                .ok_or(CenterInboxRepositoryError::NotFound { operation_id })?;
            let stored = map_stored_inbox_entry(InboxEntryId::from_uuid(model.id), &model)?;
            if stored.state() == event.to_state() {
                InboxAdvanceOutcome::AlreadyInState
            } else {
                return Err(CenterInboxRepositoryError::StateConflict {
                    operation_id,
                    event,
                    current: stored.state(),
                });
            }
        };
        transaction
            .commit()
            .await
            .map_err(CenterInboxRepositoryError::Database)?;
        Ok(outcome)
    }
}

async fn insert_inbox_entry<C>(
    database: &C,
    entry: &InboxEntry,
) -> Result<(), CenterInboxRepositoryError>
where
    C: ConnectionTrait,
{
    center_inbox::ActiveModel {
        id: Set(entry.id().into_uuid()),
        operation_id: Set(entry.operation_id().to_string()),
        instance_id: Set(entry.instance_id().into_uuid()),
        payload_json: Set(entry.payload_json().to_owned()),
        state: Set(entry.state().as_str().to_owned()),
        expires_at: Set(entry.expires_at()),
        received_at: Set(entry.received_at()),
    }
    .insert(database)
    .await
    .map_err(CenterInboxRepositoryError::Database)?;
    Ok(())
}

fn map_stored_inbox_entry(
    entry_id: InboxEntryId,
    model: &center_inbox::Model,
) -> Result<InboxEntry, CenterInboxRepositoryError> {
    let operation_id = model
        .operation_id
        .parse::<OperationId>()
        .map_err(StoredCenterInboxError::InvalidOperationId)
        .map_err(|source| CenterInboxRepositoryError::Corrupt { entry_id, source })?;
    let state = model
        .state
        .parse::<InboxEntryState>()
        .map_err(StoredCenterInboxError::InvalidState)
        .map_err(|source| CenterInboxRepositoryError::Corrupt { entry_id, source })?;
    Ok(InboxEntry::from_parts(
        entry_id,
        operation_id,
        InstanceId::from_uuid(model.instance_id),
        model.payload_json.clone(),
        state,
        model.expires_at,
        model.received_at,
    ))
}

/// The outcome of an idempotent inbox insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateInboxOutcome {
    /// The envelope was stored as a new `received` entry.
    Created,
    /// A stored entry with the same operation id is still being processed.
    DuplicateInProgress,
    /// A stored entry with the same operation id already finished; the
    /// duplicate is answered with the recorded outcome instead of being
    /// executed again.
    DuplicateResolved(InboxEntryState),
}

/// The outcome of an inbox state-machine write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InboxAdvanceOutcome {
    /// The transition was applied; the entry now carries the given state.
    Advanced(InboxEntryState),
    /// The entry already carried the target state; nothing changed.
    AlreadyInState,
}

/// A controlled failure while persisting or advancing received envelopes.
#[derive(Debug, Error)]
pub enum CenterInboxRepositoryError {
    #[error("inbox write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("inbox entry for operation {operation_id} was not found")]
    NotFound { operation_id: OperationId },
    #[error(
        "event {event} cannot apply to inbox entry of operation {operation_id} in state {current}"
    )]
    StateConflict {
        operation_id: OperationId,
        event: InboxEvent,
        current: InboxEntryState,
    },
    #[error("stored inbox entry {entry_id} is invalid: {source}")]
    Corrupt {
        entry_id: InboxEntryId,
        #[source]
        source: StoredCenterInboxError,
    },
    #[error("inbox database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted inbox data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredCenterInboxError {
    #[error("stored operation id is invalid: {0}")]
    InvalidOperationId(#[source] uuid::Error),
    #[error("stored inbox state is invalid: {0}")]
    InvalidState(#[source] InboxEntryStateParseError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        InboxEntryId, InboxEvent, InstanceId, InstanceKind, OperationId, SiteInstance,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    fn site_instance(now: OffsetDateTime) -> SiteInstance {
        SiteInstance::new(
            InstanceId::generate(),
            String::from("Site One"),
            InstanceKind::Site,
            now,
        )
    }

    fn inbox_entry(
        site: &SiteInstance,
        operation_id: OperationId,
        base: OffsetDateTime,
        state: InboxEntryState,
    ) -> InboxEntry {
        InboxEntry::from_parts(
            InboxEntryId::generate(),
            operation_id,
            site.id(),
            String::from(r#"{"operation_id":"1"}"#),
            state,
            base + Duration::hours(1),
            base,
        )
    }

    #[tokio::test]
    async fn operation_id_is_the_idempotency_key() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();

        // A fresh operation id proceeds and is stored as received.
        let first = inbox_entry(&site, operation_id, base, InboxEntryState::Received);
        assert_eq!(
            store.create_inbox_entry(&first).await?,
            CreateInboxOutcome::Created
        );

        // The same operation id is parked while still being processed.
        let duplicate = inbox_entry(&site, operation_id, base, InboxEntryState::Received);
        assert_eq!(
            store.create_inbox_entry(&duplicate).await?,
            CreateInboxOutcome::DuplicateInProgress
        );

        // Once the recorded lifecycle finishes, the duplicate is answered
        // with the recorded outcome instead of a second execution.
        store
            .advance_inbox_entry(operation_id, InboxEvent::Accepted)
            .await?;
        store
            .advance_inbox_entry(operation_id, InboxEvent::Completed)
            .await?;
        assert_eq!(
            store.create_inbox_entry(&duplicate).await?,
            CreateInboxOutcome::DuplicateResolved(InboxEntryState::Completed)
        );

        // The idempotency lookup returns the stored entry.
        let stored = store
            .find_inbox_entry_by_operation(operation_id)
            .await?
            .ok_or("stored inbox entry is missing")?;
        assert_eq!(stored.state(), InboxEntryState::Completed);
        assert_eq!(stored.operation_id(), operation_id);
        assert_eq!(
            store
                .find_inbox_entry_by_operation(OperationId::generate())
                .await?,
            None
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn advance_walks_the_state_machine_idempotently() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;
        let operation_id = OperationId::generate();
        store
            .create_inbox_entry(&inbox_entry(
                &site,
                operation_id,
                base,
                InboxEntryState::Received,
            ))
            .await?;

        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::Advanced(InboxEntryState::Accepted)
        );
        // A repeated acceptance is a no-op, not an error: the center may
        // re-deliver progress.
        assert_eq!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Accepted)
                .await?,
            InboxAdvanceOutcome::AlreadyInState
        );
        // A rejection while accepted is an illegal transition.
        assert!(matches!(
            store
                .advance_inbox_entry(operation_id, InboxEvent::Rejected)
                .await,
            Err(CenterInboxRepositoryError::StateConflict { .. })
        ));
        // An unknown operation id is refused.
        assert!(matches!(
            store
                .advance_inbox_entry(OperationId::generate(), InboxEvent::Accepted)
                .await,
            Err(CenterInboxRepositoryError::NotFound { .. })
        ));

        store.close().await?;
        drop(directory);
        Ok(())
    }

    async fn store_with_directory() -> Result<(tempfile::TempDir, SqliteStore), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let store = SqliteStore::open(directory.path().join("rutilus.db")).await?;
        Ok((directory, store))
    }
}
