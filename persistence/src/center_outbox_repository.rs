use rutilus_center_protocol::{Envelope, EnvelopeMessage};
use rutilus_domain::{
    InstanceId, OutboxEntry, OutboxEntryError, OutboxEntryId, OutboxEntryState,
    OutboxEntryStateParseError,
};
use rutilus_entity::center_outbox;
use sea_orm::sea_query::{Expr, ExprTrait};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter, QueryOrder,
    QuerySelect, Set, TransactionTrait,
};
use thiserror::Error;
use time::OffsetDateTime;

use crate::SqliteStore;

impl SqliteStore {
    /// Allocates the next per-instance sequence and persists one envelope
    /// as one atomic write (design §17, D4; §15.4).
    ///
    /// The envelope's payload column holds the §9.4 typed payload: the serde
    /// JSON serialization of the center-protocol `Envelope`, built here from
    /// `message` with the allocated sequence and `acked_sequence: 0`, so the
    /// stored payload always agrees with the row's sequence column and can
    /// only ever be JSON produced by a successfully serialized wire type.
    /// The allocation and the insert run under one write-gate acquisition,
    /// so two concurrent enqueues can never observe the same maximum.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::SequenceOverflow`] when the
    /// next sequence exceeds the signed `SQLite` range, and
    /// [`CenterOutboxRepositoryError`] variants for coordination,
    /// serialization, or database failures.
    pub async fn enqueue_outbox_entry(
        &self,
        instance_id: InstanceId,
        message: &EnvelopeMessage,
        created_at: OffsetDateTime,
    ) -> Result<OutboxEntry, CenterOutboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let maximum = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .select_only()
            .column_as(Expr::col(center_outbox::Column::Sequence).max(), "max")
            .into_tuple::<(Option<i64>,)>()
            .one(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?
            .and_then(|(maximum,)| maximum)
            .unwrap_or(0);
        let sequence = maximum
            .checked_add(1)
            .ok_or(CenterOutboxRepositoryError::SequenceOverflow { sequence: maximum })?;
        // The wire sequence is an unsigned field; the allocation is bounded
        // by the signed SQLite range above, so the conversion is exact.
        let wire_sequence = u64::try_from(sequence)
            .map_err(|_| CenterOutboxRepositoryError::SequenceOverflow { sequence })?;
        let envelope = Envelope {
            sequence: wire_sequence,
            acked_sequence: 0,
            message: Some(message.clone()),
        };
        let payload_json =
            serde_json::to_string(&envelope).map_err(CenterOutboxRepositoryError::Payload)?;
        let entry = OutboxEntry::new(
            OutboxEntryId::generate(),
            instance_id,
            sequence,
            payload_json,
            created_at,
        );
        insert_outbox_entry(&transaction, &entry).await?;
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(entry)
    }

    /// Queues one outbound envelope for delivery (design §17, D4).
    ///
    /// The per-instance sequence is pinned by the unique
    /// `(instance_id, sequence)` index, so a duplicate sequence fails the
    /// insert atomically instead of a check-then-insert race.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError`] when write coordination fails
    /// or the insert fails.
    pub async fn create_outbox_entry(
        &self,
        entry: &OutboxEntry,
    ) -> Result<(), CenterOutboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        insert_outbox_entry(&self.database, entry).await
    }

    /// Computes the next per-instance envelope sequence: the stored maximum
    /// plus one, or 1 for a site that has never queued anything.
    ///
    /// The computation runs on the write gate, so the returned sequence
    /// cannot collide with a concurrently queued envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError`] when write coordination fails
    /// or the query fails.
    pub async fn next_outbox_sequence(
        &self,
        instance_id: InstanceId,
    ) -> Result<i64, CenterOutboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let maximum = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .select_only()
            .column_as(Expr::col(center_outbox::Column::Sequence).max(), "max")
            .into_tuple::<(Option<i64>,)>()
            .one(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?
            .and_then(|(maximum,)| maximum)
            .unwrap_or(0);
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(maximum + 1)
    }

    /// Reads one outbound envelope by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when the stored row
    /// violates domain invariants.
    pub async fn find_outbox_entry(
        &self,
        entry_id: OutboxEntryId,
    ) -> Result<Option<OutboxEntry>, CenterOutboxRepositoryError> {
        let Some(model) = center_outbox::Entity::find_by_id(entry_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?
        else {
            return Ok(None);
        };
        map_stored_outbox_entry(entry_id, &model).map(Some)
    }

    /// Lists the oldest pending envelopes of one instance in sequence order.
    ///
    /// This is the delivery scan of the site sender: the transport slice
    /// takes the head of this list, sends it, and acknowledges it on the
    /// center's `Ack`.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants.
    pub async fn list_pending_outbox(
        &self,
        instance_id: InstanceId,
        limit: u64,
    ) -> Result<Vec<OutboxEntry>, CenterOutboxRepositoryError> {
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .filter(center_outbox::Column::State.eq("pending"))
            .order_by_asc(center_outbox::Column::Sequence)
            .order_by_asc(center_outbox::Column::Id)
            .limit(Some(limit))
            .all(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        models
            .iter()
            .map(|model| {
                let entry_id = OutboxEntryId::from_uuid(model.id);
                map_stored_outbox_entry(entry_id, model)
            })
            .collect()
    }

    /// Lists every outbox entry of one instance, oldest first — the §15.6
    /// offer scan of the center's operation tracking view.
    ///
    /// The center's durable outbox holds exactly the §15.6 operation offers,
    /// acknowledged or not, so the scan rebuilds the offer facts — the
    /// target, the actor context, and the offer expiry — that the tracking
    /// operation record does not persist.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::Corrupt`] when any stored row
    /// violates domain invariants.
    pub async fn list_outbox_entries(
        &self,
        instance_id: InstanceId,
    ) -> Result<Vec<OutboxEntry>, CenterOutboxRepositoryError> {
        let models = center_outbox::Entity::find()
            .filter(center_outbox::Column::InstanceId.eq(instance_id.into_uuid()))
            .order_by_asc(center_outbox::Column::Sequence)
            .order_by_asc(center_outbox::Column::Id)
            .all(&self.database)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        models
            .iter()
            .map(|model| {
                let entry_id = OutboxEntryId::from_uuid(model.id);
                map_stored_outbox_entry(entry_id, model)
            })
            .collect()
    }

    /// Acknowledges one outbound envelope (design §17, D4).
    ///
    /// The conditional update makes the write idempotent: only a `pending`
    /// row is updated, and a row that is already acknowledged is reported
    /// as [`AckOutcome::AlreadyAcknowledged`] instead of failing — the
    /// center may deliver its `Ack` more than once.
    ///
    /// # Errors
    ///
    /// Returns [`CenterOutboxRepositoryError::NotFound`] for an unknown
    /// entry.
    pub async fn ack_outbox_entry(
        &self,
        entry_id: OutboxEntryId,
        acked_at: OffsetDateTime,
    ) -> Result<AckOutcome, CenterOutboxRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(CenterOutboxRepositoryError::Coordinate)?;
        let transaction = self
            .database
            .begin()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let update = center_outbox::Entity::update_many()
            .filter(center_outbox::Column::Id.eq(entry_id.into_uuid()))
            .filter(center_outbox::Column::State.eq("pending"))
            .set(center_outbox::ActiveModel {
                state: Set(String::from("acked")),
                acked_at: Set(Some(acked_at)),
                ..Default::default()
            })
            .exec(&transaction)
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        let outcome = if update.rows_affected == 1 {
            AckOutcome::Acknowledged
        } else {
            let model = center_outbox::Entity::find_by_id(entry_id.into_uuid())
                .one(&transaction)
                .await
                .map_err(CenterOutboxRepositoryError::Database)?
                .ok_or(CenterOutboxRepositoryError::NotFound { entry_id })?;
            // The re-read also validates the stored row: a corrupt acked
            // row is refused as Corrupt instead of half-understood.
            map_stored_outbox_entry(entry_id, &model)?;
            AckOutcome::AlreadyAcknowledged
        };
        transaction
            .commit()
            .await
            .map_err(CenterOutboxRepositoryError::Database)?;
        Ok(outcome)
    }
}

async fn insert_outbox_entry<C>(
    database: &C,
    entry: &OutboxEntry,
) -> Result<(), CenterOutboxRepositoryError>
where
    C: ConnectionTrait,
{
    center_outbox::ActiveModel {
        id: Set(entry.id().into_uuid()),
        sequence: Set(entry.sequence()),
        instance_id: Set(entry.instance_id().into_uuid()),
        payload_json: Set(entry.payload_json().to_owned()),
        state: Set(entry.state().as_str().to_owned()),
        retry_count: Set(entry.retry_count()),
        created_at: Set(entry.created_at()),
        acked_at: Set(entry.acked_at()),
    }
    .insert(database)
    .await
    .map_err(CenterOutboxRepositoryError::Database)?;
    Ok(())
}

fn map_stored_outbox_entry(
    entry_id: OutboxEntryId,
    model: &center_outbox::Model,
) -> Result<OutboxEntry, CenterOutboxRepositoryError> {
    OutboxEntry::try_from_parts(
        entry_id,
        InstanceId::from_uuid(model.instance_id),
        model.sequence,
        model.payload_json.clone(),
        model
            .state
            .parse::<OutboxEntryState>()
            .map_err(StoredCenterOutboxError::InvalidState)
            .map_err(|source| CenterOutboxRepositoryError::Corrupt { entry_id, source })?,
        model.retry_count,
        model.created_at,
        model.acked_at,
    )
    .map_err(|source| CenterOutboxRepositoryError::Corrupt {
        entry_id,
        source: StoredCenterOutboxError::Invalid(source),
    })
}

/// The outcome of an outbox acknowledgement write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckOutcome {
    /// The pending entry was acknowledged.
    Acknowledged,
    /// The entry was already acknowledged; nothing changed.
    AlreadyAcknowledged,
}

/// A controlled failure while persisting or acknowledging outbound
/// envelopes.
#[derive(Debug, Error)]
pub enum CenterOutboxRepositoryError {
    #[error("outbox write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("the outbox sequence cannot advance past {sequence}")]
    SequenceOverflow { sequence: i64 },
    #[error("the envelope could not be serialized into the outbox payload: {0}")]
    Payload(#[source] serde_json::Error),
    #[error("outbox entry {entry_id} was not found")]
    NotFound { entry_id: OutboxEntryId },
    #[error("stored outbox entry {entry_id} is invalid: {source}")]
    Corrupt {
        entry_id: OutboxEntryId,
        #[source]
        source: StoredCenterOutboxError,
    },
    #[error("outbox database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why persisted outbox data cannot be mapped into valid product types.
#[derive(Debug, Error)]
pub enum StoredCenterOutboxError {
    #[error("stored outbox state is invalid: {0}")]
    InvalidState(#[source] OutboxEntryStateParseError),
    #[error("stored outbox entry is invalid: {0}")]
    Invalid(#[source] OutboxEntryError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{
        InstanceId, InstanceKind, OutboxEntry, OutboxEntryId, OutboxEntryState, SiteInstance,
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

    fn outbox_entry(site: &SiteInstance, sequence: i64, created_at: OffsetDateTime) -> OutboxEntry {
        OutboxEntry::new(
            OutboxEntryId::generate(),
            site.id(),
            sequence,
            format!(r#"{{"sequence":{sequence}}}"#),
            created_at,
        )
    }

    #[tokio::test]
    async fn pending_listing_is_sequence_ordered_and_bounded() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;

        store
            .create_outbox_entry(&outbox_entry(&site, 1, base))
            .await?;
        store
            .create_outbox_entry(&outbox_entry(&site, 3, base))
            .await?;
        store
            .create_outbox_entry(&outbox_entry(&site, 2, base))
            .await?;

        // The pending scan replays in sequence order, bounded by the limit.
        let page = store.list_pending_outbox(site.id(), 2).await?;
        assert_eq!(
            page.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![1, 2],
            "the page must hold the two oldest sequences in order"
        );
        let all = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(
            all.iter().map(OutboxEntry::sequence).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the full scan must replay every pending envelope in sequence order"
        );

        // Another instance's pending envelopes never leak into this scan.
        let other = SiteInstance::new(
            InstanceId::generate(),
            String::from("Site Two"),
            InstanceKind::Site,
            base,
        );
        store.create_instance(&other).await?;
        store
            .create_outbox_entry(&outbox_entry(&other, 1, base))
            .await?;
        let all = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(all.len(), 3);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn ack_is_idempotent_and_sequence_allocation_is_monotonic() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let base = OffsetDateTime::now_utc();
        let site = site_instance(base);
        store.create_instance(&site).await?;

        // The first sequence of an empty site is 1, and it continues after
        // the stored maximum.
        assert_eq!(store.next_outbox_sequence(site.id()).await?, 1);
        let entry = outbox_entry(&site, 1, base);
        store.create_outbox_entry(&entry).await?;
        store
            .create_outbox_entry(&outbox_entry(&site, 5, base))
            .await?;
        assert_eq!(store.next_outbox_sequence(site.id()).await?, 6);

        // Acknowledging moves the entry out of the pending scan and is
        // idempotent: a repeated ack of the same entry is a no-op.
        assert_eq!(
            store
                .ack_outbox_entry(entry.id(), base + Duration::SECOND)
                .await?,
            AckOutcome::Acknowledged
        );
        let pending = store.list_pending_outbox(site.id(), 10).await?;
        assert_eq!(
            pending
                .iter()
                .map(OutboxEntry::sequence)
                .collect::<Vec<_>>(),
            vec![5],
            "the acked entry must leave the delivery scan"
        );
        assert_eq!(
            store
                .ack_outbox_entry(entry.id(), base + Duration::SECOND)
                .await?,
            AckOutcome::AlreadyAcknowledged
        );
        assert!(matches!(
            store
                .ack_outbox_entry(OutboxEntryId::generate(), base)
                .await,
            Err(CenterOutboxRepositoryError::NotFound { .. })
        ));

        // An acked entry rehydrates with its acknowledgement time.
        let stored = store
            .find_outbox_entry(entry.id())
            .await?
            .ok_or("stored outbox entry is missing")?;
        assert_eq!(stored.state(), OutboxEntryState::Acked);
        assert_eq!(stored.acked_at(), Some(base + Duration::SECOND));

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
