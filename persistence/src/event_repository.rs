use std::str::FromStr;

use rutilus_domain::{
    EndpointId, Event, EventId, EventSeverity, EventSeverityParseError, EventTimelineError,
    MessageId, MessageIdError,
};
use rutilus_entity::event;
use sea_orm::{DbErr, EntityTrait, QueryOrder, QuerySelect, Set, TryInsertResult};
use thiserror::Error;

use crate::SqliteStore;

impl SqliteStore {
    /// Persists one received BMC event (§14.4), deduplicated.
    ///
    /// §14.4 去除明显重复 means: the same endpoint reporting the same
    /// `MessageId` at the same BMC event time is one event, and only the first
    /// occurrence is stored. The unique index on
    /// `(endpoint_id, dedup_key)` (migration 000008) is the enforcer: the
    /// insert uses `ON CONFLICT (endpoint_id, dedup_key) DO NOTHING`, so a
    /// duplicate lands as a no-op conflict instead of an error. This makes
    /// dedup atomic under concurrency — there is no check-then-insert race —
    /// and keeps the at-least-once delivery discipline of design §15.4:
    /// a redelivered event (subscription redelivery, event-log re-poll, SSE
    /// reconnect replay) is acknowledged as `Ok` and the first row is never
    /// rewritten.
    ///
    /// The write gate serializes writers exactly like the other repositories,
    /// so `SqliteStore::close` can coordinate with an in-flight append.
    ///
    /// # Errors
    ///
    /// Returns [`EventRepositoryError`] when write coordination fails or
    /// `SQLite` rejects the append for a reason other than the dedup
    /// conflict.
    pub async fn append_event(&self, event: &Event) -> Result<(), EventRepositoryError> {
        let _write_permit = self
            .write_gate
            .acquire()
            .await
            .map_err(EventRepositoryError::Coordinate)?;
        let result = event::Entity::insert(project_event(event))
            .on_conflict_do_nothing_on([event::Column::EndpointId, event::Column::DedupKey])
            .exec(&self.database)
            .await
            .map_err(EventRepositoryError::Database)?;
        match result {
            // `Inserted` persisted a new row; `Conflicted` is a dedup hit —
            // the first row is authoritative and never rewritten. `Empty`
            // cannot occur for a single-model insert and exists only for the
            // iterator API; naming it keeps the match exhaustive.
            TryInsertResult::Inserted(_) | TryInsertResult::Conflicted | TryInsertResult::Empty => {
            }
        }
        Ok(())
    }

    /// Reads one stored event by stable identity.
    ///
    /// # Errors
    ///
    /// Returns [`EventRepositoryError`] when the query fails or the stored
    /// row violates a domain invariant (unknown severity, invalid `MessageId`,
    /// or an inverted timeline).
    pub async fn find_event(
        &self,
        event_id: EventId,
    ) -> Result<Option<Event>, EventRepositoryError> {
        let Some(model) = event::Entity::find_by_id(event_id.into_uuid())
            .one(&self.database)
            .await
            .map_err(EventRepositoryError::Database)?
        else {
            return Ok(None);
        };
        let domain = map_stored_event(&model).map_err(|source| corrupt(event_id, source))?;
        Ok(Some(domain))
    }

    /// Lists the `limit` most recently observed events, newest first.
    ///
    /// The listing is bounded by design (§14.4: 展示原始 `MessageId` 和
    /// `Severity` 的有界历史, not an unbounded scan): the query applies
    /// `LIMIT`, so it never returns more than `limit` rows, and `limit = 0`
    /// returns an empty list. Ordering is by the product receive time
    /// (`observed_at`) — the SSE replay order — with the event identity as a
    /// deterministic tie-breaker for events observed at the same instant.
    ///
    /// Each row is rehydrated as a complete domain event, so one corrupt row
    /// poisons the whole listing: the caller must surface the corruption
    /// rather than silently drop an unreadable event (the `list_operations`
    /// precedent).
    ///
    /// # Errors
    ///
    /// Returns [`EventRepositoryError`] when the query fails or any stored
    /// event violates domain invariants.
    pub async fn list_recent_events(
        &self,
        limit: usize,
    ) -> Result<Vec<Event>, EventRepositoryError> {
        let models = event::Entity::find()
            .order_by_desc(event::Column::ObservedAt)
            .order_by_desc(event::Column::Id)
            .limit(limit as u64)
            .all(&self.database)
            .await
            .map_err(EventRepositoryError::Database)?;
        let mut events = Vec::with_capacity(models.len());
        for model in models {
            let event_id = EventId::from_uuid(model.id);
            events.push(map_stored_event(&model).map_err(|source| corrupt(event_id, source))?);
        }
        Ok(events)
    }
}

fn project_event(event: &Event) -> event::ActiveModel {
    event::ActiveModel {
        id: Set(event.id().into_uuid()),
        endpoint_id: Set(event.endpoint_id().into_uuid()),
        message_id: Set(event.message_id().to_string()),
        severity: Set(event.severity().as_str().to_owned()),
        message: Set(event.message().map(str::to_owned)),
        event_timestamp: Set(event.event_timestamp()),
        observed_at: Set(event.observed_at()),
        dedup_key: Set(event.dedup_key().to_owned()),
    }
}

fn map_stored_event(model: &event::Model) -> Result<Event, StoredEventError> {
    let severity =
        EventSeverity::from_str(&model.severity).map_err(StoredEventError::InvalidSeverity)?;
    let message_id =
        MessageId::parse(&model.message_id).map_err(StoredEventError::InvalidMessageId)?;
    Event::try_from_parts(
        EventId::from_uuid(model.id),
        EndpointId::from_uuid(model.endpoint_id),
        message_id,
        severity,
        model.message.clone(),
        model.event_timestamp,
        model.observed_at,
    )
    .map_err(StoredEventError::InvalidTimeline)
}

fn corrupt(event_id: EventId, source: StoredEventError) -> EventRepositoryError {
    EventRepositoryError::Corrupt { event_id, source }
}

/// A controlled failure while appending or reading persisted events.
#[derive(Debug, Error)]
pub enum EventRepositoryError {
    #[error("event write coordination is unavailable")]
    Coordinate(#[source] tokio::sync::AcquireError),
    #[error("stored event {event_id} is invalid: {source}")]
    Corrupt {
        event_id: EventId,
        #[source]
        source: StoredEventError,
    },
    #[error("event database operation failed: {0}")]
    Database(#[source] DbErr),
}

/// Why a persisted event row cannot be mapped into a valid domain event.
#[derive(Debug, Error)]
pub enum StoredEventError {
    #[error("stored event severity is unknown: {0}")]
    InvalidSeverity(#[source] EventSeverityParseError),
    #[error("stored event MessageId is invalid: {0}")]
    InvalidMessageId(#[source] MessageIdError),
    #[error("stored event timeline is invalid: {0}")]
    InvalidTimeline(#[source] EventTimelineError),
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use rutilus_domain::{EndpointId, EventSeverity, MessageId};
    use sea_orm::{
        ActiveModelTrait, ConnectOptions, ConnectionTrait, Database, IntoActiveModel, Set,
    };
    use time::{Duration, OffsetDateTime};

    use super::*;
    use crate::SqliteStore;

    /// The dedup key that §14.4 treats as one event: the same endpoint
    /// reporting the same message at the same BMC time.
    fn critical_event(
        endpoint_id: EndpointId,
        event_timestamp: OffsetDateTime,
        observed_at: OffsetDateTime,
    ) -> Result<Event, Box<dyn Error>> {
        Ok(Event::new(
            EventId::generate(),
            endpoint_id,
            MessageId::parse("Alert.1.0.PowerSupplyFailure")?,
            EventSeverity::Critical,
            Some(String::from("a power supply lost input")),
            event_timestamp,
            observed_at,
        )?)
    }

    #[tokio::test]
    async fn appends_and_loads_events_with_their_reported_fields() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let observed_at = OffsetDateTime::now_utc();
        let first = critical_event(endpoint_id, observed_at - Duration::SECOND, observed_at)?;
        let second = Event::new(
            EventId::generate(),
            endpoint_id,
            MessageId::parse("ResourceEvent.1.0.LanResetType")?,
            EventSeverity::Warning,
            None,
            observed_at,
            observed_at,
        )?;

        store.append_event(&first).await?;
        store.append_event(&second).await?;

        assert_eq!(store.find_event(first.id()).await?, Some(first.clone()));
        assert_eq!(store.find_event(second.id()).await?, Some(second.clone()));
        assert!(store.find_event(EventId::generate()).await?.is_none());

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn a_dedup_hit_is_idempotent_and_keeps_the_first_row() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let observed_at = OffsetDateTime::now_utc();
        let event = critical_event(endpoint_id, observed_at - Duration::SECOND, observed_at)?;

        store.append_event(&event).await?;
        store.append_event(&event).await?;
        let listed = store.list_recent_events(100).await?;
        assert_eq!(listed.len(), 1, "a redelivery must not duplicate the row");
        assert_eq!(
            listed[0], event,
            "the stored row must equal the first delivery"
        );

        // A redelivery with a different id but the same dedup key is the same
        // event (§14.4 明显重复): the first row is authoritative and the
        // re-delivered record must not displace it.
        let redelivered = Event::try_from_parts(
            EventId::generate(),
            endpoint_id,
            event.message_id().clone(),
            event.severity(),
            Some(String::from("a power supply lost input")),
            event.event_timestamp(),
            observed_at,
        )?;
        assert_eq!(redelivered.dedup_key(), event.dedup_key());
        store.append_event(&redelivered).await?;
        let listed = store.list_recent_events(100).await?;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], event);

        // A different message at the same time, or the same message at a
        // different time, is a new event and must be stored.
        let other_message = Event::new(
            EventId::generate(),
            endpoint_id,
            MessageId::parse("ResourceEvent.1.0.LanResetType")?,
            EventSeverity::Warning,
            None,
            event.event_timestamp(),
            observed_at,
        )?;
        let later = critical_event(endpoint_id, observed_at, observed_at + Duration::SECOND)?;
        store.append_event(&other_message).await?;
        store.append_event(&later).await?;
        assert_eq!(store.list_recent_events(100).await?.len(), 3);

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn the_same_key_on_different_endpoints_is_not_a_duplicate() -> Result<(), Box<dyn Error>>
    {
        let (directory, store) = store_with_directory().await?;
        let observed_at = OffsetDateTime::now_utc();
        let first_endpoint = critical_event(
            EndpointId::generate(),
            observed_at - Duration::SECOND,
            observed_at,
        )?;
        let second_endpoint = critical_event(
            EndpointId::generate(),
            observed_at - Duration::SECOND,
            observed_at,
        )?;

        store.append_event(&first_endpoint).await?;
        store.append_event(&second_endpoint).await?;

        // §14.4 记录事件来源: the endpoint is part of the dedup scope, so the
        // same message at the same BMC time on two endpoints is two events.
        let listed = store.list_recent_events(100).await?;
        assert_eq!(listed.len(), 2);
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn recent_listing_is_bounded_and_newest_first() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let endpoint_id = EndpointId::generate();
        let base = OffsetDateTime::now_utc();
        let mut stored = Vec::new();
        for index in 0..5_i64 {
            let observed_at = base + Duration::seconds(index);
            let event = critical_event(endpoint_id, observed_at - Duration::SECOND, observed_at)?;
            store.append_event(&event).await?;
            stored.push(event);
        }

        let recent = store.list_recent_events(3).await?;
        assert_eq!(recent.len(), 3, "the listing must respect the limit");
        assert_eq!(
            recent.iter().map(Event::id).collect::<Vec<_>>(),
            vec![stored[4].id(), stored[3].id(), stored[2].id(),],
            "the newest events must come first"
        );
        assert_eq!(
            store.list_recent_events(0).await?.len(),
            0,
            "a zero limit must return an empty listing"
        );
        assert_eq!(
            store.list_recent_events(100).await?.len(),
            stored.len(),
            "a limit above the table size must return every event"
        );

        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn an_unknown_stored_severity_is_corrupt() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let observed_at = OffsetDateTime::now_utc();
        let valid = critical_event(
            EndpointId::generate(),
            observed_at - Duration::SECOND,
            observed_at,
        )?;
        store.append_event(&valid).await?;

        // The `ck_events_severity` CHECK refuses an unknown severity, so the
        // row that this build cannot classify is written on a dedicated
        // single-connection writer with check constraints ignored — exactly
        // what a newer build's row (a severity code this build does not know)
        // looks like to this build, the upgrade-order discipline documented
        // on `find_operation`. One connection executes both the pragma and
        // the update, so the bypass is deterministic.
        let database_path = store.database_path();
        let normalized_path = database_path.to_string_lossy().replace('\\', "/");
        let mut options = ConnectOptions::new(format!("sqlite://{normalized_path}?mode=rwc"));
        options.max_connections(1);
        options.sqlx_logging(false);
        let writer = Database::connect(options).await?;
        writer
            .execute_unprepared("PRAGMA ignore_check_constraints = ON")
            .await?;
        let mut stored = event::Entity::find_by_id(valid.id().into_uuid())
            .one(&writer)
            .await?
            .ok_or("inserted event is missing")?
            .into_active_model();
        stored.severity = Set(String::from("informational"));
        stored.update(&writer).await?;
        writer.close().await?;

        assert!(matches!(
            store.find_event(valid.id()).await,
            Err(EventRepositoryError::Corrupt {
                event_id,
                source: StoredEventError::InvalidSeverity(_),
            }) if event_id == valid.id()
        ));
        assert!(matches!(
            store.list_recent_events(100).await,
            Err(EventRepositoryError::Corrupt {
                source: StoredEventError::InvalidSeverity(_),
                ..
            })
        ));
        store.close().await?;
        drop(directory);
        Ok(())
    }

    #[tokio::test]
    async fn an_inverted_stored_timeline_is_corrupt() -> Result<(), Box<dyn Error>> {
        let (directory, store) = store_with_directory().await?;
        let observed_at = OffsetDateTime::now_utc();
        let event_id = EventId::generate();
        let message_id = MessageId::parse("Alert.1.0.PowerSupplyFailure")?;
        // The database has no timeline constraint, so a row whose BMC event
        // timestamp lies in the future of its receive time is written
        // directly; reading it back must refuse it. The severity and
        // MessageId are valid on purpose, so the failure is exactly the
        // timeline error and not a mapping error.
        event::ActiveModel {
            id: Set(event_id.into_uuid()),
            endpoint_id: Set(EndpointId::generate().into_uuid()),
            message_id: Set(message_id.to_string()),
            severity: Set(String::from("critical")),
            message: Set(None),
            event_timestamp: Set(observed_at + Duration::SECOND),
            observed_at: Set(observed_at),
            dedup_key: Set(format!(
                "{message_id}\u{1F}{}",
                observed_at + Duration::SECOND
            )),
        }
        .insert(&store.database)
        .await?;

        assert!(matches!(
            store.find_event(event_id).await,
            Err(EventRepositoryError::Corrupt {
                event_id: id,
                source: StoredEventError::InvalidTimeline(_),
            }) if id == event_id
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
