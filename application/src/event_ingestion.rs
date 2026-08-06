use std::{error::Error, num::NonZeroU64};

use rutilus_domain::{EndpointId, Event};
use thiserror::Error;

use crate::BoundaryFuture;

/// The pull side of one open endpoint event stream (§14.4, §7.8).
///
/// # The drain contract (design §7.8)
///
/// The pull handle is self-contained: it owns its connection and its
/// transient Session. The listener observes its stop signal by cancelling
/// the in-flight [`Self::pull`] (dropping the future) and then awaiting
/// [`Self::close`] — never by simply dropping the handle. `close` shuts the
/// stream down gracefully: it fires the implementation's cancellation, closes
/// the connection, and deletes the transient Session, so no Session survives
/// the listener. This is the "every long-lived connection has a shutdown
/// signal" rule of §7.8: the signal lives outside the boundary, but the
/// shutdown sequence is part of the boundary contract.
pub trait EventStreamPull: Send {
    /// The stream's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Pulls the next event from the stream.
    ///
    /// `Ok(None)` reports a clean stream end — the server closed the
    /// connection — which the listener treats as reconnectable. An `Err`
    /// reports a transport or protocol failure, also reconnectable. Only the
    /// listener's bounded reconnect policy decides when an endpoint is given
    /// up on. After [`Self::close`], pulls return `Ok(None)`.
    fn pull(&mut self) -> BoundaryFuture<'_, Result<Option<Event>, Self::Error>>;

    /// Shuts the stream down gracefully: closes the connection and deletes
    /// the transient Session (see the trait doc). Safe to call after an
    /// in-flight pull was cancelled by dropping its future.
    fn close(&mut self) -> BoundaryFuture<'_, ()>;
}

/// The SSE event-stream boundary of one endpoint's `EventService` (§14.4).
///
/// Implemented over the Redfish gateway (infra-redfish): the implementation
/// resolves the endpoint's address, trust decision, and active credential,
/// opens the endpoint's advertised `EventService` SSE stream, and yields one
/// complete domain [`Event`] per event frame — the source endpoint, the
/// product-side receive time, and the derived dedup key already stamped
/// (§14.4 记录事件来源). The boundary deliberately takes the endpoint id
/// only — never an address or credential — so the caller cannot reach into
/// the endpoint's identity layer.
///
/// # The cancellation contract
///
/// Cancellation is observed outside the boundary (the listener's stop
/// watch); the boundary's side is [`EventStreamPull::close`], which must
/// close the connection and delete the transient Session when the listener
/// shuts down. A stop that lands while the stream is still being *opened*
/// abandons the in-flight open; the implementation's transient Session
/// cleanup is best-effort there, exactly like every other authenticated
/// gateway call that is cancelled mid-flight.
pub trait EventStream: Send + Sync {
    /// The boundary's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// The concrete pull handle of one open stream.
    type Stream: EventStreamPull<Error = Self::Error> + Send + 'static;

    /// Opens the endpoint's `EventService` stream.
    fn open_stream(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Self::Stream, Self::Error>>;
}

impl<Stream> EventStream for &Stream
where
    Stream: EventStream + ?Sized,
{
    type Error = Stream::Error;
    type Stream = Stream::Stream;

    fn open_stream(
        &self,
        endpoint_id: EndpointId,
    ) -> BoundaryFuture<'_, Result<Self::Stream, Self::Error>> {
        Stream::open_stream(*self, endpoint_id)
    }
}

/// The persistence boundary of the Event lifecycle (§14.4, §9.3).
///
/// The boundary exposes exactly two operations: append one event, and list
/// the bounded newest-first tail. There is intentionally no update or
/// delete — an event record is immutable once persisted.
///
/// # The dedup contract
///
/// §14.4 去除明显重复 is enforced by the repository: appending an event
/// whose derived dedup key (`MessageId` + BMC event timestamp, scoped to the
/// endpoint) already has a row is a successful no-op — never an error, so
/// redelivered SSE frames are absorbed without surfacing to the caller. The
/// persistence implementation enforces this with a unique index, which makes
/// the dedup atomic under concurrency instead of a check-then-insert race.
pub trait EventRepository: Send + Sync {
    /// The repository's controlled failure type.
    type Error: Error + Send + Sync + 'static;

    /// Persists one event, or absorbs it as a duplicate (§14.4 去除明显重复).
    fn append_event<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>>;

    /// Lists the newest events first, bounded by `limit`.
    ///
    /// The order is descending product receive time (`observed_at`), the
    /// same timeline the dedup key orders by, so the console's newest-first
    /// contract needs no secondary sort. The exact tiebreak between two
    /// events received at the same instant is the repository's choice.
    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>>;
}

impl<Repository> EventRepository for &Repository
where
    Repository: EventRepository + ?Sized,
{
    type Error = Repository::Error;

    fn append_event<'a>(&'a self, event: &'a Event) -> BoundaryFuture<'a, Result<(), Self::Error>> {
        Repository::append_event(*self, event)
    }

    fn list_recent_events(
        &self,
        limit: NonZeroU64,
    ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
        Repository::list_recent_events(*self, limit)
    }
}

/// The §14.4 event ingestion use case: records one received endpoint event.
///
/// # Why the use case receives the complete event
///
/// The event is already complete when it reaches the use case: the stream
/// boundary yields the domain [`Event`] with the source endpoint, the
/// product-side receive time, and the derived dedup key stamped (§14.4 记录
/// 事件来源), so the use case has exactly one job — append it durably
/// through the repository boundary, whose §14.4 去除明显重复 unique index
/// absorbs redelivered frames as successful no-ops. Keeping the use case
/// this thin keeps every rejection decision (`MessageId` validation, severity
/// classification, timeline ordering) in one place: the stream
/// implementation that builds the event.
pub struct EventIngestion<Repository> {
    repository: Repository,
}

impl<Repository> EventIngestion<Repository>
where
    Repository: EventRepository,
{
    #[must_use]
    pub const fn new(repository: Repository) -> Self {
        Self { repository }
    }

    /// Persists one endpoint event (or absorbs it as a duplicate).
    ///
    /// # Errors
    ///
    /// Returns [`IngestionError::Append`] when the repository write fails.
    pub async fn ingest(&self, event: Event) -> Result<(), IngestionError<Repository::Error>> {
        self.repository
            .append_event(&event)
            .await
            .map_err(IngestionError::Append)
    }
}

/// A controlled failure while recording one endpoint event.
#[derive(Debug, Error)]
pub enum IngestionError<RepositoryError>
where
    RepositoryError: Error + 'static,
{
    /// The repository write failed.
    #[error("event append failed: {0}")]
    Append(#[source] RepositoryError),
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        fmt,
        num::NonZeroU64,
        sync::{Arc, Mutex},
    };

    use rutilus_domain::{EventId, EventSeverity, MessageId};
    use time::{Duration, OffsetDateTime};

    use super::*;

    /// A complete domain event in the shape the stream boundary yields.
    fn endpoint_event(endpoint_id: EndpointId) -> Result<Event, Box<dyn Error>> {
        let observed_at = OffsetDateTime::UNIX_EPOCH + Duration::SECOND * 100;
        Ok(Event::new(
            EventId::generate(),
            endpoint_id,
            MessageId::parse("Alert.1.0.PowerSupplyFailure")?,
            EventSeverity::Critical,
            Some("Power supply 1 lost input".to_owned()),
            observed_at - Duration::SECOND * 50,
            observed_at,
        )?)
    }

    #[tokio::test]
    async fn ingestion_appends_the_received_event_verbatim() -> Result<(), Box<dyn Error>> {
        let repository = RecordingRepository::new();
        let service = EventIngestion::new(&repository);
        let event = endpoint_event(EndpointId::generate())?;

        service.ingest(event.clone()).await?;

        let appended = repository.appended();
        assert_eq!(appended.len(), 1);
        assert_eq!(appended[0], event);
        Ok(())
    }

    #[tokio::test]
    async fn ingestion_is_idempotent_against_redelivery() -> Result<(), Box<dyn Error>> {
        let repository = RecordingRepository::new();
        let service = EventIngestion::new(&repository);
        let event = endpoint_event(EndpointId::generate())?;

        // A redelivered SSE frame is the same event; the repository's
        // §14.4 去除明显重复 unique index absorbs the second append as a
        // successful no-op, and the use case never sees a duplicate error.
        service.ingest(event.clone()).await?;
        service.ingest(event.clone()).await?;

        let appended = repository.appended();
        assert_eq!(appended.len(), 2);
        assert_eq!(appended[0].dedup_key(), appended[1].dedup_key());
        Ok(())
    }

    #[tokio::test]
    async fn ingestion_surfaces_the_repository_write_failure() -> Result<(), Box<dyn Error>> {
        let mut repository = RecordingRepository::new();
        repository.fail_appends = true;
        let service = EventIngestion::new(&repository);
        let event = endpoint_event(EndpointId::generate())?;

        let error = service.ingest(event).await;
        let source = match error {
            Err(IngestionError::Append(source)) => source,
            other => {
                return Err(std::io::Error::other(format!(
                    "expected an append failure, got {other:?}"
                ))
                .into());
            }
        };
        assert_eq!(source, MockError::Store);
        assert_eq!(
            IngestionError::Append(source).to_string(),
            "event append failed: mock store failed"
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum MockError {
        Store,
        Lock,
    }

    impl fmt::Display for MockError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(match self {
                Self::Store => "mock store failed",
                Self::Lock => "mock state is unavailable",
            })
        }
    }

    impl Error for MockError {}

    /// Records every appended event and its count.
    #[derive(Clone, Debug, Default)]
    struct RecordingRepository {
        appended: Arc<Mutex<Vec<Event>>>,
        fail_appends: bool,
    }

    impl RecordingRepository {
        fn new() -> Self {
            Self::default()
        }

        fn appended(&self) -> Vec<Event> {
            self.appended
                .lock()
                .map(|events| events.clone())
                .unwrap_or_default()
        }
    }

    impl EventRepository for RecordingRepository {
        type Error = MockError;

        fn append_event<'a>(
            &'a self,
            event: &'a Event,
        ) -> BoundaryFuture<'a, Result<(), Self::Error>> {
            Box::pin(async move {
                if self.fail_appends {
                    return Err(MockError::Store);
                }
                self.appended
                    .lock()
                    .map_err(|_| MockError::Lock)?
                    .push(event.clone());
                Ok(())
            })
        }

        fn list_recent_events(
            &self,
            _limit: NonZeroU64,
        ) -> BoundaryFuture<'_, Result<Vec<Event>, Self::Error>> {
            Box::pin(async { Err(MockError::Store) })
        }
    }

    /// A never-opening stream boundary proving the trait surface is
    /// implementable; the listener tests own the behavioral fakes.
    struct ScriptedStream;

    impl ScriptedStream {
        fn new() -> Self {
            Self
        }
    }

    impl EventStream for ScriptedStream {
        type Error = MockError;
        type Stream = EmptyPull;

        fn open_stream(
            &self,
            _endpoint_id: EndpointId,
        ) -> BoundaryFuture<'_, Result<Self::Stream, Self::Error>> {
            Box::pin(async { Err(MockError::Store) })
        }
    }

    struct EmptyPull;

    impl EventStreamPull for EmptyPull {
        type Error = MockError;

        fn pull(&mut self) -> BoundaryFuture<'_, Result<Option<Event>, Self::Error>> {
            Box::pin(async { Err(MockError::Store) })
        }

        fn close(&mut self) -> BoundaryFuture<'_, ()> {
            Box::pin(async {})
        }
    }

    #[test]
    fn stream_boundary_forwarding_through_references() {
        // The blanket `EventStream for &T` forwarding keeps the boundary
        // usable behind `Arc`s and references, like every other application
        // boundary.
        let boundary = ScriptedStream::new();
        let forwarded = &boundary;
        let _: &dyn Send = &forwarded;
    }
}
