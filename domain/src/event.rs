//! The unified persisted BMC event model (§9.3 事件和遥测, §14.4 Event).
//!
//! Every Redfish event the product receives — from an `EventService`
//! subscription (SSE) or from event-log polling — is converted into one
//! persisted [`Event`] (§14.4: `EventService` 公开能力、支持订阅和 SSE、记录事件
//! 来源、去除明显重复、展示原始 `MessageId` 和 `Severity`). The record keeps the
//! event exactly as the BMC reported it — the raw Redfish `MessageId` and
//! `Severity`, the original `Message` text when present, and the BMC's own
//! `EventTimestamp` — beside the product-side receive time
//! (`observed_at`), so a viewer can always see the BMC's clock and the
//! product's clock side by side.
//!
//! §14.4 去除明显重复 is implemented as a derived dedup key: the combination
//! of the `MessageId` and the BMC event timestamp. The key is derived inside
//! the constructor — never caller-supplied — so a persisted row can never
//! disagree with the message and time it records. Persistence enforces the
//! "same key on the same endpoint keeps only the first row" rule with a
//! unique index (see `rutilus_migration` 000008 and the persistence
//! `append_event`), which makes dedup atomic under concurrency instead of a
//! check-then-insert race.
//!
//! The absorption cost of that rule is accepted deliberately: two genuinely
//! distinct events from the same endpoint that share a `MessageId` and the
//! same BMC timestamp — for example, two different resources reporting the
//! same generic alert within the same second — are collapsed into the first
//! row. 去除明显重复 is duplicate removal, not event correlation, and §14.4
//! scopes the product to the former; a later milestone that needs to
//! distinguish such collisions must widen the key (for example with the
//! resource `@odata.id`) rather than relax the rule.

use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::EndpointId;

/// The longest Redfish `MessageId` the product records.
///
/// Registry message ids such as `ResourceEvent.1.0.LanResetType` are short
/// (well under half this bound), but OEM registries can use long qualified
/// names; 128 Unicode scalar values keeps the bound generous without letting
/// a runaway payload grow the table and the dedup key without limit.
const MAX_MESSAGE_ID_CHARS: usize = 128;

/// The separator between the `MessageId` and the event timestamp inside a
/// dedup key.
///
/// [`MessageId`] validation refuses control characters, so this separator
/// can never occur inside a `MessageId` and the composition is injective:
/// the same key implies the same `MessageId` and the same event timestamp,
/// and different (`MessageId`, timestamp) pairs never collide.
const DEDUP_KEY_SEPARATOR: char = '\u{1F}';

/// The stable identity of one persisted BMC event (§9.3, §14.4).
///
/// This is the identity of the `events` row. It is distinct from
/// `AuditEventId`: an `AuditEventId` names an append-only accountability
/// record the product itself writes, while an `EventId` names a BMC event
/// record the product received and stored. The two identifiers never
/// interchange.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EventId(Uuid);

impl EventId {
    /// Generates a time-ordered UUID version 7 identifier.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID without changing its value.
    #[must_use]
    pub const fn from_uuid(value: Uuid) -> Self {
        Self(value)
    }

    /// Returns the underlying UUID value.
    #[must_use]
    pub const fn into_uuid(self) -> Uuid {
        self.0
    }
}

impl fmt::Display for EventId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for EventId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// A Redfish `MessageId` as the BMC reported it.
///
/// This is its own type rather than a plain `String` so the §14.4 "展示原始
/// `MessageId`" contract is enforced on the way in: an event never carries an
/// empty or unbounded message id, and the dedup key built from it is
/// therefore always well-formed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MessageId(String);

impl MessageId {
    /// Validates and normalizes a Redfish `MessageId`.
    ///
    /// Surrounding whitespace is trimmed (a BMC may pad the value); the
    /// result is the exact id text shown to users and used in the dedup key.
    ///
    /// # Errors
    ///
    /// Returns [`MessageIdError`] for an empty value, a control character,
    /// or a value longer than [`MAX_MESSAGE_ID_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, MessageIdError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(MessageIdError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(MessageIdError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_MESSAGE_ID_CHARS {
            return Err(MessageIdError::TooLong {
                actual,
                maximum: MAX_MESSAGE_ID_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for MessageId {
    type Err = MessageIdError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a Redfish `MessageId` cannot be recorded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageIdError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for MessageIdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("Redfish MessageId cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("Redfish MessageId cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "Redfish MessageId has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for MessageIdError {}

/// The Redfish event `Severity` as the BMC reported it (`Event_v1` CSDL).
///
/// The CSDL `Event.Severity` vocabulary is exactly `OK`, `Warning`, and
/// `Critical`; the codes returned by [`Self::as_str`] are the product's
/// stable lowercase spellings used by persistence and protocols, and they
/// never change across milestones. A severity this build cannot classify is
/// refused — persistence treats a stored row with an unknown code as
/// corrupt, so rehydration never has to guess at a severity.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum EventSeverity {
    Ok,
    Warning,
    Critical,
}

impl EventSeverity {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for EventSeverity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EventSeverity {
    type Err = EventSeverityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ok" => Ok(Self::Ok),
            "warning" => Ok(Self::Warning),
            "critical" => Ok(Self::Critical),
            _ => Err(EventSeverityParseError),
        }
    }
}

/// A persisted event severity is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventSeverityParseError;

impl fmt::Display for EventSeverityParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown event severity code")
    }
}

impl Error for EventSeverityParseError {}

/// One persisted BMC event (§9.3, §14.4).
///
/// The BMC-reported fields — `MessageId`, `Severity`, the original `Message`
/// text, and the BMC's own `EventTimestamp` — are recorded verbatim:
/// §14.4 展示原始 `MessageId` 和 `Severity` means the viewer sees exactly what
/// the BMC reported, not a product-side rephrasing. `observed_at` is the
/// product-side receive time, recorded so the two clocks are always
/// comparable. The dedup key is derived from the `MessageId` and the event
/// timestamp (see the module doc); it is a private fact of the record and is
/// never caller-supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
// The `event_timestamp` field deliberately repeats the type name: it is the
// Redfish `EventTimestamp` property name (§14.4 展示原始), and renaming it
// would divorce the record from the wire vocabulary it mirrors.
#[allow(clippy::struct_field_names)]
pub struct Event {
    id: EventId,
    endpoint_id: EndpointId,
    message_id: MessageId,
    severity: EventSeverity,
    message: Option<String>,
    event_timestamp: OffsetDateTime,
    observed_at: OffsetDateTime,
    dedup_key: String,
}

impl Event {
    /// Records a BMC event the product received at `observed_at`.
    ///
    /// `observed_at` is the product clock's receive time, supplied by the
    /// caller exactly like `Operation::apply`'s `now` parameter, so the
    /// domain stays free of clock access.
    ///
    /// # Errors
    ///
    /// Returns [`EventTimelineError`] when the BMC's event timestamp is
    /// after the product's receive time: a received event cannot have a
    /// future timestamp, and recording one would silently invert the
    /// timeline that the dedup key and the recent listing order by.
    pub fn new(
        id: EventId,
        endpoint_id: EndpointId,
        message_id: MessageId,
        severity: EventSeverity,
        message: Option<String>,
        event_timestamp: OffsetDateTime,
        observed_at: OffsetDateTime,
    ) -> Result<Self, EventTimelineError> {
        build(
            id,
            endpoint_id,
            message_id,
            severity,
            message,
            event_timestamp,
            observed_at,
        )
    }

    /// Rehydrates a persisted event record.
    ///
    /// This is the persistence loading path, which must accept whatever the
    /// database stored — but only what is internally consistent. The
    /// database has no timeline constraint (mirroring the audit and
    /// operation precedents), so a stored row with an inverted timeline is
    /// refused here as a corrupt aggregate; the severity and `MessageId` are
    /// re-validated by their own types on the way in. The derived dedup key
    /// is recomputed from the stored message id and timestamp, so a stored
    /// row can never be rehydrated with a key that disagrees with its own
    /// fields.
    ///
    /// # Errors
    ///
    /// Returns [`EventTimelineError`] when the stored event timestamp is
    /// after the stored receive time.
    pub fn try_from_parts(
        id: EventId,
        endpoint_id: EndpointId,
        message_id: MessageId,
        severity: EventSeverity,
        message: Option<String>,
        event_timestamp: OffsetDateTime,
        observed_at: OffsetDateTime,
    ) -> Result<Self, EventTimelineError> {
        build(
            id,
            endpoint_id,
            message_id,
            severity,
            message,
            event_timestamp,
            observed_at,
        )
    }

    #[must_use]
    pub const fn id(&self) -> EventId {
        self.id
    }

    /// Returns the endpoint that reported the event (§14.4 记录事件来源).
    ///
    /// The endpoint is the event's source: the dedup key applies within one
    /// endpoint only, so the same message id at the same time on two
    /// different endpoints is two events, not a duplicate.
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    /// Returns the raw Redfish `MessageId`, as the BMC reported it.
    #[must_use]
    pub fn message_id(&self) -> &MessageId {
        &self.message_id
    }

    #[must_use]
    pub const fn severity(&self) -> EventSeverity {
        self.severity
    }

    /// Returns the original Redfish `Message` text, when the BMC provided
    /// one (§14.4 展示原始 `MessageId` 和 `Severity` keeps the text verbatim).
    #[must_use]
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// Returns the BMC's own event timestamp (its `EventTimestamp`).
    #[must_use]
    pub const fn event_timestamp(&self) -> OffsetDateTime {
        self.event_timestamp
    }

    /// Returns when the product received the event.
    #[must_use]
    pub const fn observed_at(&self) -> OffsetDateTime {
        self.observed_at
    }

    /// Returns the dedup key: `MessageId` + event timestamp, scoped to the
    /// endpoint (see the module doc for the §14.4 semantics).
    #[must_use]
    pub fn dedup_key(&self) -> &str {
        &self.dedup_key
    }
}

/// A BMC event has an invalid timestamp ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EventTimelineError;

impl fmt::Display for EventTimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("event timestamp cannot be after the product receive time")
    }
}

impl Error for EventTimelineError {}

/// Validates the timeline and assembles an event with its derived dedup key.
///
/// Both constructors run the same invariant: `event_timestamp` must not be
/// after `observed_at`. The dedup key is derived here, never taken from a
/// caller, so a row can never disagree with the message id and timestamp it
/// records.
fn build(
    id: EventId,
    endpoint_id: EndpointId,
    message_id: MessageId,
    severity: EventSeverity,
    message: Option<String>,
    event_timestamp: OffsetDateTime,
    observed_at: OffsetDateTime,
) -> Result<Event, EventTimelineError> {
    if event_timestamp > observed_at {
        return Err(EventTimelineError);
    }
    let dedup_key = derive_dedup_key(&message_id, event_timestamp);
    Ok(Event {
        id,
        endpoint_id,
        message_id,
        severity,
        message,
        event_timestamp,
        observed_at,
        dedup_key,
    })
}

/// Builds the dedup key for one event.
///
/// The key is the `MessageId` and the BMC event timestamp joined by a
/// separator that [`MessageId`] validation refuses, so the composition is
/// injective. The timestamp is formatted as its stable RFC 3339-style text,
/// which is deterministic per instant, so a redelivered event — the same
/// BMC message at the same BMC time — always produces the identical key.
fn derive_dedup_key(message_id: &MessageId, event_timestamp: OffsetDateTime) -> String {
    format!("{message_id}{DEDUP_KEY_SEPARATOR}{event_timestamp}")
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::EndpointId;

    use super::*;

    /// Every severity, so the stable-code tests cannot silently miss a
    /// variant.
    const ALL_SEVERITIES: [EventSeverity; 3] = [
        EventSeverity::Ok,
        EventSeverity::Warning,
        EventSeverity::Critical,
    ];

    /// A valid event with the given message id, severity, and timestamps.
    fn event(
        message_id: &str,
        severity: EventSeverity,
        event_timestamp: OffsetDateTime,
        observed_at: OffsetDateTime,
    ) -> Result<Event, Box<dyn Error>> {
        Ok(Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse(message_id)?,
            severity,
            Some(String::from("a power supply lost input")),
            event_timestamp,
            observed_at,
        )?)
    }

    #[test]
    fn event_id_round_trips_through_text() -> Result<(), uuid::Error> {
        let original = EventId::generate();

        assert_eq!(original.into_uuid().get_version_num(), 7);
        assert_eq!(original.to_string().parse::<EventId>()?, original);
        Ok(())
    }

    #[test]
    fn severity_codes_are_unique_non_empty_and_round_trip() {
        let mut seen = Vec::new();
        for severity in ALL_SEVERITIES {
            let code = severity.as_str();
            assert!(!code.is_empty(), "severity codes must not be empty");
            assert!(
                !seen.contains(&code),
                "product code {code} is used by more than one severity"
            );
            seen.push(code);
            assert_eq!(code.parse(), Ok(severity));
            assert_eq!(severity.to_string(), code);
        }
        // The Event_v1 CSDL vocabulary is exactly OK/Warning/Critical; a
        // sibling vocabulary value must never be silently accepted.
        assert_eq!(
            "informational".parse::<EventSeverity>(),
            Err(EventSeverityParseError)
        );
    }

    #[test]
    fn message_id_validation_normalizes_and_rejects_bad_values() -> Result<(), Box<dyn Error>> {
        let message_id = MessageId::parse("  ResourceEvent.1.0.LanResetType  ")?;
        assert_eq!(message_id.as_str(), "ResourceEvent.1.0.LanResetType");
        assert_eq!("  ".parse::<MessageId>(), Err(MessageIdError::Empty));
        assert_eq!(
            "ResourceEvent.1.0.Lan\nResetType".parse::<MessageId>(),
            Err(MessageIdError::ControlCharacter)
        );
        assert!(matches!(
            MessageId::parse(&"x".repeat(MAX_MESSAGE_ID_CHARS + 1)),
            Err(MessageIdError::TooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn dedup_key_is_derived_from_message_id_and_event_timestamp() -> Result<(), Box<dyn Error>> {
        let timestamp = OffsetDateTime::now_utc();
        let observed_at = timestamp + time::Duration::SECOND;
        let first = event(
            "Alert.1.0.PowerSupplyFailure",
            EventSeverity::Critical,
            timestamp,
            observed_at,
        )?;
        let redelivered = event(
            "Alert.1.0.PowerSupplyFailure",
            EventSeverity::Critical,
            timestamp,
            observed_at,
        )?;

        assert_eq!(
            first.dedup_key(),
            redelivered.dedup_key(),
            "the same BMC message at the same BMC time must deduplicate"
        );
        let expected_key = format!("{}\u{1F}{}", first.message_id(), first.event_timestamp());
        assert_eq!(first.dedup_key(), expected_key);

        // A distinct message id at the same time, or the same message id at
        // a distinct time, is a different event — never a duplicate.
        let other_message = event(
            "ResourceEvent.1.0.LanResetType",
            EventSeverity::Warning,
            timestamp,
            observed_at,
        )?;
        assert_ne!(first.dedup_key(), other_message.dedup_key());
        let later = event(
            "Alert.1.0.PowerSupplyFailure",
            EventSeverity::Critical,
            timestamp + time::Duration::SECOND,
            observed_at + time::Duration::SECOND,
        )?;
        assert_ne!(first.dedup_key(), later.dedup_key());
        Ok(())
    }

    #[test]
    fn new_records_the_reported_fields_verbatim() -> Result<(), Box<dyn Error>> {
        let id = EventId::generate();
        let endpoint_id = EndpointId::generate();
        let message_id = MessageId::parse("ResourceEvent.1.0.LanResetType")?;
        let event_timestamp = OffsetDateTime::now_utc();
        let observed_at = event_timestamp + time::Duration::SECOND;
        let event = Event::new(
            id,
            endpoint_id,
            message_id.clone(),
            EventSeverity::Warning,
            Some(String::from("LAN reset requested")),
            event_timestamp,
            observed_at,
        )?;

        assert_eq!(event.id(), id);
        assert_eq!(event.endpoint_id(), endpoint_id);
        assert_eq!(event.message_id(), &message_id);
        assert_eq!(event.severity(), EventSeverity::Warning);
        assert_eq!(event.message(), Some("LAN reset requested"));
        assert_eq!(event.event_timestamp(), event_timestamp);
        assert_eq!(event.observed_at(), observed_at);
        assert_eq!(
            event.dedup_key(),
            "ResourceEvent.1.0.LanResetType\u{1F}".to_owned() + &event_timestamp.to_string()
        );
        Ok(())
    }

    #[test]
    fn events_without_a_message_text_report_none() -> Result<(), Box<dyn Error>> {
        let timestamp = OffsetDateTime::now_utc();
        let event = Event::new(
            EventId::generate(),
            EndpointId::generate(),
            MessageId::parse("Alert.1.0.PowerSupplyFailure")?,
            EventSeverity::Critical,
            None,
            timestamp,
            timestamp,
        )?;

        assert_eq!(event.message(), None);
        Ok(())
    }

    #[test]
    fn equal_timestamps_are_accepted_and_inverted_timelines_are_refused()
    -> Result<(), Box<dyn Error>> {
        let timestamp = OffsetDateTime::now_utc();
        let message_id = MessageId::parse("Alert.1.0.PowerSupplyFailure")?;
        let endpoint_id = EndpointId::generate();
        let id = EventId::generate();

        // The BMC clock and the product clock may read exactly the same; the
        // boundary is inclusive.
        Event::new(
            id,
            endpoint_id,
            message_id.clone(),
            EventSeverity::Critical,
            None,
            timestamp,
            timestamp,
        )?;
        assert!(matches!(
            Event::new(
                id,
                endpoint_id,
                message_id.clone(),
                EventSeverity::Critical,
                None,
                timestamp + time::Duration::SECOND,
                timestamp,
            ),
            Err(EventTimelineError)
        ));
        assert!(matches!(
            Event::try_from_parts(
                id,
                endpoint_id,
                message_id,
                EventSeverity::Critical,
                None,
                timestamp + time::Duration::SECOND,
                timestamp,
            ),
            Err(EventTimelineError)
        ));
        Ok(())
    }

    #[test]
    fn rehydration_restores_a_persisted_record_with_its_derived_key() -> Result<(), Box<dyn Error>>
    {
        let event_timestamp = OffsetDateTime::now_utc();
        let observed_at = event_timestamp + time::Duration::SECOND;
        let id = EventId::generate();
        let endpoint_id = EndpointId::generate();
        let message_id = MessageId::parse("ResourceEvent.1.0.LanResetType")?;
        let restored = Event::try_from_parts(
            id,
            endpoint_id,
            message_id.clone(),
            EventSeverity::Warning,
            Some(String::from("LAN reset requested")),
            event_timestamp,
            observed_at,
        )?;

        assert_eq!(restored.id(), id);
        assert_eq!(restored.endpoint_id(), endpoint_id);
        assert_eq!(restored.message_id(), &message_id);
        assert_eq!(restored.severity(), EventSeverity::Warning);
        assert_eq!(restored.message(), Some("LAN reset requested"));
        assert_eq!(restored.event_timestamp(), event_timestamp);
        assert_eq!(restored.observed_at(), observed_at);
        assert_eq!(
            restored.dedup_key(),
            format!(
                "ResourceEvent.1.0.LanResetType\u{1F}{}",
                restored.event_timestamp()
            )
        );
        Ok(())
    }
}
