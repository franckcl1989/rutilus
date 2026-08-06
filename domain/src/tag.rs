//! The unified persisted endpoint tag model (§9.3 组织与标签, §14.2 标签).
//!
//! A tag is one operator-defined label bound to one endpoint. The binding is
//! endpoint-scoped by design: the natural key of a tag is the pair
//! `(endpoint_id, tag_name)`, so the same label on two different endpoints is
//! two bindings. §9.3 lists a `resource_tags` table; this milestone realizes
//! that table as `endpoint_tags` — the tagged object is the endpoint, which is
//! the object the §14.2 homepage tag filter actually filters. Resource-level
//! tags are a later milestone and are deliberately not designed here.
//!
//! The persistence layout keeps the pair unique atomically (migration
//! 000010): the `tags` table holds one row per distinct name — names are
//! globally unique — and `endpoint_tags` binds each name row to the endpoints
//! carrying it, with the composite primary key `(tag_id, endpoint_id)`.
//! Because a name maps to exactly one tag row, the pair `(endpoint_id,
//! tag_name)` is unique by composition: the same endpoint can never carry the
//! same name twice, and two endpoints carrying the same name share the name
//! row while keeping independent bindings. The persistence `assign_tag`
//! find-or-creates the name row and binds with `ON CONFLICT DO NOTHING`, so
//! assignment is idempotent without a check-then-insert race.
//!
//! A tag is immutable once bound: there is no rename or rebind operation in
//! this milestone; persistence offers only assignment, removal, and the two
//! listing projections (per endpoint and per tag name).

use std::{error::Error, fmt, str::FromStr};

use uuid::Uuid;

use crate::EndpointId;

/// The longest tag name the product records.
///
/// 64 Unicode scalar values keeps an operator-defined tag label comfortably
/// bounded for the §14.2 homepage tag filter and per-endpoint tag chips,
/// without the 128-value bound artifact names need (artifact names may embed
/// version strings).
const MAX_TAG_NAME_CHARS: usize = 64;

/// The stable identity of one persisted tag name row (§9.3 组织与标签,
/// §14.2 标签).
///
/// This is the identity of the `tags` row a binding references (see the
/// module doc for the endpoint-scoped tag layout). It is globally unique:
/// every binding carries its own identity, and the same name on two
/// endpoints is two bindings sharing one name row.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TagId(Uuid);

impl TagId {
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

impl fmt::Display for TagId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for TagId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// A normalized operator-facing label for one endpoint tag.
///
/// This is its own type rather than a plain `String` so the §14.2 标签
/// contract is enforced on the way in: a tag never carries an empty or
/// unbounded name. The validation mirrors the `GroupName` precedent exactly,
/// keeping the two operator-facing label types consistent.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TagName(String);

impl TagName {
    /// Validates and normalizes a tag label.
    ///
    /// Surrounding whitespace is trimmed; the result is the exact label shown
    /// to users and stored in the `tags.name` column.
    ///
    /// # Errors
    ///
    /// Returns [`TagNameError`] for an empty label, a control character, or
    /// a label longer than [`MAX_TAG_NAME_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, TagNameError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(TagNameError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(TagNameError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_TAG_NAME_CHARS {
            return Err(TagNameError::TooLong {
                actual,
                maximum: MAX_TAG_NAME_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TagName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for TagName {
    type Err = TagNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a tag label cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TagNameError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for TagNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("tag name cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("tag name cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "tag name has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for TagNameError {}

/// One endpoint tag binding (§9.3 组织与标签, §14.2 标签).
///
/// `id` is the globally unique identity of the persisted name row the binding
/// references; `endpoint_id` is the tagged endpoint; `name` is the
/// operator-facing label. `(endpoint_id, name)` is the natural key of a tag
/// (see the module doc for the endpoint-scoped design decision).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tag {
    id: TagId,
    endpoint_id: EndpointId,
    name: TagName,
}

impl Tag {
    /// Binds `name` to `endpoint_id` under the new identity `id`.
    ///
    /// This is the single constructor: the tag is immutable once bound, and
    /// rehydration of a persisted binding needs no separate path because
    /// there is no invariant beyond the already-validated name to re-verify.
    #[must_use]
    pub fn new(id: TagId, endpoint_id: EndpointId, name: TagName) -> Self {
        Self {
            id,
            endpoint_id,
            name,
        }
    }

    #[must_use]
    pub const fn id(&self) -> TagId {
        self.id
    }

    /// Returns the tagged endpoint (see the module doc: the tagged object is
    /// the endpoint in this milestone).
    #[must_use]
    pub const fn endpoint_id(&self) -> EndpointId {
        self.endpoint_id
    }

    #[must_use]
    pub const fn name(&self) -> &TagName {
        &self.name
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::EndpointId;

    use super::*;

    #[test]
    fn tag_id_round_trips_through_text() -> Result<(), uuid::Error> {
        let original = TagId::generate();

        assert_eq!(original.into_uuid().get_version_num(), 7);
        assert_eq!(original.to_string().parse::<TagId>()?, original);
        Ok(())
    }

    #[test]
    fn name_validation_normalizes_and_rejects_bad_labels() -> Result<(), Box<dyn Error>> {
        let name = TagName::parse("  production  ")?;
        assert_eq!(name.as_str(), "production");
        assert_eq!("  ".parse::<TagName>(), Err(TagNameError::Empty));
        assert_eq!(
            "prod\nuction".parse::<TagName>(),
            Err(TagNameError::ControlCharacter)
        );
        assert!(matches!(
            TagName::parse(&"t".repeat(MAX_TAG_NAME_CHARS + 1)),
            Err(TagNameError::TooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn new_binds_the_name_to_the_endpoint() -> Result<(), Box<dyn Error>> {
        let id = TagId::generate();
        let endpoint_id = EndpointId::generate();
        let name = TagName::parse("production")?;

        let tag = Tag::new(id, endpoint_id, name.clone());

        assert_eq!(tag.id(), id);
        assert_eq!(tag.endpoint_id(), endpoint_id);
        assert_eq!(tag.name(), &name);
        Ok(())
    }
}
