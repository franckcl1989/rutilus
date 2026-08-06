//! The unified persisted static endpoint group model (§9.3 组织与标签,
//! §12.1 分组, §14.2 静态分组).
//!
//! A group is an operator-defined name and the static list of endpoints that
//! belong to it. §14.2 scopes the product to static membership and
//! explicitly excludes dynamic rule groups and a general query language
//! ("1.0.0 不设计动态规则组和通用查询语言"), so a group's membership is exactly
//! the stored endpoint list and changes only through [`Group::add_member`]
//! and [`Group::remove_member`] — never through a rule or a query.
//!
//! Membership is a set: adding an endpoint that is already a member is a
//! no-op, and removing an endpoint that is not a member is a no-op, so a
//! redelivered or racing membership write converges on the same state instead
//! of duplicating a row (the §15.4 at-least-once discipline, same as the
//! event append). The set is kept sorted by `EndpointId`, and persistence
//! loads membership rows ordered by endpoint identity, so a persisted group
//! always rehydrates equal to the value the caller built — equality of this
//! value object must not depend on the order a caller happened to add members
//! in.
//!
//! The group name is validated on the way in (see [`GroupName`]); the
//! database enforces global name uniqueness (migration 000010), which is the
//! atomic duplicate refusal behind the persistence `create_group`.

use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;
use uuid::Uuid;

use crate::EndpointId;

/// The longest group name the product records.
///
/// 64 Unicode scalar values keeps an operator-defined group label comfortably
/// bounded for the §12.1 分组 navigation and the §14.2 homepage group filter,
/// without the 128-value bound artifact names need (artifact names may embed
/// version strings).
const MAX_GROUP_NAME_CHARS: usize = 64;

/// The stable identity of one persisted static group (§9.3 组织与标签,
/// §12.1 分组).
///
/// This is the identity of the `groups` row that carries the operator-defined
/// static membership list of §14.2 静态分组.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GroupId(Uuid);

impl GroupId {
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

impl fmt::Display for GroupId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for GroupId {
    type Err = uuid::Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(value).map(Self)
    }
}

/// A normalized operator-facing label for one static group.
///
/// This is its own type rather than a plain `String` so the §12.1 分组
/// contract is enforced on the way in: a group never carries an empty or
/// unbounded name, and the unique-name persistence rule operates on a value
/// that is always well-formed. The validation mirrors the `ArtifactName`
/// precedent exactly.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct GroupName(String);

impl GroupName {
    /// Validates and normalizes a group label.
    ///
    /// Surrounding whitespace is trimmed; the result is the exact label shown
    /// to users and stored in the `groups.name` column.
    ///
    /// # Errors
    ///
    /// Returns [`GroupNameError`] for an empty label, a control character,
    /// or a label longer than [`MAX_GROUP_NAME_CHARS`] Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, GroupNameError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(GroupNameError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(GroupNameError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_GROUP_NAME_CHARS {
            return Err(GroupNameError::TooLong {
                actual,
                maximum: MAX_GROUP_NAME_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for GroupName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for GroupName {
    type Err = GroupNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a group label cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupNameError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for GroupNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("group name cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("group name cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "group name has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for GroupNameError {}

/// One persisted static endpoint group (§9.3 组织与标签, §14.2 静态分组).
///
/// The name and the membership are private and only change through the
/// documented constructors and the two membership methods, which enforce the
/// set invariants: membership never duplicates and never depends on call
/// order, and §14.2 scopes groups to static membership — there is no rule or
/// query that could change a membership in 1.0.0.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Group {
    id: GroupId,
    name: GroupName,
    member_endpoint_ids: Vec<EndpointId>,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Group {
    /// Declares a new static group with an empty membership list.
    ///
    /// The update time equals the creation time until persistence records a
    /// membership change. The caller supplies the clock, keeping the domain
    /// free of clock access (§7.2), mirroring `Artifact::new`.
    #[must_use]
    pub fn new(id: GroupId, name: GroupName, created_at: OffsetDateTime) -> Self {
        Self {
            id,
            name,
            member_endpoint_ids: Vec::new(),
            created_at,
            updated_at: created_at,
        }
    }

    /// Rehydrates a persisted group record.
    ///
    /// This is the persistence loading path, which must accept whatever the
    /// database stored — but only what is internally consistent. The
    /// database has no timeline constraint (mirroring the artifact
    /// precedent), so a stored row with an inverted timeline is refused here
    /// as a corrupt aggregate; the name is re-validated by its own type on
    /// the way in. The membership is normalized to the canonical sorted set,
    /// so a row whose members were stored in any order rehydrates equal to
    /// the value the caller built.
    ///
    /// # Errors
    ///
    /// Returns [`GroupRestoreError`] when the stored update time precedes the
    /// stored creation time.
    pub fn try_from_parts(
        id: GroupId,
        name: GroupName,
        member_endpoint_ids: Vec<EndpointId>,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, GroupRestoreError> {
        if updated_at < created_at {
            return Err(GroupRestoreError::InvalidTimeline);
        }
        let mut member_endpoint_ids = member_endpoint_ids;
        member_endpoint_ids.sort_unstable();
        member_endpoint_ids.dedup();
        Ok(Self {
            id,
            name,
            member_endpoint_ids,
            created_at,
            updated_at,
        })
    }

    /// Adds `endpoint_id` to the membership, unless it is already a member.
    ///
    /// §14.2 静态分组: membership changes only through this method and
    /// [`Group::remove_member`]. The operation is idempotent — adding an
    /// endpoint that is already a member has no effect — so a redelivered
    /// membership write converges instead of duplicating (the §15.4
    /// at-least-once discipline). The set stays sorted by `EndpointId`, so a
    /// persisted group always rehydrates equal to the value the caller built.
    ///
    /// Returns whether the membership actually changed.
    #[must_use]
    pub fn add_member(&mut self, endpoint_id: EndpointId) -> bool {
        match self.member_endpoint_ids.binary_search(&endpoint_id) {
            Ok(_) => false,
            Err(position) => {
                self.member_endpoint_ids.insert(position, endpoint_id);
                true
            }
        }
    }

    /// Removes `endpoint_id` from the membership, unless it is not a member.
    ///
    /// Idempotent, mirroring [`Group::add_member`]: removing an endpoint that
    /// is not a member has no effect. Returns whether the membership actually
    /// changed.
    #[must_use]
    pub fn remove_member(&mut self, endpoint_id: EndpointId) -> bool {
        match self.member_endpoint_ids.binary_search(&endpoint_id) {
            Ok(position) => {
                self.member_endpoint_ids.remove(position);
                true
            }
            Err(_) => false,
        }
    }

    #[must_use]
    pub const fn id(&self) -> GroupId {
        self.id
    }

    #[must_use]
    pub const fn name(&self) -> &GroupName {
        &self.name
    }

    /// Returns the static membership list, sorted by endpoint identity.
    ///
    /// The order is the canonical set order (see the module doc); callers
    /// that need display order sort for the endpoint display name instead.
    #[must_use]
    pub fn member_endpoint_ids(&self) -> &[EndpointId] {
        &self.member_endpoint_ids
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    /// Returns when the group or its membership last changed at the
    /// persistence boundary; equals `created_at` for a fresh group.
    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// A persisted group record violates a domain invariant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GroupRestoreError {
    /// The stored update time precedes the stored creation time.
    InvalidTimeline,
}

impl fmt::Display for GroupRestoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTimeline => {
                formatter.write_str("group update time cannot precede its creation time")
            }
        }
    }
}

impl Error for GroupRestoreError {}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use crate::EndpointId;

    use super::*;

    #[test]
    fn group_id_round_trips_through_text() -> Result<(), uuid::Error> {
        let original = GroupId::generate();

        assert_eq!(original.into_uuid().get_version_num(), 7);
        assert_eq!(original.to_string().parse::<GroupId>()?, original);
        Ok(())
    }

    #[test]
    fn name_validation_normalizes_and_rejects_bad_labels() -> Result<(), Box<dyn Error>> {
        let name = GroupName::parse("  Lab servers  ")?;
        assert_eq!(name.as_str(), "Lab servers");
        assert_eq!("  ".parse::<GroupName>(), Err(GroupNameError::Empty));
        assert_eq!(
            "Lab\nservers".parse::<GroupName>(),
            Err(GroupNameError::ControlCharacter)
        );
        assert!(matches!(
            GroupName::parse(&"g".repeat(MAX_GROUP_NAME_CHARS + 1)),
            Err(GroupNameError::TooLong { .. })
        ));
        Ok(())
    }

    #[test]
    fn new_groups_start_empty_with_their_creation_time() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let group = Group::new(
            GroupId::generate(),
            GroupName::parse("Lab servers")?,
            created_at,
        );

        assert!(group.member_endpoint_ids().is_empty());
        assert_eq!(group.created_at(), created_at);
        assert_eq!(group.updated_at(), created_at);
        Ok(())
    }

    #[test]
    fn add_member_is_idempotent_and_keeps_the_set_sorted() -> Result<(), Box<dyn Error>> {
        let mut group = group_with_name("Lab servers")?;
        let first = EndpointId::generate();
        let second = EndpointId::generate();
        let third = EndpointId::generate();

        assert!(group.add_member(first));
        assert!(group.add_member(third));
        assert!(group.add_member(second));
        assert!(
            !group.add_member(first),
            "adding an existing member must be a no-op"
        );

        let mut expected = vec![first, second, third];
        expected.sort();
        assert_eq!(
            group.member_endpoint_ids(),
            expected.as_slice(),
            "membership must be a set in canonical endpoint order"
        );
        Ok(())
    }

    #[test]
    fn remove_member_is_idempotent_and_keeps_the_set_sorted() -> Result<(), Box<dyn Error>> {
        let mut group = group_with_name("Lab servers")?;
        let first = EndpointId::generate();
        let second = EndpointId::generate();
        assert!(group.add_member(first));
        assert!(group.add_member(second));

        assert!(group.remove_member(first));
        assert!(
            !group.remove_member(first),
            "removing an absent member must be a no-op"
        );
        assert!(
            !group.remove_member(EndpointId::generate()),
            "removing an endpoint that never was a member must be a no-op"
        );
        assert_eq!(group.member_endpoint_ids(), &[second]);
        Ok(())
    }

    #[test]
    fn rehydration_restores_membership_and_normalizes_its_order() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let updated_at = created_at + time::Duration::SECOND;
        let id = GroupId::generate();
        let name = GroupName::parse("Lab servers")?;
        let members = [
            EndpointId::generate(),
            EndpointId::generate(),
            EndpointId::generate(),
        ];
        let mut expected = members.to_vec();
        expected.sort();

        let restored =
            Group::try_from_parts(id, name.clone(), members.to_vec(), created_at, updated_at)?;

        assert_eq!(restored.id(), id);
        assert_eq!(restored.name(), &name);
        assert_eq!(restored.created_at(), created_at);
        assert_eq!(restored.updated_at(), updated_at);
        assert_eq!(
            restored.member_endpoint_ids(),
            expected.as_slice(),
            "a stored membership in any order must rehydrate canonical"
        );
        Ok(())
    }

    #[test]
    fn rehydration_refuses_an_inverted_timeline() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let inverted = created_at - time::Duration::SECOND;

        assert_eq!(
            Group::try_from_parts(
                GroupId::generate(),
                GroupName::parse("Lab servers")?,
                Vec::new(),
                created_at,
                inverted,
            ),
            Err(GroupRestoreError::InvalidTimeline)
        );
        Ok(())
    }

    fn group_with_name(name: &str) -> Result<Group, GroupNameError> {
        Ok(Group::new(
            GroupId::generate(),
            GroupName::parse(name)?,
            OffsetDateTime::now_utc(),
        ))
    }
}
