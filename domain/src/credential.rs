use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;

use crate::{CredentialId, CredentialVersionId};

const MAX_CREDENTIAL_NAME_CHARS: usize = 128;
const MAX_USERNAME_CHARS: usize = 256;

/// A human-readable, normalized label for a reusable credential.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialName(String);

impl CredentialName {
    /// Validates and normalizes a credential label.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialNameError`] for an empty label, a control character,
    /// or a label longer than 128 Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, CredentialNameError> {
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(CredentialNameError::Empty);
        }
        if normalized.chars().any(char::is_control) {
            return Err(CredentialNameError::ControlCharacter);
        }
        let actual = normalized.chars().count();
        if actual > MAX_CREDENTIAL_NAME_CHARS {
            return Err(CredentialNameError::TooLong {
                actual,
                maximum: MAX_CREDENTIAL_NAME_CHARS,
            });
        }
        Ok(Self(normalized.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CredentialName {
    type Err = CredentialNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a credential label cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialNameError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for CredentialNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("credential name cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("credential name cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "credential name has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for CredentialNameError {}

/// The exact account name sent to a BMC authentication service.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CredentialUsername(String);

impl CredentialUsername {
    /// Validates a BMC account name without changing significant whitespace.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialUsernameError`] for an empty account name, a control
    /// character, or a value longer than 256 Unicode scalar values.
    pub fn parse(value: &str) -> Result<Self, CredentialUsernameError> {
        if value.trim().is_empty() {
            return Err(CredentialUsernameError::Empty);
        }
        if value.chars().any(char::is_control) {
            return Err(CredentialUsernameError::ControlCharacter);
        }
        let actual = value.chars().count();
        if actual > MAX_USERNAME_CHARS {
            return Err(CredentialUsernameError::TooLong {
                actual,
                maximum: MAX_USERNAME_CHARS,
            });
        }
        Ok(Self(value.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CredentialUsername {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CredentialUsername {
    type Err = CredentialUsernameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Why a BMC account name cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialUsernameError {
    Empty,
    ControlCharacter,
    TooLong { actual: usize, maximum: usize },
}

impl fmt::Display for CredentialUsernameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("credential username cannot be empty"),
            Self::ControlCharacter => {
                formatter.write_str("credential username cannot contain control characters")
            }
            Self::TooLong { actual, maximum } => write!(
                formatter,
                "credential username has {actual} characters; maximum is {maximum}"
            ),
        }
    }
}

impl Error for CredentialUsernameError {}

/// Secret-free metadata for one reusable BMC credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Credential {
    id: CredentialId,
    name: CredentialName,
    username: CredentialUsername,
    active_version_id: CredentialVersionId,
    created_at: OffsetDateTime,
    updated_at: OffsetDateTime,
}

impl Credential {
    /// Constructs credential metadata while enforcing its timestamp ordering.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialTimelineError`] when the update time precedes the
    /// creation time.
    pub fn try_new(
        id: CredentialId,
        name: CredentialName,
        username: CredentialUsername,
        active_version_id: CredentialVersionId,
        created_at: OffsetDateTime,
        updated_at: OffsetDateTime,
    ) -> Result<Self, CredentialTimelineError> {
        if updated_at < created_at {
            return Err(CredentialTimelineError);
        }
        Ok(Self {
            id,
            name,
            username,
            active_version_id,
            created_at,
            updated_at,
        })
    }

    #[must_use]
    pub const fn id(&self) -> CredentialId {
        self.id
    }

    #[must_use]
    pub const fn name(&self) -> &CredentialName {
        &self.name
    }

    #[must_use]
    pub const fn username(&self) -> &CredentialUsername {
        &self.username
    }

    #[must_use]
    pub const fn active_version_id(&self) -> CredentialVersionId {
        self.active_version_id
    }

    #[must_use]
    pub const fn created_at(&self) -> OffsetDateTime {
        self.created_at
    }

    #[must_use]
    pub const fn updated_at(&self) -> OffsetDateTime {
        self.updated_at
    }
}

/// A persisted credential has an invalid timestamp ordering.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CredentialTimelineError;

impl fmt::Display for CredentialTimelineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("credential update time cannot precede its creation time")
    }
}

impl Error for CredentialTimelineError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_labels_but_preserves_exact_usernames() -> Result<(), Box<dyn Error>> {
        let name = CredentialName::parse("  Rack administrators  ")?;
        let username = CredentialUsername::parse(" administrator ")?;

        assert_eq!(name.as_str(), "Rack administrators");
        assert_eq!(username.as_str(), " administrator ");
        Ok(())
    }

    #[test]
    fn rejects_empty_control_and_oversized_values() {
        assert_eq!(
            CredentialName::parse(" \t "),
            Err(CredentialNameError::Empty)
        );
        assert_eq!(
            CredentialName::parse("rack\nadmin"),
            Err(CredentialNameError::ControlCharacter)
        );
        assert!(matches!(
            CredentialName::parse(&"n".repeat(MAX_CREDENTIAL_NAME_CHARS + 1)),
            Err(CredentialNameError::TooLong { .. })
        ));

        assert_eq!(
            CredentialUsername::parse("admin\0"),
            Err(CredentialUsernameError::ControlCharacter)
        );
        assert!(matches!(
            CredentialUsername::parse(&"u".repeat(MAX_USERNAME_CHARS + 1)),
            Err(CredentialUsernameError::TooLong { .. })
        ));
    }

    #[test]
    fn rejects_an_inverted_persisted_timeline() -> Result<(), Box<dyn Error>> {
        let created_at = OffsetDateTime::now_utc();
        let updated_at = created_at - time::Duration::SECOND;
        let result = Credential::try_new(
            CredentialId::generate(),
            CredentialName::parse("lab")?,
            CredentialUsername::parse("administrator")?,
            CredentialVersionId::generate(),
            created_at,
            updated_at,
        );

        assert_eq!(result, Err(CredentialTimelineError));
        Ok(())
    }
}
