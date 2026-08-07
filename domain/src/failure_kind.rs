use std::{error::Error, fmt, str::FromStr};

/// The classification of one failed operation (§13.7 batch reporting).
///
/// A `Failed` operation carries a kind only when the product can prove *why*
/// it failed in product vocabulary: the kind separates an unsupported
/// capability — an endpoint-side limitation the operator can act on — from an
/// ordinary failure. The persisted value is a stable product code, enforced by
/// the `operations.failure_kind` CHECK constraint (migration 000012), so
/// rehydration never has to parse a code this build cannot classify, exactly
/// like the state and source codes.
///
/// The vocabulary is deliberately open: the CHECK constraint uses an `IN`
/// list so later slices can extend it with new kinds without a table rebuild.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FailureKind {
    /// The endpoint cannot execute this write because the required capability
    /// is provably unsupported — not compiled, not advertised,
    /// schema-incompatible, or read-only (§13.3 step 2 pre-flight). The write
    /// was never dispatched, so the refusal is provable and the bucket
    /// "unsupported" is the honest reporting verdict: this is not an ordinary
    /// failure the operator can retry against the same endpoint.
    CapabilityUnsupported,
}

impl FailureKind {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CapabilityUnsupported => "capability-unsupported",
        }
    }
}

impl fmt::Display for FailureKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for FailureKind {
    type Err = FailureKindParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "capability-unsupported" => Ok(Self::CapabilityUnsupported),
            _ => Err(FailureKindParseError),
        }
    }
}

/// A persisted failure-kind code is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureKindParseError;

impl fmt::Display for FailureKindParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown failure kind code")
    }
}

impl Error for FailureKindParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_single_known_kind_round_trips_through_its_stable_code() {
        assert_eq!(
            FailureKind::CapabilityUnsupported.as_str(),
            "capability-unsupported"
        );
        assert_eq!(
            "capability-unsupported".parse::<FailureKind>(),
            Ok(FailureKind::CapabilityUnsupported)
        );
        assert_eq!(
            FailureKind::CapabilityUnsupported.to_string(),
            "capability-unsupported"
        );
    }

    #[test]
    fn unknown_codes_are_refused() {
        assert_eq!(
            "capability-missing".parse::<FailureKind>(),
            Err(FailureKindParseError)
        );
        assert_eq!("failed".parse::<FailureKind>(), Err(FailureKindParseError));
        assert_eq!("".parse::<FailureKind>(), Err(FailureKindParseError));
    }
}
