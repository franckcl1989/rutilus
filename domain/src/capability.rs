use std::{error::Error, fmt, str::FromStr};

/// A standard Redfish capability needed by the 0.1 endpoint read loop.
///
/// Each variant maps to one public `nv-redfish` feature and can be extended as
/// later milestones bring the remaining standard capability surface online.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum EndpointCapability {
    SessionService,
    Systems,
    Chassis,
    Managers,
}

impl EndpointCapability {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionService => "session-service",
            Self::Systems => "systems",
            Self::Chassis => "chassis",
            Self::Managers => "managers",
        }
    }

    /// Returns the public upstream feature that compiles this capability.
    #[must_use]
    pub const fn upstream_feature(self) -> &'static str {
        match self {
            Self::SessionService => "session-service",
            Self::Systems => "computer-systems",
            Self::Chassis => "chassis",
            Self::Managers => "managers",
        }
    }

    /// Returns the capability-ledger classification required by the product
    /// design.
    #[must_use]
    pub const fn classification(self) -> CapabilityClassification {
        match self {
            Self::SessionService => CapabilityClassification::Infrastructure,
            Self::Systems | Self::Chassis | Self::Managers => CapabilityClassification::UserFacing,
        }
    }
}

impl fmt::Display for EndpointCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EndpointCapability {
    type Err = EndpointCapabilityParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "session-service" => Ok(Self::SessionService),
            "systems" => Ok(Self::Systems),
            "chassis" => Ok(Self::Chassis),
            "managers" => Ok(Self::Managers),
            _ => Err(EndpointCapabilityParseError),
        }
    }
}

/// A persisted capability code is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointCapabilityParseError;

impl fmt::Display for EndpointCapabilityParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown endpoint capability code")
    }
}

impl Error for EndpointCapabilityParseError {}

/// Product-facing classification for one capability-ledger entry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityClassification {
    UserFacing,
    Infrastructure,
    LegacyCompatibility,
    Internal,
}

/// The final state obtained from the compiled, advertised, and usable
/// capability layers.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CapabilityState {
    Supported,
    ReadOnly,
    Unauthorized,
    TemporarilyUnavailable,
    SchemaIncompatible,
    NotAdvertised,
    NotCompiled,
}

impl CapabilityState {
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::ReadOnly => "read-only",
            Self::Unauthorized => "unauthorized",
            Self::TemporarilyUnavailable => "temporarily-unavailable",
            Self::SchemaIncompatible => "schema-incompatible",
            Self::NotAdvertised => "not-advertised",
            Self::NotCompiled => "not-compiled",
        }
    }

    /// Reports whether the current binary includes the upstream feature.
    #[must_use]
    pub const fn is_compiled(self) -> bool {
        !matches!(self, Self::NotCompiled)
    }

    /// Reports whether the endpoint advertised the capability after accounting
    /// for the current binary's compiled surface.
    #[must_use]
    pub const fn is_advertised(self) -> bool {
        !matches!(self, Self::NotCompiled | Self::NotAdvertised)
    }

    /// Reports whether the capability can currently serve product reads.
    #[must_use]
    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Supported | Self::ReadOnly)
    }
}

impl fmt::Display for CapabilityState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for CapabilityState {
    type Err = CapabilityStateParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "supported" => Ok(Self::Supported),
            "read-only" => Ok(Self::ReadOnly),
            "unauthorized" => Ok(Self::Unauthorized),
            "temporarily-unavailable" => Ok(Self::TemporarilyUnavailable),
            "schema-incompatible" => Ok(Self::SchemaIncompatible),
            "not-advertised" => Ok(Self::NotAdvertised),
            "not-compiled" => Ok(Self::NotCompiled),
            _ => Err(CapabilityStateParseError),
        }
    }
}

/// A persisted capability state is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityStateParseError;

impl fmt::Display for CapabilityStateParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown endpoint capability state")
    }
}

impl Error for CapabilityStateParseError {}

/// One endpoint's observed state for one compiled product capability.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EndpointCapabilityObservation {
    capability: EndpointCapability,
    state: CapabilityState,
}

impl EndpointCapabilityObservation {
    #[must_use]
    pub const fn new(capability: EndpointCapability, state: CapabilityState) -> Self {
        Self { capability, state }
    }

    #[must_use]
    pub const fn capability(self) -> EndpointCapability {
        self.capability
    }

    #[must_use]
    pub const fn state(self) -> CapabilityState {
        self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CAPABILITIES: [EndpointCapability; 4] = [
        EndpointCapability::SessionService,
        EndpointCapability::Systems,
        EndpointCapability::Chassis,
        EndpointCapability::Managers,
    ];

    const STATES: [CapabilityState; 7] = [
        CapabilityState::Supported,
        CapabilityState::ReadOnly,
        CapabilityState::Unauthorized,
        CapabilityState::TemporarilyUnavailable,
        CapabilityState::SchemaIncompatible,
        CapabilityState::NotAdvertised,
        CapabilityState::NotCompiled,
    ];

    #[test]
    fn core_capability_codes_and_upstream_features_are_stable() {
        for capability in CAPABILITIES {
            assert_eq!(capability.as_str().parse(), Ok(capability));
            assert!(!capability.upstream_feature().is_empty());
        }
        assert_eq!(
            EndpointCapability::SessionService.classification(),
            CapabilityClassification::Infrastructure
        );
        assert_eq!(
            EndpointCapability::Systems.classification(),
            CapabilityClassification::UserFacing
        );
        assert_eq!(
            "unknown".parse::<EndpointCapability>(),
            Err(EndpointCapabilityParseError)
        );
    }

    #[test]
    fn final_states_preserve_compiled_advertised_and_usable_layers() {
        for state in STATES {
            assert_eq!(state.as_str().parse(), Ok(state));
        }

        assert!(CapabilityState::Supported.is_usable());
        assert!(CapabilityState::ReadOnly.is_usable());
        assert!(CapabilityState::Unauthorized.is_advertised());
        assert!(CapabilityState::SchemaIncompatible.is_advertised());
        assert!(!CapabilityState::NotAdvertised.is_advertised());
        assert!(CapabilityState::NotAdvertised.is_compiled());
        assert!(!CapabilityState::NotCompiled.is_compiled());
        assert!(!CapabilityState::NotCompiled.is_advertised());
        assert!(!CapabilityState::TemporarilyUnavailable.is_usable());
        assert_eq!(
            "unknown".parse::<CapabilityState>(),
            Err(CapabilityStateParseError)
        );
    }

    #[test]
    fn observations_keep_capability_and_state_together() {
        let observation = EndpointCapabilityObservation::new(
            EndpointCapability::Managers,
            CapabilityState::ReadOnly,
        );

        assert_eq!(observation.capability(), EndpointCapability::Managers);
        assert_eq!(observation.state(), CapabilityState::ReadOnly);
    }
}
