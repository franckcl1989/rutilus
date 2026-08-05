#![forbid(unsafe_code)]

mod credential;
mod endpoint_address;
mod ids;

pub use credential::{
    Credential, CredentialName, CredentialNameError, CredentialTimelineError, CredentialUsername,
    CredentialUsernameError,
};
pub use endpoint_address::{EndpointAddress, EndpointAddressError};
pub use ids::{CredentialId, CredentialVersionId, EndpointId};

/// The upstream version used as the starting point for product development.
pub const NV_REDFISH_DEVELOPMENT_BASELINE: &str = "0.12.1";

/// The execution boundary inside the single Rutilus binary.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RuntimeRole {
    /// Directly manages BMC endpoints.
    Edge,
    /// Aggregates sites and never connects directly to a BMC.
    Center,
}

/// A supported product deployment posture.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum DeploymentPosture {
    /// Local, foreground Edge usage with loopback-only defaults.
    Standalone,
    /// Long-running Edge usage on a management network.
    Site,
    /// The central aggregation service.
    Center,
}

impl DeploymentPosture {
    /// Returns the only runtime role valid for this posture.
    #[must_use]
    pub const fn role(self) -> RuntimeRole {
        match self {
            Self::Standalone | Self::Site => RuntimeRole::Edge,
            Self::Center => RuntimeRole::Center,
        }
    }

    /// Reports whether this posture may connect directly to BMC endpoints.
    #[must_use]
    pub const fn manages_bmc_endpoints(self) -> bool {
        matches!(self.role(), RuntimeRole::Edge)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeploymentPosture, RuntimeRole};

    #[test]
    fn standalone_and_site_share_the_edge_role() {
        assert_eq!(DeploymentPosture::Standalone.role(), RuntimeRole::Edge);
        assert_eq!(DeploymentPosture::Site.role(), RuntimeRole::Edge);
    }

    #[test]
    fn only_edge_postures_manage_bmc_endpoints() {
        assert!(DeploymentPosture::Standalone.manages_bmc_endpoints());
        assert!(DeploymentPosture::Site.manages_bmc_endpoints());
        assert!(!DeploymentPosture::Center.manages_bmc_endpoints());
    }
}
