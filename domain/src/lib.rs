#![forbid(unsafe_code)]

use std::{error::Error, fmt, str::FromStr};

mod audit;
mod capability;
mod credential;
mod endpoint;
mod endpoint_address;
mod ids;
mod operation;
mod redfish_command;
mod resource_snapshot;

pub use audit::{
    AuditAction, AuditActor, AuditCodeParseError, AuditEvent, AuditEventError, AuditFailure,
    AuditFailureVerification, AuditOperationContext, AuditOperationContextError, AuditOutcome,
    AuditOutcomeKind, AuditParameterSummary, AuditParameterSummaryError, AuditProgress,
    AuditRedfishOperation, AuditSequence, AuditSequenceError, AuditTarget, AuditTlsTrust,
    AuditVerification, ProductPermission,
};
pub use capability::{
    CAPABILITY_LEDGER_ORDER, CapabilityClassification, CapabilityState, CapabilityStateParseError,
    EndpointCapability, EndpointCapabilityObservation, EndpointCapabilityParseError, UiLocation,
    UiLocationParseError,
};
pub use credential::{
    Credential, CredentialName, CredentialNameError, CredentialTimelineError, CredentialUsername,
    CredentialUsernameError,
};
pub use endpoint::{
    CertificateFingerprint, CertificateFingerprintParseError, Endpoint, EndpointDisplayName,
    EndpointDisplayNameError, EndpointTimelineError, TlsCertificate, TlsCertificateError,
    TlsIdentityChanged, TlsTrust,
};
pub use endpoint_address::{EndpointAddress, EndpointAddressError};
pub use ids::{
    AuditEventId, AuditOperationId, CredentialId, CredentialVersionId, EndpointId, OperationId,
    ResourceId, TargetId,
};
pub use operation::{
    InvalidTransition, Operation, OperationEvent, OperationSource, OperationSourceParseError,
    OperationState, OperationStateParseError, OperationTarget, OperationTimelineError, transition,
};
pub use redfish_command::{
    BootCommand, BootSource, BootSourceOverrideEnabled, BootSourceOverrideMode, ChassisCommand,
    CreateSubscription, DeleteSubscription, EventCommand, EventDestinationProtocol,
    EventSubscriptionError, EventType, ManagerCommand, RedfishCommand, ResetKeysType, ResetType,
    SecureBootCommand, SetBootSourceOverride, SystemCommand,
};
pub use resource_snapshot::{
    RefreshGeneration, RefreshGenerationError, ResourceEtag, ResourceEtagError, ResourceFeature,
    ResourceFeatureParseError, ResourceODataId, ResourceODataIdError, ResourceODataType,
    ResourceODataTypeError, ResourceSnapshot, ResourceSnapshotPayload,
    ResourceSnapshotPayloadError,
};

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
    /// Returns the stable product code used by persistence and protocols.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Site => "site",
            Self::Center => "center",
        }
    }

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

impl fmt::Display for DeploymentPosture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for DeploymentPosture {
    type Err = DeploymentPostureParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "standalone" => Ok(Self::Standalone),
            "site" => Ok(Self::Site),
            "center" => Ok(Self::Center),
            _ => Err(DeploymentPostureParseError),
        }
    }
}

/// A persisted deployment posture is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentPostureParseError;

impl fmt::Display for DeploymentPostureParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("unknown deployment posture code")
    }
}

impl Error for DeploymentPostureParseError {}

#[cfg(test)]
mod tests {
    use super::{DeploymentPosture, RuntimeRole};

    #[test]
    fn standalone_and_site_share_the_edge_role() {
        assert_eq!(DeploymentPosture::Standalone.role(), RuntimeRole::Edge);
        assert_eq!(DeploymentPosture::Site.role(), RuntimeRole::Edge);
        assert_eq!(
            DeploymentPosture::Standalone
                .to_string()
                .parse::<DeploymentPosture>(),
            Ok(DeploymentPosture::Standalone)
        );
        assert_eq!(
            DeploymentPosture::Site
                .to_string()
                .parse::<DeploymentPosture>(),
            Ok(DeploymentPosture::Site)
        );
        assert_eq!(
            DeploymentPosture::Center
                .to_string()
                .parse::<DeploymentPosture>(),
            Ok(DeploymentPosture::Center)
        );
    }

    #[test]
    fn only_edge_postures_manage_bmc_endpoints() {
        assert!(DeploymentPosture::Standalone.manages_bmc_endpoints());
        assert!(DeploymentPosture::Site.manages_bmc_endpoints());
        assert!(!DeploymentPosture::Center.manages_bmc_endpoints());
    }
}
