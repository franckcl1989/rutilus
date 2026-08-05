#![forbid(unsafe_code)]

mod audit_log;
mod endpoint_enrollment;
mod endpoint_onboarding;
mod endpoint_refresh;
mod endpoint_trust;

pub use audit_log::{AuditEventWriter, AuditRecordError};
pub use endpoint_enrollment::{EndpointEnrollment, EndpointEnrollmentError, EnrolledEndpoint};
pub use endpoint_onboarding::{
    AuditedEndpointOnboarding, AuditedOnboardEndpointError, BoundaryFuture, Clock,
    CredentialResolver, DiscoveredEndpointRepository, EndpointDiscovery, EndpointOnboarding,
    OnboardEndpointError, OnboardEndpointRequest, OnboardedEndpoint, OnboardingAuditStage,
    RedfishDiscovery, ResolvedCredential,
};
pub use endpoint_refresh::{
    CoreResourceReader, EndpointRefresh, EndpointRefreshError, EndpointRefreshRepository,
    ResourceObservation,
};
pub use endpoint_trust::{
    EndpointTrustChallenge, EndpointTrustEstablishment, EndpointTrustTimelineError,
    PendingEndpointTrust, SystemCaEvaluation, TlsIdentityObservation, TlsIdentityProbe,
    TrustedEndpoint,
};
