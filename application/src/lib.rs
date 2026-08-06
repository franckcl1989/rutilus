#![forbid(unsafe_code)]

mod audit_log;
mod credential_management;
mod endpoint_csv;
mod endpoint_csv_import;
mod endpoint_enrollment;
mod endpoint_inventory;
mod endpoint_onboarding;
mod endpoint_refresh;
mod endpoint_resources;
mod endpoint_trust;

pub use audit_log::{AuditEventWriter, AuditRecordError};
pub use credential_management::{
    CREDENTIAL_SECRET_MAX_BYTES, CredentialCreation, CredentialCreationError,
    CredentialCreationRepository, CredentialInventoryQuery, CredentialInventoryQueryError,
    CredentialInventoryRepository, CredentialSecretError, CredentialSecretProtector,
    NewCredentialRequest, ProtectedCredentialCreation,
};
pub use endpoint_csv::{
    ENDPOINT_CSV_HEADERS, ENDPOINT_CSV_MAX_BYTES, ENDPOINT_CSV_MAX_ROWS, EndpointCsvImport,
    EndpointCsvImportError, EndpointCsvRequiredField, EndpointCsvRow, EndpointImportTrust,
    parse_endpoint_csv,
};
pub use endpoint_csv_import::{
    EndpointCsvImportAuditStage, EndpointCsvImportExecutionError, EndpointCsvImportExecutor,
    EndpointCsvImportReport, EndpointCsvRowOutcome, EndpointCsvRowResult,
};
pub use endpoint_enrollment::{
    EndpointEnroller, EndpointEnrollment, EndpointEnrollmentError, EnrolledEndpoint,
};
pub use endpoint_inventory::{
    EndpointInventoryItem, EndpointInventoryItemError, EndpointInventoryQuery,
    EndpointInventoryQueryError, EndpointInventoryRepository,
};
pub use endpoint_onboarding::{
    AuditedEndpointOnboarding, AuditedOnboardEndpointError, BoundaryFuture, Clock,
    CredentialResolver, DiscoveredEndpointRepository, EndpointDiscovery, EndpointOnboarding,
    OnboardEndpointError, OnboardEndpointRequest, OnboardedEndpoint, OnboardingAuditStage,
    RedfishDiscovery, ResolvedCredential,
};
pub use endpoint_refresh::{
    AuditedEndpointRefresh, AuditedEndpointRefreshError, CoreResourceReader, EndpointRefresh,
    EndpointRefreshError, EndpointRefreshRepository, RefreshAuditStage, ResourceObservation,
};
pub use endpoint_resources::{
    CoreResourceCommon, CoreResourceDetails, CoreResourceSummary, EndpointResourceInventory,
    EndpointResourceInventoryQuery, EndpointResourceInventoryQueryError, ResourceStatusSummary,
};
pub use endpoint_trust::{
    EndpointTrustChallenge, EndpointTrustEstablishment, EndpointTrustExpectation,
    EndpointTrustExpectationError, EndpointTrustTimelineError, PendingEndpointTrust,
    SystemCaEvaluation, TlsIdentityObservation, TlsIdentityProbe, TrustedEndpoint,
};
