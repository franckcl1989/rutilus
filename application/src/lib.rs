#![forbid(unsafe_code)]

mod artifact_store;
mod audit_log;
mod capability_query;
mod command_executor;
mod credential_management;
mod endpoint_csv;
mod endpoint_csv_import;
mod endpoint_enrollment;
mod endpoint_inventory;
mod endpoint_onboarding;
mod endpoint_refresh;
mod endpoint_resources;
mod endpoint_trust;
mod event_ingestion;
mod group_management;
mod operation_executor;
mod operation_submission;
mod tag_management;
mod task_monitor;
mod telemetry_sampler;
mod update_executor;

pub use artifact_store::{
    ARTIFACT_CHUNK_BASE64_MAX_BYTES, ArtifactProgress, ArtifactRepository, ArtifactStore,
    ArtifactStoreError,
};
pub use audit_log::{AuditEventWriter, AuditRecordError};
pub use capability_query::{
    CapabilityLedgerEntry, CapabilityQueryRepository, EndpointCapabilityQuery,
    EndpointCapabilityQueryError, StoredCapability,
};
pub use command_executor::{
    CommandExecutor, CommandOutcome, CommandVerifier, DispatchVerdict, DispatchVerdictClassifier,
    VerificationVerdict,
};
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
    AuditedEndpointRefresh, AuditedEndpointRefreshError, CapabilitySnapshotRepository,
    CoreResourceReader, EndpointRefresh, EndpointRefreshError, EndpointRefreshRepository,
    RefreshAuditStage, ResourceObservation,
};
pub use endpoint_resources::{
    CoreResourceCommon, CoreResourceDetails, CoreResourceSummary, EndpointResourceInventory,
    EndpointResourceInventoryQuery, EndpointResourceInventoryQueryError, MetricValueSummary,
    ResourceStatusSummary,
};
pub use endpoint_trust::{
    EndpointTrustChallenge, EndpointTrustEstablishment, EndpointTrustExpectation,
    EndpointTrustExpectationError, EndpointTrustTimelineError, PendingEndpointTrust,
    SystemCaEvaluation, TlsIdentityObservation, TlsIdentityProbe, TrustedEndpoint,
};
pub use event_ingestion::{
    EventIngestion, EventRepository, EventStream, EventStreamPull, IngestionError,
};
pub use group_management::{GroupManagement, GroupManagementError, GroupRepository};
pub use operation_executor::{ExecutorError, OperationAuditStage, OperationExecutor};
pub use operation_submission::{OperationSubmission, SubmissionError};
pub use tag_management::{TagManagement, TagManagementError, TagRepository};
pub use task_monitor::{
    MonitorAuditStage, TaskMonitor, TaskMonitorError, TaskObservation, TaskPoll, TaskReader,
};
pub use telemetry_sampler::{
    EndpointSampling, MetricReportReadError, MetricReportReader, MetricReportReading,
    MetricReportSnapshotReader, MetricReportValues, MetricReportValuesError, TelemetryRepository,
    TelemetrySampler, TelemetrySamplerError,
};
pub use update_executor::{UpdateArtifactPayload, UpdateExecutor};

/// The persistence boundary of the Operation lifecycle, re-exported from the
/// engine so the Web crate can aggregate it into its product-services bundle
/// without a direct engine dependency; the application use cases compose the
/// same trait behind this facade.
pub use rutilus_operation_engine::OperationStore;
