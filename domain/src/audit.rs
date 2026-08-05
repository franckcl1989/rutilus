use std::{error::Error, fmt, str::FromStr};

use time::OffsetDateTime;

use crate::{
    AuditEventId, AuditOperationId, CredentialId, DeploymentPosture, EndpointAddress, EndpointId,
};

macro_rules! stable_audit_codes {
    (
        $(#[$metadata:meta])*
        pub enum $name:ident for $vocabulary:literal {
            $($variant:ident => $code:literal),+ $(,)?
        }
    ) => {
        $(#[$metadata])*
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub enum $name {
            $($variant),+
        }

        impl $name {
            /// Returns the stable product code used by persistence and protocols.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $code),+
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl FromStr for $name {
            type Err = AuditCodeParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($code => Ok(Self::$variant)),+,
                    _ => Err(AuditCodeParseError::new($vocabulary)),
                }
            }
        }
    };
}

stable_audit_codes! {
    /// The accountable product-side identity category for an operation.
    pub enum AuditActor for "actor" {
        System => "system",
        LocalOperator => "local-operator",
    }
}

stable_audit_codes! {
    /// A product permission checked before the audited action.
    pub enum ProductPermission for "product permission" {
        ManageEndpoints => "manage-endpoints",
        RefreshEndpoints => "refresh-endpoints",
    }
}

stable_audit_codes! {
    /// A stable product action represented by an audit operation.
    pub enum AuditAction for "action" {
        EnrollEndpoint => "enroll-endpoint",
        RefreshEndpoint => "refresh-endpoint",
        ImportEndpoints => "import-endpoints",
    }
}

stable_audit_codes! {
    /// The public typed Redfish operation used by a product action.
    pub enum AuditRedfishOperation for "Redfish operation" {
        None => "none",
        ProbeCoreCapabilities => "probe-core-capabilities",
        ReadCoreResources => "read-core-resources",
    }
}

stable_audit_codes! {
    /// A safe, non-secret progress milestone.
    pub enum AuditProgress for "progress" {
        EndpointCreated => "endpoint-created",
        RowValidated => "row-validated",
    }
}

stable_audit_codes! {
    /// The verification state derived from a terminal audit event.
    pub enum AuditVerification for "verification" {
        Confirmed => "confirmed",
        Rejected => "rejected",
        Inconclusive => "inconclusive",
    }
}

stable_audit_codes! {
    /// A verification state valid specifically for a failed operation.
    pub enum AuditFailureVerification for "failure verification" {
        Rejected => "rejected",
        Inconclusive => "inconclusive",
    }
}

impl AuditFailureVerification {
    #[must_use]
    pub const fn verification(self) -> AuditVerification {
        match self {
            Self::Rejected => AuditVerification::Rejected,
            Self::Inconclusive => AuditVerification::Inconclusive,
        }
    }
}

stable_audit_codes! {
    /// The lifecycle kind of one append-only audit event.
    pub enum AuditOutcomeKind for "outcome" {
        Started => "started",
        Progress => "progress",
        Succeeded => "succeeded",
        Failed => "failed",
    }
}

stable_audit_codes! {
    /// A bounded error category that cannot carry a credential or token.
    pub enum AuditFailure for "failure" {
        CredentialUnavailable => "credential-unavailable",
        TlsTrustFailed => "tls-trust-failed",
        RedfishDiscoveryFailed => "redfish-discovery-failed",
        EndpointPersistenceFailed => "endpoint-persistence-failed",
        CoreResourceReadFailed => "core-resource-read-failed",
        SnapshotPersistenceFailed => "snapshot-persistence-failed",
        CsvInvalid => "csv-invalid",
    }
}

/// A persisted audit vocabulary code is unknown to this product build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditCodeParseError {
    vocabulary: &'static str,
}

impl AuditCodeParseError {
    const fn new(vocabulary: &'static str) -> Self {
        Self { vocabulary }
    }

    #[must_use]
    pub const fn vocabulary(self) -> &'static str {
        self.vocabulary
    }
}

impl fmt::Display for AuditCodeParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown audit {} code", self.vocabulary)
    }
}

impl Error for AuditCodeParseError {}

/// A target described only by domain-validated, non-secret identity data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuditTarget {
    Product,
    EndpointAddress(EndpointAddress),
    Endpoint(EndpointId),
}

impl AuditTarget {
    /// Returns the stable target kind stored with every event.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Product => "product",
            Self::EndpointAddress(_) => "endpoint-address",
            Self::Endpoint(_) => "endpoint",
        }
    }

    /// Returns the validated target identifier, when the target has one.
    #[must_use]
    pub fn identifier(&self) -> Option<String> {
        match self {
            Self::Product => None,
            Self::EndpointAddress(address) => Some(address.to_string()),
            Self::Endpoint(endpoint_id) => Some(endpoint_id.to_string()),
        }
    }
}

/// The TLS trust decision category retained without certificate material.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuditTlsTrust {
    SystemCa,
    PinnedCertificate,
}

impl AuditTlsTrust {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SystemCa => "system-ca",
            Self::PinnedCertificate => "pinned-certificate",
        }
    }
}

impl fmt::Display for AuditTlsTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for AuditTlsTrust {
    type Err = AuditCodeParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "system-ca" => Ok(Self::SystemCa),
            "pinned-certificate" => Ok(Self::PinnedCertificate),
            _ => Err(AuditCodeParseError::new("TLS trust")),
        }
    }
}

/// A closed, typed parameter summary whose variants cannot contain secrets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditParameterSummary {
    EndpointEnrollment {
        credential_id: CredentialId,
        trust: AuditTlsTrust,
    },
    EndpointRefresh,
    CsvEndpointImport {
        row_count: u32,
    },
}

impl AuditParameterSummary {
    /// Creates a non-empty CSV import summary.
    ///
    /// # Errors
    ///
    /// Returns [`AuditParameterSummaryError`] when no row can be represented
    /// by the operation.
    pub const fn csv_endpoint_import(row_count: u32) -> Result<Self, AuditParameterSummaryError> {
        if row_count == 0 {
            return Err(AuditParameterSummaryError);
        }
        Ok(Self::CsvEndpointImport { row_count })
    }

    #[must_use]
    pub const fn kind(self) -> &'static str {
        match self {
            Self::EndpointEnrollment { .. } => "endpoint-enrollment",
            Self::EndpointRefresh => "endpoint-refresh",
            Self::CsvEndpointImport { .. } => "csv-endpoint-import",
        }
    }

    #[must_use]
    pub const fn credential_id(self) -> Option<CredentialId> {
        match self {
            Self::EndpointEnrollment { credential_id, .. } => Some(credential_id),
            Self::EndpointRefresh | Self::CsvEndpointImport { .. } => None,
        }
    }

    #[must_use]
    pub const fn trust(self) -> Option<AuditTlsTrust> {
        match self {
            Self::EndpointEnrollment { trust, .. } => Some(trust),
            Self::EndpointRefresh | Self::CsvEndpointImport { .. } => None,
        }
    }

    #[must_use]
    pub const fn row_count(self) -> Option<u32> {
        match self {
            Self::CsvEndpointImport { row_count } => Some(row_count),
            Self::EndpointEnrollment { .. } | Self::EndpointRefresh => None,
        }
    }
}

/// A CSV audit summary cannot represent an empty operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditParameterSummaryError;

impl fmt::Display for AuditParameterSummaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an audited CSV import must contain at least one row")
    }
}

impl Error for AuditParameterSummaryError {}

/// Immutable metadata shared by every event in one audited operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditOperationContext {
    operation_id: AuditOperationId,
    actor: AuditActor,
    origin: DeploymentPosture,
    target: AuditTarget,
    parameters: AuditParameterSummary,
    permission: ProductPermission,
    action: AuditAction,
    redfish_operation: AuditRedfishOperation,
}

impl AuditOperationContext {
    /// Creates one semantically consistent 0.1 audit operation context.
    ///
    /// # Errors
    ///
    /// Returns [`AuditOperationContextError`] when the target, parameter
    /// summary, permission, or typed Redfish operation does not match the
    /// product action.
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        operation_id: AuditOperationId,
        actor: AuditActor,
        origin: DeploymentPosture,
        target: AuditTarget,
        parameters: AuditParameterSummary,
        permission: ProductPermission,
        action: AuditAction,
        redfish_operation: AuditRedfishOperation,
    ) -> Result<Self, AuditOperationContextError> {
        let consistent = matches!(
            (&target, parameters, permission, action, redfish_operation),
            (
                AuditTarget::EndpointAddress(_),
                AuditParameterSummary::EndpointEnrollment { .. },
                ProductPermission::ManageEndpoints,
                AuditAction::EnrollEndpoint,
                AuditRedfishOperation::ProbeCoreCapabilities,
            ) | (
                AuditTarget::Endpoint(_),
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::RefreshEndpoints,
                AuditAction::RefreshEndpoint,
                AuditRedfishOperation::ReadCoreResources,
            ) | (
                AuditTarget::Product,
                AuditParameterSummary::CsvEndpointImport { .. },
                ProductPermission::ManageEndpoints,
                AuditAction::ImportEndpoints,
                AuditRedfishOperation::None,
            )
        );
        if !consistent {
            return Err(AuditOperationContextError);
        }
        Ok(Self {
            operation_id,
            actor,
            origin,
            target,
            parameters,
            permission,
            action,
            redfish_operation,
        })
    }

    #[must_use]
    pub const fn operation_id(&self) -> AuditOperationId {
        self.operation_id
    }

    #[must_use]
    pub const fn actor(&self) -> AuditActor {
        self.actor
    }

    #[must_use]
    pub const fn origin(&self) -> DeploymentPosture {
        self.origin
    }

    #[must_use]
    pub const fn target(&self) -> &AuditTarget {
        &self.target
    }

    #[must_use]
    pub const fn parameters(&self) -> AuditParameterSummary {
        self.parameters
    }

    #[must_use]
    pub const fn permission(&self) -> ProductPermission {
        self.permission
    }

    #[must_use]
    pub const fn action(&self) -> AuditAction {
        self.action
    }

    #[must_use]
    pub const fn redfish_operation(&self) -> AuditRedfishOperation {
        self.redfish_operation
    }
}

/// An audit context combined fields from different product actions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuditOperationContextError;

impl fmt::Display for AuditOperationContextError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("audit operation context fields do not describe one product action")
    }
}

impl Error for AuditOperationContextError {}

/// One immutable lifecycle fact for an audited operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditOutcome {
    Started,
    Progress(AuditProgress),
    Succeeded,
    Failed {
        failure: AuditFailure,
        verification: AuditFailureVerification,
    },
}

/// A positive, operation-local ordering key for append-only audit events.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuditSequence(u32);

impl AuditSequence {
    pub const FIRST: Self = Self(1);

    /// Validates a persisted audit sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSequenceError::Zero`] when the value cannot identify an
    /// event in an operation.
    pub const fn try_new(value: u32) -> Result<Self, AuditSequenceError> {
        if value == 0 {
            return Err(AuditSequenceError::Zero);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Returns the next contiguous operation-local sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditSequenceError::Exhausted`] instead of wrapping when an
    /// operation has reached the representable event limit.
    pub const fn next(self) -> Result<Self, AuditSequenceError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(AuditSequenceError::Exhausted),
        }
    }
}

/// An audit sequence is zero or cannot advance without wrapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditSequenceError {
    Zero,
    Exhausted,
}

impl fmt::Display for AuditSequenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter.write_str("audit event sequence must be positive"),
            Self::Exhausted => formatter.write_str("audit event sequence is exhausted"),
        }
    }
}

impl Error for AuditSequenceError {}

impl AuditOutcome {
    #[must_use]
    pub const fn kind(self) -> AuditOutcomeKind {
        match self {
            Self::Started => AuditOutcomeKind::Started,
            Self::Progress(_) => AuditOutcomeKind::Progress,
            Self::Succeeded => AuditOutcomeKind::Succeeded,
            Self::Failed { .. } => AuditOutcomeKind::Failed,
        }
    }

    #[must_use]
    pub const fn progress(self) -> Option<AuditProgress> {
        match self {
            Self::Progress(progress) => Some(progress),
            Self::Started | Self::Succeeded | Self::Failed { .. } => None,
        }
    }

    #[must_use]
    pub const fn failure(self) -> Option<AuditFailure> {
        match self {
            Self::Failed { failure, .. } => Some(failure),
            Self::Started | Self::Progress(_) | Self::Succeeded => None,
        }
    }

    #[must_use]
    pub const fn verification(self) -> Option<AuditVerification> {
        match self {
            Self::Succeeded => Some(AuditVerification::Confirmed),
            Self::Failed { verification, .. } => Some(verification.verification()),
            Self::Started | Self::Progress(_) => None,
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed { .. })
    }
}

/// One immutable, append-only audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEvent {
    id: AuditEventId,
    context: AuditOperationContext,
    sequence: AuditSequence,
    outcome: AuditOutcome,
    occurred_at: OffsetDateTime,
}

impl AuditEvent {
    /// Rehydrates an event while preserving action-specific progress meaning.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventError`] when a progress code belongs to a different
    /// product action.
    pub fn try_from_parts(
        id: AuditEventId,
        context: AuditOperationContext,
        sequence: AuditSequence,
        outcome: AuditOutcome,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, AuditEventError> {
        let sequence_matches_outcome = match outcome {
            AuditOutcome::Started => sequence == AuditSequence::FIRST,
            AuditOutcome::Progress(_) | AuditOutcome::Succeeded | AuditOutcome::Failed { .. } => {
                sequence > AuditSequence::FIRST
            }
        };
        if !sequence_matches_outcome {
            return Err(AuditEventError::InvalidSequence);
        }
        if let AuditOutcome::Progress(progress) = outcome {
            let consistent = matches!(
                (context.action(), progress),
                (AuditAction::EnrollEndpoint, AuditProgress::EndpointCreated)
                    | (AuditAction::ImportEndpoints, AuditProgress::RowValidated)
            );
            if !consistent {
                return Err(AuditEventError::InvalidProgress);
            }
        }
        Ok(Self::new(id, context, sequence, outcome, occurred_at))
    }

    #[must_use]
    pub fn started(context: AuditOperationContext, occurred_at: OffsetDateTime) -> Self {
        Self::new(
            AuditEventId::generate(),
            context,
            AuditSequence::FIRST,
            AuditOutcome::Started,
            occurred_at,
        )
    }

    /// Creates an action-compatible progress event.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventError`] when the milestone belongs to another
    /// product action.
    pub fn progress(
        context: AuditOperationContext,
        sequence: AuditSequence,
        progress: AuditProgress,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, AuditEventError> {
        Self::try_from_parts(
            AuditEventId::generate(),
            context,
            sequence,
            AuditOutcome::Progress(progress),
            occurred_at,
        )
    }

    /// Creates a confirmed terminal event after the start sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventError::InvalidSequence`] for the start sequence.
    pub fn succeeded(
        context: AuditOperationContext,
        sequence: AuditSequence,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, AuditEventError> {
        Self::try_from_parts(
            AuditEventId::generate(),
            context,
            sequence,
            AuditOutcome::Succeeded,
            occurred_at,
        )
    }

    /// Creates a failed terminal event after the start sequence.
    ///
    /// # Errors
    ///
    /// Returns [`AuditEventError::InvalidSequence`] for the start sequence.
    pub fn failed(
        context: AuditOperationContext,
        sequence: AuditSequence,
        failure: AuditFailure,
        verification: AuditFailureVerification,
        occurred_at: OffsetDateTime,
    ) -> Result<Self, AuditEventError> {
        Self::try_from_parts(
            AuditEventId::generate(),
            context,
            sequence,
            AuditOutcome::Failed {
                failure,
                verification,
            },
            occurred_at,
        )
    }

    #[must_use]
    pub const fn id(&self) -> AuditEventId {
        self.id
    }

    #[must_use]
    pub const fn context(&self) -> &AuditOperationContext {
        &self.context
    }

    #[must_use]
    pub const fn sequence(&self) -> AuditSequence {
        self.sequence
    }

    #[must_use]
    pub const fn outcome(&self) -> AuditOutcome {
        self.outcome
    }

    #[must_use]
    pub const fn occurred_at(&self) -> OffsetDateTime {
        self.occurred_at
    }

    const fn new(
        id: AuditEventId,
        context: AuditOperationContext,
        sequence: AuditSequence,
        outcome: AuditOutcome,
        occurred_at: OffsetDateTime,
    ) -> Self {
        Self {
            id,
            context,
            sequence,
            outcome,
            occurred_at,
        }
    }
}

/// An audit event combined an outcome with an invalid sequence or action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEventError {
    InvalidSequence,
    InvalidProgress,
}

impl fmt::Display for AuditEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSequence => {
                formatter.write_str("audit outcome is invalid at this operation sequence")
            }
            Self::InvalidProgress => {
                formatter.write_str("audit progress does not belong to the operation action")
            }
        }
    }
}

impl Error for AuditEventError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_vocabularies_round_trip_without_dynamic_text() {
        assert_codes(&[AuditActor::System, AuditActor::LocalOperator]);
        assert_codes(&[
            ProductPermission::ManageEndpoints,
            ProductPermission::RefreshEndpoints,
        ]);
        assert_codes(&[
            AuditAction::EnrollEndpoint,
            AuditAction::RefreshEndpoint,
            AuditAction::ImportEndpoints,
        ]);
        assert_codes(&[
            AuditRedfishOperation::None,
            AuditRedfishOperation::ProbeCoreCapabilities,
            AuditRedfishOperation::ReadCoreResources,
        ]);
        assert_codes(&[AuditProgress::EndpointCreated, AuditProgress::RowValidated]);
        assert_codes(&[
            AuditVerification::Confirmed,
            AuditVerification::Rejected,
            AuditVerification::Inconclusive,
        ]);
        assert_codes(&[
            AuditFailureVerification::Rejected,
            AuditFailureVerification::Inconclusive,
        ]);
        assert_codes(&[
            AuditOutcomeKind::Started,
            AuditOutcomeKind::Progress,
            AuditOutcomeKind::Succeeded,
            AuditOutcomeKind::Failed,
        ]);
        assert_codes(&[
            AuditFailure::CredentialUnavailable,
            AuditFailure::TlsTrustFailed,
            AuditFailure::RedfishDiscoveryFailed,
            AuditFailure::EndpointPersistenceFailed,
            AuditFailure::CoreResourceReadFailed,
            AuditFailure::SnapshotPersistenceFailed,
            AuditFailure::CsvInvalid,
        ]);
        assert_eq!(
            "unknown".parse::<AuditAction>(),
            Err(AuditCodeParseError::new("action"))
        );
    }

    #[test]
    fn context_accepts_only_coherent_action_metadata() -> Result<(), Box<dyn Error>> {
        let address = EndpointAddress::parse("https://192.0.2.80")?;
        let credential_id = CredentialId::generate();
        let context = enrollment_context(address.clone(), credential_id)?;

        assert_eq!(context.actor(), AuditActor::LocalOperator);
        assert_eq!(context.origin(), DeploymentPosture::Standalone);
        assert_eq!(context.target(), &AuditTarget::EndpointAddress(address));
        assert_eq!(context.permission(), ProductPermission::ManageEndpoints);
        assert_eq!(context.action(), AuditAction::EnrollEndpoint);
        assert_eq!(
            context.redfish_operation(),
            AuditRedfishOperation::ProbeCoreCapabilities
        );
        assert!(matches!(
            context.parameters(),
            AuditParameterSummary::EndpointEnrollment {
                credential_id: id,
                trust: AuditTlsTrust::PinnedCertificate,
            } if id == credential_id
        ));

        assert!(matches!(
            AuditOperationContext::try_new(
                AuditOperationId::generate(),
                AuditActor::System,
                DeploymentPosture::Site,
                AuditTarget::Product,
                AuditParameterSummary::EndpointRefresh,
                ProductPermission::RefreshEndpoints,
                AuditAction::RefreshEndpoint,
                AuditRedfishOperation::ReadCoreResources,
            ),
            Err(AuditOperationContextError)
        ));
        Ok(())
    }

    #[test]
    fn typed_parameter_summaries_expose_no_secret_value_slot() -> Result<(), Box<dyn Error>> {
        let credential_id = CredentialId::generate();
        let enrollment = AuditParameterSummary::EndpointEnrollment {
            credential_id,
            trust: AuditTlsTrust::SystemCa,
        };
        let import = AuditParameterSummary::csv_endpoint_import(25)?;

        assert_eq!(enrollment.kind(), "endpoint-enrollment");
        assert_eq!(enrollment.credential_id(), Some(credential_id));
        assert_eq!(enrollment.trust(), Some(AuditTlsTrust::SystemCa));
        assert_eq!(enrollment.row_count(), None);
        assert_eq!(import.kind(), "csv-endpoint-import");
        assert_eq!(import.row_count(), Some(25));
        assert_eq!(
            AuditParameterSummary::csv_endpoint_import(0),
            Err(AuditParameterSummaryError)
        );
        Ok(())
    }

    #[test]
    fn immutable_events_retain_start_progress_and_terminal_facts() -> Result<(), Box<dyn Error>> {
        let context = enrollment_context(
            EndpointAddress::parse("https://bmc.example.test")?,
            CredentialId::generate(),
        )?;
        let now = OffsetDateTime::now_utc();
        let started = AuditEvent::started(context.clone(), now);
        let progress_sequence = AuditSequence::FIRST.next()?;
        let progress = AuditEvent::progress(
            context.clone(),
            progress_sequence,
            AuditProgress::EndpointCreated,
            now,
        )?;
        let terminal_sequence = progress_sequence.next()?;
        let succeeded = AuditEvent::succeeded(context.clone(), terminal_sequence, now)?;
        let failed = AuditEvent::failed(
            context,
            terminal_sequence,
            AuditFailure::CoreResourceReadFailed,
            AuditFailureVerification::Inconclusive,
            now,
        )?;

        assert_eq!(started.outcome().kind(), AuditOutcomeKind::Started);
        assert!(!started.outcome().is_terminal());
        assert_eq!(
            progress.outcome().progress(),
            Some(AuditProgress::EndpointCreated)
        );
        assert_eq!(
            succeeded.outcome().verification(),
            Some(AuditVerification::Confirmed)
        );
        assert!(succeeded.outcome().is_terminal());
        assert_eq!(
            failed.outcome().failure(),
            Some(AuditFailure::CoreResourceReadFailed)
        );
        assert_eq!(failed.occurred_at(), now);
        assert_eq!(started.sequence(), AuditSequence::FIRST);
        assert_eq!(progress.sequence(), progress_sequence);
        assert_ne!(started.id(), progress.id());
        assert_eq!(
            started.context().operation_id(),
            progress.context().operation_id()
        );
        assert_eq!(
            AuditEvent::progress(
                context_for_refresh()?,
                progress_sequence,
                AuditProgress::EndpointCreated,
                now,
            ),
            Err(AuditEventError::InvalidProgress)
        );
        assert_eq!(
            AuditEvent::succeeded(context_for_refresh()?, AuditSequence::FIRST, now),
            Err(AuditEventError::InvalidSequence)
        );
        Ok(())
    }

    #[test]
    fn audit_sequences_are_positive_contiguous_and_non_wrapping() {
        assert_eq!(AuditSequence::try_new(0), Err(AuditSequenceError::Zero));
        assert_eq!(AuditSequence::FIRST.get(), 1);
        assert_eq!(AuditSequence::FIRST.next(), AuditSequence::try_new(2));
        assert_eq!(
            AuditSequence::try_new(u32::MAX).and_then(AuditSequence::next),
            Err(AuditSequenceError::Exhausted)
        );
    }

    fn enrollment_context(
        address: EndpointAddress,
        credential_id: CredentialId,
    ) -> Result<AuditOperationContext, AuditOperationContextError> {
        AuditOperationContext::try_new(
            AuditOperationId::generate(),
            AuditActor::LocalOperator,
            DeploymentPosture::Standalone,
            AuditTarget::EndpointAddress(address),
            AuditParameterSummary::EndpointEnrollment {
                credential_id,
                trust: AuditTlsTrust::PinnedCertificate,
            },
            ProductPermission::ManageEndpoints,
            AuditAction::EnrollEndpoint,
            AuditRedfishOperation::ProbeCoreCapabilities,
        )
    }

    fn context_for_refresh() -> Result<AuditOperationContext, AuditOperationContextError> {
        AuditOperationContext::try_new(
            AuditOperationId::generate(),
            AuditActor::System,
            DeploymentPosture::Site,
            AuditTarget::Endpoint(EndpointId::generate()),
            AuditParameterSummary::EndpointRefresh,
            ProductPermission::RefreshEndpoints,
            AuditAction::RefreshEndpoint,
            AuditRedfishOperation::ReadCoreResources,
        )
    }

    fn assert_codes<Value>(values: &[Value])
    where
        Value: Copy + Eq + fmt::Debug + fmt::Display + FromStr<Err = AuditCodeParseError>,
    {
        for value in values {
            assert_eq!(value.to_string().parse::<Value>(), Ok(*value));
        }
    }
}
